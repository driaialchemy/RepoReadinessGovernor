"""Multi-repository governance runner."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

from .accepted_risks import load_accepted_risks
from .classifier import classify_repo
from .evidence_report import enrich_repo_result_for_report, generate_evidence_reports
from .goal_based_loop import (
    _classified_repo_to_dict,
    _repo_info_to_dict,
    _remaining_issues,
    generate_starter_agent_prompt,
    run_goal_based_loop,
    run_initial_scan,
    run_remediation_agent,
)
from .policy import generate_repo_policy
from .repo_discovery import (
    VALID_MODES,
    RegistryRepo,
    load_effective_repo_registry,
    load_repo_discovery_config,
)
from .scanner import scan_repo
from .security import redact_dict, redact_secrets, resolve_github_token

RunMode = Literal["scan_only", "prompt_only", "goal_loop"]


@dataclass
class MultiRepoRunResult:
    run_id: str
    timestamp: str
    report_date: str
    github_owner: str
    mode: str
    total_discovered: int = 0
    repo_results: list[dict[str, Any]] = field(default_factory=list)
    skipped_repos: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    discovery_warnings: list[str] = field(default_factory=list)
    audit_summary_path: str | None = None
    email_delivery_status: str = "not_attempted"
    email_delivery_message: str = ""
    evidence_report_paths: dict[str, str] = field(default_factory=dict)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_mode(mode: str) -> str:
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode: {mode}. Must be one of: {', '.join(sorted(VALID_MODES))}")
    return mode


def _sanitize_message(message: str, token: str | None = None) -> str:
    """Remove secrets from error messages before logging or reporting."""
    extras = [token] if token else []
    return redact_secrets(message, extra_values=extras)


def _log_repo_diag(message: str, *, token: str | None = None) -> None:
    """Emit sanitized diagnostic lines for CI without leaking secrets."""
    logger.info(_sanitize_message(message, token))


def _verify_cloned_repo(target: Path) -> Path:
    """Ensure clone destination exists, is a directory, and contains .git."""
    resolved = target.resolve()
    if not resolved.is_dir():
        raise RuntimeError(f"Clone target is not a directory: {resolved}")
    if not (resolved / ".git").exists():
        raise RuntimeError(f"Clone target is missing .git directory: {resolved}")
    return resolved


def clone_or_update_target_repo(
    repo_entry: RegistryRepo,
    workspace_dir: Path,
    *,
    token: str | None = None,
) -> Path:
    """Clone or update a repository into the workspace directory.

    Workspace and clone destinations are resolved to absolute paths before
    invoking git. A relative destination with cwd=workspace/repos would
    otherwise nest clones at workspace/repos/workspace/repos/<name>, after
    which the scanner looks at workspace/repos/<name> and reports
    "Not a directory".
    """
    workspace = workspace_dir.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    target = (workspace / repo_entry.name).resolve()

    clone_url = repo_entry.url
    clean_token = (token or "").strip()
    if clean_token and clone_url.startswith("https://"):
        clone_url = clone_url.replace("https://", f"https://x-access-token:{clean_token}@", 1)

    if target.exists() and target.is_dir() and (target / ".git").exists():
        _git(["fetch", "--all", "--prune"], cwd=target, token=token)
        _git(["checkout", repo_entry.branch], cwd=target, token=token)
        _git(["pull", "--ff-only", "origin", repo_entry.branch], cwd=target, token=token)
        return _verify_cloned_repo(target)

    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()

    try:
        _git(
            [
                "clone",
                "--branch",
                repo_entry.branch,
                "--single-branch",
                clone_url,
                str(target),
            ],
            cwd=workspace,
            token=token,
        )
    except RuntimeError:
        if clean_token and repo_entry.visibility == "public":
            _git(
                [
                    "clone",
                    "--branch",
                    repo_entry.branch,
                    "--single-branch",
                    repo_entry.url,
                    str(target),
                ],
                cwd=workspace,
                token=token,
            )
        else:
            raise
    return _verify_cloned_repo(target)


def _git(args: list[str], *, cwd: Path, token: str | None = None) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip()
        safe_args = " ".join(redact_secrets(arg) for arg in args)
        raise RuntimeError(_sanitize_message(f"git {safe_args} failed: {stderr}", token))


def _write_repo_audit(audit_dir: Path, repo_name: str, payload: dict[str, Any]) -> Path:
    audit_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = audit_dir / f"repo_{repo_name}_{ts}.json"
    path.write_text(json.dumps(redact_dict(payload), indent=2), encoding="utf-8")
    return path


def run_repo_governance_check(
    repo_path: Path,
    repo_entry: RegistryRepo,
    *,
    mode: str,
    audit_dir: Path,
    goal: str = "make repo agent-ready",
) -> dict[str, Any]:
    """Run governance check for a single repo in the requested mode."""
    mode = _validate_mode(mode)
    effective_mode = repo_entry.mode if repo_entry.mode in VALID_MODES else mode
    _validate_mode(effective_mode)

    result: dict[str, Any] = {
        "name": repo_entry.name,
        "full_name": repo_entry.full_name,
        "mode": effective_mode,
        "status": "failed",
        "passed": False,
        "errors": [],
    }

    try:
        if effective_mode == "goal_loop":
            loop_result = run_goal_based_loop(
                repo_path,
                goal=goal,
                audit_dir=audit_dir / "goal_loops",
                overwrite_policy=False,
            )
            result.update({
                "status": "scanned",
                "passed": loop_result.passed,
                "risk_level": loop_result.initial_risk_level,
                "verification_risk_level": loop_result.verification_risk_level,
                "agent_ready": loop_result.verification_agent_ready,
                "remediation_status": (
                    "goal_loop_requested_but_agent_execution_not_configured"
                    if loop_result.remediation_status == "manual_agent_prompt_generated"
                    else loop_result.remediation_status
                ),
                "verification_status": "verified" if loop_result.verification_risk_level else "not_verified",
                "remaining_issues": loop_result.remaining_issues,
                "audit_path": loop_result.audit_log_path,
                "policy_artifact_status": (
                    "generated" if loop_result.generated_artifacts else "existing or not generated"
                ),
                "errors": loop_result.errors,
            })
            if loop_result.audit_log_path and Path(loop_result.audit_log_path).exists():
                audit_data = json.loads(Path(loop_result.audit_log_path).read_text(encoding="utf-8"))
                scan = audit_data.get("initial_scan") or {}
                risk = audit_data.get("risk_classification") or {}
                result["initial_scan"] = scan
                result["has_claude_md"] = scan.get("has_claude_md", False)
                result["readiness_score"] = risk.get("readiness_score")
            return enrich_repo_result_for_report(result)

        repo_info = run_initial_scan(repo_path)
        classified = classify_repo(repo_info, accepted=load_accepted_risks())
        scan_dict = _repo_info_to_dict(repo_info)
        risk_dict = _classified_repo_to_dict(classified)

        result.update({
            "status": "scanned",
            "passed": classified.agent_ready,
            "risk_level": classified.risk_level.value,
            "readiness_score": classified.readiness_score,
            "agent_ready": classified.agent_ready,
            "initial_scan": scan_dict,
            "has_claude_md": repo_info.has_claude_md,
            "remaining_issues": _remaining_issues(classified),
            "accepted_risks": classified.accepted_risks,
            "policy_artifact_status": "recommendations_only",
            "remediation_status": "not_requested",
            "verification_status": "scan_only_no_verification_loop",
            "governance_status": classified.governance_status,
        })

        loop_output = audit_dir / "prompts" / repo_entry.name
        remediation_status = "not_requested"
        remediation_summary = ""
        agent_prompt_path = None
        remediation_plan_path = None
        generated_artifacts: list[str] = []

        if effective_mode == "prompt_only":
            policy_dict = generate_repo_policy(classified)
            prompt = generate_starter_agent_prompt(
                repo_path, repo_info, classified, policy_dict, goal=goal
            )
            plan_lines = [
                "# Remediation Plan",
                "",
                f"Repository: {repo_entry.full_name}",
                f"Risk level: {classified.risk_level.value}",
                "",
                "## Recommended actions",
            ]
            plan_lines.extend(f"- {a}" for a in classified.recommended_actions)
            remediation_status, remediation_summary, prompt_file, plan_file = (
                run_remediation_agent(
                    repo_path,
                    prompt,
                    "\n".join(plan_lines),
                    loop_output,
                )
            )
            agent_prompt_path = str(prompt_file)
            remediation_plan_path = str(plan_file)
            result["policy_artifact_status"] = "prompt_generated_not_written_to_repo"
            result["verification_status"] = "prompt_only_no_repo_changes"

        audit_payload = {
            "repo": repo_entry.full_name,
            "mode": effective_mode,
            "timestamp": _utc_now_iso(),
            "initial_scan": scan_dict,
            "risk_classification": risk_dict,
            "generated_artifacts": generated_artifacts,
            "agent_prompt_path": agent_prompt_path,
            "remediation_plan_path": remediation_plan_path,
            "remediation_status": remediation_status,
            "remediation_summary": remediation_summary,
            "passed": classified.agent_ready,
            "remaining_issues": result["remaining_issues"],
            "errors": [],
        }
        audit_path = _write_repo_audit(audit_dir, repo_entry.name, audit_payload)
        result["audit_path"] = str(audit_path)
        result["remediation_status"] = remediation_status
        return enrich_repo_result_for_report(result)

    except Exception as exc:
        safe_exc = _sanitize_message(str(exc))
        result["errors"].append(safe_exc)
        result["status"] = "scan_failed"
        result["failure_stage"] = "scan"
        audit_path = _write_repo_audit(
            audit_dir,
            repo_entry.name,
            {
                "repo": repo_entry.full_name,
                "mode": effective_mode,
                "timestamp": _utc_now_iso(),
                "status": "failed",
                "errors": result["errors"],
            },
        )
        result["audit_path"] = str(audit_path)
        return enrich_repo_result_for_report(result)


def run_multi_repo_governance_check(
    *,
    owner: str | None = None,
    mode: str = "scan_only",
    discover: bool = True,
    workspace_dir: Path | None = None,
    audit_dir: Path | None = None,
    send_email: bool = False,
    use_local_path_for: dict[str, Path] | None = None,
) -> MultiRepoRunResult:
    """Discover and run governance checks across all eligible repositories."""
    mode = _validate_mode(mode)
    run_id = str(uuid.uuid4())
    now = _utc_now_iso()
    report_date = date.today().isoformat()

    config = load_repo_discovery_config()
    github_owner = owner or config.get("github_owner", "driaialchemy")

    run = MultiRepoRunResult(
        run_id=run_id,
        timestamp=now,
        report_date=report_date,
        github_owner=github_owner,
        mode=mode,
    )

    if discover:
        try:
            enabled, skipped, warnings = load_effective_repo_registry(owner=github_owner)
            run.discovery_warnings = warnings
            run.total_discovered = len(enabled) + len(skipped)
            run.skipped_repos = [s.to_dict() for s in skipped]
        except Exception as exc:
            run.errors.append(f"Discovery failed: {exc}")
            return run
    else:
        from .repo_discovery import load_generated_repo_registry

        enabled = [r for r in load_generated_repo_registry() if r.enabled]
        run.total_discovered = len(enabled)

    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    ws = (workspace_dir or Path("workspace") / "repos").expanduser().resolve()
    audit_root = audit_dir or Path("audit") / "multi_repo" / report_date
    audit_root.mkdir(parents=True, exist_ok=True)

    token, token_warning = resolve_github_token()
    if token_warning:
        run.discovery_warnings.append(token_warning)
    local_overrides = use_local_path_for or {}

    for entry in enabled:
        effective_mode = entry.mode if entry.mode in VALID_MODES else mode
        clone_dest = ws / entry.name
        _log_repo_diag(f"Preparing repo: {entry.full_name}", token=token)
        _log_repo_diag(f"Clone destination: {clone_dest}", token=token)
        try:
            if entry.name in local_overrides:
                repo_path = local_overrides[entry.name].resolve()
                _log_repo_diag(f"Using local override path: {repo_path}", token=token)
            else:
                repo_path = clone_or_update_target_repo(entry, ws, token=token)
                _log_repo_diag("Clone status: success", token=token)
            repo_result = run_repo_governance_check(
                repo_path,
                entry,
                mode=effective_mode,
                audit_dir=audit_root,
            )
            scan_ok = repo_result.get("status") == "scanned"
            _log_repo_diag(
                f"Scan status: {'success' if scan_ok else 'failed'}",
                token=token,
            )
            if repo_result.get("audit_path"):
                _log_repo_diag(f"Audit path: {repo_result['audit_path']}", token=token)
            run.repo_results.append(repo_result)
        except Exception as exc:
            safe_exc = _sanitize_message(str(exc), token)
            _log_repo_diag("Clone status: failed", token=token)
            run.errors.append(f"{entry.name}: {safe_exc}")
            run.repo_results.append({
                "name": entry.name,
                "full_name": entry.full_name,
                "status": "clone_failed",
                "failure_stage": "clone",
                "passed": False,
                "errors": [safe_exc],
                "audit_path": None,
            })

    unattempted_count = max(len(enabled) - len(run.repo_results), 0)
    if unattempted_count:
        run.errors.append(
            f"{unattempted_count} eligible repositories were not attempted by the scan loop."
        )

    scanned_results = [r for r in run.repo_results if r.get("status") == "scanned"]
    clone_failed_results = [r for r in run.repo_results if r.get("status") == "clone_failed"]
    scan_failed_results = [r for r in run.repo_results if r.get("status") == "scan_failed"]
    passed_results = [r for r in scanned_results if r.get("passed")]

    summary_path = audit_root / f"multi_repo_run_{run_id[:8]}.json"
    summary = {
        "run_id": run_id,
        "timestamp": now,
        "github_owner": github_owner,
        "mode": mode,
        "total_discovered": run.total_discovered,
        "total_eligible": len(enabled),
        "total_scanned": len(scanned_results),
        "total_clone_failed": len(clone_failed_results),
        "total_scan_failed": len(scan_failed_results),
        "total_skipped": len(run.skipped_repos),
        "total_passed": len(passed_results),
        "total_needs_work": len([r for r in scanned_results if not r.get("passed")]),
        "skipped_repos": run.skipped_repos,
        "repo_results": run.repo_results,
        "errors": run.errors,
        "discovery_warnings": run.discovery_warnings,
    }
    summary_path.write_text(json.dumps(redact_dict(summary), indent=2), encoding="utf-8")
    run.audit_summary_path = str(summary_path)

    report_paths = generate_evidence_reports(run)

    if send_email:
        from .email_delivery import send_evidence_email

        email_result = send_evidence_email(
            report_date=date.fromisoformat(report_date),
            text_path=report_paths.text_path,
            markdown_path=report_paths.markdown_path,
            json_path=report_paths.json_path,
            run_summary_path=summary_path,
        )
        run.email_delivery_status = email_result.status
        run.email_delivery_message = email_result.message
        if email_result.missing_variables:
            run.discovery_warnings.append(
                "Missing email env vars: " + ", ".join(email_result.missing_variables)
            )
        report_paths = generate_evidence_reports(run)
    else:
        run.email_delivery_status = "not_attempted"

    run.evidence_report_paths = {
        "markdown": str(report_paths.markdown_path),
        "text": str(report_paths.text_path),
        "json": str(report_paths.json_path),
    }

    summary["email_delivery_status"] = run.email_delivery_status
    summary["email_delivery_message"] = run.email_delivery_message
    summary_path.write_text(json.dumps(redact_dict(summary), indent=2), encoding="utf-8")

    return run


def main() -> None:
    import argparse
    import sys

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(
        description="Run multi-repo governance checks for a GitHub owner.",
    )
    parser.add_argument("--owner", default=None, help="GitHub owner (default: from config).")
    parser.add_argument(
        "--mode",
        default="scan_only",
        choices=sorted(VALID_MODES),
        help="Governance mode (default: scan_only).",
    )
    parser.add_argument("--discover", action="store_true", help="Discover repos from GitHub.")
    parser.add_argument("--send-email", action="store_true", help="Email the evidence report.")
    parser.add_argument("--workspace", default=None, help="Clone workspace directory.")
    parser.add_argument("--audit-dir", default=None, help="Audit output directory.")
    args = parser.parse_args()

    try:
        result = run_multi_repo_governance_check(
            owner=args.owner,
            mode=args.mode,
            discover=args.discover or True,
            workspace_dir=Path(args.workspace) if args.workspace else None,
            audit_dir=Path(args.audit_dir) if args.audit_dir else None,
            send_email=args.send_email,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    scanned = len([r for r in result.repo_results if r.get("status") == "scanned"])
    clone_failed = len([r for r in result.repo_results if r.get("status") == "clone_failed"])
    scan_failed = len([r for r in result.repo_results if r.get("status") == "scan_failed"])
    passed = len([r for r in result.repo_results if r.get("passed")])
    print(f"Run ID: {result.run_id}")
    print(f"Discovered: {result.total_discovered}")
    print(f"Eligible: {len(result.repo_results)}")
    print(f"Scanned: {scanned}")
    print(f"Clone failed: {clone_failed}")
    print(f"Scan failed: {scan_failed}")
    print(f"Skipped: {len(result.skipped_repos)}")
    print(f"Passed: {passed}")
    print(f"Email: {result.email_delivery_status}")
    if result.evidence_report_paths:
        print(f"Report: {result.evidence_report_paths.get('markdown')}")
    if result.email_delivery_status == "skipped_missing_credentials":
        from .email_delivery import GITHUB_SECRETS_HELP, missing_email_env_vars

        missing = missing_email_env_vars()
        print(f"Missing SMTP env vars: {', '.join(missing)}")
        print(f"Configure GitHub secrets: {', '.join(GITHUB_SECRETS_HELP)}")
    sys.exit(1 if result.errors else 0)


if __name__ == "__main__":
    main()
