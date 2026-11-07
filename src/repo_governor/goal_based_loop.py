"""Goal-based governance loop — scan, classify, policy, remediate, verify."""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .accepted_risks import load_accepted_risks
from .classifier import ClassifiedRepo, RiskLevel, classify_repo
from .policy import generate_repo_policy, write_policy, write_repo_policy
from .scanner import RepoInfo, scan_repo

RemediationStatus = Literal["executed", "manual_agent_prompt_generated", "failed"]

DEFAULT_GOAL = "make repo agent-ready"

ALLOWED_ACTIONS = [
    "Read source files, tests, and documentation.",
    "Add or update README.md, CLAUDE.md, AGENTS.md, and .gitignore.",
    "Create a tests/ directory with a minimal passing test when appropriate.",
    "Run linters, formatters, and the test suite.",
    "Make minimal, targeted edits to resolve blocking agent-readiness issues.",
]

PROHIBITED_ACTIONS = [
    "Do not read, print, log, or modify .env, secrets, credentials, or key files.",
    "Do not touch production deployment configuration without explicit approval.",
    "Do not delete files or directories.",
    "Do not commit or push changes automatically.",
    "Do not run destructive shell commands (rm -rf, git reset --hard, DROP TABLE, etc.).",
    "Do not install packages globally or modify system configuration.",
]

VERIFICATION_REQUIREMENTS = [
    "Re-run repo-governor scan and classify after remediation.",
    "Risk level should be LOW with no blocking issues.",
    "CLAUDE.md and .gitignore must be present.",
    "No exposed secret or credential files in the repository.",
    "Agent-ready check must pass before the loop is considered successful.",
]


@dataclass
class GoalLoopResult:
    loop_id: str
    target_repo: str
    goal: str
    initial_agent_ready: bool
    initial_risk_level: str
    generated_artifacts: list[str] = field(default_factory=list)
    agent_prompt_path: str | None = None
    remediation_plan_path: str | None = None
    remediation_status: RemediationStatus = "manual_agent_prompt_generated"
    remediation_summary: str = ""
    verification_agent_ready: bool = False
    verification_risk_level: str = ""
    passed: bool = False
    remaining_issues: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    audit_log_path: str | None = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _repo_info_to_dict(repo: RepoInfo) -> dict[str, Any]:
    return {
        "name": repo.name,
        "path": repo.path.as_posix(),
        "is_git_repo": repo.is_git_repo,
        "has_gitignore": repo.has_gitignore,
        "has_readme": repo.has_readme,
        "has_claude_md": repo.has_claude_md,
        "has_agents_md": repo.has_agents_md,
        "has_env_files": repo.has_env_files,
        "env_file_paths": repo.env_file_paths,
        "file_count": repo.file_count,
        "languages": repo.languages,
        "has_tests_dir": repo.has_tests_dir,
        "has_pyproject": repo.has_pyproject,
        "has_requirements_txt": repo.has_requirements_txt,
        "has_package_json": repo.has_package_json,
        "has_dockerfile": repo.has_dockerfile,
        "has_docker_compose": repo.has_docker_compose,
        "has_github_workflows": repo.has_github_workflows,
        "has_wrangler_toml": repo.has_wrangler_toml,
        "has_vercel_json": repo.has_vercel_json,
        "has_netlify_toml": repo.has_netlify_toml,
        "has_render_yaml": repo.has_render_yaml,
        "artifact_paths": repo.artifact_paths,
        "api_terms_found": repo.api_terms_found,
        "last_modified": repo.last_modified.isoformat(),
    }


def _classified_repo_to_dict(cr: ClassifiedRepo) -> dict[str, Any]:
    return {
        "risk_level": cr.risk_level.value,
        "readiness_score": cr.readiness_score,
        "agent_ready": cr.agent_ready,
        "risk_reasons": cr.risk_reasons,
        "blocking_issues": cr.blocking_issues,
        "accepted_risks": cr.accepted_risks,
        "recommended_actions": cr.recommended_actions,
        "decision_taxonomy": cr.decision_taxonomy or None,
        "governance_status": cr.governance_status or None,
        "scan": _repo_info_to_dict(cr.repo),
    }


def _remaining_issues(cr: ClassifiedRepo) -> list[str]:
    issues: list[str] = []
    if cr.blocking_issues:
        issues.extend(cr.blocking_issues)
    if not cr.agent_ready:
        if cr.risk_level != RiskLevel.LOW:
            issues.append(f"Risk level is {cr.risk_level.value}, expected LOW.")
        if not cr.repo.has_claude_md:
            issues.append("Missing CLAUDE.md.")
        if not cr.repo.has_gitignore:
            issues.append("Missing .gitignore.")
        if cr.repo.has_env_files:
            issues.append("Exposed secret or credential files detected.")
        for reason in cr.risk_reasons:
            if reason not in issues:
                issues.append(reason)
    return issues


def run_initial_scan(repo_path: Path) -> RepoInfo:
    """Scan a single target repository and return RepoInfo."""
    repo_path = repo_path.resolve()
    if not repo_path.is_dir():
        raise ValueError(f"Not a directory: {repo_path}")
    return scan_repo(repo_path)


def classify_repo_risk(repo_info: RepoInfo) -> ClassifiedRepo:
    """Classify repository risk from scan results."""
    return classify_repo(repo_info, accepted=load_accepted_risks())


def generate_policy_artifacts(
    repo_path: Path,
    classified: ClassifiedRepo,
    *,
    overwrite: bool = False,
) -> list[str]:
    """Generate CLAUDE.md and repo_policy.yaml; return written artifact paths."""
    repo_path = repo_path.resolve()
    claude_path = write_policy(
        repo_path,
        risk_level=classified.risk_level.value,
        overwrite=overwrite,
    )
    yaml_path = write_repo_policy(repo_path, classified, overwrite=overwrite)
    return [str(claude_path), str(yaml_path)]


def generate_starter_agent_prompt(
    repo_path: Path,
    repo_info: RepoInfo,
    classified: ClassifiedRepo,
    policy_dict: dict[str, Any],
    *,
    goal: str = DEFAULT_GOAL,
) -> str:
    """Build a bounded starter prompt for a remediation agent."""
    scan_summary = _repo_info_to_dict(repo_info)
    risk_summary = {
        "risk_level": classified.risk_level.value,
        "readiness_score": classified.readiness_score,
        "agent_ready": classified.agent_ready,
        "blocking_issues": classified.blocking_issues,
        "risk_reasons": classified.risk_reasons,
        "recommended_actions": classified.recommended_actions,
    }

    allowed = "\n".join(f"- {item}" for item in ALLOWED_ACTIONS)
    prohibited = "\n".join(f"- {item}" for item in PROHIBITED_ACTIONS)
    verification = "\n".join(f"- {item}" for item in VERIFICATION_REQUIREMENTS)
    policy_requirements = json.dumps(policy_dict, indent=2, sort_keys=False)

    return f"""# Goal-Based Remediation Prompt

## Goal
{goal}

## Target Repository
Path: `{repo_path.resolve().as_posix()}`
Name: `{repo_info.name}`

## Scan Findings
```json
{json.dumps(scan_summary, indent=2)}
```

## Risk Classification
```json
{json.dumps(risk_summary, indent=2)}
```

## Generated Policy Requirements
```json
{policy_requirements}
```

## Allowed Actions
{allowed}

## Prohibited Actions
{prohibited}

## Verification Requirements
{verification}

## Instructions
1. Make **minimal, safe changes** only — fix agent-readiness blockers, nothing more.
2. Do **not** touch secrets, credentials, production config, or destructive files.
3. Prefer adding missing governance files (README, CLAUDE.md, AGENTS.md, .gitignore) over broad refactors.
4. If a blocking issue cannot be fixed safely (e.g. exposed secrets), document it and stop.
5. After changes, the repo will be re-scanned to verify agent-ready status.
"""


def _generate_remediation_plan(classified: ClassifiedRepo) -> str:
    lines = [
        "# Remediation Plan",
        "",
        f"**Risk level:** {classified.risk_level.value}",
        f"**Readiness score:** {classified.readiness_score}/100",
        f"**Agent ready:** {'Yes' if classified.agent_ready else 'No'}",
        "",
    ]
    if classified.blocking_issues:
        lines.append("## Blocking Issues")
        for issue in classified.blocking_issues:
            lines.append(f"- {issue}")
        lines.append("")
    if classified.recommended_actions:
        lines.append("## Recommended Actions")
        for action in classified.recommended_actions:
            lines.append(f"- {action}")
        lines.append("")
    if classified.agent_ready:
        lines.append("No remediation required — repository already passes agent-ready checks.")
    else:
        lines.append(
            "## Next Step\n"
            "Run this prompt in your AI agent (Cursor, Claude Code, etc.) "
            "to apply minimal safe fixes, then re-run `repo-governor goal-loop` to verify."
        )
    return "\n".join(lines)


def _configured_agent_runner() -> str | None:
    """Return an agent runner command if one is configured via environment."""
    return os.environ.get("REPO_GOVERNOR_AGENT_RUNNER")


def run_remediation_agent(
    repo_path: Path,
    prompt: str,
    remediation_plan: str,
    output_dir: Path,
) -> tuple[RemediationStatus, str, Path, Path]:
    """Run remediation or write prompt/plan files for manual agent use.

    Returns (status, summary, prompt_path, plan_path).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = output_dir / "remediation_agent_prompt.md"
    plan_path = output_dir / "remediation_plan.md"
    prompt_path.write_text(prompt, encoding="utf-8")
    plan_path.write_text(remediation_plan, encoding="utf-8")

    runner = _configured_agent_runner()
    if runner:
        return (
            "failed",
            (
                f"Agent runner configured ({runner!r}) but automatic execution "
                "is not implemented. Prompt and plan were written for manual use."
            ),
            prompt_path,
            plan_path,
        )

    return (
        "manual_agent_prompt_generated",
        (
            "Remediation prompt and plan written. No autonomous agent runner is "
            "configured; remediation was not executed."
        ),
        prompt_path,
        plan_path,
    )


def run_verification_scan(repo_path: Path) -> tuple[RepoInfo, ClassifiedRepo]:
    """Re-scan and re-classify the repository after remediation."""
    repo_info = run_initial_scan(repo_path)
    classified = classify_repo_risk(repo_info)
    return repo_info, classified


def write_goal_loop_audit_log(
    audit_dir: Path,
    loop_id: str,
    *,
    target_repo: str,
    goal: str,
    initial_scan: dict[str, Any],
    risk_classification: dict[str, Any],
    generated_artifacts: list[str],
    agent_prompt_path: str | None,
    remediation_status: RemediationStatus,
    remediation_summary: str,
    verification_scan: dict[str, Any] | None,
    passed: bool,
    remaining_issues: list[str],
    errors: list[str],
    remediation_plan_path: str | None = None,
) -> Path:
    """Write a timestamped JSON audit log and return its path."""
    audit_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"goal_loop_{timestamp}_{loop_id[:8]}.json"
    audit_path = audit_dir / filename

    payload = {
        "loop_id": loop_id,
        "timestamp": _utc_now_iso(),
        "target_repo": target_repo,
        "goal": goal,
        "initial_scan": initial_scan,
        "risk_classification": risk_classification,
        "generated_artifacts": generated_artifacts,
        "agent_prompt_path": agent_prompt_path,
        "remediation_plan_path": remediation_plan_path,
        "remediation_status": remediation_status,
        "remediation_summary": remediation_summary,
        "verification_scan": verification_scan,
        "passed": passed,
        "remaining_issues": remaining_issues,
        "errors": errors,
    }
    audit_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return audit_path


def run_goal_based_loop(
    repo_path: Path,
    *,
    goal: str = DEFAULT_GOAL,
    audit_dir: Path | None = None,
    overwrite_policy: bool = False,
) -> GoalLoopResult:
    """Run the full goal-based governance loop for a single repository."""
    loop_id = str(uuid.uuid4())
    repo_path = repo_path.resolve()
    audit_root = (audit_dir or Path.cwd() / "audit").resolve()
    loop_output_dir = audit_root / loop_id

    result = GoalLoopResult(
        loop_id=loop_id,
        target_repo=repo_path.as_posix(),
        goal=goal,
        initial_agent_ready=False,
        initial_risk_level="UNKNOWN",
    )

    errors: list[str] = []
    initial_scan_dict: dict[str, Any] = {}
    risk_dict: dict[str, Any] = {}
    generated_artifacts: list[str] = []
    agent_prompt_path: str | None = None
    remediation_plan_path: str | None = None
    remediation_status: RemediationStatus = "failed"
    remediation_summary = ""
    verification_dict: dict[str, Any] | None = None
    passed = False
    remaining: list[str] = []

    try:
        repo_info = run_initial_scan(repo_path)
        initial_scan_dict = _repo_info_to_dict(repo_info)
        result.initial_agent_ready = False
    except ValueError as exc:
        errors.append(str(exc))
        result.errors = errors
        audit_path = write_goal_loop_audit_log(
            audit_root,
            loop_id,
            target_repo=repo_path.as_posix(),
            goal=goal,
            initial_scan=initial_scan_dict,
            risk_classification=risk_dict,
            generated_artifacts=generated_artifacts,
            agent_prompt_path=None,
            remediation_status="failed",
            remediation_summary="Initial scan failed.",
            verification_scan=None,
            passed=False,
            remaining_issues=errors,
            errors=errors,
        )
        result.audit_log_path = str(audit_path)
        return result

    try:
        classified = classify_repo_risk(repo_info)
        risk_dict = _classified_repo_to_dict(classified)
        result.initial_agent_ready = classified.agent_ready
        result.initial_risk_level = classified.risk_level.value
    except Exception as exc:
        errors.append(f"Classification failed: {exc}")
        result.errors = errors
        audit_path = write_goal_loop_audit_log(
            audit_root,
            loop_id,
            target_repo=repo_path.as_posix(),
            goal=goal,
            initial_scan=initial_scan_dict,
            risk_classification=risk_dict,
            generated_artifacts=generated_artifacts,
            agent_prompt_path=None,
            remediation_status="failed",
            remediation_summary="Classification failed.",
            verification_scan=None,
            passed=False,
            remaining_issues=errors,
            errors=errors,
        )
        result.audit_log_path = str(audit_path)
        return result

    try:
        generated_artifacts = generate_policy_artifacts(
            repo_path, classified, overwrite=overwrite_policy
        )
        result.generated_artifacts = generated_artifacts
    except FileExistsError as exc:
        errors.append(str(exc))
    except Exception as exc:
        errors.append(f"Policy generation failed: {exc}")

    policy_dict = generate_repo_policy(classified)
    prompt = generate_starter_agent_prompt(
        repo_path, repo_info, classified, policy_dict, goal=goal
    )
    plan_text = _generate_remediation_plan(classified)

    try:
        remediation_status, remediation_summary, prompt_file, plan_file = (
            run_remediation_agent(repo_path, prompt, plan_text, loop_output_dir)
        )
        agent_prompt_path = str(prompt_file)
        remediation_plan_path = str(plan_file)
        result.agent_prompt_path = agent_prompt_path
        result.remediation_plan_path = remediation_plan_path
        result.remediation_status = remediation_status
        result.remediation_summary = remediation_summary
    except Exception as exc:
        errors.append(f"Remediation stage failed: {exc}")
        remediation_status = "failed"
        remediation_summary = str(exc)

    try:
        verify_repo, verify_classified = run_verification_scan(repo_path)
        verification_dict = _classified_repo_to_dict(verify_classified)
        result.verification_agent_ready = verify_classified.agent_ready
        result.verification_risk_level = verify_classified.risk_level.value
        remaining = _remaining_issues(verify_classified)
        passed = verify_classified.agent_ready and not errors
        result.passed = passed
        result.remaining_issues = remaining
    except Exception as exc:
        errors.append(f"Verification scan failed: {exc}")
        remaining = list(errors)

    result.errors = errors
    audit_path = write_goal_loop_audit_log(
        audit_root,
        loop_id,
        target_repo=repo_path.as_posix(),
        goal=goal,
        initial_scan=initial_scan_dict,
        risk_classification=risk_dict,
        generated_artifacts=generated_artifacts,
        agent_prompt_path=agent_prompt_path,
        remediation_plan_path=remediation_plan_path,
        remediation_status=remediation_status,
        remediation_summary=remediation_summary,
        verification_scan=verification_dict,
        passed=passed,
        remaining_issues=remaining,
        errors=errors,
    )
    result.audit_log_path = str(audit_path)
    return result
