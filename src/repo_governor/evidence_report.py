"""Combined evidence report generation for multi-repo governance runs."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .report_analysis import (
    analyze_scanned_repos,
    build_executive_narrative,
    build_prioritized_corrective_actions,
    build_repo_action_plan,
)
from .security import redact_dict, redact_secrets


@dataclass
class EvidenceReportPaths:
    markdown_path: Path
    text_path: Path
    json_path: Path
    output_dir: Path


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _missing_controls(result_item: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    scan = result_item.get("initial_scan") or {}
    if not scan.get("has_claude_md"):
        missing.append("CLAUDE.md")
    if not scan.get("has_gitignore"):
        missing.append(".gitignore")
    if not scan.get("has_readme"):
        missing.append("README")
    if not scan.get("has_agents_md"):
        missing.append("AGENTS.md")
    if scan.get("has_env_files"):
        missing.append("secret/credential file handling")
    if not scan.get("is_git_repo"):
        missing.append("version control (git)")
    return missing


def _recommended_action(result_item: dict[str, Any]) -> str:
    if result_item.get("passed"):
        return "No action required — repository is agent-ready."
    plan = build_repo_action_plan(result_item)
    if plan["top_corrective_actions"]:
        return plan["top_corrective_actions"][0]["corrective_action"]
    if plan["recommended_mode"] == "human_review_first":
        return "Complete human review before any remediation agent is used."
    return "Review audit evidence and run prompt_only when ready to remediate."


def _risk_level_counts(scanned: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in scanned:
        level = (item.get("risk_level") or "LOW").upper()
        if level in counts:
            counts[level] += 1
    return {
        "total_high_risk": counts["HIGH"],
        "total_medium_risk": counts["MEDIUM"],
        "total_low_risk": counts["LOW"],
    }


def summarize_multi_repo_results(run: Any) -> dict[str, Any]:
    """Build a structured summary dict from a multi-repo run."""
    scanned = [r for r in run.repo_results if r.get("status") == "scanned"]
    passed = [r for r in scanned if r.get("passed")]
    needs_work = [r for r in scanned if not r.get("passed")]
    clone_failed = [r for r in run.repo_results if r.get("status") == "clone_failed"]
    scan_failed = [r for r in run.repo_results if r.get("status") == "scan_failed"]
    legacy_failed = [
        r for r in run.repo_results
        if r.get("status") == "failed" and r not in clone_failed + scan_failed
    ]
    scan_failed = scan_failed + legacy_failed
    eligible = len(run.repo_results)
    unattempted = max(run.total_discovered - len(run.skipped_repos) - eligible, 0)
    risk_counts = _risk_level_counts(scanned)
    analysis = analyze_scanned_repos(scanned)
    corrective_actions = build_prioritized_corrective_actions(
        run, scanned, clone_failed, scan_failed
    )

    summary = {
        "run_id": run.run_id,
        "report_timestamp": run.timestamp,
        "github_owner": run.github_owner,
        "mode": run.mode,
        "total_discovered": run.total_discovered,
        "total_eligible": eligible,
        "total_scanned": len(scanned),
        "total_clone_failed": len(clone_failed),
        "total_scan_failed": len(scan_failed),
        "total_unattempted": unattempted,
        "total_skipped": len(run.skipped_repos),
        "total_passed": len(passed),
        "total_needs_work": len(needs_work),
        **risk_counts,
        "skipped_repos": run.skipped_repos,
        "repo_results": run.repo_results,
        "corrective_actions": corrective_actions,
        "repo_action_plans": analysis["repo_action_plans"],
        "remediation_order": analysis["remediation_order"],
        "top_portfolio_issues": analysis["top_portfolio_issues"],
        "errors": [redact_secrets(e) for e in run.errors],
        "discovery_warnings": [redact_secrets(w) for w in run.discovery_warnings],
        "email_delivery_status": run.email_delivery_status,
        "email_delivery_message": redact_secrets(run.email_delivery_message),
        "audit_summary_path": run.audit_summary_path,
    }
    summary["executive_narrative"] = build_executive_narrative(run, scanned, summary)
    return summary


def _format_remediation_order_md(order: dict[str, list[str]]) -> list[str]:
    if not any(order.values()):
        return []
    lines = ["## Recommended Remediation Order", ""]
    sections = [
        ("start_here", "Start here (low-risk, simple documentation fixes)"),
        ("next", "Next (medium-risk or missing agent policy files)"),
        ("human_review_first", "Human review first (high-risk, credentials, AI, databases, CI/CD, containers)"),
    ]
    for key, title in sections:
        repos = order.get(key) or []
        if not repos:
            continue
        lines.append(f"### {title}")
        lines.append("")
        for name in repos:
            lines.append(f"- {name}")
        lines.append("")
    return lines


def _format_remediation_order_txt(order: dict[str, list[str]]) -> list[str]:
    lines: list[str] = []
    if not any(order.values()):
        return lines
    lines += ["Recommended Remediation Order", ""]
    for key, title in [
        ("start_here", "Start here"),
        ("next", "Next"),
        ("human_review_first", "Human review first"),
    ]:
        repos = order.get(key) or []
        if repos:
            lines.append(f"{title}: {', '.join(repos)}")
    lines.append("")
    return lines


def _format_repo_action_plans_md(plans: list[dict[str, Any]]) -> list[str]:
    if not plans:
        return []
    lines = ["## Per-Repo Action Plans", ""]
    for plan in sorted(plans, key=lambda p: (p.get("agent_ready"), p.get("repo", ""))):
        lines += [
            f"### {plan['repo']}",
            "",
            f"- **Risk:** {plan.get('risk', 'unknown')}",
            f"- **Agent-ready:** {'PASS' if plan.get('agent_ready') else 'FAIL'}",
            f"- **Recommended mode:** {plan.get('recommended_mode', 'scan_only')}",
            f"- **Human review required:** {'Yes' if plan.get('human_review_required') else 'No'}",
        ]
        actions = plan.get("top_corrective_actions") or []
        if actions:
            lines.append("- **Top corrective actions:**")
            for idx, action in enumerate(actions[:5], start=1):
                lines.append(f"  {idx}. {action['title']}")
                lines.append(f"     - {action['corrective_action']}")
        signals = plan.get("risk_signals") or []
        if signals:
            lines.append("- **Risk signals (context, not automatic defects):**")
            for signal in signals[:5]:
                lines.append(f"  - {signal['label']}")
                lines.append(f"    - {signal['governance_implication']}")
        accepted = plan.get("accepted_risks") or []
        if accepted:
            lines.append("- **Accepted risks (reviewed exceptions):**")
            for note in accepted:
                lines.append(f"  - {note}")
        verification = plan.get("verification_steps") or []
        if verification:
            lines.append("- **Verification steps:**")
            for step in verification[:3]:
                lines.append(f"  - {step}")
        if plan.get("audit_path"):
            lines.append(f"- **Audit file:** `{plan['audit_path']}`")
        lines.append("")
    return lines


def _format_repo_action_plans_txt(plans: list[dict[str, Any]]) -> list[str]:
    if not plans:
        return []
    lines = ["Per-Repo Action Plans", ""]
    for plan in sorted(plans, key=lambda p: (p.get("agent_ready"), p.get("repo", ""))):
        lines += [
            f"Repo: {plan['repo']}",
            f"  Risk: {plan.get('risk')}",
            f"  Agent-ready: {'PASS' if plan.get('agent_ready') else 'FAIL'}",
            f"  Recommended mode: {plan.get('recommended_mode')}",
            f"  Human review required: {'Yes' if plan.get('human_review_required') else 'No'}",
        ]
        for idx, action in enumerate((plan.get("top_corrective_actions") or [])[:5], start=1):
            lines.append(f"  {idx}. {action['title']}: {action['corrective_action']}")
        for signal in (plan.get("risk_signals") or [])[:3]:
            lines.append(f"  Risk signal: {signal['label']} — {signal['governance_implication']}")
        for note in plan.get("accepted_risks") or []:
            lines.append(f"  Accepted risk: {note}")
        lines.append("")
    return lines


def _novice_summary(run: Any, summary: dict[str, Any]) -> str:
    discovered = summary["total_discovered"]
    eligible = summary["total_eligible"]
    scanned = summary["total_scanned"]
    skipped = summary["total_skipped"]
    passed = summary["total_passed"]
    needs_work = summary["total_needs_work"]
    clone_failed = summary["total_clone_failed"]
    scan_failed = summary["total_scan_failed"]
    unattempted = summary["total_unattempted"]

    lines = [
        (
            f"Repo Governor discovered {discovered} repositories under {run.github_owner}. "
            f"{eligible} were eligible for scanning. {scanned} were scanned successfully. "
            f"{skipped} were skipped because they were archived, forks, excluded by "
            f"configuration, or otherwise disabled."
        ),
    ]
    if clone_failed or scan_failed:
        lines.append(
            f"{clone_failed} could not be cloned and {scan_failed} failed during scanning."
        )
    elif not scanned:
        lines.append("No repositories were scanned in this run.")
    if scanned:
        lines.append(
            f"{passed} passed agent-readiness checks and {needs_work} still need governance work."
        )
    if unattempted:
        lines.append(
            f"{unattempted} eligible repositories were not attempted. Treat this as a "
            "failed governance run and inspect the workflow logs before trusting the report."
        )

    lines.append("")
    lines.append(summary.get("executive_narrative", ""))

    if run.discovery_warnings:
        lines.append("")
        lines.append("Discovery notes:")
        for warning in run.discovery_warnings:
            lines.append(f"- {warning}")

    if run.email_delivery_status == "skipped_missing_credentials":
        lines.append("")
        lines.append(
            "Email delivery was skipped because SMTP credentials are not configured. "
            "The report was saved locally."
        )
    elif run.email_delivery_status == "sent":
        lines.append("")
        lines.append("The evidence report was emailed successfully.")

    return "\n".join(lines)


def generate_evidence_reports(
    run: Any,
    output_root: Path | None = None,
) -> EvidenceReportPaths:
    """Write evidence-summary.md, .txt, and .json for a multi-repo run."""
    report_date = run.report_date
    output_dir = (output_root or Path("reports")) / report_date
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = summarize_multi_repo_results(run)
    novice = _novice_summary(run, summary)

    md_lines = [
        "# AIAlchemy Repo Governor — Weekly Evidence Report",
        "",
        f"**Report date:** {run.timestamp}",
        f"**GitHub owner:** {run.github_owner}",
        f"**Run mode:** {run.mode}",
        "",
        "## Executive Summary",
        "",
        novice,
        "",
        "## Counts",
        "",
        f"- Repositories discovered: {summary['total_discovered']}",
        f"- Repositories eligible: {summary['total_eligible']}",
        f"- Repositories scanned successfully: {summary['total_scanned']}",
        f"- Agent-ready (passed): {summary['total_passed']}",
        f"- Need governance work: {summary['total_needs_work']}",
        f"- High-risk repositories: {summary['total_high_risk']}",
        f"- Medium-risk repositories: {summary['total_medium_risk']}",
        f"- Low-risk repositories: {summary['total_low_risk']}",
        f"- Clone failures: {summary['total_clone_failed']}",
        f"- Scan failures: {summary['total_scan_failed']}",
        f"- Unattempted eligible repositories: {summary['total_unattempted']}",
        f"- Repositories skipped: {summary['total_skipped']}",
        "",
    ]

    top_issues = summary.get("top_portfolio_issues") or []
    if top_issues:
        md_lines += ["## Top Portfolio-Wide Issues", ""]
        for item in top_issues:
            md_lines.append(f"- {item['repo_count']} repos: {item['issue']}")
        md_lines.append("")

    md_lines += _format_remediation_order_md(summary.get("remediation_order") or {})

    if run.skipped_repos:
        md_lines += ["## Skipped Repositories", ""]
        for item in run.skipped_repos:
            reason = item.get("skip_reason", "unknown")
            md_lines.append(f"- **{item.get('name')}** — {reason}")
        md_lines.append("")

    clone_failed = [r for r in run.repo_results if r.get("status") == "clone_failed"]
    scan_failed = [
        r for r in run.repo_results
        if r.get("status") in ("scan_failed", "failed")
    ]

    md_lines += _format_repo_action_plans_md(summary.get("repo_action_plans") or [])

    if clone_failed or scan_failed:
        md_lines += ["## Failed Repositories", ""]
        for item in clone_failed + scan_failed:
            status_label = item.get("status", "failed").replace("_", " ")
            md_lines += [
                f"### {item.get('full_name', item.get('name'))}",
                "",
                f"- **Status:** {status_label}",
            ]
            if item.get("status") == "clone_failed":
                md_lines += [
                    "- **Issue:** The repository could not be cloned into the workflow workspace.",
                    "- **Corrective action:** Verify clone URL, branch name, token access, and "
                    "GitHub Actions permissions; then rerun the workflow.",
                    "- **Verification action:** Confirm the next evidence report shows the repo "
                    "status as scanned_successfully.",
                ]
            for err in item.get("errors") or []:
                if item.get("status") != "clone_failed":
                    md_lines.append(f"- **Error:** {redact_secrets(str(err))}")
                else:
                    md_lines.append(f"- **Technical detail:** {redact_secrets(str(err))}")
            md_lines.append("")

    txt_lines = [
        "AIAlchemy Repo Governor — Weekly Evidence Report",
        f"Report date: {run.timestamp}",
        f"GitHub owner: {run.github_owner}",
        f"Run mode: {run.mode}",
        "",
        novice,
        "",
        f"Discovered: {summary['total_discovered']}",
        f"Eligible: {summary['total_eligible']}",
        f"Scanned: {summary['total_scanned']}",
        f"Passed: {summary['total_passed']}",
        f"Needs work: {summary['total_needs_work']}",
        f"High risk: {summary['total_high_risk']}",
        f"Medium risk: {summary['total_medium_risk']}",
        f"Low risk: {summary['total_low_risk']}",
        f"Clone failed: {summary['total_clone_failed']}",
        f"Scan failed: {summary['total_scan_failed']}",
        f"Unattempted eligible: {summary['total_unattempted']}",
        f"Skipped: {summary['total_skipped']}",
        "",
    ]

    if top_issues:
        txt_lines.append("Top portfolio-wide issues:")
        for item in top_issues:
            txt_lines.append(f"  - {item['repo_count']} repos: {item['issue']}")
        txt_lines.append("")

    txt_lines += _format_remediation_order_txt(summary.get("remediation_order") or [])

    if run.skipped_repos:
        txt_lines.append("Skipped repositories:")
        for item in run.skipped_repos:
            txt_lines.append(f"  - {item.get('name')}: {item.get('skip_reason', 'unknown')}")
        txt_lines.append("")

    txt_lines += _format_repo_action_plans_txt(summary.get("repo_action_plans") or [])

    markdown_path = output_dir / "evidence-summary.md"
    text_path = output_dir / "evidence-summary.txt"
    json_path = output_dir / "evidence-summary.json"

    markdown_path.write_text("\n".join(md_lines), encoding="utf-8")
    text_path.write_text("\n".join(txt_lines), encoding="utf-8")
    json_path.write_text(json.dumps(redact_dict(summary), indent=2), encoding="utf-8")

    return EvidenceReportPaths(
        markdown_path=markdown_path,
        text_path=text_path,
        json_path=json_path,
        output_dir=output_dir,
    )


def enrich_repo_result_for_report(result_item: dict[str, Any]) -> dict[str, Any]:
    """Add report-friendly fields to a per-repo result dict."""
    result_item["missing_controls"] = _missing_controls(result_item)
    result_item["recommended_action"] = _recommended_action(result_item)
    plan = build_repo_action_plan(result_item)
    result_item["action_plan"] = plan
    return result_item
