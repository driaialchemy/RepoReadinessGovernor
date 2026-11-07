"""Prioritized findings and risk-signal analysis for human-facing evidence reports."""
from __future__ import annotations

import re
from typing import Any

_CRED_TERMS = frozenset({"api_key", "database_url"})
_AI_TERMS = frozenset({"openai", "anthropic", "gemini", "google.generativeai"})
_HTTP_TERMS = frozenset({"requests", "httpx", "aiohttp"})
_EXT_DB_TERMS = frozenset({"postgres", "supabase"})

_RISK_SIGNAL_PATTERNS = (
    re.compile(r"dependency manifests present", re.I),
    re.compile(r"test suite present", re.I),
    re.compile(r"http networking libraries", re.I),
    re.compile(r"ci/cd workflow", re.I),
    re.compile(r"container configuration present", re.I),
    re.compile(r"dockerfile", re.I),
    re.compile(r"large file count", re.I),
    re.compile(r"node_modules present", re.I),
    re.compile(r"external ai api usage", re.I),
    re.compile(r"multiple ai provider integrations", re.I),
    re.compile(r"external database terms detected", re.I),
    re.compile(r"cloud deployment configuration present", re.I),
)

_POSITIVE_SIGNAL_PATTERNS = (
    re.compile(r"test suite present", re.I),
)


def _scan(item: dict[str, Any]) -> dict[str, Any]:
    return item.get("initial_scan") or {}


def _api_terms(item: dict[str, Any]) -> set[str]:
    return set(_scan(item).get("api_terms_found") or [])


def _finding(
    *,
    finding_id: str,
    priority: int,
    title: str,
    corrective_action: str,
    verification: str,
    human_review: bool = False,
) -> dict[str, Any]:
    return {
        "id": finding_id,
        "priority": priority,
        "title": title,
        "corrective_action": corrective_action,
        "verification": verification,
        "human_review_required": human_review,
    }


def _build_structured_findings(item: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive deduplicated actionable findings from scan structure, not raw issue noise."""
    scan = _scan(item)
    risk = (item.get("risk_level") or "UNKNOWN").upper()
    findings: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def add(finding: dict[str, Any]) -> None:
        if finding["id"] in seen_ids:
            return
        seen_ids.add(finding["id"])
        findings.append(finding)

    if scan.get("has_env_files"):
        paths = ", ".join((scan.get("env_file_paths") or [])[:3]) or ".env-like files"
        add(_finding(
            finding_id="exposed_secrets",
            priority=1,
            title=f"Exposed secret or credential files ({paths})",
            corrective_action=(
                "Confirm whether the file contains real secrets. If real secrets are present, "
                "remove the file from the repo, rotate exposed credentials, and add the file "
                "pattern to .gitignore."
            ),
            verification="Re-run scan_only and confirm no credential files are detected.",
            human_review=True,
        ))

    cred_found = _api_terms(item) & _CRED_TERMS
    if cred_found:
        add(_finding(
            finding_id="credential_patterns",
            priority=1,
            title=f"Credential pattern indicators found ({', '.join(sorted(cred_found))})",
            corrective_action=(
                "Review flagged files to confirm whether actual credentials are present. "
                "Replace hardcoded secrets with environment variables or secret manager references."
            ),
            verification="Confirm credential pattern indicators are cleared or documented as safe.",
            human_review=True,
        ))

    if not scan.get("is_git_repo", True):
        add(_finding(
            finding_id="no_git",
            priority=1,
            title="No version control — changes cannot be rolled back",
            corrective_action="Initialize git and configure a remote before agent use.",
            verification="Confirm repository is a valid git worktree.",
            human_review=True,
        ))

    artifacts = scan.get("artifact_paths") or []
    db_like = [p for p in artifacts if p.lower().endswith((".db", ".sqlite", ".sqlite3"))]
    if db_like:
        add(_finding(
            finding_id="database_files",
            priority=1,
            title=f"Database files committed ({', '.join(db_like[:3])})",
            corrective_action=(
                "Move database files outside the repository or add their patterns to .gitignore."
            ),
            verification="Confirm database artifacts are no longer tracked.",
            human_review=True,
        ))

    if not scan.get("has_claude_md", item.get("has_claude_md")):
        add(_finding(
            finding_id="missing_claude_md",
            priority=2,
            title="Missing CLAUDE.md / agent operating instructions",
            corrective_action=(
                "Create CLAUDE.md with repo purpose, allowed agent actions, prohibited actions, "
                "sensitive files, test commands, and reporting expectations."
            ),
            verification="Re-run scan_only and confirm CLAUDE.md is present.",
        ))

    if not scan.get("has_agents_md"):
        add(_finding(
            finding_id="missing_agents_md",
            priority=2,
            title="Missing AGENTS.md / machine-readable safety policy",
            corrective_action=(
                "Create AGENTS.md with machine-readable agent safety policy, allowed tools, "
                "restricted files, approval gates, and verification requirements."
            ),
            verification="Re-run scan_only and confirm AGENTS.md is present.",
        ))

    if risk == "HIGH":
        add(_finding(
            finding_id="high_risk_controls",
            priority=2,
            title="High-risk repo requires additional controls before agent access",
            corrective_action=(
                "Document approval gates, sensitive areas, and verification steps before any "
                "remediation agent is used."
            ),
            verification=(
                "Confirm governance files exist and high-risk blockers are resolved or explicitly "
                "approved for human-supervised remediation."
            ),
            human_review=True,
        ))
    elif risk == "MEDIUM":
        add(_finding(
            finding_id="medium_risk_controls",
            priority=2,
            title="Medium-risk repo requires governance controls before agent access",
            corrective_action=(
                "Add agent policy files and document verification requirements before agent use."
            ),
            verification="Confirm required governance controls are present for a medium-risk repo.",
        ))

    if not scan.get("has_readme"):
        add(_finding(
            finding_id="missing_readme",
            priority=3,
            title="Missing README / project context for agents",
            corrective_action=(
                "Add README with repo purpose, setup instructions, test command, expected "
                "inputs/outputs, and safe-use notes."
            ),
            verification="Re-run scan_only and confirm README is present.",
        ))

    if not scan.get("has_gitignore"):
        add(_finding(
            finding_id="missing_gitignore",
            priority=3,
            title="Missing .gitignore / unintended files may be tracked",
            corrective_action=(
                "Add .gitignore entries for .env, virtual environments, caches, local reports, "
                "audit temp files, and generated workspaces."
            ),
            verification="Re-run scan_only and confirm .gitignore is present.",
        ))

    # Parse remaining_issues only for unmatched blocking content.
    for raw in item.get("remaining_issues") or []:
        text = str(raw).strip()
        lower = text.lower()
        if any(p.search(text) for p in _RISK_SIGNAL_PATTERNS):
            continue
        if lower.startswith("risk level is") and "expected low" in lower:
            continue
        if "missing claude.md" in lower:
            continue
        if "missing agents.md" in lower or "machine-readable safety policy" in lower:
            continue
        if "missing .gitignore" in lower:
            continue
        if "missing readme" in lower:
            continue
        if "exposed secret" in lower or "credential files" in lower:
            continue
        if lower in {f["title"].lower() for f in findings}:
            continue
        add(_finding(
            finding_id=f"issue_{len(findings)}",
            priority=2 if risk == "HIGH" else 3,
            title=text.rstrip("."),
            corrective_action="Review the audit evidence and remediate this blocking issue.",
            verification="Re-run scan_only and confirm the issue is resolved.",
            human_review=risk == "HIGH",
        ))

    findings.sort(key=lambda f: (f["priority"], f["title"]))
    return findings


def _build_risk_signals(item: dict[str, Any]) -> list[dict[str, Any]]:
    scan = _scan(item)
    signals: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(label: str, implication: str) -> None:
        key = label.lower()
        if key in seen:
            return
        seen.add(key)
        signals.append({"label": label, "governance_implication": implication})

    pkg = [
        name
        for name, flag in [
            ("requirements.txt", scan.get("has_requirements_txt")),
            ("pyproject.toml", scan.get("has_pyproject")),
            ("package.json", scan.get("has_package_json")),
        ]
        if flag
    ]
    if pkg:
        add(
            f"Dependency manifest detected ({', '.join(pkg)})",
            "Dependency changes should require review and test verification.",
        )

    if scan.get("has_tests_dir"):
        add(
            "Test suite detected",
            "Use the existing test suite as the primary verification mechanism after agent changes.",
        )

    http_found = _api_terms(item) & _HTTP_TERMS
    if http_found:
        add(
            f"HTTP networking detected ({', '.join(sorted(http_found))})",
            "Agent changes should require review for external calls and data handling.",
        )

    if scan.get("has_github_workflows"):
        add(
            "CI/CD workflow present",
            "Review workflow permissions before allowing agent changes to pipeline files.",
        )

    if scan.get("has_dockerfile") or scan.get("has_docker_compose"):
        add(
            "Container configuration present",
            "Restrict agent access to container build and deployment commands.",
        )

    ai_found = _api_terms(item) & _AI_TERMS
    if ai_found:
        add(
            f"AI provider integrations present ({', '.join(sorted(ai_found))})",
            "Document API key handling and require human review for provider configuration changes.",
        )

    ext_db = _api_terms(item) & _EXT_DB_TERMS
    if ext_db:
        add(
            f"Database terms present ({', '.join(sorted(ext_db))})",
            "Ensure connection strings use environment variables and data handling is documented.",
        )

    deploy_cfgs = [
        name
        for name, flag in [
            ("wrangler.toml", scan.get("has_wrangler_toml")),
            ("vercel.json", scan.get("has_vercel_json")),
            ("netlify.toml", scan.get("has_netlify_toml")),
            ("render.yaml", scan.get("has_render_yaml")),
        ]
        if flag
    ]
    if deploy_cfgs:
        add(
            f"Cloud deployment configuration present ({', '.join(deploy_cfgs)})",
            "Deployment changes should require explicit human approval.",
        )

    if (scan.get("file_count") or 0) > 500:
        add(
            f"Large repository ({scan['file_count']} files)",
            "Scope agent edits narrowly to reduce unintended changes.",
        )

    for raw in item.get("remaining_issues") or []:
        text = str(raw).strip()
        if not any(p.search(text) for p in _RISK_SIGNAL_PATTERNS):
            continue
        if any(p.search(text) for p in _POSITIVE_SIGNAL_PATTERNS):
            add(
                "Test suite present — actively developed project",
                "Use the existing test suite as the primary verification mechanism after agent changes.",
            )
            continue
        implication = "Review governance implications in the audit evidence before agent use."
        if "dependency manifests" in text.lower():
            implication = "Dependency changes should require review and test verification."
        elif "http networking" in text.lower():
            implication = "Agent changes should require review for external calls and data handling."
        add(text.rstrip("."), implication)

    return signals


def _recommended_mode_for_repo(item: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    risk = (item.get("risk_level") or "LOW").upper()
    if item.get("passed"):
        return "scan_only"
    if risk == "HIGH" or any(f["priority"] == 1 for f in findings):
        return "human_review_first"
    if any(f["id"] in {"missing_claude_md", "missing_agents_md"} for f in findings):
        return "prompt_only"
    return "prompt_only"


def build_repo_action_plan(item: dict[str, Any], *, max_actions: int = 5) -> dict[str, Any]:
    findings = _build_structured_findings(item)
    risk_signals = _build_risk_signals(item)
    top_actions = findings[:max_actions]
    human_review = (
        (item.get("risk_level") or "").upper() == "HIGH"
        or any(f.get("human_review_required") for f in findings)
    )
    verification_steps = [
        f["verification"] for f in top_actions[:3]
    ] or ["Re-run weekly evidence in scan_only mode and confirm agent-ready PASS."]

    return {
        "repo": item.get("full_name", item.get("name", "unknown")),
        "risk": item.get("risk_level", "unknown"),
        "agent_ready": bool(item.get("passed")),
        "top_corrective_actions": [
            {
                "title": f["title"],
                "corrective_action": f["corrective_action"],
                "priority": f["priority"],
            }
            for f in top_actions
        ],
        "risk_signals": risk_signals,
        "accepted_risks": list(item.get("accepted_risks") or []),
        "actionable_findings": findings,
        "verification_steps": verification_steps,
        "recommended_mode": _recommended_mode_for_repo(item, findings),
        "human_review_required": human_review,
        "audit_path": item.get("audit_path"),
    }


def _has_priority_one(item: dict[str, Any]) -> bool:
    scan = _scan(item)
    if scan.get("has_env_files"):
        return True
    if _api_terms(item) & _CRED_TERMS:
        return True
    artifacts = scan.get("artifact_paths") or []
    return any(p.lower().endswith((".db", ".sqlite", ".sqlite3")) for p in artifacts)


def _missing_policy(item: dict[str, Any]) -> bool:
    scan = _scan(item)
    return not scan.get("has_claude_md", item.get("has_claude_md")) or not scan.get("has_agents_md")


def _remediation_bucket(item: dict[str, Any]) -> str:
    risk = (item.get("risk_level") or "LOW").upper()
    scan = _scan(item)
    if risk == "HIGH" or _has_priority_one(item):
        return "human_review_first"
    complex_signals = (
        scan.get("has_dockerfile")
        or scan.get("has_docker_compose")
        or scan.get("has_github_workflows")
        or bool(_api_terms(item) & (_AI_TERMS | _EXT_DB_TERMS))
    )
    if risk == "MEDIUM" or complex_signals:
        return "next"
    return "start_here"


def build_remediation_order(scanned: list[dict[str, Any]]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "start_here": [],
        "next": [],
        "human_review_first": [],
    }
    for item in scanned:
        if item.get("passed"):
            continue
        bucket = _remediation_bucket(item)
        name = item.get("name") or item.get("full_name", "unknown")
        buckets[bucket].append(name)
    for key in buckets:
        buckets[key].sort()
    return buckets


def _portfolio_issue_counts(scanned: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    labels = {
        "missing_claude_md": "missing agent operating instructions (CLAUDE.md)",
        "missing_agents_md": "missing machine-readable safety policy (AGENTS.md)",
        "missing_readme": "missing README",
        "missing_gitignore": "missing .gitignore",
        "exposed_secrets": "exposed secret/credential files",
        "credential_patterns": "credential pattern indicators",
        "high_risk_controls": "high-risk repos needing controls",
    }
    for item in scanned:
        if item.get("passed"):
            continue
        for finding in _build_structured_findings(item):
            label = labels.get(finding["id"], finding["title"])
            counts[label] = counts.get(label, 0) + 1
    return sorted(counts.items(), key=lambda x: (-x[1], x[0]))


def build_executive_narrative(
    run: Any,
    scanned: list[dict[str, Any]],
    summary: dict[str, Any],
) -> str:
    passed = summary["total_passed"]
    needs_work = summary["total_needs_work"]
    scanned_count = summary["total_scanned"]
    high = summary.get("total_high_risk", 0)
    medium = summary.get("total_medium_risk", 0)
    low = summary.get("total_low_risk", 0)

    if passed == scanned_count and scanned_count:
        readiness = "All scanned repositories are currently agent-ready."
    elif passed == 0 and scanned_count:
        readiness = "None are currently agent-ready."
    else:
        readiness = f"{passed} of {scanned_count} scanned repositories are agent-ready."

    top_issues = _portfolio_issue_counts(scanned)[:3]
    issue_sentence = ""
    if top_issues:
        parts = [f"{count} repos with {label}" for label, count in top_issues[:2]]
        issue_sentence = (
            f"The most common issues are {parts[0]}"
            + (f" and {parts[1]}" if len(parts) > 1 else "")
            + "."
        )

    high_sentence = ""
    if high:
        high_sentence = (
            f" {high} {'repository is' if high == 1 else 'repositories are'} high-risk and "
            "should receive human review before any remediation agent is used."
        )

    order = build_remediation_order(scanned)
    if order["start_here"]:
        next_step = (
            f"The safest next step is to run prompt_only on a start-here repo such as "
            f"{order['start_here'][0]}."
        )
    elif order["next"]:
        next_step = (
            f"The safest next step is to add agent policy files on a medium-risk repo such as "
            f"{order['next'][0]} using prompt_only mode."
        )
    else:
        next_step = "Review high-risk repositories with human oversight before remediation."

    return (
        f"Repo Governor scanned {scanned_count} repositories under {run.github_owner}. "
        f"{readiness}{high_sentence} {issue_sentence} {next_step}"
    ).strip()


def build_prioritized_corrective_actions(
    run: Any,
    scanned: list[dict[str, Any]],
    clone_failed: list[dict[str, Any]],
    scan_failed: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Condensed corrective actions — one entry per deduplicated finding, not per raw issue."""
    actions: list[dict[str, Any]] = []
    for item in scanned:
        if item.get("passed"):
            continue
        plan = build_repo_action_plan(item)
        repo_name = plan["repo"]
        for entry in plan["top_corrective_actions"]:
            actions.append({
                "repo": repo_name,
                "issue": entry["title"],
                "why_it_matters": (
                    "Autonomous coding agents need explicit governance controls before making changes."
                ),
                "corrective_action": entry["corrective_action"],
                "verification_action": plan["verification_steps"][0],
                "expected_evidence": (
                    f"Updated audit with PASS status: {plan.get('audit_path', 'n/a')}"
                ),
                "recommended_mode": plan["recommended_mode"],
                "human_review_required": plan["human_review_required"],
                "priority": entry["priority"],
            })

    for item in clone_failed:
        repo_name = item.get("full_name", item.get("name", "unknown"))
        actions.append({
            "repo": repo_name,
            "issue": "The repository could not be cloned into the workflow workspace.",
            "why_it_matters": "The repository could not be assessed, leaving a governance gap.",
            "corrective_action": (
                "Verify clone URL, branch name, token access, and GitHub Actions permissions; "
                "then rerun the workflow."
            ),
            "verification_action": (
                "Confirm the next evidence report shows the repo status as scanned_successfully."
            ),
            "expected_evidence": "Per-repo audit JSON exists and contains scan results.",
            "recommended_mode": run.mode,
            "human_review_required": True,
            "priority": 1,
        })

    for item in scan_failed:
        repo_name = item.get("full_name", item.get("name", "unknown"))
        actions.append({
            "repo": repo_name,
            "issue": "The repository could not be scanned after checkout.",
            "why_it_matters": "The repository could not be assessed, leaving a governance gap.",
            "corrective_action": (
                "Review the audit evidence and repository layout; fix blocking issues "
                "and rerun the weekly evidence workflow."
            ),
            "verification_action": (
                "Confirm the next evidence report shows the repo status as scanned_successfully."
            ),
            "expected_evidence": "Per-repo audit JSON exists and contains scan results.",
            "recommended_mode": run.mode,
            "human_review_required": True,
            "priority": 1,
        })

    actions.sort(key=lambda a: (a.get("priority", 99), a.get("repo", "")))
    if run.mode == "scan_only" and actions:
        for action in actions:
            action.setdefault(
                "note",
                "Weekly scan_only mode reports findings only — target repos are not modified automatically.",
            )
    return actions


def analyze_scanned_repos(scanned: list[dict[str, Any]]) -> dict[str, Any]:
    plans = [build_repo_action_plan(item) for item in scanned if not item.get("passed")]
    passed_plans = [build_repo_action_plan(item) for item in scanned if item.get("passed")]
    return {
        "repo_action_plans": plans + passed_plans,
        "remediation_order": build_remediation_order(scanned),
        "top_portfolio_issues": [
            {"issue": label, "repo_count": count}
            for label, count in _portfolio_issue_counts(scanned)[:8]
        ],
    }
