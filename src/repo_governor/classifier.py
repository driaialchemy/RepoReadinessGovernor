"""Repository risk classifier — deterministic rule-based only, no LLM."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .accepted_risks import AcceptedRisks, RepoAcceptance
from .governance_status import discover_confidence_feeders, evaluate_governance_status
from .scanner import RepoInfo


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def _decision_taxonomy(repo: RepoInfo, risk_level: RiskLevel) -> dict[str, str]:
    """Classify the repo along decision-taxonomy axes (docs/labels; existing risk_level unchanged)."""
    ai_found = set(repo.api_terms_found) & _AI_TERMS
    cred_found = set(repo.api_terms_found) & _CRED_TERMS
    ext_db_found = set(repo.api_terms_found) & _EXT_DB_TERMS
    has_deploy = any(
        [
            repo.has_wrangler_toml,
            repo.has_vercel_json,
            repo.has_netlify_toml,
            repo.has_render_yaml,
        ]
    )
    has_ci = repo.has_github_workflows
    has_containers = repo.has_dockerfile or repo.has_docker_compose

    if repo.file_count > 500 or len(ai_found) >= 2 or (has_containers and has_ci):
        complexity = "HIGH"
    elif repo.has_tests_dir or repo.has_package_json or repo.has_pyproject or has_containers:
        complexity = "MEDIUM"
    else:
        complexity = "LOW"

    if repo.has_env_files or cred_found or ext_db_found:
        regulatory_impact = "HIGH"
    elif has_deploy or has_ci:
        regulatory_impact = "MEDIUM"
    else:
        regulatory_impact = "LOW"

    if has_deploy:
        business_importance = "HIGH"
    elif has_ci or repo.has_tests_dir:
        business_importance = "MEDIUM"
    else:
        business_importance = "LOW"

    return {
        "risk": risk_level.value,
        "complexity": complexity,
        "regulatory_impact": regulatory_impact,
        "business_importance": business_importance,
    }


@dataclass
class ClassifiedRepo:
    repo: RepoInfo
    risk_level: RiskLevel
    risk_reasons: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    blocking_issues: list[str] = field(default_factory=list)
    readiness_score: int = 100
    agent_ready: bool = False
    decision_taxonomy: dict[str, str] = field(default_factory=dict)
    governance_status: dict[str, str] = field(default_factory=dict)
    accepted_risks: list[str] = field(default_factory=list)

    @property
    def repo_name(self) -> str:
        return self.repo.name

    # ── backward-compat aliases ──────────────────────────────────────────────

    @property
    def risk_factors(self) -> list[str]:
        return self.risk_reasons

    @property
    def recommendations(self) -> list[str]:
        return self.recommended_actions


# ── term groups (mirror scanner.API_TERMS partitions) ───────────────────────

_AI_TERMS = frozenset({"openai", "anthropic", "gemini", "google.generativeai"})
_CRED_TERMS = frozenset({"api_key", "database_url"})
_EXT_DB_TERMS = frozenset({"postgres", "supabase"})
_HTTP_TERMS = frozenset({"requests", "httpx", "aiohttp"})

_DB_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})
_SHEET_SUFFIXES = frozenset({".xlsx", ".xls", ".csv"})


def _any_suffix(paths: list[str], suffixes: frozenset[str]) -> list[str]:
    return [p for p in paths if any(p.lower().endswith(s) for s in suffixes)]


def _any_log(paths: list[str]) -> list[str]:
    return [p for p in paths if p.lower().endswith(".log")]


# ── signal collectors ────────────────────────────────────────────────────────

def _high_signals(
    repo: RepoInfo,
    acc: RepoAcceptance,
) -> tuple[list[str], list[str], list[str]]:
    """Return (reasons, blocking, actions) for HIGH-level risks."""
    reasons: list[str] = []
    blocking: list[str] = []
    actions: list[str] = []

    def _add(reason: str, action: str) -> None:
        reasons.append(reason)
        blocking.append(reason)
        actions.append(action)

    if not repo.is_git_repo:
        _add(
            "No version control — agent changes cannot be rolled back.",
            "Run `git init` and configure a remote before using an agent.",
        )

    if repo.has_env_files:
        paths = ", ".join(repo.env_file_paths[:3])
        _add(
            f"Credential/secret files present: {paths}",
            "Remove secret files, add patterns to .gitignore, and rotate exposed credentials.",
        )

    db_files = acc.accept_paths(
        "database_files", _any_suffix(repo.artifact_paths, _DB_SUFFIXES), "Database files found"
    )
    if db_files:
        _add(
            f"Database files found: {', '.join(db_files[:3])}",
            "Move database files outside the repository or add their patterns to .gitignore.",
        )

    sheet_files = acc.accept_paths(
        "spreadsheet_files",
        _any_suffix(repo.artifact_paths, _SHEET_SUFFIXES),
        "Spreadsheet/data export files found",
    )
    if sheet_files:
        _add(
            f"Spreadsheet/data export files found: {', '.join(sheet_files[:3])}",
            "Remove data export files from the repository and add patterns to .gitignore.",
        )

    log_files = acc.accept_paths("log_files", _any_log(repo.artifact_paths), "Log files found")
    if log_files:
        _add(
            f"Log files found: {', '.join(log_files[:3])}",
            "Add *.log to .gitignore and remove committed log files.",
        )

    ai_found = set(repo.api_terms_found) & _AI_TERMS
    if ai_found and acc.accept_terms(
        "ai_providers", ai_found, f"AI provider usage ({', '.join(sorted(ai_found))})"
    ):
        pass
    elif len(ai_found) >= 2:
        _add(
            f"Multiple AI provider integrations ({', '.join(sorted(ai_found))})"
            " — elevated orchestration complexity.",
            "Document required API keys in .env.example; ensure keys are never committed.",
        )
    elif len(ai_found) == 1:
        _add(
            f"External AI API usage: {next(iter(ai_found))} — API key management required.",
            "Document required API keys in .env.example; ensure keys are never committed.",
        )

    cred_found = set(repo.api_terms_found) & _CRED_TERMS
    if cred_found:
        _add(
            f"Credential pattern indicators in code: {', '.join(sorted(cred_found))}",
            "Audit source code for hardcoded credentials and replace with environment variables.",
        )

    ext_db_found = set(repo.api_terms_found) & _EXT_DB_TERMS
    if ext_db_found and acc.accept_terms(
        "external_database",
        ext_db_found,
        f"External database use ({', '.join(sorted(ext_db_found))})",
    ):
        pass
    elif ext_db_found:
        _add(
            f"External database terms detected ({', '.join(sorted(ext_db_found))})"
            " — potential data compliance risk.",
            "Ensure database connection strings use environment variables; add .env to .gitignore.",
        )

    cloud_cfgs = [
        name
        for name, flag in [
            ("wrangler.toml", repo.has_wrangler_toml),
            ("vercel.json", repo.has_vercel_json),
            ("netlify.toml", repo.has_netlify_toml),
            ("render.yaml", repo.has_render_yaml),
        ]
        if flag
    ]
    if cloud_cfgs and acc.accept_terms(
        "cloud_deployment",
        {c.lower() for c in cloud_cfgs},
        f"Cloud deployment configuration ({', '.join(cloud_cfgs)})",
    ):
        pass
    elif cloud_cfgs:
        _add(
            f"Cloud deployment configuration present: {', '.join(cloud_cfgs)}",
            "Restrict agent access to deployment commands and review config before any session.",
        )

    # Condition 10: missing .gitignore while artifacts exist
    gitignore_high = not repo.has_gitignore and bool(repo.artifact_paths)
    if gitignore_high:
        _add(
            "Missing .gitignore while generated artifacts exist"
            " — artifacts may be accidentally committed.",
            "Add .gitignore immediately to prevent committing generated files.",
        )

    return reasons, blocking, actions, gitignore_high  # type: ignore[return-value]


def _medium_signals(
    repo: RepoInfo, gitignore_already_high: bool, acc: RepoAcceptance
) -> tuple[list[str], list[str]]:
    """Return (signals, actions) for MEDIUM-level concerns."""
    signals: list[str] = []
    actions: list[str] = []

    def _add(signal: str, action: str) -> None:
        signals.append(signal)
        actions.append(action)

    pkg_files = [
        n
        for n, flag in [
            ("pyproject.toml", repo.has_pyproject),
            ("requirements.txt", repo.has_requirements_txt),
            ("package.json", repo.has_package_json),
        ]
        if flag
    ]
    if pkg_files and not acc.accepts_context("dependency_manifests"):
        _add(
            f"Dependency manifests present: {', '.join(pkg_files)}",
            "Run a dependency audit before starting an agent session.",
        )

    if (repo.has_dockerfile or repo.has_docker_compose) and not acc.accepts_context("containers"):
        _add(
            "Container configuration present (Dockerfile / docker-compose).",
            "Ensure agents cannot trigger container builds or deployments without confirmation.",
        )

    if repo.has_github_workflows and not acc.accepts_context("ci_cd"):
        _add(
            "CI/CD workflow configuration present (.github/workflows).",
            "Review CI/CD workflow permissions before an agent session.",
        )

    http_found = set(repo.api_terms_found) & _HTTP_TERMS
    if http_found and not acc.accepts_context("http_libraries"):
        _add(
            f"HTTP networking libraries in use: {', '.join(sorted(http_found))}",
            "Document external API endpoints in README to give agents accurate context.",
        )

    if repo.has_tests_dir and not acc.accepts_context("test_suite"):
        _add(
            "Test suite present — actively developed project.",
            "Run the test suite before and after any agent session.",
        )

    if repo.has_node_modules and not acc.accepts_context("node_modules"):
        signals.append("node_modules present — dependencies installed in tree.")

    if repo.file_count > 500 and not acc.accepts_context("large_file_count"):
        _add(
            f"Large file count ({repo.file_count} files)"
            " — broad agent scope increases risk of unintended changes.",
            "Consider scoping agent access to specific subdirectories.",
        )

    if not repo.has_readme:
        _add(
            "Missing README — project context unavailable to agent.",
            "Add README.md describing the project purpose and structure.",
        )

    if not repo.has_claude_md:
        _add(
            "Missing CLAUDE.md — no agent policy defined.",
            "Run `repo-governor policy-init <repo_path>` to generate CLAUDE.md.",
        )

    if not repo.has_agents_md:
        _add(
            "Missing AGENTS.md — no machine-readable safety policy.",
            "Add AGENTS.md defining permitted agent behaviors.",
        )

    if not repo.has_gitignore and not gitignore_already_high:
        _add(
            "Missing .gitignore — unintended files may be tracked.",
            "Add a .gitignore appropriate for the repository's language stack.",
        )

    return signals, actions


def _compute_readiness_score(repo: RepoInfo) -> int:
    score = 100

    if repo.has_env_files:
        score -= 20

    if _any_suffix(repo.artifact_paths, _DB_SUFFIXES):
        score -= 20

    if _any_suffix(repo.artifact_paths, _SHEET_SUFFIXES):
        score -= 15

    if _any_log(repo.artifact_paths):
        score -= 15

    if not repo.has_readme:
        score -= 10

    if not repo.has_tests_dir:
        score -= 10

    if not repo.has_gitignore:
        score -= 10

    has_any_api = bool(
        set(repo.api_terms_found)
        & (_AI_TERMS | _CRED_TERMS | _EXT_DB_TERMS | _HTTP_TERMS)
    )
    if has_any_api and not repo.has_env_example:
        score -= 10

    has_deployment = any([
        repo.has_wrangler_toml,
        repo.has_vercel_json,
        repo.has_netlify_toml,
        repo.has_render_yaml,
        repo.has_dockerfile,
        repo.has_docker_compose,
        repo.has_github_workflows,
    ])
    if has_deployment and not repo.has_readme:
        score -= 10

    return max(0, score)


# ── public API ───────────────────────────────────────────────────────────────

def classify_repo(
    repo: RepoInfo,
    *,
    confidence_feeders: list[str] | None = None,
    accepted: AcceptedRisks | None = None,
) -> ClassifiedRepo:
    """Apply deterministic risk classification rules to a RepoInfo."""
    acc = (accepted or AcceptedRisks()).for_repo(repo.name)
    high_reasons, blocking, high_actions, gitignore_high = _high_signals(repo, acc)
    medium_signals, medium_actions = _medium_signals(repo, gitignore_high, acc)

    if high_reasons:
        risk_level = RiskLevel.HIGH
    elif len(medium_signals) >= 2:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    readiness_score = _compute_readiness_score(repo)

    all_actions = list(dict.fromkeys(high_actions + medium_actions))

    agent_ready = (
        not blocking
        and risk_level == RiskLevel.LOW
        and repo.has_claude_md
        and repo.has_gitignore
        and not repo.has_env_files
    )

    return ClassifiedRepo(
        repo=repo,
        risk_level=risk_level,
        risk_reasons=high_reasons + medium_signals,
        recommended_actions=all_actions,
        blocking_issues=blocking,
        readiness_score=readiness_score,
        agent_ready=agent_ready,
        accepted_risks=acc.notes,
        decision_taxonomy=_decision_taxonomy(repo, risk_level),
        governance_status=evaluate_governance_status(
            repo.path,
            confidence_feeders=confidence_feeders,
        ),
    )


def classify_all(repos: list[RepoInfo]) -> list[ClassifiedRepo]:
    feeders = discover_confidence_feeders([r.path for r in repos])
    return [classify_repo(r, confidence_feeders=feeders) for r in repos]
