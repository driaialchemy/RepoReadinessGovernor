"""Reviewed, per-repo accepted-risk exceptions.

An exception downgrades a finding from "blocking" to "accepted" only when it is
narrowly scoped (specific providers, config files or paths) and carries a
reason, an approver and a date. Anything outside that scope is still flagged.

Never exceptable: committed secret files, credential patterns in code, and
missing version control.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml

DEFAULT_CONFIG_RELATIVE = Path("config") / "accepted_risks.yml"
ENV_VAR = "REPO_GOVERNOR_ACCEPTED_RISKS"

TERM_CATEGORIES = frozenset({
    "ai_providers",
    "external_database",
    "cloud_deployment",
    "context_signals",
})
PATH_CATEGORIES = frozenset({"spreadsheet_files", "database_files", "log_files"})
CATEGORIES = TERM_CATEGORIES | PATH_CATEGORIES

CONTEXT_SIGNAL_KEYS = frozenset({
    "dependency_manifests",
    "containers",
    "ci_cd",
    "http_libraries",
    "test_suite",
    "node_modules",
    "large_file_count",
})


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


@dataclass(frozen=True)
class AcceptedRisk:
    category: str
    reason: str
    approved_by: str
    approved_on: str
    terms: frozenset[str] = frozenset()
    paths: tuple[str, ...] = ()

    def note(self, description: str) -> str:
        return (
            f"{description} — accepted: {self.reason} "
            f"(approved by {self.approved_by} on {self.approved_on})"
        )


@dataclass
class RepoAcceptance:
    """Exceptions that apply to one repo, plus the notes recorded while classifying."""

    entries: dict[str, AcceptedRisk] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def accept_terms(self, category: str, found: set[str], description: str) -> bool:
        entry = self.entries.get(category)
        if entry is None or not found or not found <= entry.terms:
            return False
        self.notes.append(entry.note(description))
        return True

    def accept_paths(
        self, category: str, paths: list[str], description_prefix: str
    ) -> list[str]:
        """Return the paths NOT covered by an exception; record a note for covered ones."""
        entry = self.entries.get(category)
        if entry is None:
            return paths
        covered = [p for p in paths if any(fnmatch(p, pat) for pat in entry.paths)]
        uncovered = [p for p in paths if p not in covered]
        if covered:
            self.notes.append(entry.note(f"{description_prefix}: {', '.join(covered[:3])}"))
        return uncovered

    def accepts_context(self, key: str) -> bool:
        entry = self.entries.get("context_signals")
        return entry is not None and key in entry.terms


@dataclass
class AcceptedRisks:
    by_repo: dict[str, dict[str, AcceptedRisk]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def for_repo(self, repo_name: str) -> RepoAcceptance:
        return RepoAcceptance(entries=dict(self.by_repo.get(_norm(repo_name), {})))


def _parse_entry(repo: str, raw: dict, warnings: list[str]) -> AcceptedRisk | None:
    category = str(raw.get("category", "")).strip()
    if category not in CATEGORIES:
        warnings.append(f"{repo}: unknown or non-exceptable category '{category}' ignored")
        return None
    reason = str(raw.get("reason", "")).strip()
    approver = str(raw.get("approved_by", "")).strip()
    approved_on = str(raw.get("approved_on", "")).strip()
    if not (reason and approver and approved_on):
        warnings.append(f"{repo}/{category}: needs reason, approved_by and approved_on; ignored")
        return None
    terms = frozenset(str(t).strip().lower() for t in raw.get("terms") or [])
    paths = tuple(str(p).strip() for p in raw.get("paths") or [])
    if category in TERM_CATEGORIES and not terms:
        warnings.append(f"{repo}/{category}: 'terms' is required; ignored")
        return None
    if category in PATH_CATEGORIES and not paths:
        warnings.append(f"{repo}/{category}: 'paths' is required; ignored")
        return None
    if category == "context_signals" and not terms <= CONTEXT_SIGNAL_KEYS:
        warnings.append(f"{repo}/{category}: unknown signal keys; ignored")
        return None
    return AcceptedRisk(category, reason, approver, approved_on, terms, paths)


def parse_accepted_risks(data: object) -> AcceptedRisks:
    result = AcceptedRisks()
    if not isinstance(data, dict):
        return result
    for repo, body in (data.get("repos") or {}).items():
        entries: dict[str, AcceptedRisk] = {}
        for raw in (body or {}).get("accepted") or []:
            if not isinstance(raw, dict):
                continue
            entry = _parse_entry(str(repo), raw, result.warnings)
            if entry is not None:
                entries[entry.category] = entry
        if entries:
            result.by_repo[_norm(str(repo))] = entries
    return result


def load_accepted_risks(path: Path | None = None) -> AcceptedRisks:
    """Load exceptions from *path*, $REPO_GOVERNOR_ACCEPTED_RISKS, or config/accepted_risks.yml."""
    if path is None:
        env = os.environ.get(ENV_VAR)
        path = Path(env) if env else DEFAULT_CONFIG_RELATIVE
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return AcceptedRisks()
    return parse_accepted_risks(yaml.safe_load(text))
