# AGENTS.md â€” Agent Safety Policy

This file defines the safety constraints for any AI agent (Claude Code, Codex, Copilot, etc.) working in the AIAlchemy Repo Governor repository.

## Permitted Behaviors

- Read source code, tests, and documentation.
- Run the test suite (`pytest`) before claiming a task is complete.
- Generate or update Markdown reports (but do not commit them automatically).
- Write new Python source files under `src/repo_governor/` when adding a feature.
- Suggest improvements to risk classification logic.
- Run `repo-governor` CLI commands against the `repositories/` scan target.
- Run `pip install -e .` to install in editable mode (inside a virtual environment).

## Prohibited Behaviors

| Prohibition | Reason |
|------------|--------|
| Print, log, or surface secret/env values | Risk of credential leakage |
| Auto-commit or auto-push | Requires human review |
| Delete files | Irreversible without explicit user intent |
| Modify `.git/` directly | Corrupts version history |
| Add external dependencies without approval | Increases attack surface |
| Run `pip install` globally (outside venv) | Pollutes system Python |
| Add a web dashboard, database, or background scheduler | Out of MVP scope |
| Claim completion without running `pytest` | Breaks the feedback loop |

## Coding Standards

- Use `pathlib.Path` everywhere â€” no `os.path` or string path manipulation.
- Use dataclasses for data models.
- All filesystem operations must be Windows-compatible.
- Keep functions small and independently testable.
- No external dependencies beyond the existing `pyproject.toml` list without approval.
- Prefer small, reviewable diffs. One feature or fix per commit.
- Summarize what changed and why before suggesting a commit.

## Scope Boundaries

Agents should operate only within this repository directory. Scanning other directories is done via the `scan` command, which is read-only and never modifies scanned repos.

## Non-Goals (do not implement these)

- Cloud sync or remote storage of any kind
- User accounts or authentication
- A web UI or REST API
- Database persistence
- Automatic remediation of scanned repos
- Auto-generated `.gitignore` entries in scanned repos

## Output Conventions

- Reports are written to `./reports/` by default (excluded from git).
- Policy files (`CLAUDE.md`, `repo_policy.yaml`) are written to the target repo, never auto-committed.
- All console output must be human-readable and must never print raw secret values.

## Escalation

If the agent encounters a HIGH-risk repo (exposed secrets, no git init), it should surface the finding clearly and stop. It must not attempt auto-remediation.

If tests fail after a change, the agent must diagnose and fix the failure before proceeding, rather than bypassing or disabling tests.

# Audit remediation metadata
audit_path: audit/multi_repo/2026-09-18/repo_AIAlchemy-Repo-Governor_20260918T004839Z.json
risk_level: HIGH
human_review_required: true
audit_findings:
  - "Multiple AI provider integrations (anthropic, gemini, google.generativeai, openai) — elevated orchestration complexity."
  - "Credential pattern indicators in code: api_key, database_url"
  - "External database terms detected (postgres, supabase) — potential data compliance risk."
  - "Risk level is HIGH, expected LOW."
  - "Dependency manifests present: pyproject.toml"
  - "CI/CD workflow configuration present (.github/workflows)."
  - "HTTP networking libraries in use: aiohttp, httpx, requests"
  - "Test suite present — actively developed project."

## Approval gates

Human approval is required before dependency changes, external-call changes, deploy or container config, secrets, and AI-provider or database config.

## Setup

pip install -e .
python -m pytest -q

