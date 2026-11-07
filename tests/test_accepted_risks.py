"""Accepted-risk exceptions: narrow, attributed, and unable to hide real secrets."""
from repo_governor.accepted_risks import AcceptedRisks, parse_accepted_risks
from repo_governor.classifier import RiskLevel, classify_repo
from repo_governor.scanner import RepoInfo


def _repo(**kw) -> RepoInfo:
    base = dict(
        name="Demo", path=__import__("pathlib").Path("."), is_git_repo=True,
        has_gitignore=True, has_readme=True, has_claude_md=True, has_agents_md=True,
        has_pyproject=False, has_requirements_txt=False, has_env_files=False,
    )
    base.update(kw)
    return RepoInfo(**base)


def _cfg(*entries) -> AcceptedRisks:
    return parse_accepted_risks({"repos": {"demo": {"accepted": list(entries)}}})


def _entry(category, **kw):
    return {"category": category, "reason": "documented fixture", "approved_by": "Owner",
            "approved_on": "2026-11-06", **kw}


def test_without_exception_ai_usage_is_blocking():
    c = classify_repo(_repo(api_terms_found=["openai"]))
    assert c.risk_level == RiskLevel.HIGH and c.blocking_issues


def test_ai_exception_clears_blocker_and_records_note():
    cfg = _cfg(_entry("ai_providers", terms=["openai"]))
    c = classify_repo(_repo(api_terms_found=["openai"]), accepted=cfg)
    assert c.risk_level == RiskLevel.LOW and not c.blocking_issues
    assert any("accepted" in n and "Owner" in n for n in c.accepted_risks)


def test_new_provider_outside_exception_is_still_flagged():
    cfg = _cfg(_entry("ai_providers", terms=["openai"]))
    c = classify_repo(_repo(api_terms_found=["openai", "anthropic"]), accepted=cfg)
    assert c.risk_level == RiskLevel.HIGH


def test_spreadsheet_exception_is_path_scoped():
    cfg = _cfg(_entry("spreadsheet_files", paths=["sample_data/*.xlsx"]))
    ok = classify_repo(_repo(artifact_paths=["sample_data/a.xlsx"]), accepted=cfg)
    bad = classify_repo(_repo(artifact_paths=["sample_data/a.xlsx", "exports/real.xlsx"]), accepted=cfg)
    assert ok.risk_level == RiskLevel.LOW
    assert bad.risk_level == RiskLevel.HIGH and "exports/real.xlsx" in bad.blocking_issues[0]


def test_entry_without_reason_or_approver_is_ignored():
    cfg = parse_accepted_risks({"repos": {"demo": {"accepted": [
        {"category": "ai_providers", "terms": ["openai"]}]}}})
    c = classify_repo(_repo(api_terms_found=["openai"]), accepted=cfg)
    assert c.risk_level == RiskLevel.HIGH and cfg.warnings


def test_secrets_and_credentials_cannot_be_excepted():
    cfg = _cfg(_entry("secret_files", terms=["x"]), _entry("credential_patterns", terms=["api_key"]))
    c = classify_repo(_repo(has_env_files=True, env_file_paths=[".env"],
                            api_terms_found=["api_key"]), accepted=cfg)
    assert c.risk_level == RiskLevel.HIGH
    assert len(cfg.warnings) == 2


def test_missing_version_control_cannot_be_excepted():
    cfg = _cfg(_entry("context_signals", terms=["ci_cd"]))
    c = classify_repo(_repo(is_git_repo=False), accepted=cfg)
    assert c.risk_level == RiskLevel.HIGH


def test_context_signal_exception_removes_it_from_medium_count():
    repo = _repo(has_requirements_txt=True, has_tests_dir=True)
    assert classify_repo(repo).risk_level == RiskLevel.MEDIUM
    cfg = _cfg(_entry("context_signals", terms=["dependency_manifests", "test_suite"]))
    assert classify_repo(repo, accepted=cfg).risk_level == RiskLevel.LOW


def test_exception_only_applies_to_named_repo():
    cfg = _cfg(_entry("ai_providers", terms=["openai"]))
    other = _repo(name="Other", api_terms_found=["openai"])
    assert classify_repo(other, accepted=cfg).risk_level == RiskLevel.HIGH


def test_accepted_risks_appear_in_report_plan_and_formats():
    from repo_governor.evidence_report import (
        _format_repo_action_plans_md,
        _format_repo_action_plans_txt,
    )
    from repo_governor.report_analysis import build_repo_action_plan

    note = "External AI usage (openai) — accepted: intended (approved by Owner on 2026-11-06)"
    plan = build_repo_action_plan(
        {"full_name": "o/Demo", "risk_level": "LOW", "passed": True, "accepted_risks": [note]}
    )
    assert plan["accepted_risks"] == [note]
    assert note in "\n".join(_format_repo_action_plans_md([plan]))
    assert note in "\n".join(_format_repo_action_plans_txt([plan]))
