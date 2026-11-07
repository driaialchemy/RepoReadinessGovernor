"""Tests for repo_governor.scanner."""
from pathlib import Path

import pytest

from repo_governor.scanner import (
    MAX_SCAN_BYTES,
    RepoInfo,
    scan_repo,
    scan_root,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_git_repo(path: Path) -> None:
    (path / ".git").mkdir()
    (path / ".gitignore").write_text("*.pyc\n")


# ---------------------------------------------------------------------------
# Existing tests (11) — must remain green
# ---------------------------------------------------------------------------

def test_scan_repo_basic(tmp_path):
    _make_git_repo(tmp_path)
    (tmp_path / "README.md").write_text("# Test")
    (tmp_path / "main.py").write_text("print('hello')")

    repo = scan_repo(tmp_path)

    assert repo.is_git_repo is True
    assert repo.has_gitignore is True
    assert repo.has_readme is True
    assert repo.has_claude_md is False
    assert repo.has_agents_md is False
    assert repo.has_env_files is False
    assert "Python" in repo.languages


def test_scan_repo_detects_env_file(tmp_path):
    (tmp_path / ".env").write_text("SECRET=hunter2")

    repo = scan_repo(tmp_path)

    assert repo.has_env_files is True
    assert ".env" in repo.env_file_paths


def test_scan_repo_detects_claude_md(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("# Policy")

    repo = scan_repo(tmp_path)

    assert repo.has_claude_md is True


def test_scan_repo_detects_agents_md(tmp_path):
    (tmp_path / "AGENTS.md").write_text("# Agents")

    repo = scan_repo(tmp_path)

    assert repo.has_agents_md is True


def test_scan_repo_counts_files_excludes_git(tmp_path):
    (tmp_path / "a.py").write_text("")
    (tmp_path / "b.py").write_text("")
    (tmp_path / "c.md").write_text("")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main")

    repo = scan_repo(tmp_path)

    assert repo.file_count == 3


def test_scan_repo_no_git(tmp_path):
    repo = scan_repo(tmp_path)
    assert repo.is_git_repo is False


def test_scan_repo_detects_multiple_languages(tmp_path):
    (tmp_path / "main.py").write_text("")
    (tmp_path / "app.js").write_text("")
    (tmp_path / "util.go").write_text("")

    repo = scan_repo(tmp_path)

    assert "Python" in repo.languages
    assert "JavaScript" in repo.languages
    assert "Go" in repo.languages


def test_scan_root_finds_subdirectories(tmp_path):
    (tmp_path / "repo_a").mkdir()
    (tmp_path / "repo_b").mkdir()

    results = scan_root(tmp_path)
    names = {r.name for r in results}

    assert "repo_a" in names
    assert "repo_b" in names


def test_scan_root_ignores_files(tmp_path):
    (tmp_path / "repo_a").mkdir()
    (tmp_path / "README.md").write_text("# root")

    results = scan_root(tmp_path)

    assert all(r.name != "README.md" for r in results)
    assert len(results) == 1


def test_scan_root_raises_on_missing_dir():
    with pytest.raises(ValueError, match="Not a directory"):
        scan_root(Path("C:/nonexistent/path/that/does/not/exist"))


def test_scan_root_returns_sorted(tmp_path):
    (tmp_path / "zebra").mkdir()
    (tmp_path / "alpha").mkdir()
    (tmp_path / "mango").mkdir()

    results = scan_root(tmp_path)
    names = [r.name for r in results]

    assert names == sorted(names)


# ---------------------------------------------------------------------------
# New tests — requirements 2–6 + expanded coverage
# ---------------------------------------------------------------------------

# --- requirement 2: README and tests folder ---

def test_scan_repo_detects_tests_dir(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_something.py").write_text("def test_ok(): pass")

    repo = scan_repo(tmp_path)

    assert repo.has_tests_dir is True


def test_scan_repo_no_tests_dir(tmp_path):
    (tmp_path / "README.md").write_text("# No tests yet")

    repo = scan_repo(tmp_path)

    assert repo.has_tests_dir is False


# --- .env.example ---

def test_scan_repo_detects_env_example(tmp_path):
    (tmp_path / ".env.example").write_text("SECRET=\nDATABASE_URL=\n")

    repo = scan_repo(tmp_path)

    assert repo.has_env_example is True
    assert repo.has_env_files is False  # example file is NOT a secret


# --- requirement 4: generated artefacts ---

def test_scan_repo_detects_artifacts(tmp_path):
    (tmp_path / "export.xlsx").write_bytes(b"\x00" * 10)
    (tmp_path / "data.csv").write_text("a,b,c\n1,2,3\n")
    (tmp_path / "app.log").write_text("INFO started\n")
    (tmp_path / "local.db").write_bytes(b"\x00" * 10)

    repo = scan_repo(tmp_path)

    assert "export.xlsx" in repo.artifact_paths
    assert "data.csv" in repo.artifact_paths
    assert "app.log" in repo.artifact_paths
    assert "local.db" in repo.artifact_paths


def test_scan_repo_artifacts_exclude_source_files(tmp_path):
    (tmp_path / "main.py").write_text("x = 1")

    repo = scan_repo(tmp_path)

    assert repo.artifact_paths == []


# --- Node.js / frontend ---

def test_scan_repo_detects_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"app"}')

    repo = scan_repo(tmp_path)

    assert repo.has_package_json is True


# --- containerisation ---

def test_scan_repo_detects_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n")

    repo = scan_repo(tmp_path)

    assert repo.has_dockerfile is True


def test_scan_repo_detects_docker_compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text("services:\n  app:\n    image: python\n")

    repo = scan_repo(tmp_path)

    assert repo.has_docker_compose is True


# --- CI/CD ---

def test_scan_repo_detects_github_workflows(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("on: [push]\n")

    repo = scan_repo(tmp_path)

    assert repo.has_github_workflows is True


# --- deployment configs ---

def test_scan_repo_detects_wrangler_toml(tmp_path):
    (tmp_path / "wrangler.toml").write_text('[project]\nname = "worker"\n')

    repo = scan_repo(tmp_path)

    assert repo.has_wrangler_toml is True


def test_scan_repo_detects_vercel_json(tmp_path):
    (tmp_path / "vercel.json").write_text('{"version":2}')

    repo = scan_repo(tmp_path)

    assert repo.has_vercel_json is True


def test_scan_repo_detects_netlify_toml(tmp_path):
    (tmp_path / "netlify.toml").write_text('[build]\ncommand = "npm run build"\n')

    repo = scan_repo(tmp_path)

    assert repo.has_netlify_toml is True


def test_scan_repo_detects_render_yaml(tmp_path):
    (tmp_path / "render.yaml").write_text("services:\n  - type: web\n")

    repo = scan_repo(tmp_path)

    assert repo.has_render_yaml is True


# --- virtual environments ---

def test_scan_repo_detects_venv_dir(tmp_path):
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")

    repo = scan_repo(tmp_path)

    assert repo.has_venv is True


def test_scan_repo_detects_venv_named_venv(tmp_path):
    (tmp_path / "venv").mkdir()

    repo = scan_repo(tmp_path)

    assert repo.has_venv is True


# --- __pycache__ ---

def test_scan_repo_detects_pycache(tmp_path):
    (tmp_path / "__pycache__").mkdir()

    repo = scan_repo(tmp_path)

    assert repo.has_pycache is True


# --- node_modules ---

def test_scan_repo_detects_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()

    repo = scan_repo(tmp_path)

    assert repo.has_node_modules is True


# --- dist / build ---

def test_scan_repo_detects_dist_and_build(tmp_path):
    (tmp_path / "dist").mkdir()
    (tmp_path / "build").mkdir()

    repo = scan_repo(tmp_path)

    assert repo.has_dist_dir is True
    assert repo.has_build_dir is True


# --- requirement 5: skip dirs keep files private + don't inflate counts ---

def test_scan_repo_env_inside_node_modules_not_detected(tmp_path):
    """A .env file inside node_modules must NOT trigger has_env_files."""
    nm = tmp_path / "node_modules"
    nm.mkdir()
    (nm / ".env").write_text("SECRET=do_not_read")
    (tmp_path / "index.js").write_text("console.log('hi')")

    repo = scan_repo(tmp_path)

    assert repo.has_env_files is False
    assert repo.env_file_paths == []


def test_scan_repo_files_inside_skip_dirs_not_counted(tmp_path):
    """Files inside SKIP_DIRS must not inflate file_count."""
    (tmp_path / "main.py").write_text("x = 1")
    node = tmp_path / "node_modules"
    node.mkdir()
    for i in range(50):
        (node / f"dep{i}.js").write_text("")

    repo = scan_repo(tmp_path)

    assert repo.file_count == 1


def test_scan_repo_pycache_files_excluded_from_count(tmp_path):
    (tmp_path / "app.py").write_text("x = 1")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "app.cpython-312.pyc").write_bytes(b"\x00" * 20)

    repo = scan_repo(tmp_path)

    assert repo.file_count == 1


# --- requirement 3 / API term detection ---

def test_scan_repo_api_term_detection_in_python(tmp_path):
    (tmp_path / "client.py").write_text("import openai\nclient = openai.OpenAI()\n")

    repo = scan_repo(tmp_path)

    assert "openai" in repo.api_terms_found


def test_scan_repo_api_term_detection_multiple(tmp_path):
    (tmp_path / "main.py").write_text(
        "import anthropic\nimport httpx\nDATABASE_URL = 'postgres://localhost/db'\n"
    )

    repo = scan_repo(tmp_path)

    assert "anthropic" in repo.api_terms_found
    assert "httpx" in repo.api_terms_found
    assert "postgres" in repo.api_terms_found


def test_scan_repo_api_term_env_file_not_scanned(tmp_path):
    """Contents of .env must never be scanned for API terms."""
    (tmp_path / ".env").write_text(
        "OPENAI_API_KEY=sk-secret\nANTHROPIC_API_KEY=sk-ant-secret\n"
    )

    repo = scan_repo(tmp_path)

    assert repo.api_terms_found == []


def test_scan_repo_api_term_large_file_skipped(tmp_path):
    """Files larger than MAX_SCAN_BYTES must not be content-scanned."""
    padding = "x" * (MAX_SCAN_BYTES + 1)
    (tmp_path / "huge.py").write_text(padding + "\nopenai\n")

    repo = scan_repo(tmp_path)

    assert "openai" not in repo.api_terms_found


def test_scan_repo_api_term_binary_extension_skipped(tmp_path):
    """Binary-extension files (.xlsx) must not be content-scanned."""
    content = b"openai" + b"\x00" * 100
    (tmp_path / "data.xlsx").write_bytes(content)

    repo = scan_repo(tmp_path)

    assert "openai" not in repo.api_terms_found


# --- requirement 6: invalid / missing paths ---

def test_scan_root_raises_on_file_path(tmp_path):
    f = tmp_path / "notadir.txt"
    f.write_text("hello")

    with pytest.raises(ValueError, match="Not a directory"):
        scan_root(f)


# --- credential detection: real secrets only ---

def test_credential_words_in_docs_are_not_flagged(tmp_path):
    (tmp_path / "CLAUDE.md").write_text("Never commit api_key or DATABASE_URL values.\n")
    (tmp_path / "README.md").write_text("Set API_KEY in your environment.\n")

    repo = scan_repo(tmp_path)

    assert "api_key" not in repo.api_terms_found
    assert "database_url" not in repo.api_terms_found


def test_credential_env_var_reads_are_not_flagged(tmp_path):
    (tmp_path / "app.py").write_text(
        "import os\napi_key = os.environ['OPENAI_API_KEY']\n"
        "DATABASE_URL = os.getenv('DATABASE_URL')\n"
    )

    repo = scan_repo(tmp_path)

    assert "api_key" not in repo.api_terms_found
    assert "database_url" not in repo.api_terms_found


def test_credential_placeholders_and_weak_dev_urls_are_not_flagged(tmp_path):
    (tmp_path / "config.py").write_text(
        'api_key = "your-api-key-here"\n'
        'DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/app"\n'
    )

    repo = scan_repo(tmp_path)

    assert "api_key" not in repo.api_terms_found
    assert "database_url" not in repo.api_terms_found


def test_hardcoded_api_key_is_flagged(tmp_path):
    value = "q8Zr2LmN" + "7vXc4TbK9wPd"
    (tmp_path / "client.py").write_text("api_key = '" + value + "'\n")

    repo = scan_repo(tmp_path)

    assert "api_key" in repo.api_terms_found


def test_provider_key_format_is_flagged(tmp_path):
    (tmp_path / "notes.txt").write_text("key: sk-" + "aB3dE5gH7jK9mN2pQ4sT6vX8zC1fL0rW5yU3" + "\n")

    repo = scan_repo(tmp_path)

    assert "api_key" in repo.api_terms_found


def test_url_with_real_password_is_flagged(tmp_path):
    url = "postgresql://" + "svc_user:" + "Xk29fQ7m" + "LpR4vZ" + "@db.internal:5432/prod"
    (tmp_path / "db.py").write_text("URL = '" + url + "'\n")

    repo = scan_repo(tmp_path)

    assert "database_url" in repo.api_terms_found


def test_key_prefix_inside_ordinary_words_is_not_flagged(tmp_path):
    (tmp_path / "audit.json").write_text(
        '{"repo": "risk-review-pipeline-for-contracts-and-agreements-v2"}\n'
    )

    repo = scan_repo(tmp_path)

    assert "api_key" not in repo.api_terms_found
