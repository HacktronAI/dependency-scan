"""Tests for scripts/hfw_report.py.

The report script intentionally has zero non-stdlib imports so the action runs
on a fresh `actions/setup-python@v5` checkout without an install step. These
tests cover the same surface the action depends on.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "hfw_report.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("hfw_report", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["hfw_report"] = module
    spec.loader.exec_module(module)
    return module


hfw = _load_module()


# ---------------------------------------------------------------------------
# ecosystem detection


def test_detect_ecosystem_pnpm():
    assert hfw.detect_ecosystem(Path("pnpm-lock.yaml")) == "npm"


def test_detect_ecosystem_pyproject():
    assert hfw.detect_ecosystem(Path("pyproject.toml")) == "pypi"


def test_detect_ecosystem_uv_lock():
    assert hfw.detect_ecosystem(Path("uv.lock")) == "pypi"


def test_detect_ecosystem_requirements_variants():
    assert hfw.detect_ecosystem(Path("requirements.txt")) == "pypi"
    assert hfw.detect_ecosystem(Path("requirements-dev.txt")) == "pypi"
    assert hfw.detect_ecosystem(Path("requirements/prod.txt")) == "pypi"


def test_detect_ecosystem_package_lock():
    assert hfw.detect_ecosystem(Path("package-lock.json")) == "npm"
    assert hfw.detect_ecosystem(Path("npm-shrinkwrap.json")) == "npm"


def test_detect_ecosystem_unsupported_returns_none():
    # yarn.lock and Pipfile.lock still have no parser; be explicit so we
    # don't silently mis-parse them.
    assert hfw.detect_ecosystem(Path("yarn.lock")) is None
    assert hfw.detect_ecosystem(Path("Pipfile.lock")) is None


# ---------------------------------------------------------------------------
# pnpm-lock.yaml parser


def test_parse_pnpm_lock_strips_peer_dep_suffix(tmp_path: Path):
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text(
        "lockfileVersion: '9.0'\n"
        "packages:\n"
        "  '@scope/pkg@1.2.3':\n"
        "    resolution: {}\n"
        "  zod@3.24.3(peer-dep@1.0.0):\n"
        "    resolution: {}\n"
        "  workspace-thing@workspace:*:\n"
        "    resolution: {}\n"
    )
    parsed = hfw.parse_pnpm_lock(lock)
    assert ("@scope/pkg", "1.2.3") in parsed
    assert ("zod", "3.24.3") in parsed
    assert all("workspace-thing" not in nv[0] for nv in parsed)


def test_parse_pnpm_lock_drops_trailing_colon(tmp_path: Path):
    """Regression: unquoted keys had the YAML colon picked up as part of version."""
    lock = tmp_path / "pnpm-lock.yaml"
    lock.write_text(
        "lockfileVersion: '9.0'\npackages:\n  zod@4.4.3:\n    resolution: {}\n"
    )
    parsed = hfw.parse_pnpm_lock(lock)
    assert parsed == {("zod", "4.4.3")}


def test_parse_pnpm_lock_empty_file(tmp_path: Path):
    lock = tmp_path / "pnpm-lock.yaml"
    lock.touch()
    assert hfw.parse_pnpm_lock(lock) == set()


# ---------------------------------------------------------------------------
# package-lock.json parser


def test_parse_package_lock_v3_flat_packages(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("""{
      "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/diff": {"version": "4.0.4"},
        "node_modules/@babel/core": {"version": "7.24.0"},
        "node_modules/@babel/runtime": {"version": "7.24.1"}
      }
    }""")
    parsed = hfw.parse_package_lock_json(lock)
    assert ("diff", "4.0.4") in parsed
    assert ("@babel/core", "7.24.0") in parsed
    assert ("@babel/runtime", "7.24.1") in parsed
    assert ("demo", "1.0.0") not in parsed  # root project skipped


def test_parse_package_lock_v3_handles_nested_node_modules(tmp_path: Path):
    """When deps duplicate at different versions, each instance is counted."""
    lock = tmp_path / "package-lock.json"
    lock.write_text("""{
      "name": "demo", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "node_modules/diff": {"version": "4.0.4"},
        "node_modules/mocha/node_modules/diff": {"version": "5.0.0"}
      }
    }""")
    parsed = hfw.parse_package_lock_json(lock)
    assert ("diff", "4.0.4") in parsed
    assert ("diff", "5.0.0") in parsed


def test_parse_package_lock_v3_skips_workspace_links(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("""{
      "name": "monorepo", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "node_modules/my-workspace-pkg": {"resolved": "packages/foo", "link": true},
        "node_modules/lodash": {"version": "4.17.21"}
      }
    }""")
    parsed = hfw.parse_package_lock_json(lock)
    assert parsed == {("lodash", "4.17.21")}


def test_parse_package_lock_v1_nested_dependencies(tmp_path: Path):
    """npm 6 and earlier used a nested `dependencies` tree."""
    lock = tmp_path / "package-lock.json"
    lock.write_text("""{
      "name": "old", "version": "1.0.0", "lockfileVersion": 1,
      "dependencies": {
        "lodash": {"version": "4.17.21"},
        "mocha": {
          "version": "8.0.0",
          "dependencies": {"diff": {"version": "4.0.2"}}
        }
      }
    }""")
    parsed = hfw.parse_package_lock_json(lock)
    assert ("lodash", "4.17.21") in parsed
    assert ("mocha", "8.0.0") in parsed
    assert ("diff", "4.0.2") in parsed


def test_parse_package_lock_invalid_json_returns_empty(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("not valid json {")
    assert hfw.parse_package_lock_json(lock) == set()


def test_parse_package_lock_empty_file(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.touch()
    assert hfw.parse_package_lock_json(lock) == set()


def test_parse_manifest_routes_package_lock_to_npm_parser(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text("""{"lockfileVersion": 3, "packages": {
      "node_modules/diff": {"version": "4.0.4"}}}""")
    parsed = hfw.parse_manifest(lock, "npm")
    assert parsed == {("diff", "4.0.4")}


def test_parse_manifest_routes_npm_shrinkwrap_to_npm_parser(tmp_path: Path):
    lock = tmp_path / "npm-shrinkwrap.json"
    lock.write_text("""{"lockfileVersion": 3, "packages": {
      "node_modules/diff": {"version": "4.0.4"}}}""")
    parsed = hfw.parse_manifest(lock, "npm")
    assert parsed == {("diff", "4.0.4")}


def test_parse_manifest_accepts_explicit_pypi_txt_requirements(tmp_path: Path):
    req = tmp_path / "prod.txt"
    req.write_text("requests==2.31.0\n")
    parsed = hfw.parse_manifest(req, "pypi")
    assert parsed == {("requests", "2.31.0")}


# ---------------------------------------------------------------------------
# pyproject.toml parser


def test_parse_pyproject_picks_up_pinned_main_deps(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[project]\n"
        'name = "x"\n'
        'version = "0.1"\n'
        "dependencies = [\n"
        '  "fastapi==0.136.1",\n'
        '  "uvicorn[standard]==0.46.0",\n'
        '  "google-auth",\n'
        '  "ranged>=1.2",\n'
        "]\n"
    )
    parsed = hfw.parse_pyproject_toml(pp)
    assert ("fastapi", "0.136.1") in parsed
    assert ("uvicorn", "0.46.0") in parsed
    # unconstrained and range-only deps are skipped on purpose
    assert all(name != "google-auth" for name, _ in parsed)
    assert all(name != "ranged" for name, _ in parsed)


def test_parse_pyproject_walks_optional_dependencies_table(tmp_path: Path):
    """Regression: [project.optional-dependencies] uses extras names like
    `test = [...]`; the old regex parser only matched keys ending in
    `dependencies` and missed them entirely."""
    pp = tmp_path / "pyproject.toml"
    pp.write_text(
        "[project]\n"
        'name = "x"\n'
        'version = "0.1"\n'
        "dependencies = []\n"
        "\n"
        "[project.optional-dependencies]\n"
        "test = [\n"
        '  "httpx==0.27.0",\n'
        '  "pytest==8.3.4",\n'
        "]\n"
        "dev = [\n"
        '  "ruff==0.7.4",\n'
        "]\n"
    )
    parsed = hfw.parse_pyproject_toml(pp)
    assert ("httpx", "0.27.0") in parsed
    assert ("pytest", "8.3.4") in parsed
    assert ("ruff", "0.7.4") in parsed


def test_parse_pyproject_malformed_returns_empty(tmp_path: Path):
    pp = tmp_path / "pyproject.toml"
    pp.write_text("[project\nname = ")  # invalid TOML
    assert hfw.parse_pyproject_toml(pp) == set()


# ---------------------------------------------------------------------------
# uv.lock + requirements.txt parsers


def test_parse_uv_lock(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        "version = 1\n"
        "\n"
        "[[package]]\n"
        'name = "fastapi"\n'
        'version = "0.136.1"\n'
        "\n"
        "[[package]]\n"
        'name = "Jinja2"\n'
        'version = "3.1.6"\n'
    )
    parsed = hfw.parse_uv_lock(lock)
    assert parsed == {("fastapi", "0.136.1"), ("jinja2", "3.1.6")}


def test_parse_requirements_skips_comments_and_ranges(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "# pip-tools output\n"
        "fastapi==0.136.1\n"
        "uvicorn==0.46.0  # via -r requirements.in\n"
        "ranged>=1.0\n"
    )
    parsed = hfw.parse_requirements_txt(req)
    assert parsed == {("fastapi", "0.136.1"), ("uvicorn", "0.46.0")}


# ---------------------------------------------------------------------------
# uv.lock: skip editable / directory / virtual entries (our own code)


def test_parse_uv_lock_skips_editable_project_self(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        "version = 1\nrevision = 2\n\n"
        '[[package]]\nname = "myapp"\nversion = "0.1.0"\n'
        'source = { editable = "." }\n\n'
        '[[package]]\nname = "requests"\nversion = "2.31.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    parsed = hfw.parse_uv_lock(lock)
    assert ("requests", "2.31.0") in parsed
    assert ("myapp", "0.1.0") not in parsed


def test_parse_uv_lock_skips_workspace_directory_members(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        "version = 1\n\n"
        '[[package]]\nname = "shared-utils"\nversion = "0.2.0"\n'
        'source = { directory = "./packages/shared-utils" }\n\n'
        '[[package]]\nname = "django"\nversion = "5.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    parsed = hfw.parse_uv_lock(lock)
    assert parsed == {("django", "5.0.0")}


def test_parse_uv_lock_skips_virtual_placeholder(tmp_path: Path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        "version = 1\n\n"
        '[[package]]\nname = "workspace-root"\nversion = "0.0.0"\n'
        'source = { virtual = "." }\n'
    )
    assert hfw.parse_uv_lock(lock) == set()


# ---------------------------------------------------------------------------
# pyproject.toml extended dep-list shapes (PEP 735 / Poetry / PDM)


def test_parse_pyproject_pep735_dependency_groups(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname="x"\nversion="0"\n'
        'dependencies = ["requests==2.31.0"]\n'
        "[dependency-groups]\n"
        'dev = ["pytest==8.0.0", "ruff>=0.6"]\n'
        'test = ["coverage==7.4.0"]\n'
    )
    parsed = hfw.parse_pyproject_toml(py)
    assert ("requests", "2.31.0") in parsed
    assert ("pytest", "8.0.0") in parsed
    assert ("coverage", "7.4.0") in parsed
    assert ("ruff", "0.6") not in parsed


def test_parse_pyproject_poetry_dependencies(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[tool.poetry]\nname="x"\nversion="0"\n'
        "[tool.poetry.dependencies]\n"
        'python = "^3.11"\n'
        'requests = "2.31.0"\n'
        'fastapi = { version = "0.110.0" }\n'
        'caret_dep = "^1.2.3"\n'
        'tilde_dep = "~1.2"\n'
    )
    parsed = hfw.parse_pyproject_toml(py)
    assert ("requests", "2.31.0") in parsed
    assert ("fastapi", "0.110.0") in parsed
    assert all(name != "python" for (name, _) in parsed)
    assert ("caret_dep", "^1.2.3") not in parsed
    assert ("tilde_dep", "~1.2") not in parsed


def test_parse_pyproject_poetry_groups(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[tool.poetry]\nname="x"\nversion="0"\n'
        "[tool.poetry.dependencies]\n"
        "[tool.poetry.group.dev.dependencies]\n"
        'pytest = "8.0.0"\n'
        "[tool.poetry.dev-dependencies]\n"
        'black = "24.4.0"\n'
    )
    parsed = hfw.parse_pyproject_toml(py)
    assert ("pytest", "8.0.0") in parsed
    assert ("black", "24.4.0") in parsed


def test_parse_pyproject_poetry_skips_git_path_url(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[tool.poetry]\nname="x"\nversion="0"\n'
        "[tool.poetry.dependencies]\n"
        'gitdep = { git = "https://example.com/r.git", branch = "main" }\n'
        'pathdep = { path = "../local" }\n'
        'urldep = { url = "https://example.com/foo.tar.gz" }\n'
        'normal = "1.0.0"\n'
    )
    parsed = hfw.parse_pyproject_toml(py)
    assert parsed == {("normal", "1.0.0")}


def test_parse_pyproject_pdm_dev_dependencies(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname="x"\nversion="0"\n'
        "[tool.pdm.dev-dependencies]\n"
        'test = ["pytest==8.0.0", "coverage>=7"]\n'
        'lint = ["ruff==0.6.0"]\n'
    )
    parsed = hfw.parse_pyproject_toml(py)
    assert ("pytest", "8.0.0") in parsed
    assert ("ruff", "0.6.0") in parsed


# ---------------------------------------------------------------------------
# Direct-reference detection (security: prevent silent supply-chain bypass)


def test_direct_ref_pep508_git_url():
    assert hfw._direct_ref_from_line("foo @ git+https://attacker.example.com/r@v1") == (
        "foo",
        "git+https://attacker.example.com/r@v1",
    )


def test_direct_ref_pep508_https_tarball():
    assert hfw._direct_ref_from_line("bar @ https://example.com/bar-1.0.tar.gz") == (
        "bar",
        "https://example.com/bar-1.0.tar.gz",
    )


def test_direct_ref_pip_vcs_with_egg():
    name, ref = hfw._direct_ref_from_line(
        "git+https://github.com/x/foo.git@v1.0.0#egg=foo"
    )
    assert name == "foo"
    assert "git+https" in ref


def test_direct_ref_editable_vcs():
    name, ref = hfw._direct_ref_from_line(
        "-e git+https://github.com/x/bar.git@main#egg=bar"
    )
    assert name == "bar"
    assert "-e" in ref


def test_direct_ref_tarball_url_guesses_name_from_filename():
    out = hfw._direct_ref_from_line("https://example.com/diff-4.0.4.tar.gz")
    assert out is not None
    assert out[0] == "diff"


def test_direct_ref_skips_plain_pin():
    assert hfw._direct_ref_from_line("foo==1.0.0") is None


def test_parse_requirements_direct_refs(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "requests==2.31.0\n"  # registry pin, should be skipped here
        "foo @ git+https://attacker.example.com/evil@main\n"
        "-e git+https://github.com/x/bar.git@main#egg=bar\n"
        "# a comment\n"
    )
    refs = hfw.parse_requirements_direct_refs(req)
    names = {n for (n, _) in refs}
    assert "foo" in names
    assert "bar" in names
    assert "requests" not in names


def test_parse_pyproject_direct_refs(tmp_path: Path):
    py = tmp_path / "pyproject.toml"
    py.write_text(
        '[project]\nname="x"\nversion="0"\n'
        "dependencies = ["
        '"requests==2.31.0",'
        '"evil @ git+https://attacker.example.com/r@main"'
        "]\n"
    )
    refs = hfw.parse_pyproject_direct_refs(py)
    assert ("evil", "git+https://attacker.example.com/r@main") in refs
    assert all(n != "requests" for (n, _) in refs)


def test_diff_direct_refs_ignores_unchanged_entries(tmp_path: Path):
    """Direct refs that existed on base should NOT be reported as new."""
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    head_dir = tmp_path / "head"
    head_dir.mkdir()
    common = "evil @ git+https://x.example.com/r@main\n"
    (base_dir / "requirements.txt").write_text(common)
    (head_dir / "requirements.txt").write_text(
        common + "newone @ git+https://x.example.com/n@v1\n"
    )
    out = hfw.diff_direct_refs(
        base_dir / "requirements.txt",
        head_dir / "requirements.txt",
    )
    names = {n for (n, _) in out}
    assert "newone" in names
    assert "evil" not in names


def test_diff_direct_refs_accepts_requirements_folder_filenames(tmp_path: Path):
    """The action copies `requirements/prod.txt` to temp as `prod.txt`; direct
    refs should still be surfaced because the project ecosystem is pypi."""
    base = tmp_path / "prod.txt"
    head = tmp_path / "prod-head.txt"
    base.write_text("")
    head.write_text("evil @ git+https://x.example.com/r@main\n")
    assert hfw.diff_direct_refs(base, head) == [
        ("evil", "git+https://x.example.com/r@main")
    ]


# ---------------------------------------------------------------------------
# diff_lockfiles + unsupported manifests


def test_diff_lockfiles_returns_only_new(tmp_path: Path):
    base_dir = tmp_path / "base"
    head_dir = tmp_path / "head"
    base_dir.mkdir()
    head_dir.mkdir()
    base = base_dir / "pyproject.toml"
    head = head_dir / "pyproject.toml"
    base.write_text(
        '[project]\nname="x"\nversion="0"\ndependencies = ["fastapi==0.136.0"]\n'
    )
    head.write_text(
        '[project]\nname="x"\nversion="0"\n'
        'dependencies = ["fastapi==0.136.1", "jinja2==3.1.6"]\n'
    )
    diff = hfw.diff_lockfiles(base, head, "pypi")
    # version bump + new dep are both "added"; removed entries are not reported
    assert ("fastapi", "0.136.1") in diff
    assert ("jinja2", "3.1.6") in diff
    assert ("fastapi", "0.136.0") not in diff


def test_parse_manifest_rejects_unsupported_npm_manifest(tmp_path: Path):
    yarn = tmp_path / "yarn.lock"
    yarn.write_text("# yarn lockfile v1\n")
    with pytest.raises(hfw.UnsupportedManifestError):
        hfw.parse_manifest(yarn, "npm")


def test_parse_manifest_rejects_unknown_ecosystem(tmp_path: Path):
    f = tmp_path / "pyproject.toml"
    f.write_text('[project]\nname="x"\nversion="0"\ndependencies = []\n')
    with pytest.raises(hfw.UnsupportedManifestError):
        hfw.parse_manifest(f, "rubygems")


# ---------------------------------------------------------------------------
# load_ignore + intersection behaviour


def test_load_ignore_skips_comments_and_blanks(tmp_path: Path):
    ig = tmp_path / ".hfwignore"
    ig.write_text(
        "# accepted false positive\n@docusaurus/core@3.10.1\n\nlodash@4.17.21\n"
    )
    parsed = hfw.load_ignore(ig)
    assert parsed == {("@docusaurus/core", "3.10.1"), ("lodash", "4.17.21")}


def test_ignore_intersection_only_counts_diff_entries():
    diff = {("a", "1"), ("b", "2")}
    ignore = {("a", "1"), ("c", "3")}
    assert diff & ignore == {("a", "1")}
    assert len(diff & ignore) == 1
    # the previous bug reported `len(ignore)` (= 2) instead of 1


# ---------------------------------------------------------------------------
# probe() http error handling -- monkey-patch http_get_json


def test_probe_marks_auth_failure_as_error(monkeypatch):
    def fake_get(url: str, timeout: float):
        return 401, {}, "http error 401"

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    monkeypatch.setattr(hfw, "WAIT_SECONDS", 1)
    r = hfw.probe("npm", "anything", "1.0.0")
    assert r["error"] == "http error 401"
    assert r["level"] == "unknown"


def test_probe_marks_connection_failure_as_error(monkeypatch):
    def fake_get(url: str, timeout: float):
        return -1, {}, "name resolution failed"

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    monkeypatch.setattr(hfw, "WAIT_SECONDS", 1)
    r = hfw.probe("npm", "anything", "1.0.0")
    assert r["error"] == "name resolution failed"


def test_probe_no_error_when_server_returns_pending(monkeypatch):
    """A 'pending' verdict means the scan is running; that's not an error."""
    calls = {"n": 0}

    def fake_get(url: str, timeout: float):
        calls["n"] += 1
        return 202, {"status": "pending"}, None

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    monkeypatch.setattr(
        hfw, "WAIT_SECONDS", 1
    )  # one 8-second window; we don't actually sleep
    r = hfw.probe("npm", "anything", "1.0.0")
    assert r["error"] is None
    assert r["level"] == "unknown"
    assert r["verdict_status"] == "pending"


def test_probe_treats_cloudflare_html_redirect_as_error(monkeypatch):
    """Regression: CF Access answers unauthenticated requests with 200 + HTML.
    The non-JSON body must NOT be silently coerced into a clean verdict."""

    def fake_get(url: str, timeout: float):
        return 200, {}, "non-json body (status=200)"

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    monkeypatch.setattr(hfw, "WAIT_SECONDS", 1)
    r = hfw.probe("pypi", "fastapi", "0.136.1")
    assert r["error"] is not None
    assert r["level"] == "unknown"


def test_probe_treats_200_without_status_as_error(monkeypatch):
    """If the response is valid JSON but missing the 'status' envelope key,
    something is wrong upstream (e.g. an unexpected proxy or staging mismatch).
    Treat it as a hard failure rather than 'clean'."""

    def fake_get(url: str, timeout: float):
        return 200, {"some": "garbage"}, None

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    monkeypatch.setattr(hfw, "WAIT_SECONDS", 1)
    r = hfw.probe("pypi", "fastapi", "0.136.1")
    assert r["error"] is not None or r["level"] == "unknown"
    assert r["verdict_status"] is None


# ---------------------------------------------------------------------------
# multi-project: HFW_PROJECTS parsing


def test_load_projects_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("HFW_PROJECTS", raising=False)
    assert hfw._load_projects() is None


def test_load_projects_returns_none_when_blank(monkeypatch):
    monkeypatch.setenv("HFW_PROJECTS", "   ")
    assert hfw._load_projects() is None


def test_load_projects_rejects_bad_json(monkeypatch, capsys):
    monkeypatch.setenv("HFW_PROJECTS", "{not json")
    out = hfw._load_projects()
    assert out == []
    assert "HFW_PROJECTS is not valid JSON" in capsys.readouterr().err


def test_load_projects_rejects_non_list(monkeypatch, capsys):
    monkeypatch.setenv("HFW_PROJECTS", '{"label": "a"}')
    assert hfw._load_projects() == []
    assert "must be a non-empty JSON list" in capsys.readouterr().err


def test_load_projects_parses_valid_list(monkeypatch):
    monkeypatch.setenv(
        "HFW_PROJECTS",
        '[{"label":"root","base":"a","head":"b","ecosystem":"pypi"}]',
    )
    out = hfw._load_projects()
    assert out == [{"label": "root", "base": "a", "head": "b", "ecosystem": "pypi"}]


# ---------------------------------------------------------------------------
# render(): single vs multi-project layout


def _result(label: str, name: str, version: str, level: str) -> dict:
    return {
        "label": label,
        "ecosystem": "pypi",
        "name": name,
        "version": version,
        "http": 200,
        "verdict_status": "ready",
        "level": level,
        "summary": f"static analysis flagged {name}",
        "cached": True,
        "error": None,
    }


def test_render_single_project_omits_project_column():
    projects = [{"label": "root"}]
    results = [_result("root", "requests", "2.31.0", "suspicious")]
    md = hfw.render(projects, results, set())
    assert "| Project | Package" not in md
    assert "| Package | Version | Why | Details |" in md
    assert "| `requests` | `2.31.0` |" in md


def test_render_multi_project_adds_project_column():
    projects = [{"label": "root"}, {"label": "infra/pulumi"}]
    results = [
        _result("root", "requests", "2.31.0", "suspicious"),
        _result("infra/pulumi", "pulumi", "3.0.0", "suspicious"),
    ]
    md = hfw.render(projects, results, set())
    assert "| Project | Package | Version | Why | Details |" in md
    assert "| `root` | `requests` |" in md
    assert "| `infra/pulumi` | `pulumi` |" in md
    assert "scanned 2 project(s)" in md


def test_render_empty_diff_shows_scanned_footer_in_multi_mode():
    projects = [{"label": "root"}, {"label": "env_manager"}]
    md = hfw.render(projects, [], set())
    assert "No dependency changes detected in this PR." in md
    assert "Scanned 2 project(s)" in md
    assert "`root`" in md
    assert "`env_manager`" in md


def test_render_empty_diff_single_project_omits_scanned_footer():
    md = hfw.render([{"label": "root"}], [], set())
    assert "No dependency changes detected in this PR." in md
    assert "Scanned" not in md


# ---------------------------------------------------------------------------
# Name / version validation -- guards against path traversal in URL building.
# An attacker-controlled lockfile must not be able to make probe() request
# anything other than /v1/verdict/{eco}/{pkg}.


@pytest.mark.parametrize(
    "name",
    [
        "../../admin/force-scan",  # the PoC from the security review
        "..%2F..%2Fadmin",  # pre-encoded traversal
        "name with space",
        ".hidden",  # leading dot is not a valid npm/pypi name
        "@scope/../evil",  # tries to slip past the scope split
        "@scope/sub/extra",  # double slash -- not a real scoped form
        "",
    ],
)
def test_validate_coord_rejects_malicious_names(name):
    err = hfw._validate_coord("npm", name, "1.0.0")
    assert err is not None, f"expected rejection for {name!r}"


@pytest.mark.parametrize(
    "name",
    [
        "lodash",
        "@babel/runtime",
        "is-number",
        "@types/node",
    ],
)
def test_validate_coord_accepts_real_npm_names(name):
    assert hfw._validate_coord("npm", name, "1.0.0") is None


@pytest.mark.parametrize(
    "name",
    [
        "requests",
        "Django",
        "google-cloud-storage",
        "typing_extensions",
    ],
)
def test_validate_coord_accepts_real_pypi_names(name):
    assert hfw._validate_coord("pypi", name, "1.0.0") is None


def test_validate_coord_rejects_slash_on_pypi():
    assert hfw._validate_coord("pypi", "a/b", "1.0.0") is not None


@pytest.mark.parametrize("version", ["../1", "1 2", "", "v?evil"])
def test_validate_coord_rejects_bad_versions(version):
    assert hfw._validate_coord("npm", "lodash", version) is not None


def test_probe_short_circuits_traversal_attempt(monkeypatch):
    """The PoC from the security review must never reach the network."""
    calls: list[str] = []

    def fake_get(url: str, timeout: float):
        calls.append(url)
        return 200, {"status": "ready", "level": "clean"}, None

    monkeypatch.setattr(hfw, "http_get_json", fake_get)
    r = hfw.probe("npm", "../../admin/force-scan", "1.0.0")
    assert r["error"] and "invalid" in r["error"]
    assert r["http"] == -1
    assert calls == []


def test_verdict_url_keeps_scoped_slash_literal():
    url = hfw._verdict_url("npm", "@babel/runtime", "7.24.0", 8)
    assert url.startswith(
        "https://api-staging.hacktron.ai/v1/hfw/verdict/npm/@babel/runtime?"
    )
    assert "/verdict/npm/@babel/runtime?" in url
    assert "%2F" not in url
    assert "scan_mode" not in url


def test_verdict_url_preserves_direct_hfw_v1_contract(monkeypatch):
    monkeypatch.setattr(hfw, "HFW_SERVER", "https://hfw.hacktron.ai")

    url = hfw._verdict_url("npm", "@babel/runtime", "7.24.0", 8)

    assert url.startswith("https://hfw.hacktron.ai/v1/verdict/npm/@babel/runtime?")


def test_verdict_url_does_not_double_v1_for_public_api_proxy(monkeypatch):
    monkeypatch.setattr(hfw, "HFW_SERVER", "https://api-staging.hacktron.ai/v1/hfw")

    url = hfw._verdict_url("npm", "@babel/runtime", "7.24.0", 8)

    assert url.startswith(
        "https://api-staging.hacktron.ai/v1/hfw/verdict/npm/@babel/runtime?"
    )
    assert "/v1/hfw/v1/" not in url


def test_verdict_url_encodes_query_unfriendly_characters():
    url = hfw._verdict_url("pypi", "requests", "2.31.0+meta", 8)
    assert "version=2.31.0%2Bmeta" in url


def test_verdict_url_adds_deep_scan_mode_when_configured(monkeypatch):
    monkeypatch.setattr(hfw, "SCAN_MODE", "deep")
    url = hfw._verdict_url("pypi", "requests", "2.31.0", 8)
    assert "scan_mode=deep" in url


def test_verdict_url_adds_fast_scan_mode_when_configured(monkeypatch):
    monkeypatch.setattr(hfw, "SCAN_MODE", "fast")
    url = hfw._verdict_url("pypi", "requests", "2.31.0", 8)
    assert "scan_mode=fast" in url
