from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def load_script(relative_path: str, module_name: str):
    path = Path(__file__).resolve().parents[1] / relative_path
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_validator():
    return load_script("scripts/github_action/validate_inputs.py", "validate_inputs")


def load_resolver():
    return load_script(
        "scripts/github_action/resolve_manifests.py",
        "resolve_manifests",
    )


def load_extractor():
    return load_script(
        "scripts/github_action/extract_manifests.py",
        "extract_manifests",
    )


def test_resolve_manifest_input_trims_edges_without_stripping_inner_spaces(
    monkeypatch,
    tmp_path,
):
    resolver = load_resolver()
    manifest = tmp_path / "service api" / "pnpm-lock.yaml"
    manifest.parent.mkdir()
    manifest.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("LOCKFILE", " service api/pnpm-lock.yaml ")
    monkeypatch.delenv("LOCKFILES", raising=False)

    assert resolver.main() == 0

    assert "service api/pnpm-lock.yaml" in output.read_text(encoding="utf-8")


def test_extract_manifest_targets_trim_edges_without_stripping_inner_spaces(
    monkeypatch,
    tmp_path,
):
    extractor = load_extractor()
    manifest = tmp_path / "service api" / "pnpm-lock.yaml"
    manifest.parent.mkdir()
    manifest.write_text("lockfileVersion: '9.0'\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TARGETS", " service api/pnpm-lock.yaml ")
    monkeypatch.delenv("BASE_REF", raising=False)

    assert extractor.main() == 0

    projects_file = tmp_path / ".hfw-tmp/projects.json"
    projects = json.loads(projects_file.read_text(encoding="utf-8"))
    assert projects == [
        {
            "label": "service api",
            "base": ".hfw-tmp/base/service api_pnpm-lock_yaml/pnpm-lock.yaml",
            "head": ".hfw-tmp/head/service api_pnpm-lock_yaml/pnpm-lock.yaml",
            "ecosystem": "npm",
        }
    ]


def test_validate_inputs_normalizes_fail_on_malicious(monkeypatch, tmp_path):
    validator = load_validator()
    output = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("FAIL_ON_MALICIOUS", "TRUE")

    assert validator.main() == 0

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines == ["fail_on_malicious=true"]


def test_validate_inputs_accepts_false(monkeypatch, tmp_path):
    validator = load_validator()
    output = tmp_path / "github_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("FAIL_ON_MALICIOUS", "false")

    assert validator.main() == 0

    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines == ["fail_on_malicious=false"]


def test_validate_inputs_rejects_invalid_boolean(monkeypatch):
    validator = load_validator()
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.setenv("FAIL_ON_MALICIOUS", "yes")

    assert validator.main() == 1
