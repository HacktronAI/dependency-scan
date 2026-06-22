from __future__ import annotations

import importlib.util
from pathlib import Path


def load_validator():
    path = (
        Path(__file__).resolve().parents[1] / "scripts/github_action/validate_inputs.py"
    )
    spec = importlib.util.spec_from_file_location("validate_inputs", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
