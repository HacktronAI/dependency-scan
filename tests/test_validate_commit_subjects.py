from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "github_action"
    / "validate_commit_subjects.py"
)


def load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_commit_subjects", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "subject",
    [
        "fix: use staging API for dependency scan action",
        "feat(action): add pnpm lockfile support",
        "chore(main): release 0.1.1",
        "fix!: remove deprecated action input",
        "docs(readme): update release instructions",
    ],
)
def test_accepts_conventional_commit_subjects(subject: str):
    validator = load_validator()

    assert validator.is_conventional_subject(subject)


@pytest.mark.parametrize(
    "subject",
    [
        "Merge pull request #1 from HacktronAI/use-staging-api-default",
        "Use staging API for dependency scan action",
        "Initial public dependency scan action",
        "fix use staging API",
    ],
)
def test_rejects_non_conventional_commit_subjects(subject: str):
    validator = load_validator()

    assert not validator.is_conventional_subject(subject)


def test_main_reports_invalid_subjects(capsys):
    validator = load_validator()

    exit_code = validator.main(["fix: valid subject", "Use staging API"])

    assert exit_code == 1
    assert "Use staging API" in capsys.readouterr().err
