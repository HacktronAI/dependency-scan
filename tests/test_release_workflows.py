from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_yaml(relative_path: str):
    return yaml.safe_load((REPO_ROOT / relative_path).read_text(encoding="utf-8"))


def load_workflow(relative_path: str):
    workflow = load_yaml(relative_path)
    workflow["on"] = workflow.get("on", workflow.get(True))
    return workflow


def test_release_please_runs_on_main_merges_and_manual_dispatch():
    workflow = load_workflow(".github/workflows/release-please.yml")

    assert workflow["name"] == "Release PR"
    assert workflow["on"]["push"]["branches"] == ["main"]
    assert "workflow_dispatch" in workflow["on"]
    assert workflow["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }

    steps = workflow["jobs"]["release-please"]["steps"]
    release_step = next(
        step
        for step in steps
        if step.get("uses") == "googleapis/release-please-action@v4"
    )
    assert release_step["with"] == {
        "config-file": "release-please-config.json",
        "manifest-file": ".release-please-manifest.json",
    }


def test_ci_enforces_conventional_commit_subjects():
    workflow = load_workflow(".github/workflows/ci.yml")

    job = workflow["jobs"]["conventional-commits"]
    steps = job["steps"]

    pr_title_step = next(
        step for step in steps if step.get("name") == "Validate pull request title"
    )
    assert pr_title_step["if"] == "github.event_name == 'pull_request'"
    assert (
        pr_title_step["run"]
        == 'python scripts/github_action/validate_commit_subjects.py "$PR_TITLE"'
    )

    pushed_commits_step = next(
        step for step in steps if step.get("name") == "Validate pushed commit subjects"
    )
    assert pushed_commits_step["if"] == "github.event_name == 'push'"
    assert "git log --format=%s" in pushed_commits_step["run"]
    assert 'git cat-file -e "$BEFORE_SHA^{commit}"' in pushed_commits_step["run"]
    assert (
        "scripts/github_action/validate_commit_subjects.py"
        in pushed_commits_step["run"]
    )


def test_release_please_manifest_tracks_project_version():
    config = json.loads((REPO_ROOT / "release-please-config.json").read_text())
    manifest = json.loads((REPO_ROOT / ".release-please-manifest.json").read_text())
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())

    assert config["packages"] == {
        ".": {
            "package-name": "dependency-scan",
            "release-type": "simple",
            "changelog-path": "CHANGELOG.md",
            "include-component-in-tag": False,
            "extra-files": [
                {
                    "type": "toml",
                    "path": "pyproject.toml",
                    "jsonpath": "$.project.version",
                }
            ],
        }
    }
    assert manifest == {".": pyproject["project"]["version"]}


def test_release_workflow_updates_major_tag_after_published_semver_release():
    workflow = load_workflow(".github/workflows/release.yml")

    assert workflow["name"] == "Release"
    assert workflow["on"] == {"release": {"types": ["published"]}}
    assert workflow["permissions"] == {"contents": "write"}

    job = workflow["jobs"]["move-major-tag"]
    assert job["if"] == "startsWith(github.event.release.tag_name, 'v')"

    run_script = "\n".join(
        step.get("run", "")
        for step in job["steps"]
        if step.get("name") == "Move major tag"
    )
    assert r"^v[0-9]+\.[0-9]+\.[0-9]+([.-].*)?$" in run_script
    assert 'major="${TAG_NAME%%.*}"' in run_script
    assert 'git push origin "refs/tags/$major" --force' in run_script
