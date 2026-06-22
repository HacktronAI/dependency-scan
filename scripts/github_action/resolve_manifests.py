#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import os
import subprocess
import sys
from pathlib import Path

SUPPORTED = (
    "pnpm-lock.yaml",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pyproject.toml",
    "uv.lock",
)
IGNORED_PARTS = {".git", "node_modules", ".venv", "venv", "vendor"}


def main() -> int:
    lockfiles = os.environ.get("LOCKFILES", "")
    lockfile = os.environ.get("LOCKFILE", "")
    expanded: list[str] = []

    if lockfiles or lockfile:
        targets = lockfiles or lockfile
        tracked = None
        for raw in targets.splitlines():
            path = "".join(raw.split())
            if not path:
                continue
            if any(char in path for char in "*?["):
                if tracked is None:
                    tracked = git_ls_files()
                matches = [item for item in tracked if matches_pattern(item, path)]
                if not matches:
                    error(f"no tracked manifests matched pattern: {path}")
                    return 1
                for match in matches:
                    if append_manifest(expanded, match) != 0:
                        return 1
            elif append_manifest(expanded, path) != 0:
                return 1
    else:
        targets = "<auto-discovery>"
        for tracked in git_ls_files():
            if is_ignored_path(tracked) or not is_supported_manifest(tracked):
                continue
            if append_manifest(expanded, tracked) != 0:
                return 1

    unique = dedupe(expanded)
    if not unique:
        error("No lockfiles matched. Inputs:")
        for target in targets.splitlines():
            if target:
                error(f"  - {target}")
        return 1

    print(f"resolved {len(unique)} manifest(s):")
    for path in unique:
        print(f"  {path}")
    write_multiline_output("paths", unique)
    return 0


def git_ls_files() -> list[str]:
    completed = subprocess.run(
        ["git", "ls-files"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [line for line in completed.stdout.splitlines() if line]


def append_manifest(expanded: list[str], raw_path: str) -> int:
    path = raw_path.removeprefix("./")
    if not path or is_ignored_path(path):
        return 0
    if not is_supported_manifest(path):
        error(f"unsupported manifest for dependency scan: {path}")
        error(
            "Supported: pnpm-lock.yaml, package-lock.json, npm-shrinkwrap.json, "
            "pyproject.toml, uv.lock, requirements*.txt, requirements/*.txt"
        )
        return 1
    if not Path(path).is_file():
        error(f"lockfile not found: {path}")
        error("Did you run actions/checkout before this action?")
        return 1
    expanded.append(path)
    return 0


def is_ignored_path(path: str) -> bool:
    return bool(IGNORED_PARTS.intersection(Path(path).parts))


def is_supported_manifest(path: str) -> bool:
    p = Path(path)
    base = p.name
    if base in SUPPORTED or (base.startswith("requirements") and base.endswith(".txt")):
        return True
    return base.endswith(".txt") and p.parent.name == "requirements"


def matches_pattern(tracked: str, pattern: str) -> bool:
    if fnmatch.fnmatchcase(tracked, pattern):
        return True
    if pattern.startswith("**/"):
        return fnmatch.fnmatchcase(tracked, pattern[3:])
    return False


def dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def write_multiline_output(name: str, values: list[str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with open(output, "a", encoding="utf-8") as fh:
        fh.write(f"{name}<<HFW_EOF\n")
        for value in values:
            fh.write(f"{value}\n")
        fh.write("HFW_EOF\n")


def error(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
