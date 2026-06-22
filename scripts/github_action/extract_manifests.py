#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def main() -> int:
    tmp = Path(".hfw-tmp")
    tmp.mkdir(exist_ok=True)
    projects_file = tmp / "projects.json"
    projects: list[dict[str, str]] = []

    for raw in os.environ.get("TARGETS", "").splitlines():
        path = raw.strip()
        if not path:
            continue
        projects.append(extract_manifest(path))

    projects_file.write_text(
        json.dumps(projects, separators=(",", ":")), encoding="utf-8"
    )
    print(f"scanned {len(projects)} manifest(s):")
    print(projects_file.read_text(encoding="utf-8"))
    write_output("projects_file", str(projects_file))
    return 0


def extract_manifest(path: str) -> dict[str, str]:
    source = Path(path)
    basename = source.name
    dirname = source.parent
    label = "root" if str(dirname) in ("", ".") else str(dirname)
    ecosystem = resolve_ecosystem(basename, dirname)

    slot = path.translate(str.maketrans({"/": "_", ".": "_"}))
    base_dir = Path(".hfw-tmp/base") / slot
    head_dir = Path(".hfw-tmp/head") / slot
    base_dir.mkdir(parents=True, exist_ok=True)
    head_dir.mkdir(parents=True, exist_ok=True)

    base_out = base_dir / basename
    head_out = head_dir / basename
    base_ref = os.environ.get("BASE_REF", "")

    if base_ref and git_cat_file_exists(base_ref, path):
        base_out.write_bytes(git_show(base_ref, path))
    else:
        print(f"(no {path} on base ref; treating every current package as newly added)")
        base_out.write_text("", encoding="utf-8")
    head_out.write_bytes(source.read_bytes())

    return {
        "label": label,
        "base": str(base_out),
        "head": str(head_out),
        "ecosystem": ecosystem,
    }


def resolve_ecosystem(basename: str, dirname: Path) -> str:
    if basename in {"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"}:
        return "npm"
    if basename in {"pyproject.toml", "uv.lock"} or (
        basename.startswith("requirements") and basename.endswith(".txt")
    ):
        return "pypi"
    if basename.endswith(".txt") and dirname.name == "requirements":
        return "pypi"
    raise ValueError(f"unsupported manifest: {dirname / basename}")


def git_cat_file_exists(base_ref: str, path: str) -> bool:
    return (
        subprocess.run(
            ["git", "cat-file", "-e", f"origin/{base_ref}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def git_show(base_ref: str, path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"origin/{base_ref}:{path}"],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with open(output, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
