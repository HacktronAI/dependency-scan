from __future__ import annotations

import argparse
import re
import sys

CONVENTIONAL_SUBJECT_RE = re.compile(
    r"^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)"
    r"(\([a-z0-9._/-]+\))?!?: .+"
)

HELP_TEXT = (
    "Use a Conventional Commit subject, for example "
    "'fix: reject invalid package versions' or 'feat(action): add npm support'."
)


def is_conventional_subject(subject: str) -> bool:
    return bool(CONVENTIONAL_SUBJECT_RE.fullmatch(subject.strip()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Conventional Commit subjects."
    )
    parser.add_argument(
        "subjects",
        nargs="*",
        help="Subjects to validate. Reads one subject per stdin line if omitted.",
    )
    args = parser.parse_args(argv)

    subjects = args.subjects or [
        line.rstrip("\n") for line in sys.stdin if line.strip()
    ]
    invalid_subjects = [
        subject for subject in subjects if not is_conventional_subject(subject)
    ]

    if not invalid_subjects:
        return 0

    print("Invalid commit subject(s):", file=sys.stderr)
    for subject in invalid_subjects:
        print(f"  - {subject}", file=sys.stderr)
    print(HELP_TEXT, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
