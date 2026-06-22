#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from enum import StrEnum
from typing import TypeVar

T = TypeVar("T", bound=StrEnum)


class BooleanInput(StrEnum):
    TRUE = "true"
    FALSE = "false"


def main() -> int:
    fail_on_malicious = parse_enum(
        "fail-on-malicious",
        os.environ.get("FAIL_ON_MALICIOUS", ""),
        BooleanInput,
    )
    if fail_on_malicious is None:
        return 1

    write_output("fail_on_malicious", fail_on_malicious.value)
    return 0


def parse_enum(name: str, raw: str, enum_type: type[T]) -> T | None:
    value = raw.strip().lower()
    allowed = {item.value for item in enum_type}
    if value in allowed:
        return enum_type(value)
    error(f"{name} must be one of: {', '.join(sorted(allowed))}.")
    return None


def write_output(name: str, value: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        return
    with open(output, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


def error(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
