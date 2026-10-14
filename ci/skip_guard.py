"""Fail the CI run when a test was skipped for a reason that is not explicitly allowed.

A silently skipped suite is how CI went green with PostgreSQL down (G0 test review F1: 101 DB
tests skipped, coverage still 94 %). Every skip reason must match a regex in
ci/skip-allowlist.txt (or $SIBYL_CI_ALLOW_SKIPS, extra regexes separated by newlines).
xfail outcomes are not skips and are ignored.

usage: python ci/skip_guard.py <junit.xml> [--allowlist FILE]
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ALLOWLIST = Path(__file__).with_name("skip-allowlist.txt")


@dataclass(frozen=True)
class Skip:
    test: str
    reason: str


def load_allowlist(path: Path, extra: str = "") -> tuple[re.Pattern[str], ...]:
    lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
    lines += extra.splitlines()
    return tuple(
        re.compile(ln.strip()) for ln in lines if ln.strip() and not ln.lstrip().startswith("#")
    )


def skips(junit: Path) -> list[Skip]:
    root = ET.parse(junit).getroot()  # noqa: S314
    found = []
    for case in root.iter("testcase"):
        for child in case:
            if child.tag == "skipped" and child.get("type") != "pytest.xfail":
                name = f"{case.get('classname', '')}::{case.get('name', '')}"
                found.append(Skip(name, child.get("message") or child.text or ""))
    return found


def disallowed(found: list[Skip], allow: tuple[re.Pattern[str], ...]) -> list[Skip]:
    return [s for s in found if not any(p.search(s.reason) for p in allow)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="skip_guard")
    parser.add_argument("junit", type=Path)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    args = parser.parse_args(argv)
    if not args.junit.is_file():
        print(f"skip_guard: {args.junit} not found", file=sys.stderr)
        return 2
    found = skips(args.junit)
    bad = disallowed(
        found, load_allowlist(args.allowlist, os.environ.get("SIBYL_CI_ALLOW_SKIPS", ""))
    )
    allowed = len(found) - len(bad)
    if bad:
        print(f"skip_guard: {len(bad)} test(s) skipped for a reason not in {args.allowlist.name}:")
        for s in bad:
            print(f"  {s.test}: {s.reason}")
        print("Fix the environment (e.g. start PostgreSQL / Docker) or allow-list the reason.")
        return 1
    print(f"skip_guard: ok ({allowed} allowed skip(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
