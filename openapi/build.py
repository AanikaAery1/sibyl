"""Regenerate ``openapi/sibyl-api.v1.yaml``; ``--check`` exits 1 when the file has drifted."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TARGET = HERE / "sibyl-api.v1.yaml"


def main(argv: list[str]) -> int:
    sys.path.insert(0, str(HERE))
    from sibyl_openapi.build import render_yaml

    rendered = render_yaml()
    if "--check" in argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != rendered:
            sys.stderr.write(f"{TARGET} is out of date; run: uv run python openapi/build.py\n")
            return 1
        return 0
    TARGET.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
