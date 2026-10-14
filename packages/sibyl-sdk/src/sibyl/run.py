"""`sibyl-run`: zero-code monitoring. Configures Sibyl from `SIBYL_*` env vars, instruments
every installed model client and agent framework, then runs the target unchanged.

    sibyl-run app.py --flag value          # a script
    sibyl-run -m my_package.main --flag    # a module
    python -m sibyl.run app.py             # same, without the console script

Environment (explicit `init()` arguments in the target still win when it calls `init()`):

| variable                | meaning                                                         |
|-------------------------|-----------------------------------------------------------------|
| `SIBYL_API_KEY`         | ingest key `sbl_<env>_<prefix>_<secret>` (required)             |
| `SIBYL_ENDPOINT`        | ingest URL, e.g. `https://ingest.sibyl.example` (required)      |
| `SIBYL_API_URL`         | control-plane URL for snapshots/Action Gate (default: endpoint) |
| `SIBYL_AGENT_ID`        | agent slug or uuid this process reports as                      |
| `SIBYL_ENV`             | `live` or `test` (must match the key)                           |
| `SIBYL_CAPTURE_MODE`    | `full`, `redacted` or `metadata` (registry may tighten it)      |
| `SIBYL_INSTRUMENT`      | `auto` (default), `none`, or a comma list (`openai,langchain`)   |
| `SIBYL_SENSITIVE_TOOLS` | comma list of tool-name globs that fail closed (`payments.*`)   |
| `SIBYL_ON_BEHALF_OF`    | `user:<uuid>` or `external:<ref>` for the whole process         |
| `SIBYL_DISABLED`        | `1`/`true`: run the target without Sibyl                        |
| `SIBYL_SCRUB_SALT`      | platform scrub salt (≥ 16 bytes) for stable hashes              |

Monitoring never stops the target from starting: a configuration problem is reported on
stderr and the target runs uninstrumented. The secret part of the key is never printed.
"""

from __future__ import annotations

import os
import runpy
import sys
from collections.abc import Sequence
from typing import Any, Final

USAGE: Final = "usage: sibyl-run [-m module | script.py] [args...]"
_TRUTHY: Final = frozenset({"1", "true", "yes", "on"})


def _instrument_setting() -> tuple[str, ...] | str:
    raw = os.environ.get("SIBYL_INSTRUMENT", "auto").strip().lower()
    if raw in ("", "auto"):
        return "auto"
    if raw in ("none", "off", "0", "false"):
        return ()
    return tuple(name.strip() for name in raw.split(",") if name.strip())


def _say(message: str) -> None:
    sys.stderr.write(f"sibyl-run: {message}\n")


def _on_behalf_of(value: str) -> Any:
    from sibyl import _obo

    kind, _, ref = value.partition(":")
    if kind == "user":
        return _obo.parse(user=ref)
    if kind == "external":
        return _obo.parse(external=ref)
    return _obo.parse(external=value)


def setup() -> list[str]:
    """Configure Sibyl from the environment; returns the libraries instrumented."""
    if os.environ.get("SIBYL_DISABLED", "").strip().lower() in _TRUTHY:
        return []
    import sibyl
    from sibyl import _obo

    try:
        libraries = _instrument_setting()
        sibyl.init(instrument=libraries)
        names = sibyl.instrument(libraries=libraries)
        obo = os.environ.get("SIBYL_ON_BEHALF_OF", "").strip()
        if obo:
            _obo.set_default(_on_behalf_of(obo))
    except sibyl.SibylConfigError as exc:
        _say(f"monitoring disabled: {exc}")
        return []
    except Exception as exc:  # never stop the target from starting
        _say(f"monitoring disabled: {type(exc).__name__}")
        return []
    return list(names)


def _parse(argv: Sequence[str]) -> tuple[str, str, list[str]] | None:
    args = list(argv)
    if not args or args[0] in ("-h", "--help"):
        return None
    if args[0] == "-m":
        if len(args) < 2:
            return None
        return "module", args[1], args[2:]
    return "path", args[0], args[1:]


def main(argv: Sequence[str] | None = None) -> int:
    parsed = _parse(sys.argv[1:] if argv is None else argv)
    if parsed is None:
        _say(USAGE)
        return 2
    kind, target, rest = parsed
    if kind == "path" and not os.path.exists(target):
        _say(f"no such file: {target}")
        return 2
    setup()
    if kind == "module":
        sys.argv = [target, *rest]
        runpy.run_module(target, run_name="__main__", alter_sys=True)
    else:
        sys.argv = [target, *rest]
        sys.path.insert(0, os.path.dirname(os.path.abspath(target)))
        runpy.run_path(target, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
