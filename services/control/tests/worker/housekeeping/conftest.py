"""Lane U worker fixtures: the shared governance harness and seed helpers
(``tests/api/governance/_harness.py`` / ``helpers.py``), loaded once per process by path."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parents[2] / "api" / "governance"


def _load_file(name: str, filename: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load_file("sibyl_lane_u_helpers", "helpers.py")
world = _load_file("sibyl_lane_u_harness", "_harness.py").world
