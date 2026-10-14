"""Loads the shared lane R harness (``tests/api/registry/_harness.py``) once per process."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

HARNESS = "sibyl_lane_r_harness"


def _load() -> ModuleType:
    if HARNESS in sys.modules:
        return sys.modules[HARNESS]
    path = Path(__file__).resolve().parents[1] / "registry" / "_harness.py"
    spec = importlib.util.spec_from_file_location(HARNESS, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[HARNESS] = module
    spec.loader.exec_module(module)
    return module


world = _load().world
