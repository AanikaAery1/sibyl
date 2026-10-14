"""Loads the shared lane R harness (``_harness.py``) and the registry helpers once per process."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

HARNESS = "sibyl_lane_r_harness"
HELPERS = "sibyl_lane_r_registry"


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_here = Path(__file__).resolve().parent
world = _load(HARNESS, _here / "_harness.py").world
_load(HELPERS, _here / "helpers.py")
