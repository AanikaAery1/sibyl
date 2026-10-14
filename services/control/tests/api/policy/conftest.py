"""Loads the shared lane R harness (``tests/api/registry/_harness.py``) once per process, and
the policy setup helpers (``_setup.py``) as ``sibyl_lane_r_policy_setup``."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

HARNESS = "sibyl_lane_r_harness"
SETUP = "sibyl_lane_r_policy_setup"


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_HERE = Path(__file__).resolve().parent
world = _load(HARNESS, _HERE.parent / "registry" / "_harness.py").world
_load(SETUP, _HERE / "_setup.py")
