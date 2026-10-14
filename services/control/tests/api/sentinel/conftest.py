"""Lane SENTINEL api tests: lane R's PG world, lane S's worker world and the Sentinel kit."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

_TESTS = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


world = _load("sibyl_lane_r_harness", _TESTS / "api" / "registry" / "_harness.py").world
sworld = _load("sibyl_lane_s_world", _TESTS / "worker" / "saga" / "_s_world.py").sworld
_load("sibyl_sentinel_kit", _TESTS / "worker" / "sentinel" / "_kit.py")
