"""PG17 fixtures shared with the scoring suites (lane H test kit, loaded by path)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _load() -> ModuleType:
    name = "sibyl_h_testkit"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "scoring" / "h_testkit.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_KIT = _load()
h_loop = _KIT.h_loop
kit = _KIT.kit
