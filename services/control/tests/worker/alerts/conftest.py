"""PG17 fixtures: lane H's test kit plus the INT-1 change-request DDL (alert silences)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

CR_SQL = Path(__file__).resolve().parents[2] / "api" / "alerts" / "cr_int1.sql"


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


@pytest.fixture
def akit(kit: Any) -> Any:
    kit.exe(CR_SQL.read_text())
    return kit
