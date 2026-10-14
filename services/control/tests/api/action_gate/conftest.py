"""Lane AG-CORE: lane R's PG17 harness (``world``) plus the Action Gate kit (``gate``)."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

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
kit = _load("sibyl_ag_gate", Path(__file__).resolve().parent / "_gate.py")


@pytest.fixture(scope="module")
def gate(world: Any) -> Iterator[Any]:
    yield kit.make_gate(world)
