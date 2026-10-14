"""PG17 fixtures: lane H's test kit (one migrated database per session), loaded by path."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from sibyl_control.worker.predict.gate import set_failover_requester
from sibyl_control.worker.predict.writer import reset_cursors


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


@pytest.fixture(autouse=True)
def _isolate_gate() -> Iterator[None]:
    reset_cursors()
    yield
    set_failover_requester(None)
    reset_cursors()


@pytest.fixture(scope="session")
def app_db(kit: Any) -> Iterator[Any]:
    """The kernel ``Database`` as ``sibyl_app`` (the role a human clear runs as)."""
    from sibyl_control.core.db import Database

    dsn = _KIT.worker_dsn(kit.name).replace("sibyl_worker@", "sibyl_app@", 1)
    db = kit.run(Database.connect(dsn, min_size=1, max_size=2))
    yield db
    kit.run(db.close())
