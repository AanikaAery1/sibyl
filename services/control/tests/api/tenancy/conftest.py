"""Lane fixtures: the shared migrated PG17 database and a fresh seeded world per test."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest


def _kit() -> Any:
    name = "sibyl_lane_a_kit"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[1] / "auth" / "kit.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


kit = _kit()


@pytest.fixture(scope="session")
def lane_db() -> Iterator[Any]:
    if not kit.available():
        pytest.skip(f"PostgreSQL 17 not reachable at {kit.ADMIN_DSN} (make db-up)")
    db = kit.acquire()
    yield db
    kit.release()


@pytest.fixture
def world(lane_db: Any) -> Any:
    return kit.world(lane_db)


@pytest.fixture
def lane(lane_db: Any) -> Iterator[Any]:
    with kit.lane_app(lane_db) as app:
        yield app
