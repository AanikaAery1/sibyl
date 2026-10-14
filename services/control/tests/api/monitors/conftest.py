"""Lane EXTMON api tests: one DB-backed contract world (real principal chain, peppered monitor
keys, PG17) shared by the monitor and findings suites, plus a fake webhook receiver."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sibyl_control.api.auth.common import LANE_STATE

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


pg_world = _load("sibyl_contract_pg_world", _TESTS / "contract" / "pg_world.py")
REASON = "monitor api test: exercising the D53 routes"


class Receiver:
    """A fake webhook receiver (MockTransport) whose answer a test can change."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 204
        self.error: Exception | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return httpx.Response(self.status)

    def factory(self, policy: Any) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(self.handler)


@pytest.fixture(scope="session")
def mworld() -> Iterator[Any]:
    if not pg_world.kit.available():
        pytest.skip(f"PostgreSQL 17 not reachable at {pg_world.kit.ADMIN_DSN} (make db-up)")
    with pg_world.contract_world() as world:
        yield world


@pytest.fixture
def mw(mworld: Any) -> Any:
    mworld.refresh_step_up()
    return mworld


@pytest.fixture
def receiver(mw: Any) -> Iterator[Receiver]:
    fake = Receiver()
    state = getattr(mw.client.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(mw.client.app.state, LANE_STATE, state)
    previous = state.get("webhook_transport")
    state["webhook_transport"] = fake.factory
    yield fake
    state["webhook_transport"] = previous


def post(world: Any, path: str, body: Any = None, who: str = "owner", **headers: str) -> Any:
    return world.client.post("/api/v1" + path, json=body, headers=world.idem(who, **headers))


def get(world: Any, path: str, who: str = "owner", **params: Any) -> Any:
    return world.client.get("/api/v1" + path, params=params, headers=world.headers(who))


def new_monitor(world: Any, **fields: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"name": f"m-{uuid4().hex[:8]}", "kind": "api", "key_env": "test"}
    body.update(fields)
    resp = post(world, "/monitors", body)
    assert resp.status_code == 201, resp.text
    created: dict[str, Any] = resp.json()
    if created.get("api_key"):
        world.tokens[created["id"]] = created["api_key"]["secret"]
    return created
