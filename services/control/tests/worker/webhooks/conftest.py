"""Lane EXTMON worker tests: the DB-backed contract world (monitors, keys and webhooks made through
the api) plus a ``Database`` connected as ``sibyl_worker`` on the world's loop, so the webhooks
loop runs under its real grants and RLS, and a fake receiver instead of the network."""

from __future__ import annotations

import importlib.util
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from sibyl_control.core.crypto.deks import kek_from_settings
from sibyl_control.core.db import Database
from sibyl_control.worker.webhooks import Deps, TenantReport, run_tenant

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
HOOK = "http://sibyl-sim:8400/sibyl-hook"


@dataclass
class Receiver:
    requests: list[httpx.Request] = field(default_factory=list)
    status: int = 204

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status)

    def factory(self, policy: Any) -> httpx.AsyncBaseTransport:
        return httpx.MockTransport(self.handler)


@dataclass
class WWorld:
    w: Any  # pg_world.ContractWorld
    db: Database
    receiver: Receiver

    @property
    def tenant(self) -> UUID:
        tenant: UUID = self.w.a.id
        return tenant

    def run(self, coro: Any) -> Any:
        return self.w.db.loop.run_until_complete(coro)

    def deps(self, **kw: Any) -> Deps:
        settings = self.w.lane.services.settings
        base: dict[str, Any] = {
            "settings": settings,
            "kek": kek_from_settings(settings),
            "transport_factory": self.receiver.factory,
        }
        base.update(kw)
        return Deps(**base)

    def settle(self, timeout_s: float = 60.0) -> None:
        """Wait until every committed outbox row of the tenant is below the commit horizon.

        The webhooks loop reads the outbox only below the cluster-wide horizon (R60); other test
        processes sharing this PG17 cluster hold it back while their transactions are open, so a
        tick straight after an insert can legitimately see nothing yet (as in the SSE tests)."""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            ready = self.w.admin.fetchval(
                "SELECT coalesce(max(xid) < sibyl.commit_horizon(), true) FROM sibyl.outbox"
                " WHERE tenant_id = $1",
                self.tenant,
            )
            if ready:
                return
            time.sleep(0.05)
        raise AssertionError("the commit horizon did not pass the tenant's outbox rows")

    def tick(self, **kw: Any) -> TenantReport:
        self.settle()
        report: TenantReport = self.run(run_tenant(self.db, self.deps(**kw), self.tenant))
        return report

    def api(self, method: str, path: str, body: Any = None, who: str = "owner") -> Any:
        resp = self.w.client.request(method, "/api/v1" + path, json=body, headers=self.w.idem(who))
        assert resp.status_code < 300, (path, resp.text)
        return resp.json()

    def monitor(self, **fields: Any) -> dict[str, Any]:
        body: dict[str, Any] = {"name": f"w-{uuid4().hex[:8]}", "kind": "webhook"}
        body.update({"key_env": "test", **fields})
        created: dict[str, Any] = self.api("POST", "/monitors", body)
        if created.get("api_key"):
            self.w.tokens[created["id"]] = created["api_key"]["secret"]
        return created

    def webhook(self, monitor_id: str, events: list[str]) -> dict[str, Any]:
        body = {"url": HOOK, "event_types": events}
        hook: dict[str, Any] = self.api("POST", f"/monitors/{monitor_id}/webhooks", body)
        return hook

    def outbox(self, event_type: str, aggregate_kind: str, payload: dict[str, Any]) -> UUID:
        topic = event_type.split(".", 1)[0]
        row_id = uuid4()
        aggregate = UUID(payload.get("alert_id") or payload.get("held_action_id") or str(row_id))
        self.w.admin.in_tenant(
            self.tenant,
            "INSERT INTO sibyl.outbox (tenant_id, id, topic, event_type, aggregate_kind,"
            " aggregate_id, payload, idempotency_key) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb,"
            " $8)",
            self.tenant,
            row_id,
            topic,
            event_type,
            aggregate_kind,
            aggregate,
            payload,
            f"test:{row_id}",
        )
        return row_id

    def deliveries(self, webhook_id: str) -> list[Any]:
        return list(
            self.w.admin.fetch(
                "SELECT * FROM sibyl.webhook_delivery WHERE webhook_id = $1"
                " ORDER BY created_at, event_type",
                UUID(webhook_id),
            )
        )

    def due_now(self, webhook_id: str) -> None:
        self.w.admin.in_tenant(
            self.tenant,
            "UPDATE sibyl.webhook_delivery SET next_attempt_at = now() - interval '1 second'"
            " WHERE webhook_id = $1 AND status IN ('pending', 'retrying')",
            UUID(webhook_id),
        )


@pytest.fixture(scope="session")
def wworld() -> Iterator[WWorld]:
    if not pg_world.kit.available():
        pytest.skip(f"PostgreSQL 17 not reachable at {pg_world.kit.ADMIN_DSN} (make db-up)")
    with pg_world.contract_world() as world:
        db = world.db.loop.run_until_complete(
            Database.connect(world.db.dsn("sibyl_worker"), min_size=1, max_size=4)
        )
        try:
            yield WWorld(world, db, Receiver())
        finally:
            world.db.loop.run_until_complete(db.close())


@pytest.fixture
def ww(wworld: WWorld) -> WWorld:
    wworld.w.refresh_step_up()
    wworld.receiver.requests.clear()
    wworld.receiver.status = 204
    # Disable earlier tests' webhooks and settle their deliveries: each test sees only its own.
    wworld.w.admin.execute("UPDATE sibyl.monitor_webhook SET state = 'disabled'")
    wworld.w.admin.execute(
        "UPDATE sibyl.webhook_delivery SET status = 'dead', settled_at = now(), error = 'reset'"
        " WHERE status IN ('pending', 'retrying')"
    )
    return wworld
