# ruff: noqa: S608 -- identifiers are fixed literals
"""Lane H PG17 test kit: a migrated database, worker-role pool, tenants, agents, events.

Loaded by the rollup, scoring and status_poller conftests (one session database for all three).
The database is ``sibyl_h_<hex>`` on ``SIBYL_PG_ADMIN_DSN`` and is dropped at session end.
Coroutines run on one private session loop, like the W0-DB suites.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import pytest
from sibyl_control.core.db import Database
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
REDACTION = hashlib.sha256(b"profile").digest()


def h32(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@dataclass
class Kit:
    loop: asyncio.AbstractEventLoop
    name: str
    admin: asyncpg.Connection
    worker: Database
    _seq: int = 0
    tenants: list[UUID] = field(default_factory=list)

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def q(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        return self.run(self.admin.fetch(sql, *args))

    def val(self, sql: str, *args: Any) -> Any:
        return self.run(self.admin.fetchval(sql, *args))

    def exe(self, sql: str, *args: Any) -> Any:
        return self.run(self.admin.execute(sql, *args))

    # ------------------------------------------------------------------ registry

    def tenant(self, slug: str | None = None) -> UUID:
        slug = slug or f"h-{secrets.token_hex(4)}"
        tid = self.val(
            "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', 'kek', $3, $4, $5)",
            slug,
            slug.title(),
            h32(slug + "p"),
            h32(slug + "c"),
            h32(slug + "g"),
        )
        self.tenants.append(tid)
        return tid

    def provider(self, tenant: UUID, slug: str = "provider-one", feed: str | None = None) -> UUID:
        pid = uuid4()
        self._tx(
            tenant,
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, "
            "base_url, status_feed_url) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible', "
            "$4, $5)",
            tenant,
            pid,
            slug,
            f"https://api.{slug}.example/v1",
            feed,
        )
        return pid

    def agent(
        self,
        tenant: UUID,
        *,
        tier: int = 2,
        plan: bool = True,
        age: timedelta = timedelta(days=30),
        budget: Decimal | None = None,
        slug: str | None = None,
    ) -> UUID:
        aid = uuid4()
        created = datetime.now(UTC) - age
        self._tx(
            tenant,
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, "
            "lifecycle, created_at) VALUES ($1, $2, $3, $3, 'autonomous_agent', $4, 'closed', "
            "'discovered', $5)",
            tenant,
            aid,
            slug or f"a-{aid.hex[:12]}",
            tier,
            created,
        )
        self._tx(
            tenant,
            "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register', "
            "'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3, "
            "'route.changed', NULL, NULL, NULL, NULL)",
            tenant,
            aid,
            f"register:{aid}",
        )
        if plan:
            self._tx(
                tenant,
                "INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, rto_s, rpo_s, "
                "inline_fallback, preemptive_mode, budget_usd_month, approved_by_user_id) "
                "VALUES ($1, $2, NULL, NULL, false, NULL, $3, NULL)",
                tenant,
                aid,
                budget,
            )
        return aid

    def _tx(self, tenant: UUID, sql: str, *args: Any) -> Any:
        async def go() -> Any:
            async with self.admin.transaction():
                await self.admin.execute("SELECT sibyl.set_tenant($1)", tenant)
                return await self.admin.fetch(sql, *args)

        return self.run(go())

    def in_tenant(self, tenant: UUID, sql: str, *args: Any) -> list[asyncpg.Record]:
        return self._tx(tenant, sql, *args)  # type: ignore[no-any-return]

    # ------------------------------------------------------------------ events

    def events(self, tenant: UUID, rows: Sequence[dict[str, Any]]) -> None:
        """Insert synthetic events as the ingest role would (one transaction)."""
        cols = (
            "tenant_id, event_id, ts, event_type, source, emitter_id, seq, policy_state, "
            "capture_mode, redaction_profile_hash, normaliser_version, agent_id, provider, model, "
            "status, error_class, error_type, http_status, latency_ms, ttfb_ms, tokens_in, "
            "tokens_out, cost_usd, route_decision, attrs, task_id"
        )
        sql = (
            f"INSERT INTO sibyl.events ({cols}) VALUES ($1, $2, $3, $4, 'sdk', 'emitter-1', $5, "
            "$6, 'metadata', $7, 'n/1', $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, "
            "$19, $20, $21::jsonb, $22)"
        )
        args = []
        for r in rows:
            self._seq += 1
            args.append(
                (
                    tenant,
                    r.get("event_id") or uuid4(),
                    r["ts"],
                    r.get("event_type", "gen_ai.request"),
                    self._seq,
                    r.get("policy_state", "fresh"),
                    REDACTION,
                    r.get("agent_id"),
                    r.get("provider"),
                    r.get("model"),
                    r.get("status"),
                    r.get("error_class"),
                    r.get("error_type"),
                    r.get("http_status"),
                    r.get("latency_ms"),
                    r.get("ttfb_ms"),
                    r.get("tokens_in"),
                    r.get("tokens_out"),
                    r.get("cost_usd"),
                    r.get("route_decision"),
                    r.get("attrs", {}),
                    r.get("task_id"),
                )
            )

        async def go() -> None:
            async with self.admin.transaction():
                await self.admin.executemany(sql, args)

        self.run(go())

    def ensure_partitions(self, table: str, start: datetime, end: datetime) -> None:
        self.val("SELECT sibyl.partition_ensure($1, $2, $3)", table, start, end)


async def _settle(kit: Kit, tenant: UUID, expected: int, rollup: Any) -> list[Any]:
    """Run ``rollup(conn)`` until ``expected`` events are consumed (cluster-wide horizon)."""
    results: list[Any] = []
    deadline = asyncio.get_running_loop().time() + 30
    while True:
        async with kit.worker.tenant_tx(tenant) as conn:
            results.append(await rollup(conn))
        if (
            sum(r.events for r in results) >= expected
            or asyncio.get_running_loop().time() > deadline
        ):
            return results
        await asyncio.sleep(0.05)


def settle(kit: Kit, tenant: UUID, expected: int, rollup: Any) -> list[Any]:
    return kit.run(_settle(kit, tenant, expected, rollup))  # type: ignore[no-any-return]


def calls(
    agent: UUID,
    ts: datetime,
    n: int,
    *,
    errors: int = 0,
    latency_ms: int = 400,
    provider: str = "provider-one",
    model: str = "large-1",
    error_class: str = "server_error",
    attrs: dict[str, Any] | None = None,
    spread_s: float = 50.0,
    tokens_out: int = 50,
    cost: Decimal = Decimal("0.001"),
) -> list[dict[str, Any]]:
    """``n`` gen_ai.request events in ``[ts, ts + spread_s)``; the last ``errors`` fail."""
    out = []
    for i in range(n):
        failed = i >= n - errors
        out.append(
            {
                "agent_id": agent,
                "ts": ts + timedelta(seconds=spread_s * i / max(n, 1)),
                "provider": provider,
                "model": model,
                "status": "error" if failed else "ok",
                "error_class": error_class if failed else None,
                "http_status": 503 if failed and error_class == "server_error" else 200,
                "latency_ms": latency_ms,
                "ttfb_ms": latency_ms // 4,
                "tokens_in": 100,
                "tokens_out": 0 if failed else tokens_out,
                "cost_usd": cost,
                "attrs": attrs or {},
            }
        )
    return out


def tool_calls(
    agent: UUID, ts: datetime, names: Sequence[str], *, bad: int = 0, task: UUID | None = None
) -> list[dict]:
    task = task or uuid4()
    out = []
    for i, name in enumerate(names):
        invalid = i < bad
        out.append(
            {
                "agent_id": agent,
                "ts": ts + timedelta(seconds=i * 0.5),
                "event_type": "tool.call",
                "task_id": task,
                "status": "error" if invalid else "ok",
                "error_type": "schema_validation" if invalid else None,
                "latency_ms": 20,
                "attrs": {
                    "tool_name": name,
                    "tool_type": "function",
                    "status": "ok",
                    "latency_ms": 20,
                },
            }
        )
    return out


def worker_dsn(name: str) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"sibyl_worker@{host}", f"/{name}", "", ""))


async def _admin_exec(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def h_loop() -> Iterator[asyncio.AbstractEventLoop]:
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def kit(h_loop: asyncio.AbstractEventLoop) -> Iterator[Kit]:
    async def probe() -> bool:
        try:
            conn = await asyncpg.connect(ADMIN_DSN, timeout=3)
        except (OSError, asyncpg.PostgresError):
            return False
        await conn.close()
        return True

    if not h_loop.run_until_complete(probe()):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_h_{secrets.token_hex(6)}"
    h_loop.run_until_complete(_admin_exec(f'CREATE DATABASE "{name}"'))
    try:
        cfg = MigrateConfig(
            migrate=ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name),
            admin=ConnSpec(dsn=ADMIN_DSN, database=name),
        )
        for attempt in range(5):  # other lanes bootstrap cluster roles concurrently
            try:
                h_loop.run_until_complete(apply(cfg))
                break
            except asyncpg.InternalServerError as exc:
                if "concurrently updated" not in str(exc) or attempt == 4:
                    raise
                h_loop.run_until_complete(asyncio.sleep(0.5 * (attempt + 1)))
        admin = h_loop.run_until_complete(
            asyncpg.connect(**ConnSpec(dsn=ADMIN_DSN, database=name).kwargs())
        )
        h_loop.run_until_complete(_codecs(admin))
        worker = h_loop.run_until_complete(
            Database.connect(worker_dsn(name), min_size=1, max_size=4)
        )
        yield Kit(h_loop, name, admin, worker)
        h_loop.run_until_complete(worker.close())
        h_loop.run_until_complete(admin.close())
    finally:
        h_loop.run_until_complete(_admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


async def _codecs(conn: asyncpg.Connection) -> None:
    import json

    for name in ("json", "jsonb"):
        await conn.set_type_codec(name, encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
