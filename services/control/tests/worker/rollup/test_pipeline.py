"""Rollup against a migrated PG17, as ``sibyl_worker`` (RLS and grants enforced)."""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import asyncpg
from sibyl_control.worker.loops import LoopContext
from sibyl_control.worker.rollup import tick
from sibyl_control.worker.rollup.pipeline import RollupResult, rollup_tenant
from sibyl_h_testkit import ADMIN_DSN, Kit, calls, settle, tool_calls


def roll(kit: Kit, tenant: UUID, expect: int = 0, now: datetime | None = None) -> RollupResult:
    """Roll up until ``expect`` events are consumed (the commit horizon is cluster-wide)."""
    results = settle(kit, tenant, expect, lambda conn: rollup_tenant(conn, tenant, now=now))
    hits = [r for r in results if r.events] or results[-1:]
    return replace(hits[-1], events=sum(r.events for r in results))


def minute(offset: int = 0) -> datetime:
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    return now + timedelta(minutes=offset)


def metrics(kit: Kit, table: str, tenant: UUID, agent: UUID) -> list[dict[str, Any]]:
    rows = kit.q(
        f"SELECT * FROM sibyl.{table} WHERE tenant_id = $1 AND agent_id = $2 "  # noqa: S608
        "ORDER BY bucket_start, provider, model",
        tenant,
        agent,
    )
    return [dict(r) for r in rows]


def test_events_roll_into_every_grain_and_the_cursor_advances(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    m = minute(-3)
    kit.events(t, calls(a, m, 30, errors=6) + tool_calls(a, m, ["x", "x", "y"], bad=1))
    res = roll(kit, t, 33)
    assert res.events == 33 and res.buckets_1m == 1
    one = metrics(kit, "agent_metrics_1m", t, a)
    by_model = {(r["provider"], r["model"]): r for r in one}
    gen = by_model[("provider-one", "large-1")]
    assert gen["request_count"] == 30 and gen["error_count"] == 6
    assert gen["server_error_count"] == 6
    tools = by_model[("", "")]
    assert tools["tool_call_count"] == 3 and tools["tool_schema_invalid_count"] == 1
    assert tools["tool_seq_hash_distinct"] == 2
    five = metrics(kit, "agent_metrics_5m", t, a)
    assert sum(r["request_count"] for r in five) == 30
    assert {r["children_1m"] for r in five} == {1}
    hour = metrics(kit, "agent_metrics_1h", t, a)
    assert sum(r["request_count"] for r in hour) == 30
    prov = kit.q(
        "SELECT provider, model, request_count, agent_count FROM sibyl.provider_metrics_5m "
        "WHERE tenant_id = $1 ORDER BY model",
        t,
    )
    assert [(r["model"], r["request_count"], r["agent_count"]) for r in prov] == [
        ("*", 30, 1),
        ("large-1", 30, 1),
    ]
    again = roll(kit, t)
    assert again.events == 0, "the cursor moved past every committed event"
    assert metrics(kit, "agent_metrics_1m", t, a) == one, "a no-op tick rewrites nothing"


def test_recompute_replaces_never_adds_and_is_idempotent(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    m = minute(-2)
    kit.events(t, calls(a, m, 10, errors=1))
    roll(kit, t, 10)
    kit.events(t, calls(a, m + timedelta(seconds=55), 5, errors=5, spread_s=1))
    roll(kit, t, 5)
    row = metrics(kit, "agent_metrics_1m", t, a)[0]
    assert (row["request_count"], row["error_count"]) == (15, 6)
    # replay from scratch: reset the cursor and run again, nothing doubles
    kit.exe("DELETE FROM sibyl.consumer_offsets WHERE tenant_id = $1", t)
    replay = roll(kit, t, 15)
    assert replay.events == 15
    assert metrics(kit, "agent_metrics_1m", t, a)[0]["request_count"] == 15
    assert sum(r["request_count"] for r in metrics(kit, "agent_metrics_1h", t, a)) == 15


def test_late_event_dirties_its_true_bucket_and_parents(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    old = minute(-20)
    kit.events(t, calls(a, minute(-1), 4))
    roll(kit, t, 4)
    kit.events(t, calls(a, old, 3, errors=3))
    res = roll(kit, t, 3)
    assert res.buckets_1m == 1
    rows = {r["bucket_start"]: r for r in metrics(kit, "agent_metrics_1m", t, a)}
    assert rows[old]["error_count"] == 3 and rows[old]["late_count"] == 3, "is_late counted"
    hour_total = sum(r["request_count"] for r in metrics(kit, "agent_metrics_1h", t, a))
    assert hour_total == 7
    assert res.closed_5m, "the late bucket's 5m parent is closed"


def test_bucket_beyond_1m_retention_rolls_5m_directly(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    old = minute(-20 * 24 * 60)
    kit.ensure_partitions("events", old - timedelta(days=1), old + timedelta(days=1))
    kit.events(t, calls(a, old, 6, errors=2))
    roll(kit, t, 6)
    assert not [r for r in metrics(kit, "agent_metrics_1m", t, a) if r["bucket_start"] <= old]
    five = [r for r in metrics(kit, "agent_metrics_5m", t, a)]
    assert len(five) == 1 and five[0]["children_1m"] == 0 and five[0]["request_count"] == 6


def test_uncommitted_older_transaction_is_never_skipped(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    m = minute(-1)

    slow = kit.run(asyncpg.connect(ADMIN_DSN.rsplit("/", 1)[0] + f"/{kit.name}"))
    tx = slow.transaction()
    kit.run(tx.start())
    kit.run(
        slow.execute(
            "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, emitter_id, "
            "seq, policy_state, capture_mode, redaction_profile_hash, normaliser_version, "
            "agent_id, provider, model, status, latency_ms) VALUES ($1, gen_random_uuid(), $2, "
            "'gen_ai.request', 'sdk', 'slow', 1, 'fresh', 'metadata', $3, 'n/1', $4, "
            "'provider-one', 'large-1', 'error', 10)",
            t,
            m,
            b"\x00" * 32,
            a,
        )
    )
    kit.events(t, calls(a, m, 2))  # commits after the slow transaction took its xid
    first = roll(kit, t)
    assert first.events == 0, "rows above the commit horizon wait for the older transaction"
    kit.run(tx.commit())
    kit.run(slow.close())
    second = roll(kit, t, 3)
    assert second.events == 3
    row = metrics(kit, "agent_metrics_1m", t, a)[0]
    assert (row["request_count"], row["error_count"]) == (3, 1)


def test_tenants_are_isolated(kit: Kit) -> None:
    t1, t2 = kit.tenant(), kit.tenant()
    a1, a2 = kit.agent(t1), kit.agent(t2)
    kit.events(t1, calls(a1, minute(-1), 5))
    kit.events(t2, calls(a2, minute(-1), 7))
    roll(kit, t1, 5)
    assert metrics(kit, "agent_metrics_1m", t2, a2) == []
    assert metrics(kit, "agent_metrics_1m", t1, a1)[0]["request_count"] == 5


def test_carryover_reports_lag_and_resumes(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    kit.events(t, calls(a, minute(-1), 12))

    async def small() -> RollupResult:
        async with kit.worker.tenant_tx(t) as conn:
            return await rollup_tenant(conn, t, batch=5)

    results = settle(kit, t, 12, lambda conn: rollup_tenant(conn, t, batch=5))
    first = next(r for r in results if r.events)
    assert first.carryover and first.events == 5 and first.lag_s >= 0
    del small
    assert metrics(kit, "agent_metrics_1m", t, a)[0]["request_count"] == 12


def test_tick_runs_every_active_tenant(kit: Kit) -> None:
    t = kit.tenant()
    a = kit.agent(t)
    kit.events(t, calls(a, minute(-1), 3))
    ctx = LoopContext("rollup", kit.worker, None, logging.getLogger("t"))
    deadline = time.monotonic() + 30
    while not metrics(kit, "agent_metrics_1m", t, a) and time.monotonic() < deadline:
        kit.run(tick(ctx))
    assert metrics(kit, "agent_metrics_1m", t, a)[0]["request_count"] == 3
