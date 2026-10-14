"""retention loop on PG17: payload sweep under the legal-hold predicate, hold expiry and
partition drops (the latter through the proposed ``partition_retire_expired`` CR function)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import asyncpg
import pytest
import sibyl_lane_u_helpers as h
from sibyl_control.worker.housekeeping import retention

NOW = datetime.now(UTC)
CR_SQL = Path(__file__).with_name("cr_sql") / "partition_retire_expired.sql"


def _hold(world: Any, tenant: Any, **cols: Any) -> Any:
    values = {
        "scope_kind": "agent",
        "agent_ids": [],
        "window_from": NOW - timedelta(days=900),
        "reason": "retention test hold",
        "expires_at": NOW + timedelta(days=30),
        **cols,
    }
    return world.in_tenant(
        tenant.id,
        "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, scope_ref, agent_ids, window_from,"
        " reason, expires_at, placed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
        tenant.id,
        values["scope_kind"],
        values.get("scope_ref"),
        values["agent_ids"],
        values["window_from"],
        values["reason"],
        values["expires_at"],
        values.get("placed_at", NOW),
    )[0]["id"]


def test_expired_payloads_are_swept_unless_held(world: Any) -> None:
    held_agent = world.add_agent(world.a, "ret-held")
    free_agent = world.add_agent(world.a, "ret-free")
    past = NOW - timedelta(days=2)
    free_id, free_key = h.add_payload(
        world, world.a.id, agent=free_agent, created_at=past, expires_at=past + timedelta(hours=1)
    )
    held_id, held_key = h.add_payload(
        world, world.a.id, agent=held_agent, created_at=past, expires_at=past + timedelta(hours=1)
    )
    live_id, _ = h.add_payload(world, world.a.id, agent=free_agent)
    _hold(world, world.a, scope_ref=str(held_agent), agent_ids=[held_agent])
    since = world.head(world.a.id)
    world.tick(retention)
    states = {
        r["id"]: r["state"]
        for r in world.fetch(
            "SELECT id, state FROM sibyl.payload_refs WHERE id = ANY($1::uuid[])",
            [free_id, held_id, live_id],
        )
    }
    assert states == {free_id: "swept", held_id: "stored", live_id: "stored"}
    assert world.run(world.blob.head(free_key)) is None
    assert world.run(world.blob.head(held_key)) is not None
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2"
        " AND action = 'retention.objects_swept'",
        world.a.id,
        since,
    )
    assert row["actor_type"] == "system"
    assert row["detail"]["objects"] == 1 and row["detail"]["holds_skipped"] == 1
    assert row["detail"]["date_prefix"] == past.date().isoformat()


def test_tenant_hold_keeps_everything_in_its_window(world: Any) -> None:
    agent = world.add_agent(world.b, "ret-tenant-hold")
    past = NOW - timedelta(days=3)
    ref, key = h.add_payload(
        world, world.b.id, agent=agent, created_at=past, expires_at=past + timedelta(hours=1)
    )
    hold = _hold(world, world.b, scope_kind="tenant", window_from=NOW - timedelta(days=5))
    world.tick(retention)
    assert world.fetchval("SELECT state FROM sibyl.payload_refs WHERE id = $1", ref) == "stored"
    world.in_tenant(
        world.b.id,
        "UPDATE sibyl.legal_hold SET state = 'released', released_at = now(),"
        " release_reason = 'done with it' WHERE tenant_id = $1 AND id = $2",
        world.b.id,
        hold,
    )
    world.tick(retention)
    assert world.fetchval("SELECT state FROM sibyl.payload_refs WHERE id = $1", ref) == "swept"
    assert world.run(world.blob.head(key)) is None


def test_holds_past_expiry_become_expired(world: Any) -> None:
    hold = _hold(
        world,
        world.a,
        scope_kind="tenant",
        placed_at=NOW - timedelta(days=10),
        expires_at=NOW - timedelta(minutes=1),
    )
    world.tick(retention)
    assert world.fetchval("SELECT state FROM sibyl.legal_hold WHERE id = $1", hold) == "expired"


def test_partition_drops_are_skipped_without_the_cr_function(world: Any, caplog: Any) -> None:
    assert world.run(retention.drop_partitions(world.ctx("retention"))) == 0


@pytest.fixture(scope="module")
def retire_fn(world: Any) -> None:
    async def install() -> None:
        conn = await asyncpg.connect(**_migrate_spec(world).kwargs())
        try:
            await conn.execute(CR_SQL.read_text())
        finally:
            await conn.close()

    world.run(install())


def _migrate_spec(world: Any) -> Any:
    import sibyl_lane_u_harness as H

    return H.R._spec(world.db_name, "sibyl_migrate")


def test_partitions_past_retention_are_dropped_and_audited_per_tenant(
    world: Any, retire_fn: None
) -> None:
    old = NOW - timedelta(days=60)
    h.ensure_partitions(world, "events_rejected", old, old + timedelta(hours=1))
    agent = world.add_agent(world.a, "ret-old-payload")
    held_agent = world.add_agent(world.a, "ret-old-held")
    ancient = NOW - timedelta(days=500)
    free_ref, _ = h.add_payload(world, world.a.id, agent=agent, created_at=ancient)
    older = ancient - timedelta(days=3)
    held_ref, _ = h.add_payload(world, world.a.id, agent=held_agent, created_at=older)
    _hold(world, world.a, scope_ref=str(held_agent), agent_ids=[held_agent])
    since = world.head(world.a.id)
    dropped = world.run(retention.drop_partitions(world.ctx("retention")))
    assert dropped >= 2
    registry = {
        r["partition_name"]: r["state"]
        for r in world.fetch("SELECT partition_name, state FROM sibyl.partition_registry")
    }
    assert registry[f"payload_refs_p{ancient:%Y%m%d}"] == "dropped"
    assert registry[f"payload_refs_p{older:%Y%m%d}"] == "attached"  # held content stays
    assert registry[f"events_rejected_p{old:%Y%m%d}"] == "dropped"
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", free_ref) == 0
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", held_ref) == 1
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2"
        " AND action = 'retention.partition_dropped'",
        world.a.id,
        since,
    )
    assert row["detail"]["table"] == "payload_refs" and row["detail"]["rows"] == 1
    # audit_events partitions are never dropped here
    assert all(
        r["state"] == "attached"
        for r in world.fetch(
            "SELECT state FROM sibyl.partition_registry WHERE table_name = 'audit_events'"
        )
    )
    _ = uuid4
