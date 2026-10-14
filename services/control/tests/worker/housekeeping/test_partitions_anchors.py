"""partitions + anchors loops on PG17 (lane U)."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from uuid import uuid4

import pytest
from sibyl_control.core.audit import AuditRecord, PgAuditWriter
from sibyl_control.core.outbox import OutboxMessage, PgOutboxWriter
from sibyl_control.worker.housekeeping import anchors, partitions
from sibyl_control.worker.housekeeping.anchoring import write_anchor
from sibyl_control.worker.housekeeping.chain import anchor_signature_ok
from sibyl_control.worker.housekeeping.common import active_anchor_key, resolve_signer
from sibyl_control.worker.housekeeping.verification import verify_chain


def _append(world: Any, tenant: Any, n: int = 1) -> None:
    async def run() -> None:
        async with world.worker_db.tenant_tx(tenant.id) as conn:
            for i in range(n):
                await PgAuditWriter().append(
                    conn,
                    tenant.id,
                    AuditRecord(
                        action="audit.verified",
                        actor_type="system",
                        resource_type="tenant",
                        resource_id=tenant.id,
                        detail={"from_seq": 0, "to_seq": i, "anchors_checked": 0},
                    ),
                )

    world.run(run())


def _anchor_now(world: Any, tenant: Any, payload: dict[str, Any]) -> None:
    async def run() -> None:
        async with world.worker_db.tenant_tx(tenant.id) as conn:
            message = OutboxMessage.for_event("audit.anchor_now", "audit", uuid4(), payload)
            await PgOutboxWriter().emit(conn, tenant.id, message)

    world.run(run())
    world.settle_outbox()


def test_partitions_tick_keeps_every_table_covered_ahead(world: Any) -> None:
    report = world.run(partitions.ensure(world.worker_db))
    assert not report.short
    now = world.fetchval("SELECT now()")
    for table, until in report.horizon.items():
        assert until is not None, table
        assert until >= now + timedelta(days=6), table


def test_partitions_create_what_a_future_clock_needs(world: Any) -> None:
    now = world.fetchval("SELECT now()")
    report = world.run(partitions.ensure(world.worker_db, now=now + timedelta(days=20)))
    assert report.created > 0
    outbox_until = report.horizon["outbox"]
    assert outbox_until >= now + timedelta(days=26)
    # every created partition carries the tenant RLS policy (defence in depth)
    names = world.fetch(
        "SELECT partition_name FROM sibyl.partition_registry WHERE table_name = 'outbox'"
    )
    for row in names:
        forced = world.fetchval(
            "SELECT relforcerowsecurity FROM pg_class WHERE relname = $1", row["partition_name"]
        )
        assert forced is True


def test_partitions_tick_fails_loudly_when_runway_is_short(world: Any, monkeypatch: Any) -> None:
    async def short(db: Any, *, now: Any = None) -> Any:
        return partitions.PartitionReport(0, {"outbox": None}, ("outbox",))

    monkeypatch.setattr(partitions, "ensure", short)
    with pytest.raises(partitions.PartitionRunwayLow):
        world.tick(partitions)


def test_hourly_anchor_is_signed_and_verifiable(world: Any) -> None:
    _append(world, world.a, 3)
    world.tick(anchors)
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 ORDER BY seq_to DESC LIMIT 1",
        world.a.id,
    )
    assert row["kind"] == "hourly"
    assert row["signing_kid"] == "anchor-test-1"
    assert anchor_signature_ok(dict(row), world.anchor_public_raw())
    head_row = world.fetchval(
        "SELECT hash FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = $2",
        world.a.id,
        row["seq_to"],
    )
    assert bytes(head_row) == bytes(row["head_hash"])
    assert "audit.anchored" in world.actions(world.a.id, row["seq_to"])
    # published off-database
    stored = world.run(world.blob.get(row["external_ref"]))
    assert json.loads(stored)["id"] == str(row["id"])
    # a second tick within the hour writes nothing new
    count = world.fetchval(
        "SELECT count(*) FROM sibyl.audit_anchors WHERE tenant_id = $1", world.a.id
    )
    world.tick(anchors)
    assert (
        world.fetchval("SELECT count(*) FROM sibyl.audit_anchors WHERE tenant_id = $1", world.a.id)
        == count
    )


def test_tampered_anchor_signature_fails_verification(world: Any) -> None:
    _append(world, world.b, 2)

    async def run() -> Any:
        async with world.worker_db.tenant_tx(world.b.id) as conn:
            key = await active_anchor_key(conn)
            signer = resolve_signer(key, world.settings)
            return (await write_anchor(conn, world.b.id, signer, kind="hourly")).row

    row = world.run(run())
    forged = dict(row)
    forged["seq_from"] = row["seq_from"] + 1
    assert not anchor_signature_ok(forged, world.anchor_public_raw())

    async def verify() -> Any:
        async with world.worker_db.tenant_tx(world.b.id, readonly=True) as conn:
            return await verify_chain(conn, world.b.id)

    result = world.run(verify())
    assert result.ok and result.anchors_checked >= 1


def test_break_glass_anchor_now_writes_a_break_glass_anchor(world: Any) -> None:
    _append(world, world.a, 1)
    _anchor_now(world, world.a, {"reason": "break_glass", "kill_switch_id": str(uuid4())})
    world.tick(anchors)
    kinds = [
        r["kind"]
        for r in world.fetch(
            "SELECT kind FROM sibyl.audit_anchors WHERE tenant_id = $1 ORDER BY anchored_at",
            world.a.id,
        )
    ]
    assert kinds[-1] == "break_glass"
    # the request is consumed exactly once
    before = len(kinds)
    _append(world, world.a, 1)
    world.tick(anchors)
    after = world.fetchval(
        "SELECT count(*) FROM sibyl.audit_anchors WHERE tenant_id = $1", world.a.id
    )
    assert after == before  # hourly not yet due; no new request


def test_missing_signing_key_fails_the_tick(world: Any, monkeypatch: Any) -> None:
    async def none(conn: Any) -> None:
        return None

    monkeypatch.setattr(anchors, "active_anchor_key", none)
    with pytest.raises(anchors.SignerUnavailable):
        world.tick(anchors)
