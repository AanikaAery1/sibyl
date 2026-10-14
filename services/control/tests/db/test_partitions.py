# ruff: noqa: S608 -- SQL fragments here are fixed test literals, never input
"""Partition machinery (code review M8): concurrent partition_ensure calls serialise instead of
racing to 42P07, and the migrate-time horizon covers every table's `ahead` window. There is no
DEFAULT partition on purpose (rows in it would block the partition that later covers them);
the hourly `partitions` worker loop keeps the horizon moving and is a G1 blocker."""

from __future__ import annotations

import asyncio
import uuid

import asyncpg

from .conftest import Conn, Database
from .fixtures import create_tenant

FAR = "now() + interval '900 days'"


def test_concurrent_partition_ensure_does_not_race(db: Database, admin: Conn) -> None:
    async def scenario() -> list[int]:
        one = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        two = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        probe = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        try:
            tx1 = one.transaction()
            await tx1.start()
            created = [
                await one.fetchval(
                    f"SELECT sibyl.partition_ensure('events', {FAR}, {FAR} + interval '2 days')"
                )
            ]
            tx2 = two.transaction()
            await tx2.start()
            racer = asyncio.ensure_future(
                two.fetchval(
                    f"SELECT sibyl.partition_ensure('events', {FAR}, {FAR} + interval '2 days')"
                )
            )
            for _ in range(500):
                if racer.done() or await probe.fetchval(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND wait_event_type = 'Lock'"
                ):
                    break
                await asyncio.sleep(0.01)
            await tx1.commit()
            created.append(await racer)
            await tx2.commit()
            return created
        finally:
            for conn in (one, two, probe):
                await conn.close()

    try:
        created = db.loop.run_until_complete(asyncio.wait_for(scenario(), 30))
        assert created[0] >= 2 and created[1] == 0
    finally:
        for row in admin.fetch(
            f"SELECT partition_name FROM sibyl.partition_registry WHERE table_name = 'events' "
            f"AND range_from >= date_trunc('day', {FAR}) - interval '1 day'"
        ):
            admin.execute(f'DROP TABLE IF EXISTS sibyl."{row["partition_name"]}"')
            admin.execute(
                "DELETE FROM sibyl.partition_registry WHERE partition_name = $1",
                row["partition_name"],
            )


def test_horizon_covers_every_table_ahead(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT h.table_name, h.covered_until, p.ahead, p.grain FROM sibyl.partition_horizon() h "
        "JOIN sibyl.partition_policy() p USING (table_name)"
    )
    assert {r["table_name"] for r in rows} == {
        r["table_name"] for r in admin.fetch("SELECT table_name FROM sibyl.partition_policy()")
    }
    for r in rows:
        assert admin.fetchval(
            "SELECT $1::timestamptz >= now() + $2::interval - sibyl.partition_period_step($3)",
            r["covered_until"],
            r["ahead"],
            r["grain"],
        ), r["table_name"]


def test_an_outbox_row_six_days_ahead_has_a_partition(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, f"horizon-{uuid.uuid4().hex[:6]}")
    app = roles["sibyl_app"]
    with app.tx(tenant, rollback=True):
        app.execute(
            "INSERT INTO sibyl.outbox (tenant_id, created_at, topic, event_type, aggregate_kind, "
            "aggregate_id, payload, idempotency_key) VALUES ($1, now() + interval '6 days', "
            "'alert', 'alert.fired', 'alert', $2, '{}', 'ahead')",
            tenant,
            uuid.uuid4(),
        )


def test_horizon_is_readable_by_the_worker(roles: dict[str, Conn]) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(rollback=True):
        assert worker.fetchval("SELECT count(*) FROM sibyl.partition_horizon()") > 0
