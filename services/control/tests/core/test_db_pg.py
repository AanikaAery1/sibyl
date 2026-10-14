"""Integration: Database against a real PG17 on :5433 with a minimal fixture schema.

Uses a throw-away database ``sibyl_w0ker_<random>``; creates no cluster roles. Skipped when the
dev cluster is not running. The fixture schema mimics only ``sibyl.set_tenant``/``current_tenant``
and the ``outbox`` columns. The idempotency store runs against the real migrated table in
``tests/db/test_kernel_idempotency.py`` (chair ruling G0-2).
"""

import asyncio
import os
import secrets
from uuid import uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from sibyl_control.core.db import Database  # noqa: E402
from sibyl_control.core.outbox import OutboxMessage, PgOutboxWriter  # noqa: E402

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")

FIXTURE_SQL = """
CREATE SCHEMA sibyl;
CREATE FUNCTION sibyl.current_tenant() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('app.tenant_id', true), '')::uuid $$;
CREATE FUNCTION sibyl.set_tenant(p_tenant uuid) RETURNS void LANGUAGE sql
  AS $$ SELECT set_config('app.tenant_id', p_tenant::text, true) $$;
CREATE TABLE sibyl.outbox (
  tenant_id uuid NOT NULL, id uuid NOT NULL DEFAULT gen_random_uuid(),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  topic text NOT NULL, event_type text NOT NULL, aggregate_kind text NOT NULL,
  aggregate_id uuid, payload jsonb NOT NULL, idempotency_key text,
  CHECK (tenant_id = sibyl.current_tenant())
);
"""


@pytest.fixture
async def pg_dsn():
    try:
        admin = await asyncpg.connect(ADMIN_DSN, timeout=2)
    except (OSError, asyncpg.PostgresError) as exc:
        pytest.skip(f"PG17 dev cluster not reachable: {exc}")
    name = f"sibyl_fixker_{secrets.token_hex(4)}"
    await admin.execute(f'CREATE DATABASE "{name}"')
    dsn = ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"
    try:
        setup = await asyncpg.connect(dsn)
        await setup.execute(FIXTURE_SQL)
        await setup.close()
        yield dsn
    finally:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


@pytest.fixture
async def database(pg_dsn: str):
    db = await Database.connect(pg_dsn, min_size=1, max_size=2)
    try:
        yield db
    finally:
        await db.close()


async def test_tenant_is_set_inside_and_cleared_after(database: Database) -> None:
    tenant = uuid4()
    async with database.tenant_tx(tenant) as conn:
        assert await conn.fetchval("SELECT sibyl.current_tenant()") == tenant
    async with database.pre_tenant() as conn:
        assert await conn.fetchval("SELECT sibyl.current_tenant()") is None


async def test_writes_for_another_tenant_fail_closed(database: Database) -> None:
    with pytest.raises(asyncpg.CheckViolationError):
        async with database.tenant_tx(uuid4()) as conn:
            await conn.execute(
                "INSERT INTO sibyl.outbox (tenant_id, topic, event_type, aggregate_kind, payload)"
                " VALUES ($1, 'policy', 'policy_changed', 'agent', '{}'::jsonb)",
                uuid4(),
            )


async def test_pre_tenant_is_read_only(database: Database) -> None:
    with pytest.raises(asyncpg.ReadOnlySQLTransactionError):
        async with database.pre_tenant() as conn:
            await conn.execute("CREATE TABLE sibyl.nope (x int)")


async def test_jsonb_round_trips_as_python(database: Database) -> None:
    async with database.tenant_tx(uuid4()) as conn:
        assert await conn.fetchval("SELECT $1::jsonb", {"a": [1, "x"]}) == {"a": [1, "x"]}


async def test_outbox_writer_against_postgres(database: Database) -> None:
    tenant = uuid4()
    msg = OutboxMessage("policy", "policy_changed", "agent", uuid4(), {"routing_version": 2})
    async with database.tenant_tx(tenant) as conn:
        await PgOutboxWriter().emit(conn, tenant, msg)
        row = await conn.fetchrow("SELECT topic, payload FROM sibyl.outbox")
    assert row["topic"] == "policy"
    assert row["payload"] == {"routing_version": 2}


async def test_committed_tenant_context_does_not_reach_the_next_pooled_transaction(
    pg_dsn: str,
) -> None:
    """G0 tests F6, kernel side: one pooled connection, a committed tenant tx, then another."""
    db = await Database.connect(pg_dsn, min_size=1, max_size=1)
    try:
        tenant = uuid4()
        async with db.tenant_tx(tenant) as conn:
            first_pid = await conn.fetchval("SELECT pg_backend_pid()")
        async with db.pre_tenant() as conn:
            assert await conn.fetchval("SELECT pg_backend_pid()") == first_pid
            assert await conn.fetchval("SELECT sibyl.current_tenant()") is None
        other = uuid4()
        async with db.tenant_tx(other) as conn:
            assert await conn.fetchval("SELECT sibyl.current_tenant()") == other
    finally:
        await db.close()


async def test_a_real_deadlock_is_retried_to_success(database: Database) -> None:
    """H2: two transactions taking two locks in opposite order; Postgres kills one (40P01), the
    retry wrapper re-runs it and both commit."""
    tenant = uuid4()
    holding = {1: asyncio.Event(), 2: asyncio.Event()}
    attempts = {1: 0, 2: 0}

    def body(first: int, second: int):
        async def run(conn) -> int:
            attempts[first] += 1
            await conn.execute("SET LOCAL deadlock_timeout = '50ms'")
            await conn.execute("SELECT pg_advisory_xact_lock($1)", first)
            if attempts[first] == 1:
                holding[first].set()
                await asyncio.wait_for(holding[second].wait(), 5)
            await conn.execute("SELECT pg_advisory_xact_lock($1)", second)
            return first

        return run

    results = await asyncio.wait_for(
        asyncio.gather(
            database.run_in_tenant_tx(tenant, body(1, 2)),
            database.run_in_tenant_tx(tenant, body(2, 1)),
        ),
        10,
    )
    assert sorted(results) == [1, 2]
    assert sorted(attempts.values()) == [1, 2]  # exactly one victim, re-run once


async def test_audit_and_outbox_writers_accept_uuid_values(database: Database) -> None:
    """Code review M3: UUIDs in an outbox payload must not crash the asyncpg jsonb codec."""
    tenant, ref = uuid4(), uuid4()
    msg = OutboxMessage("policy", "policy_changed", "agent", uuid4(), {"agent_id": ref})
    async with database.tenant_tx(tenant) as conn:
        await PgOutboxWriter().emit(conn, tenant, msg)
        payload = await conn.fetchval("SELECT payload FROM sibyl.outbox")
    assert payload == {"agent_id": str(ref)}
