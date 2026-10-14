"""G0 fixes to routing_apply(): idempotency keys bound to (agent, to_state, trigger)
(code-review H1), a structural audit-before-routing lock order (H2), and the
routing_transition INSERT trigger on its own (tests F19)."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import asyncpg
import pytest

from .conftest import Conn, Database
from .fixtures import TenantFixture, populate_tenant

CALL = (
    "SELECT * FROM sibyl.routing_apply($1, $2, NULL, $3, $4, NULL, $5, 'rule', NULL, NULL, "
    "NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $6, 'route.changed', NULL, NULL, NULL, NULL)"
)
APPEND = (
    "SELECT * FROM sibyl.audit_append($1, 'system', NULL, NULL, NULL, 'retention.objects_swept', "
    "'tenant', $1, NULL, NULL, $2::jsonb, NULL, now(), NULL)"
)
SWEEP = json.dumps({"date_prefix": "d", "objects": 1, "bytes": 1, "holds_skipped": 0})


@pytest.fixture
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, f"routing-g0-{uuid.uuid4().hex[:6]}")


def _apply(conn: Conn, fx: TenantFixture, agent: uuid.UUID, frm: str, to: str, key: str) -> Any:
    return conn.fetchrow(CALL, fx.tenant_id, agent, frm, to, "rule", key)


def _error(conn: Conn, fx: TenantFixture, *args: Any) -> asyncpg.PostgresError:
    with pytest.raises(asyncpg.PostgresError) as info:
        with conn.tx(fx.tenant_id, rollback=True):
            _apply(conn, fx, *args)
    return info.value


def test_same_key_same_request_replays(roles: dict[str, Conn], fx: TenantFixture) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        first = _apply(worker, fx, fx.agent_a, "active", "degraded", "k-replay")
    with worker.tx(fx.tenant_id):
        again = _apply(worker, fx, fx.agent_a, "active", "degraded", "k-replay")
    assert dict(first) == dict(again)


def test_same_key_on_another_agent_is_refused(roles: dict[str, Conn], fx: TenantFixture) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _apply(worker, fx, fx.agent_a, "active", "degraded", "k-agent")
    err = _error(worker, fx, fx.agent_b, "active", "degraded", "k-agent")
    assert err.sqlstate == "SB015" and "sibyl:idempotency_key_reuse" in str(err)


def test_same_key_with_another_target_state_is_refused(
    roles: dict[str, Conn], fx: TenantFixture
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _apply(worker, fx, fx.agent_a, "active", "degraded", "k-state")
    err = _error(worker, fx, fx.agent_a, "degraded", "active", "k-state")
    assert err.sqlstate == "SB015", err


def test_same_key_with_another_trigger_is_refused(
    roles: dict[str, Conn], fx: TenantFixture
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _apply(worker, fx, fx.agent_a, "active", "degraded", "k-trigger")
    with pytest.raises(asyncpg.PostgresError) as info:
        with worker.tx(fx.tenant_id, rollback=True):
            worker.fetchrow(
                "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'degraded', NULL, "
                "'policy', 'policy', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, "
                "'k-trigger', 'route.changed', NULL, NULL, NULL, NULL)",
                fx.tenant_id,
                fx.agent_a,
            )
    assert info.value.sqlstate == "SB015", info.value


async def _connect(db: Database, role: str) -> asyncpg.Connection:
    return await asyncpg.connect(**db.spec(role).kwargs())


async def _wait_until_blocked(probe: asyncpg.Connection, task: asyncio.Task[Any]) -> None:
    """Poll pg_stat_activity until ``task`` waits on a lock (no sleep-as-assertion)."""
    for _ in range(500):
        if task.done():
            return
        waiting = await probe.fetchval(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
            "AND wait_event_type = 'Lock'"
        )
        if waiting:
            return
        await asyncio.sleep(0.01)
    raise AssertionError("the second transaction never blocked")


async def _begin(conn: asyncpg.Connection, tenant: uuid.UUID) -> Any:
    tx = conn.transaction()
    await tx.start()
    await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
    return tx


def test_concurrent_same_key_on_two_agents_never_leaks_a_unique_violation(
    db: Database, fx: TenantFixture
) -> None:
    async def scenario() -> BaseException | None:
        one, two, probe = [await _connect(db, "sibyl_worker") for _ in range(3)]
        try:
            tx1 = await _begin(one, fx.tenant_id)
            await one.fetchrow(
                CALL, fx.tenant_id, fx.agent_a, "active", "degraded", "rule", "k-race"
            )
            tx2 = await _begin(two, fx.tenant_id)
            second = asyncio.ensure_future(
                two.fetchrow(CALL, fx.tenant_id, fx.agent_b, "active", "degraded", "rule", "k-race")
            )
            await _wait_until_blocked(probe, second)
            await tx1.commit()
            try:
                await second
            except asyncpg.PostgresError as exc:
                return exc
            finally:
                await tx2.rollback()
            return None
        finally:
            for conn in (one, two, probe):
                await conn.close()

    outcome = db.loop.run_until_complete(asyncio.wait_for(scenario(), 30))
    assert isinstance(outcome, asyncpg.PostgresError), "a second agent silently reused the key"
    assert outcome.sqlstate == "SB015", outcome


def test_audit_append_then_routing_apply_cannot_deadlock_a_concurrent_routing_apply(
    db: Database, fx: TenantFixture
) -> None:
    """Tx1 appends audit, Tx2 starts routing_apply, then Tx1 calls routing_apply. With the
    audit lock taken first by routing_apply, Tx2 waits for Tx1 instead of forming a cycle."""

    async def scenario() -> tuple[Any, BaseException | None]:
        one, two, probe = [await _connect(db, "sibyl_worker") for _ in range(3)]
        try:
            tx1 = await _begin(one, fx.tenant_id)
            await one.fetchrow(APPEND, fx.tenant_id, SWEEP)
            tx2 = await _begin(two, fx.tenant_id)
            competing = asyncio.ensure_future(
                two.fetchrow(CALL, fx.tenant_id, fx.agent_a, "active", "degraded", "rule", "k-dl-2")
            )
            await _wait_until_blocked(probe, competing)
            mine = await one.fetchrow(
                CALL, fx.tenant_id, fx.agent_a, "active", "degraded", "rule", "k-dl-1"
            )
            await tx1.commit()
            try:
                await competing
                error = None
            except asyncpg.PostgresError as exc:
                error = exc
            await tx2.rollback()
            return mine, error
        finally:
            for conn in (one, two, probe):
                await conn.close()

    mine, error = db.loop.run_until_complete(asyncio.wait_for(scenario(), 30))
    assert mine["transition_id"] is not None
    # Tx2 lost the race honestly: the agent is no longer 'active'.
    assert error is not None and error.sqlstate == "SB011", error


def test_routing_transition_insert_trigger_refuses_an_illegal_edge_on_its_own(
    admin: Conn, fx: TenantFixture
) -> None:
    """The definer role writing directly (bypassing routing_apply's own edge check)."""
    with pytest.raises(asyncpg.PostgresError) as info:
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute("SET LOCAL ROLE sibyl_routing")
            admin.execute(
                "INSERT INTO sibyl.routing_transition (tenant_id, agent_id, from_state, to_state, "
                "from_target, to_target, trigger, actor_kind, routing_version, audit_seq, "
                "idempotency_key) VALUES ($1, $2, 'killed', 'active', '{}', '{}', 'rule', 'rule', "
                "1, 0, 'direct')",
                fx.tenant_id,
                fx.agent_a,
            )
    assert info.value.sqlstate == "SB010", info.value
