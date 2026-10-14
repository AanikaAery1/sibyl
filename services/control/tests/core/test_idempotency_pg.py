"""Idempotency fencing, races and body storage against the real migrated table (PG17 :5433).

Builds its own database ``sibyl_fixker_<hex>`` with the real migration runner (the cluster roles
already exist; nothing is created at cluster level) and runs the kernel as ``sibyl_app``.
Covers code review M5 (claim fencing, U+0000 bodies), ruling G0-8 (64 KB cap, required
``principal_kind``) and test review F9 (concurrent first use).
"""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import pytest

asyncpg = pytest.importorskip("asyncpg")

from sibyl_control.core.db import Database  # noqa: E402
from sibyl_control.core.idempotency import (  # noqa: E402
    IN_PROGRESS_STALE_AFTER,
    MAX_STORED_BODY_BYTES,
    ForeignKey,
    Fresh,
    IdempotencyClaimLost,
    InProgress,
    PgIdempotencyStore,
    Replay,
    ReplayUnavailable,
    StoredResponse,
    fingerprint,
)
from sibyl_control.core.outbox import OutboxMessage, PgOutboxWriter  # noqa: E402
from sibyl_control.migrate.config import ConnSpec, MigrateConfig  # noqa: E402
from sibyl_control.migrate.runner import apply  # noqa: E402

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
ROUTE = "POST /api/v1/agents"
FP = fingerprint(b'{"x":1}', method="POST", path="/api/v1/agents", query="")


def _app_dsn(name: str) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"sibyl_app@{host}", f"/{name}", "", ""))


def _admin_dsn(name: str) -> str:
    return ADMIN_DSN.rsplit("/", 1)[0] + f"/{name}"


async def _setup(name: str) -> None:
    admin = await asyncpg.connect(ADMIN_DSN, timeout=3)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    spec = {"dsn": ADMIN_DSN, "database": name}
    await apply(
        MigrateConfig(migrate=ConnSpec(user="sibyl_migrate", **spec), admin=ConnSpec(**spec))
    )


async def _drop(name: str) -> None:
    admin = await asyncpg.connect(ADMIN_DSN)
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


@pytest.fixture(scope="module")
def migrated() -> Iterator[str]:
    async def reachable() -> bool:
        try:
            conn = await asyncpg.connect(ADMIN_DSN, timeout=3)
        except (OSError, asyncpg.PostgresError):
            return False
        await conn.close()
        return True

    if not asyncio.run(reachable()):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_fixker_{secrets.token_hex(5)}"
    try:
        asyncio.run(_setup(name))  # a failed migration must not leak the database
        yield name
    finally:
        asyncio.run(_drop(name))


@pytest.fixture
async def admin(migrated: str) -> AsyncIterator[Any]:
    conn = await asyncpg.connect(_admin_dsn(migrated))
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
async def tenant(admin: Any) -> UUID:
    slug = f"idem-{secrets.token_hex(4)}"
    return await admin.fetchval(
        "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', 'kek-test', $3, $4, $5)",
        slug,
        slug.title(),
        secrets.token_bytes(32),
        secrets.token_bytes(32),
        secrets.token_bytes(32),
    )


@pytest.fixture
async def kernel(migrated: str) -> AsyncIterator[Database]:
    db = await Database.connect(_app_dsn(migrated), min_size=1, max_size=4)
    try:
        yield db
    finally:
        await db.close()


@pytest.fixture
def store(kernel: Database) -> PgIdempotencyStore:
    return PgIdempotencyStore(kernel)


async def _age(admin: Any, tenant: UUID, key: str, by: timedelta) -> None:
    async with admin.transaction():
        await admin.execute("SET LOCAL session_replication_role = replica")
        await admin.execute(
            "UPDATE sibyl.idempotency_record SET created_at = created_at - $3::interval "
            "WHERE tenant_id = $1 AND idempotency_key = $2",
            tenant,
            key,
            by,
        )


async def test_claim_id_is_stored_and_replay_works(store, tenant, admin) -> None:
    who = uuid4()
    first = await store.begin(tenant, who, ROUTE, "k-ok", FP, principal_kind="user")
    assert isinstance(first, Fresh)
    stored = await admin.fetchval(
        "SELECT claim_id FROM sibyl.idempotency_record WHERE tenant_id=$1 AND idempotency_key=$2",
        tenant,
        "k-ok",
    )
    assert stored == first.claim_id
    await store.complete(first.token, StoredResponse(201, {"etag": '"1"'}, b'{"id":"a"}'))
    again = await store.begin(tenant, who, ROUTE, "k-ok", FP, principal_kind="user")
    assert isinstance(again, Replay) and again.response.body == b'{"id":"a"}'
    other_kind = await store.begin(tenant, who, ROUTE, "k-ok", FP, principal_kind="api_key")
    assert isinstance(other_kind, ForeignKey)


async def test_late_complete_after_a_stale_reclaim_is_fenced_and_rolls_back(
    store, kernel, tenant, admin
) -> None:
    who = uuid4()
    a = await store.begin(tenant, who, ROUTE, "k-fence", FP, principal_kind="user")
    await _age(admin, tenant, "k-fence", IN_PROGRESS_STALE_AFTER * 2)
    b = await store.begin(tenant, who, ROUTE, "k-fence", FP, principal_kind="user")
    assert isinstance(a, Fresh) and isinstance(b, Fresh) and a.claim_id != b.claim_id
    await store.complete(b.token, StoredResponse(201, {}, b'{"by":"b"}'))

    # A's handler transaction: a business write, then the fenced complete.
    with pytest.raises(IdempotencyClaimLost):
        async with kernel.tenant_tx(tenant) as conn:
            await PgOutboxWriter().emit(
                conn, tenant, OutboxMessage.for_event("policy_changed", "agent", uuid4())
            )
            await PgIdempotencyStore.complete_in(
                conn, a.token, StoredResponse(201, {}, b'{"by":"a"}')
            )
    replay = await store.begin(tenant, who, ROUTE, "k-fence", FP, principal_kind="user")
    assert isinstance(replay, Replay) and replay.response.body == b'{"by":"b"}'
    async with admin.transaction():
        await admin.execute("SELECT sibyl.set_tenant($1)", tenant)
        assert await admin.fetchval("SELECT count(*) FROM sibyl.outbox") == 0


async def test_late_abandon_does_not_expire_a_newer_live_claim(store, tenant, admin) -> None:
    who = uuid4()
    a = await store.begin(tenant, who, ROUTE, "k-abandon", FP, principal_kind="user")
    await _age(admin, tenant, "k-abandon", IN_PROGRESS_STALE_AFTER * 2)
    b = await store.begin(tenant, who, ROUTE, "k-abandon", FP, principal_kind="user")
    assert isinstance(b, Fresh)
    assert await store.abandon(a.token) is False
    assert isinstance(
        await store.begin(tenant, who, ROUTE, "k-abandon", FP, principal_kind="user"), InProgress
    )
    assert await store.abandon(b.token) is True
    assert isinstance(
        await store.begin(tenant, who, ROUTE, "k-abandon", FP, principal_kind="user"), Fresh
    )


@pytest.mark.parametrize(
    "body",
    [b'{"name":"a\\u0000b"}', b'{"k\\u0000":1}', b"\x00raw\xff"],
    ids=["value", "key", "raw"],
)
async def test_bodies_with_nul_do_not_fail_the_business_transaction(
    store, kernel, tenant, body
) -> None:
    who, key = uuid4(), f"k-nul-{secrets.token_hex(3)}"
    first = await store.begin(tenant, who, ROUTE, key, FP, principal_kind="api_key")
    async with kernel.tenant_tx(tenant) as conn:
        await PgIdempotencyStore.complete_in(conn, first.token, StoredResponse(200, {}, body))
    replay = await store.begin(tenant, who, ROUTE, key, FP, principal_kind="api_key")
    assert isinstance(replay, Replay) and replay.response.body == body


async def test_bodies_over_64_kb_keep_a_hash_and_cannot_be_replayed(store, tenant, admin) -> None:
    who = uuid4()
    big = b'{"blob":"' + b"y" * MAX_STORED_BODY_BYTES + b'"}'
    first = await store.begin(tenant, who, ROUTE, "k-big", FP, principal_kind="user")
    await store.complete(first.token, StoredResponse(201, {"etag": '"2"'}, big))
    outcome = await store.begin(tenant, who, ROUTE, "k-big", FP, principal_kind="user")
    assert isinstance(outcome, ReplayUnavailable)
    assert (outcome.status, outcome.headers) == (201, {"etag": '"2"'})
    size = await admin.fetchval(
        "SELECT octet_length(response_body::text) FROM sibyl.idempotency_record "
        "WHERE tenant_id = $1 AND idempotency_key = 'k-big'",
        tenant,
    )
    assert size < 256


async def test_concurrent_first_use_cannot_both_be_fresh(store, tenant, migrated) -> None:
    """Test review F9: a rival holds an uncommitted in-progress row; ``begin`` blocks on it and
    then sees ``InProgress``, never ``Fresh``."""
    who = uuid4()
    rival = await asyncpg.connect(_app_dsn(migrated))
    try:
        tx = rival.transaction()
        await tx.start()
        await rival.execute("SELECT sibyl.set_tenant($1)", tenant)
        await rival.execute(
            "INSERT INTO sibyl.idempotency_record (tenant_id, route, idempotency_key, "
            "principal_kind, principal_id, request_sha256, state, expires_at, claim_id) "
            "VALUES ($1, $2, 'k-race', 'user', $3, $4, 'in_progress', "
            "clock_timestamp() + interval '1 day', $5)",
            tenant,
            ROUTE,
            who,
            FP,
            uuid4(),
        )
        task = asyncio.ensure_future(
            store.begin(tenant, who, ROUTE, "k-race", FP, principal_kind="user")
        )
        for _ in range(500):  # poll for the lock wait; no sleep-as-assert
            waiting = await rival.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND wait_event_type = 'Lock'"
            )
            if waiting:
                break
            await asyncio.sleep(0.01)
        assert waiting, "begin() never blocked on the rival's row"
        assert not task.done()
        await tx.commit()
        outcome = await asyncio.wait_for(task, 5)
    finally:
        await rival.close()
    assert isinstance(outcome, InProgress)


async def test_parallel_first_uses_yield_exactly_one_fresh(store, tenant) -> None:
    who = uuid4()
    outcomes = await asyncio.gather(
        *(store.begin(tenant, who, ROUTE, "k-par", FP, principal_kind="user") for _ in range(8))
    )
    assert sum(isinstance(o, Fresh) for o in outcomes) == 1
    assert all(isinstance(o, Fresh | InProgress) for o in outcomes)
