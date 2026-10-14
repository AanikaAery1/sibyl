"""Chair ruling G0-2: the kernel's Postgres idempotency store against the real migrated table.

``sibyl.idempotency_record`` (0011_lifecycle): column ``idempotency_key``, ``principal_kind``,
``status_code``, ``response_body jsonb``, ``completed_at``; not partitioned; the app role has
SELECT/INSERT/UPDATE only (DELETE belongs to the retention worker). Runs as ``sibyl_app`` under
RLS through the kernel's own ``Database``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.db import Database as KernelDatabase
from sibyl_control.core.idempotency import (
    IN_PROGRESS_STALE_AFTER,
    ForeignKey,
    Fresh,
    InProgress,
    Mismatch,
    PgIdempotencyStore,
    Replay,
    StoredResponse,
    fingerprint,
)

from .conftest import Conn
from .fixtures import create_tenant

ROUTE = "POST /api/v1/agents"


def _fp(body: bytes) -> bytes:
    """The kernel fingerprint binds method, path and query as well as the body (FIX-KER)."""
    return fingerprint(body, method="POST", path="/api/v1/agents", query="")


@pytest.fixture(scope="module")
def tenant(admin: Conn) -> UUID:
    return create_tenant(admin, "idempotency")


@pytest.fixture
def store(kernel_db: KernelDatabase) -> PgIdempotencyStore:
    return PgIdempotencyStore(kernel_db)


def run(loop: asyncio.AbstractEventLoop, coro: Any) -> Any:
    return loop.run_until_complete(coro)


def test_first_use_complete_then_replay(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, admin: Conn, tenant: UUID
) -> None:
    principal, fp = uuid4(), _fp(b'{"name":"a"}')
    first = run(loop, store.begin(tenant, principal, ROUTE, "k-replay", fp, principal_kind="user"))
    assert isinstance(first, Fresh)
    body = json.dumps({"id": "a", "tags": ["x"], "n": 1}).encode()
    headers = {"content-type": "application/json", "etag": '"1"', "content-length": "40"}
    run(loop, store.complete(first.token, StoredResponse(201, headers, body)))
    replay = run(loop, store.begin(tenant, principal, ROUTE, "k-replay", fp, principal_kind="user"))
    assert isinstance(replay, Replay)
    assert replay.response.status == 201
    assert replay.response.headers == {"content-type": "application/json", "etag": '"1"'}
    assert json.loads(replay.response.body) == {"id": "a", "tags": ["x"], "n": 1}
    row = admin.fetchrow(
        "SELECT idempotency_key, principal_kind, principal_id, state, status_code, completed_at "
        "FROM sibyl.idempotency_record WHERE tenant_id = $1 AND route = $2",
        tenant,
        ROUTE,
    )
    assert row["idempotency_key"] == "k-replay" and row["principal_kind"] == "user"
    assert row["principal_id"] == principal and row["state"] == "done"
    assert row["status_code"] == 201 and row["completed_at"] is not None


def test_mismatch_foreign_principal_and_in_progress(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, tenant: UUID
) -> None:
    principal, fp = uuid4(), _fp(b'{"a":1}')
    assert isinstance(
        run(loop, store.begin(tenant, principal, ROUTE, "k-states", fp, principal_kind="user")),
        Fresh,
    )
    again = run(loop, store.begin(tenant, principal, ROUTE, "k-states", fp, principal_kind="user"))
    assert isinstance(again, InProgress)
    other_body = run(
        loop, store.begin(tenant, principal, ROUTE, "k-states", _fp(b"{}"), principal_kind="user")
    )
    assert isinstance(other_body, Mismatch)
    other_principal = run(
        loop, store.begin(tenant, uuid4(), ROUTE, "k-states", fp, principal_kind="user")
    )
    assert isinstance(other_principal, ForeignKey)


def test_abandon_frees_the_key_without_delete_privilege(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, tenant: UUID
) -> None:
    principal, fp = uuid4(), _fp(b'{"b":1}')
    first = run(loop, store.begin(tenant, principal, ROUTE, "k-abandon", fp, principal_kind="user"))
    assert run(loop, store.abandon(first.token)) is True
    assert isinstance(
        run(loop, store.begin(tenant, principal, ROUTE, "k-abandon", fp, principal_kind="user")),
        Fresh,
    )


def test_expired_and_stale_records_are_reused(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, admin: Conn, tenant: UUID
) -> None:
    principal, fp = uuid4(), _fp(b'{"c":1}')
    first = run(loop, store.begin(tenant, principal, ROUTE, "k-expired", fp, principal_kind="user"))
    run(loop, store.complete(first.token, StoredResponse(200, {}, b'{"ok":true}')))
    with admin.tx():
        admin.execute(
            "UPDATE sibyl.idempotency_record SET created_at = now() - interval '2 days', "
            "expires_at = now() - interval '1 day' WHERE tenant_id = $1 AND idempotency_key = $2",
            tenant,
            "k-expired",
        )
    fresh = run(
        loop, store.begin(tenant, uuid4(), ROUTE, "k-expired", _fp(b"{}"), principal_kind="user")
    )
    assert isinstance(fresh, Fresh)
    run(loop, store.begin(tenant, principal, ROUTE, "k-stale", fp, principal_kind="user"))
    stale = IN_PROGRESS_STALE_AFTER * 2
    with admin.tx():
        admin.execute(
            "UPDATE sibyl.idempotency_record SET created_at = now() - $3::interval "
            "WHERE tenant_id = $1 AND idempotency_key = $2",
            tenant,
            "k-stale",
            stale,
        )
    assert isinstance(
        run(loop, store.begin(tenant, principal, ROUTE, "k-stale", fp, principal_kind="user")),
        Fresh,
    )


def test_non_json_and_empty_bodies_round_trip(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, tenant: UUID
) -> None:
    principal = uuid4()
    for key, body in (("k-text", b"\x00binary\xffbody"), ("k-empty", b"")):
        fp = _fp(key.encode())
        first = run(loop, store.begin(tenant, principal, ROUTE, key, fp, principal_kind="user"))
        run(loop, store.complete(first.token, StoredResponse(202, {"x-a": "1"}, body)))
        replay = run(loop, store.begin(tenant, principal, ROUTE, key, fp, principal_kind="user"))
        assert replay.response == StoredResponse(202, {"x-a": "1"}, body)


def test_complete_in_the_handler_transaction_and_api_key_principals(
    store: PgIdempotencyStore,
    kernel_db: KernelDatabase,
    loop: asyncio.AbstractEventLoop,
    admin: Conn,
    tenant: UUID,
) -> None:
    key_id, fp = uuid4(), _fp(b'{"d":1}')
    first = run(loop, store.begin(tenant, key_id, ROUTE, "k-key", fp, principal_kind="api_key"))

    async def handler() -> None:
        async with kernel_db.tenant_tx(tenant) as conn:
            await PgIdempotencyStore.complete_in(conn, first.token, StoredResponse(201, {}, b"[]"))

    run(loop, handler())
    assert isinstance(
        run(loop, store.begin(tenant, key_id, ROUTE, "k-key", fp, principal_kind="api_key")), Replay
    )
    assert (
        admin.fetchval(
            "SELECT principal_kind FROM sibyl.idempotency_record WHERE tenant_id = $1 "
            "AND idempotency_key = 'k-key'",
            tenant,
        )
        == "api_key"
    )


def test_records_are_tenant_isolated(
    store: PgIdempotencyStore, loop: asyncio.AbstractEventLoop, admin: Conn, tenant: UUID
) -> None:
    other = create_tenant(admin, "idempotency-other")
    principal, fp = uuid4(), _fp(b'{"e":1}')
    run(loop, store.begin(tenant, principal, ROUTE, "k-shared", fp, principal_kind="user"))
    assert isinstance(
        run(loop, store.begin(other, principal, ROUTE, "k-shared", fp, principal_kind="user")),
        Fresh,
    )


def test_table_is_not_partitioned(admin: Conn) -> None:
    assert (
        admin.fetchval(
            "SELECT relkind::text FROM pg_class WHERE oid = 'sibyl.idempotency_record'::regclass"
        )
        == "r"
    )
