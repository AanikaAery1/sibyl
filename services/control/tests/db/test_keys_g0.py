# ruff: noqa: S608 -- SQL fragments here are fixed test literals, never input
"""API keys cannot be widened in place (security LOW L3), failover rows attribute API-key
actors (ruling G0-6), and idempotency records carry a fencing claim and a 64 KB body cap
(ruling G0-8)."""

from __future__ import annotations

import json
import secrets
import uuid

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, h32, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "keys-g0")


def _key(admin: Conn, fx: TenantFixture) -> uuid.UUID:
    prefix = secrets.token_hex(6)
    with admin.tx(fx.tenant_id):
        return admin.fetchval(
            "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash, "
            "scopes, expires_at, created_by) VALUES ($1, $2, 'k', 'live', $3, $4, "
            "'{ingest:write,routing:read}', now() + interval '90 days', $5) RETURNING id",
            fx.tenant_id,
            fx.agent_a,
            prefix,
            h32(prefix),
            fx.owner,
        )


@pytest.mark.parametrize(
    "assignment",
    [
        "scopes = '{ingest:write,routing:read,agents:write}'",
        "scopes = '{agents:write}'",
        "agent_id = NULL",
        "agent_id = $3",
        "expires_at = expires_at + interval '1 day'",
        "prefix = 'AAAAAAAAAAAA'",
        "secret_hash = sha256('other')",
        "env = 'test'",
    ],
)
def test_app_cannot_widen_or_rebind_a_key_in_place(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture, assignment: str
) -> None:
    key = _key(admin, fx)
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError) as info:
        with app.tx(fx.tenant_id, rollback=True):
            app.execute(
                f"UPDATE sibyl.api_key SET {assignment} WHERE tenant_id = $1 AND id = $2",
                fx.tenant_id,
                key,
                *([fx.agent_b] if "$3" in assignment else []),
            )
    assert info.value.sqlstate in ("SB044", "42501"), info.value
    if info.value.sqlstate == "SB044":
        assert "sibyl:key_field_immutable" in str(info.value)


@pytest.mark.parametrize(
    "assignment",
    [
        "scopes = '{ingest:write}'",
        "expires_at = expires_at - interval '1 day'",
        "status = 'revoked', revoked_at = now(), revoke_reason = 'leak'",
        "name = 'renamed'",
        "last_used_at = now()",
    ],
)
def test_narrowing_and_lifecycle_updates_still_work(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture, assignment: str
) -> None:
    key = _key(admin, fx)
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        app.execute(
            f"UPDATE sibyl.api_key SET {assignment} WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            key,
        )


def test_key_lifetime_is_capped_at_400_days(admin: Conn, fx: TenantFixture) -> None:
    prefix = secrets.token_hex(6)
    with pytest.raises(asyncpg.CheckViolationError):
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(
                "INSERT INTO sibyl.api_key (tenant_id, name, env, prefix, secret_hash, scopes, "
                "expires_at) VALUES ($1, 'k', 'live', $2, $3, '{ingest:write}', "
                "now() + interval '20 years')",
                fx.tenant_id,
                prefix,
                h32(prefix),
            )


def _failover(conn: Conn, fx: TenantFixture, actor: str, key: uuid.UUID | None) -> None:
    conn.execute(
        "INSERT INTO sibyl.failover (tenant_id, agent_id, kind, state, idempotency_key, "
        "actor_kind, actor_key_id, from_state) "
        "VALUES ($1, $2, 'kill', 'done', $3, $4, $5, 'active')",
        fx.tenant_id,
        fx.agent_b,
        f"f:{uuid.uuid4()}",
        actor,
        key,
    )


def test_failover_records_the_acting_api_key(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture
) -> None:
    key = _key(admin, fx)
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        _failover(app, fx, "api_key", key)
    for actor, key_id in (("api_key", None), ("system", key)):
        with pytest.raises(asyncpg.CheckViolationError):
            with app.tx(fx.tenant_id, rollback=True):
                _failover(app, fx, actor, key_id)


INSERT_RECORD = (
    "INSERT INTO sibyl.idempotency_record (tenant_id, route, idempotency_key, principal_kind, "
    "principal_id, request_sha256) VALUES ($1, 'POST /x', $2, 'user', $3, $4) "
    "RETURNING claim_id"
)


def test_every_claim_gets_a_fencing_token(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        first = app.fetchval(INSERT_RECORD, fx.tenant_id, "c-1", fx.owner, h32("r"))
        second = app.fetchval(INSERT_RECORD, fx.tenant_id, "c-2", fx.owner, h32("r"))
        assert isinstance(first, uuid.UUID) and first != second
        with pytest.raises(asyncpg.NotNullViolationError):
            app.execute("SAVEPOINT s")
            app.execute(
                "UPDATE sibyl.idempotency_record SET claim_id = NULL WHERE tenant_id = $1 "
                "AND idempotency_key = 'c-1'",
                fx.tenant_id,
            )
        app.execute("ROLLBACK TO SAVEPOINT s")


@pytest.mark.parametrize(("size", "ok"), [(65536, True), (65537, False)])
def test_stored_response_body_is_capped_at_64kb_of_text(
    admin: Conn, roles: dict[str, Conn], fx: TenantFixture, size: int, ok: bool
) -> None:
    body = json.dumps("x" * (size - 2))
    assert len(body.encode()) == size
    app = roles["sibyl_app"]

    def complete() -> None:
        with app.tx(fx.tenant_id, rollback=True):
            app.fetchval(INSERT_RECORD, fx.tenant_id, f"b-{size}", fx.owner, h32("r"))
            app.execute(
                "UPDATE sibyl.idempotency_record SET state = 'done', status_code = 200, "
                "completed_at = now(), response_body = $3::jsonb WHERE tenant_id = $1 "
                "AND idempotency_key = $2",
                fx.tenant_id,
                f"b-{size}",
                body,
            )

    if ok:
        complete()
    else:
        with pytest.raises(asyncpg.CheckViolationError):
            complete()


def test_oversized_responses_can_be_stored_as_a_hash_only(
    roles: dict[str, Conn], fx: TenantFixture
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        app.fetchval(INSERT_RECORD, fx.tenant_id, "h-1", fx.owner, h32("r"))
        app.execute(
            "UPDATE sibyl.idempotency_record SET state = 'done', status_code = 200, "
            "completed_at = now(), response_body = NULL, response_body_sha256 = $2 "
            "WHERE tenant_id = $1 AND idempotency_key = 'h-1'",
            fx.tenant_id,
            h32("big body"),
        )
