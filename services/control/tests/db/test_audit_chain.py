"""(b) Per-tenant audit hash chain: integrity, independent verification, tamper detection,
append-only enforcement and audit_append() validation (DATAMODEL §7 gate 2, R11)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import asyncpg
import pytest
from sibyl_schemas.canonical import canonicalize as _canonical_bytes

from .conftest import LOGIN_ROLES, Conn
from .fixtures import create_tenant

ZERO = bytes(32)
APPEND = (
    "SELECT * FROM sibyl.audit_append($1, $2, $3, NULL, NULL, $4, $5, $6, NULL, $7, $8::jsonb, $9, "
    "now(), NULL)"
)


def canonicalize(value: Any) -> str:
    return _canonical_bytes(value, allow_floats=False).decode()


def _ts(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _u(value: Any) -> str | None:
    return None if value is None else str(value)


def python_verify(rows: list[asyncpg.Record]) -> tuple[bool, int | None, str | None]:
    """Independent re-implementation of the chain recipe (security-auditor §4)."""
    running = ZERO
    for expected, r in enumerate(rows):
        if r["seq"] != expected:
            return False, expected, "gap"
        if bytes(r["prev_hash"]) != running:
            return False, r["seq"], "prev_mismatch"
        envelope = canonicalize(
            {
                "action": r["action"],
                "actor_id": _u(r["actor_id"]),
                "actor_key_id": _u(r["actor_key_id"]),
                "actor_session_id": _u(r["actor_session_id"]),
                "actor_type": r["actor_type"],
                "chain_version": r["chain_version"],
                "occurred_at": _ts(r["occurred_at"]),
                "reason": r["reason"],
                "recorded_at": _ts(r["recorded_at"]),
                "request_id": _u(r["request_id"]),
                "resource_id": _u(r["resource_id"]),
                "resource_ref": r["resource_ref"],
                "resource_type": r["resource_type"],
                "seq": r["seq"],
                "tenant_id": _u(r["tenant_id"]),
            }
        )
        env_sha = hashlib.sha256(envelope.encode()).digest()
        detail_sha = hashlib.sha256(canonicalize(json.loads(r["detail"])).encode()).digest()
        if env_sha != bytes(r["envelope_sha256"]) or detail_sha != bytes(r["detail_sha256"]):
            return False, r["seq"], "content_mismatch"
        if hashlib.sha256(running + env_sha + detail_sha).digest() != bytes(r["hash"]):
            return False, r["seq"], "hash_mismatch"
        running = bytes(r["hash"])
    return True, None, None


@pytest.fixture(scope="module")
def chain(admin: Conn, roles: dict[str, Conn]) -> uuid.UUID:
    tenant = create_tenant(admin, "audit-chain")
    app = roles["sibyl_app"]
    user = uuid.uuid4()
    with app.tx(tenant):
        for i in range(5):
            detail = {"field": f"f{i}", "before": "a", "after": 'b ü \u0001 "q"'}
            app.fetchrow(
                APPEND,
                tenant,
                "human",
                user,
                "config.changed",
                "tenant",
                tenant,
                "ops change",
                json.dumps(detail),
                canonicalize(detail).encode(),
            )
        app.fetchrow(
            APPEND,
            tenant,
            "system",
            None,
            "audit.verified",
            "tenant",
            tenant,
            None,
            json.dumps({"from_seq": 0, "to_seq": 5, "anchors_checked": 0}),
            None,
        )
    return tenant


def _rows(admin: Conn, tenant: uuid.UUID) -> list[asyncpg.Record]:
    return admin.fetch("SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 ORDER BY seq", tenant)


def _db_verify(admin: Conn, tenant: uuid.UUID) -> asyncpg.Record:
    with admin.tx(tenant, rollback=True):
        return admin.fetchrow("SELECT * FROM sibyl.audit_verify($1)", tenant)


def test_chain_is_gapless_and_verifies_both_ways(admin: Conn, chain: uuid.UUID) -> None:
    rows = _rows(admin, chain)
    assert [r["seq"] for r in rows] == list(range(len(rows)))
    assert rows[0]["action"] == "audit.genesis" and bytes(rows[0]["prev_hash"]) == ZERO
    assert python_verify(rows) == (True, None, None)
    result = _db_verify(admin, chain)
    assert result["ok"] and result["rows_checked"] == len(rows)


def test_caller_canonical_bytes_are_hashed(admin: Conn, chain: uuid.UUID) -> None:
    row = admin.fetchrow(
        "SELECT detail, detail_sha256 FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = 5",
        chain,
    )
    detail = json.loads(row["detail"])
    assert bytes(row["detail_sha256"]) == hashlib.sha256(canonicalize(detail).encode()).digest()


def _tamper(admin: Conn, sql: str, *args: Any) -> None:
    with admin.tx():
        admin.execute("SET LOCAL session_replication_role = replica")
        admin.execute(sql, *args)


def test_edited_detail_is_content_mismatch(admin: Conn, roles: dict[str, Conn]) -> None:
    tenant = create_tenant(admin, "audit-tamper-detail")
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET detail = jsonb_set(detail, '{slug}', '\"evil\"') "
        "WHERE tenant_id = $1 AND seq = 4",
        tenant,
    )
    result = _db_verify(admin, tenant)
    assert (result["ok"], result["first_break_seq"], result["kind"]) == (
        False,
        4,
        "content_mismatch",
    )
    assert python_verify(_rows(admin, tenant)) == (False, 4, "content_mismatch")


def test_edited_envelope_is_content_mismatch(admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-tamper-envelope")
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET resource_ref = 'x' WHERE tenant_id = $1 AND seq = 2",
        tenant,
    )
    assert _db_verify(admin, tenant)["kind"] == "content_mismatch"


def test_deleted_row_is_gap(admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-tamper-gap")
    _tamper(admin, "DELETE FROM sibyl.audit_events WHERE tenant_id = $1 AND seq = 2", tenant)
    result = _db_verify(admin, tenant)
    assert (result["first_break_seq"], result["kind"]) == (2, "gap")
    assert python_verify(_rows(admin, tenant))[2] == "gap"


def test_rewritten_hash_is_detected(admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-tamper-hash")
    _tamper(
        admin,
        "UPDATE sibyl.audit_events SET hash = sha256('x') WHERE tenant_id = $1 AND seq = 1",
        tenant,
    )
    result = _db_verify(admin, tenant)
    assert result["kind"] in {"hash_mismatch", "prev_mismatch"} and result["first_break_seq"] in {
        1,
        2,
    }


@pytest.mark.parametrize("role", LOGIN_ROLES)
def test_login_roles_cannot_write_audit_tables(
    roles: dict[str, Conn], chain: uuid.UUID, role: str
) -> None:
    conn = roles[role]
    statements = [
        "UPDATE sibyl.audit_events SET reason = 'x'",
        "DELETE FROM sibyl.audit_events",
        "TRUNCATE sibyl.audit_events",
        "UPDATE sibyl.audit_anchors SET external_ref = 'x'",
        "DELETE FROM sibyl.audit_anchors",
        "TRUNCATE sibyl.audit_anchors",
        "INSERT INTO sibyl.audit_events (tenant_id, recorded_at, seq, actor_type, action, "
        "resource_type, "
        "severity, detail, detail_sha256, envelope_sha256, prev_hash, hash, is_evidence) "
        "SELECT tenant_id, now(), 99, actor_type, action, resource_type, severity, detail, "
        "detail_sha256, "
        "envelope_sha256, prev_hash, hash, is_evidence FROM sibyl.audit_events LIMIT 1",
    ]
    for sql in statements:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            with conn.tx(chain, rollback=True):
                conn.execute(sql)


def test_owner_is_blocked_by_trigger(admin: Conn, chain: uuid.UUID) -> None:
    for sql in (
        "UPDATE sibyl.audit_events SET reason = 'x' WHERE tenant_id = $1",
        "DELETE FROM sibyl.audit_events WHERE tenant_id = $1",
    ):
        with pytest.raises(asyncpg.PostgresError, match="sibyl:immutable_row"):
            with admin.tx(chain, rollback=True):
                admin.execute("SET LOCAL ROLE sibyl_audit")
                admin.execute(sql, chain)
    with pytest.raises(asyncpg.PostgresError, match="sibyl:immutable_row"):
        with admin.tx(chain, rollback=True):
            admin.execute("SET LOCAL ROLE sibyl_audit")
            admin.execute("TRUNCATE sibyl.audit_events")


def _append_error(app: Conn, tenant_ctx: uuid.UUID, *args: Any) -> str:
    with pytest.raises(asyncpg.PostgresError) as info:
        with app.tx(tenant_ctx, rollback=True):
            app.fetchrow(APPEND, *args)
    return str(info.value)


def test_append_validation(roles: dict[str, Conn], chain: uuid.UUID, admin: Conn) -> None:
    app = roles["sibyl_app"]
    other = create_tenant(admin, "audit-other")
    user = uuid.uuid4()
    ok_detail = json.dumps({"field": "x", "before": "a", "after": "b"})
    assert "sibyl:tenant_mismatch" in _append_error(
        app, other, chain, "human", user, "config.changed", "tenant", chain, "r", ok_detail, None
    )
    assert "sibyl:audit_action_unknown" in _append_error(
        app, chain, chain, "human", user, "made.up", "tenant", chain, "r", ok_detail, None
    )
    assert "sibyl:audit_actor_not_allowed" in _append_error(
        app, chain, chain, "agent", user, "config.changed", "tenant", chain, "r", ok_detail, None
    )
    assert "sibyl:audit_field_missing" in _append_error(
        app,
        chain,
        chain,
        "human",
        user,
        "config.changed",
        "tenant",
        chain,
        "r",
        json.dumps({"field": "x"}),
        None,
    )
    assert "sibyl:reason_required" in _append_error(
        app, chain, chain, "human", user, "config.changed", "tenant", chain, None, ok_detail, None
    )
    assert "sibyl:audit_detail_invalid" in _append_error(
        app,
        chain,
        chain,
        "human",
        user,
        "config.changed",
        "tenant",
        chain,
        "r",
        json.dumps({"field": "x", "before": "a", "after": "b", "prompt": "secret"}),
        None,
    )
    assert "sibyl:audit_canonical_mismatch" in _append_error(
        app,
        chain,
        chain,
        "human",
        user,
        "config.changed",
        "tenant",
        chain,
        "r",
        ok_detail,
        b'{"after":"z","before":"a","field":"x"}',
    )
    assert "sibyl:audit_detail_invalid" in _append_error(
        app,
        chain,
        chain,
        "system",
        None,
        "audit.verified",
        "tenant",
        chain,
        None,
        json.dumps({"from_seq": 0.5, "to_seq": 1, "anchors_checked": 0}),
        None,
    )
    assert "sibyl:audit_chain_genesis" in _append_error(
        app,
        chain,
        chain,
        "system",
        None,
        "audit.genesis",
        "tenant",
        chain,
        None,
        json.dumps({"chain_version": 1}),
        None,
    )


def test_concurrent_appends_stay_gapless(db: Any, admin: Conn) -> None:
    tenant = create_tenant(admin, "audit-concurrent")
    first, second = db.connect("sibyl_worker"), db.connect("sibyl_worker")
    try:
        detail = json.dumps({"date_prefix": "d", "objects": 1, "bytes": 1, "holds_skipped": 0})
        tx1 = first.raw.transaction()
        first.run(tx1.start())
        first.execute("SELECT sibyl.set_tenant($1)", tenant)
        first.fetchrow(
            APPEND,
            tenant,
            "system",
            None,
            "retention.objects_swept",
            "tenant",
            tenant,
            None,
            detail,
            None,
        )
        tx2 = second.raw.transaction()
        second.run(tx2.start())
        second.execute("SELECT sibyl.set_tenant($1)", tenant)
        second.execute("SET LOCAL lock_timeout = '200ms'")
        with pytest.raises(asyncpg.LockNotAvailableError):
            second.fetchrow(
                APPEND,
                tenant,
                "system",
                None,
                "retention.objects_swept",
                "tenant",
                tenant,
                None,
                detail,
                None,
            )
        second.run(tx2.rollback())
        first.run(tx1.commit())
    finally:
        first.close()
        second.close()
    assert python_verify(_rows(admin, tenant))[0]
