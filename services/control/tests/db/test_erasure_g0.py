# ruff: noqa: S608 -- SQL identifiers here come from pg_catalog or fixed literals, never from input
"""G0 erasure fixes: four-eyes and legal holds enforced in the database (security M1),
complete removal of personal data with a keyed pseudonym (H2), chain tombstones (G0-7),
subject scope, the signed erasure ledger and its re-application (H1), and agent-scope
completeness over a fixture where both agents carry data (tests F3)."""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import asyncpg
import pytest
from sibyl_control.migrate import ledger

from .conftest import Conn, Database
from .fixtures import TenantFixture, h32, new_id, populate_tenant, tenant_tables
from .test_erasure import KEEP, _name_as_backup, _transition

SIGNING_KEY = ledger.generate_signing_key()
PUBLIC_KEY = ledger.public_key_of(SIGNING_KEY)
ERASED_EMAIL = r"^erased\+[0-9a-f]{64}@invalid$"
ERASED_SUBJECT = r"^erased:[0-9a-f]{64}$"


def _slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


def _insert_request(
    app: Conn, fx: TenantFixture, scope: str, ref: str | None, **extra: Any
) -> uuid.UUID:
    columns = ["tenant_id", "scope_kind", "scope_ref", "legal_basis", "requested_by", *extra]
    values = [fx.tenant_id, scope, ref, "gdpr_art17", fx.owner, *extra.values()]
    placeholders = ", ".join(
        f"${i}::jsonb" if c == "affected_objects" else f"${i}"
        for i, c in enumerate(columns, start=1)
    )
    return app.fetchval(
        f"INSERT INTO sibyl.erasure_request ({', '.join(columns)}) VALUES ({placeholders}) "
        "RETURNING id",
        *values,
    )


def _approve(app: Conn, fx: TenantFixture, request: uuid.UUID) -> None:
    app.execute("SET LOCAL app.transition_trigger = 'approve'")
    app.execute(
        "UPDATE sibyl.erasure_request SET state = 'approved', approved_by = $3, "
        "approved_at = now() WHERE tenant_id = $1 AND id = $2",
        fx.tenant_id,
        request,
        fx.approver,
    )


def _approved(
    roles: dict[str, Conn], fx: TenantFixture, scope: str, ref: str | None, **extra: Any
) -> uuid.UUID:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id):
        request = _insert_request(app, fx, scope, ref, **extra)
        _approve(app, fx, request)
    return request


def _executing(
    roles: dict[str, Conn], fx: TenantFixture, scope: str, ref: str | None, **extra: Any
) -> uuid.UUID:
    request = _approved(roles, fx, scope, ref, **extra)
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _transition(worker, fx.tenant_id, request, "executing")
    return request


def _run_phases(worker: Conn, fx: TenantFixture, request: uuid.UUID) -> list[Any]:
    with worker.tx(fx.tenant_id):
        out = [
            worker.fetchval("SELECT sibyl.erasure_execute_phase($1, $2)", request, phase)
            for phase in ("objects_deleted", "derived_purged")
        ]
    return [json.loads(o) for o in out]


def _error(conn: Conn, tenant: uuid.UUID, sql: str, *args: Any) -> asyncpg.PostgresError:
    with pytest.raises(asyncpg.PostgresError) as info:
        with conn.tx(tenant, rollback=True):
            conn.execute(sql, *args)
    return info.value


# --- four-eyes in the database (security M1) ---------------------------------------------


@pytest.fixture(scope="module")
def guard_fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "erase-guard")


@pytest.mark.parametrize(
    "state", ["approved", "executing", "keys_shredded", "objects_deleted", "completed"]
)
def test_a_request_cannot_be_inserted_past_requested(
    roles: dict[str, Conn], guard_fx: TenantFixture, state: str
) -> None:
    fx = guard_fx
    err = _error(
        roles["sibyl_app"],
        fx.tenant_id,
        "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, legal_basis, requested_by, "
        "state, approved_by, approved_at) VALUES ($1, 'tenant', 'gdpr_art17', $2, $3, $4, now())",
        fx.tenant_id,
        fx.owner,
        state,
        fx.approver,
    )
    assert err.sqlstate == "SB035" and "sibyl:erasure_not_approved" in str(err), err


def test_moving_to_approved_or_executing_needs_the_approval_fields(
    roles: dict[str, Conn], guard_fx: TenantFixture
) -> None:
    fx = guard_fx
    app = roles["sibyl_app"]
    for assignment in (
        "state = 'approved'",
        "state = 'approved', approved_by = $3",
        "state = 'approved', approved_at = now()",
    ):
        with pytest.raises(asyncpg.PostgresError) as info:
            with app.tx(fx.tenant_id, rollback=True):
                request = _insert_request(app, fx, "tenant", None)
                app.execute("SET LOCAL app.transition_trigger = 'approve'")
                app.execute(
                    f"UPDATE sibyl.erasure_request SET {assignment} WHERE tenant_id = $1 "
                    "AND id = $2",
                    fx.tenant_id,
                    request,
                    *([fx.approver] if "$3" in assignment else []),
                )
        assert info.value.sqlstate == "SB035", (assignment, info.value)


def test_approval_cannot_be_withdrawn_on_the_way_to_executing(
    roles: dict[str, Conn], guard_fx: TenantFixture
) -> None:
    fx = guard_fx
    request = _approved(roles, fx, "tenant", None)
    worker = roles["sibyl_worker"]
    with pytest.raises(asyncpg.PostgresError) as info:
        with worker.tx(fx.tenant_id, rollback=True):
            _transition(worker, fx.tenant_id, request, "executing", ", approved_by = NULL")
    assert info.value.sqlstate == "SB035", info.value


def test_a_request_without_a_requester_cannot_be_approved(
    roles: dict[str, Conn], guard_fx: TenantFixture
) -> None:
    fx = guard_fx
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError) as info:
        with app.tx(fx.tenant_id, rollback=True):
            request = app.fetchval(
                "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, legal_basis) "
                "VALUES ($1, 'tenant', 'gdpr_art17') RETURNING id",
                fx.tenant_id,
            )
            _approve(app, fx, request)
    assert info.value.sqlstate == "SB035", info.value


def test_login_roles_cannot_mark_a_request_as_restored(
    roles: dict[str, Conn], guard_fx: TenantFixture
) -> None:
    fx = guard_fx
    err = _error(
        roles["sibyl_app"],
        fx.tenant_id,
        "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, legal_basis, origin, state) "
        "VALUES ($1, 'tenant', 'other', 'restore', 'executing')",
        fx.tenant_id,
    )
    assert err.sqlstate == "SB035", err


def test_the_request_row_is_locked_while_a_phase_runs(
    db: Database, admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-lock"))
    request = _executing(roles, fx, "agent", str(fx.agent_b))

    async def scenario() -> None:
        worker = await asyncpg.connect(**db.spec("sibyl_worker").kwargs())
        rival = await asyncpg.connect(**db.spec("sibyl_app").kwargs())
        try:
            tx = worker.transaction()
            await tx.start()
            await worker.execute("SELECT sibyl.set_tenant($1)", fx.tenant_id)
            await worker.fetchval(
                "SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", request
            )
            async with rival.transaction():
                await rival.execute("SELECT sibyl.set_tenant($1)", fx.tenant_id)
                with pytest.raises(asyncpg.LockNotAvailableError):
                    await rival.execute(
                        "SELECT 1 FROM sibyl.erasure_request WHERE tenant_id = $1 AND id = $2 "
                        "FOR UPDATE NOWAIT",
                        fx.tenant_id,
                        request,
                    )
            await tx.rollback()
        finally:
            await worker.close()
            await rival.close()

    db.loop.run_until_complete(asyncio.wait_for(scenario(), 20))


# --- legal holds in the database (security M1) -------------------------------------------


def _hold(
    admin: Conn,
    fx: TenantFixture,
    scope: str,
    ref: str | None,
    agents: list[uuid.UUID],
    expires: str | None = None,
) -> None:
    with admin.tx(fx.tenant_id):
        admin.execute(
            "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, scope_ref, agent_ids, "
            "window_from, reason, placed_by, expires_at) VALUES ($1, $2, $3, $4, "
            "now() - interval '1 day', 'litigation', $5, $6::timestamptz)",
            fx.tenant_id,
            scope,
            ref,
            agents,
            fx.approver,
            expires,
        )


def _held_counts(admin: Conn, fx: TenantFixture) -> dict[str, int]:
    return {
        t: admin.fetchval(f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1", fx.tenant_id)
        for t in tenant_tables(admin)
    }


@pytest.mark.parametrize(
    "hold",
    [
        ("agent", "B", ["B"]),
        ("incident", None, ["B"]),
        ("subject", "subject-hash", ["B"]),
        ("tenant", None, []),
    ],
)
def test_an_active_hold_on_the_scope_refuses_every_phase(
    admin: Conn, roles: dict[str, Conn], hold: tuple[str, str | None, list[str]]
) -> None:
    fx = populate_tenant(admin, _slug("erase-held-agent"))
    scope, ref, agents = hold
    b = fx.agent_b
    if scope == "incident":
        with admin.tx(fx.tenant_id):
            incident = admin.fetchval(
                "SELECT id FROM sibyl.provider_incident WHERE tenant_id = $1 LIMIT 1", fx.tenant_id
            )
            admin.execute(
                "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, provider_incident_id, "
                "agent_ids, window_from, reason) VALUES ($1, 'incident', $2, $3, now(), 'x')",
                fx.tenant_id,
                incident,
                [b],
            )
    else:
        _hold(admin, fx, scope, str(b) if ref == "B" else ref, [b for _ in agents])
    request = _executing(roles, fx, "agent", str(b))
    before = _held_counts(admin, fx)
    worker = roles["sibyl_worker"]
    for phase in ("objects_deleted", "derived_purged"):
        err = _error(
            worker, fx.tenant_id, "SELECT sibyl.erasure_execute_phase($1, $2)", request, phase
        )
        assert err.sqlstate == "SB032" and "sibyl:legal_hold_active" in str(err), err
    assert _held_counts(admin, fx) == before, "nothing held was purged"


def test_holds_on_other_agents_or_expired_holds_do_not_block(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-unheld"))
    _hold(admin, fx, "agent", str(fx.agent_a), [fx.agent_a])
    with admin.tx(fx.tenant_id):
        admin.execute(
            "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, scope_ref, agent_ids, "
            "window_from, reason, placed_at, expires_at) VALUES ($1, 'agent', $2, $3, "
            "now() - interval '3 days', 'old', now() - interval '2 days', "
            "now() - interval '1 day')",
            fx.tenant_id,
            str(fx.agent_b),
            [fx.agent_b],
        )
    request = _executing(roles, fx, "agent", str(fx.agent_b))
    _run_phases(roles["sibyl_worker"], fx, request)


def test_tenant_shred_and_phases_refuse_under_any_active_hold(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-held-tenant"))
    request = _executing(roles, fx, "tenant", None)
    _hold(admin, fx, "agent", str(fx.agent_a), [fx.agent_a])
    worker = roles["sibyl_worker"]
    for sql in (
        "SELECT sibyl.tenant_key_shred($1)",
        "SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')",
    ):
        assert _error(worker, fx.tenant_id, sql, request).sqlstate == "SB032"


# --- personal data on tenant erasure (security H2) ---------------------------------------


def _former_employee(admin: Conn, fx: TenantFixture) -> uuid.UUID:
    """Deprovisioned before the erasure and still an audit actor (the reviewer's fixture)."""
    user = new_id()
    with admin.tx(fx.tenant_id):
        issuer = admin.fetchval(
            "SELECT oidc_issuer_id FROM sibyl.app_user WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            fx.owner,
        )
        admin.execute(
            "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email, "
            "display_name, status, last_login_at) VALUES ($1, $2, $3, 'sub-alice', "
            "'alice.former@victim.example', 'Alice Former', 'deprovisioned', now())",
            fx.tenant_id,
            user,
            issuer,
        )
        admin.fetchrow(
            "SELECT * FROM sibyl.audit_append($1, 'human', $2, NULL, NULL, 'config.changed', "
            "'tenant', $1, NULL, 'old change', $3::jsonb, NULL, now(), NULL)",
            fx.tenant_id,
            user,
            json.dumps({"field": "x", "before": "a", "after": "b"}),
        )
    return user


def _erase_tenant(admin: Conn, roles: dict[str, Conn], fx: TenantFixture) -> uuid.UUID:
    request = _executing(roles, fx, "tenant", None)
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        worker.execute("UPDATE sibyl.tenant SET status = 'erasing' WHERE id = $1", fx.tenant_id)
        worker.fetchval("SELECT sibyl.tenant_key_shred($1)", request)
        _transition(worker, fx.tenant_id, request, "keys_shredded")
        worker.fetchval("SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", request)
        _transition(worker, fx.tenant_id, request, "objects_deleted")
        worker.fetchval("SELECT sibyl.erasure_execute_phase($1, 'derived_purged')", request)
        _transition(worker, fx.tenant_id, request, "derived_purged")
    return request


def test_tenant_erasure_leaves_no_personal_data_in_any_user_row(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-pii"))
    alice = _former_employee(admin, fx)
    emails = {
        r["email"]
        for r in admin.fetch(
            "SELECT email::text FROM sibyl.app_user WHERE tenant_id = $1", fx.tenant_id
        )
    }
    request = _erase_tenant(admin, roles, fx)
    rows = admin.fetch("SELECT * FROM sibyl.app_user WHERE tenant_id = $1", fx.tenant_id)
    assert alice in {r["id"] for r in rows}, "the audit actor row survives, anonymised"
    for r in rows:
        assert admin.fetchval("SELECT $1::text ~ $2", r["email"], ERASED_EMAIL), r["email"]
        assert admin.fetchval("SELECT $1::text ~ $2", r["subject"], ERASED_SUBJECT), r["subject"]
        assert r["display_name"] is None and r["last_login_at"] is None
    dump = admin.fetchval(
        "SELECT string_agg(to_jsonb(u)::text, '') FROM sibyl.app_user u WHERE tenant_id = $1",
        fx.tenant_id,
    )
    for needle in [*emails, "sub-alice", "Alice Former", f"{fx.slug}-owner"]:
        assert needle not in dump, needle
    unsalted = admin.fetchval(
        "SELECT encode(sha256(convert_to('alice.former@victim.example', 'UTF8')), 'hex')"
    )
    assert unsalted not in dump, "the pseudonym must be keyed, not a dictionary-attackable hash"
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.tenant_pseudonym_key WHERE tenant_id = $1 "
            "AND (hmac_key IS NOT NULL OR shredded_at IS NULL)",
            fx.tenant_id,
        )
        == 0
    )
    with roles["sibyl_worker"].tx(fx.tenant_id, rollback=True):
        assert roles["sibyl_worker"].fetch("SELECT * FROM sibyl.erasure_residue($1)", request) == []


@pytest.mark.parametrize(
    "leak",
    [
        "email = 'alice@victim.example'",
        "display_name = 'Alice'",
        "subject = 'sub-alice'",
        "last_login_at = now()",
    ],
)
def test_residue_detects_any_surviving_personal_field(
    admin: Conn, roles: dict[str, Conn], leak: str
) -> None:
    fx = populate_tenant(admin, _slug("erase-residue"))
    request = _erase_tenant(admin, roles, fx)
    with admin.tx(fx.tenant_id):
        admin.execute(
            f"UPDATE sibyl.app_user SET {leak} WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            fx.owner,
        )
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        residue = {
            r["table_name"]
            for r in worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request)
        }
    assert "app_user" in residue


def test_residue_detects_an_unshredded_pseudonym_key(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, _slug("erase-residue-key"))
    request = _erase_tenant(admin, roles, fx)
    with admin.tx(fx.tenant_id):
        admin.execute(
            "UPDATE sibyl.tenant_pseudonym_key SET hmac_key = $2, shredded_at = NULL "
            "WHERE tenant_id = $1",
            fx.tenant_id,
            h32("resurrected"),
        )
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        residue = {
            r["table_name"]
            for r in worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request)
        }
    assert "tenant_pseudonym_key" in residue


def test_pseudonyms_are_keyed_per_tenant_and_the_key_is_not_readable(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    one = populate_tenant(admin, _slug("pseudo-1"))
    two = populate_tenant(admin, _slug("pseudo-2"))
    app = roles["sibyl_app"]
    values = []
    for fx in (one, two):
        with app.tx(fx.tenant_id, rollback=True):
            values.append(app.fetchval("SELECT sibyl.pseudonymise('Alice@Example.com')"))
            assert app.fetchval("SELECT sibyl.pseudonymise('alice@example.com')") == values[-1]
            with pytest.raises(asyncpg.InsufficientPrivilegeError):
                app.execute("SAVEPOINT s")
                app.fetchval("SELECT hmac_key FROM sibyl.tenant_pseudonym_key")
            app.execute("ROLLBACK TO SAVEPOINT s")
    assert values[0] != values[1]
    assert all(len(v) == 64 for v in values)


# --- chains (ruling G0-7) -----------------------------------------------------------------


def test_an_agent_referenced_only_by_a_retired_chain_is_erasable_and_tombstoned(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-retired"))
    chain = _name_as_backup(admin, fx, fx.agent_a)
    with admin.tx(fx.tenant_id):
        admin.execute(
            "UPDATE sibyl.fallback_chain SET status = 'retired', retired_at = now() "
            "WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            chain,
        )
    request = _executing(roles, fx, "agent", str(fx.agent_a))
    _run_phases(roles["sibyl_worker"], fx, request)
    step = admin.fetchrow(
        "SELECT kind, backup_agent_id, target_erased FROM sibyl.fallback_step "
        "WHERE tenant_id = $1 AND chain_id = $2 AND position = 0",
        fx.tenant_id,
        chain,
    )
    assert dict(step) == {"kind": "backup_agent", "backup_agent_id": None, "target_erased": True}
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            fx.agent_a,
        )
        == 0
    )


def test_a_draft_chain_is_tombstoned_and_can_no_longer_be_approved(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-draft"))
    chain = uuid.uuid4()
    with admin.tx(fx.tenant_id):
        admin.execute(
            "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no, "
            "requested_by_user_id) VALUES ($1, $2, $3, 7, $4)",
            fx.tenant_id,
            chain,
            fx.agent_b,
            fx.owner,
        )
        for position, kind, agent in ((0, "backup_agent", fx.agent_a), (1, "human_queue", None)):
            admin.execute(
                "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind, "
                "backup_agent_id) VALUES ($1, $2, $3, $4, $5)",
                fx.tenant_id,
                chain,
                position,
                kind,
                agent,
            )
    request = _executing(roles, fx, "agent", str(fx.agent_a))
    _run_phases(roles["sibyl_worker"], fx, request)
    err = _error(
        roles["sibyl_app"],
        fx.tenant_id,
        "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3, "
        "approved_at = now() WHERE tenant_id = $1 AND id = $2",
        fx.tenant_id,
        chain,
        fx.approver,
    )
    assert err.sqlstate == "SB040", err


def test_an_active_approved_chain_blocks_the_request_at_creation(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-chain-create"))
    _name_as_backup(admin, fx, fx.agent_a)
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError) as info:
        with app.tx(fx.tenant_id, rollback=True):
            _insert_request(app, fx, "agent", str(fx.agent_a))
    assert info.value.sqlstate == "SB034", info.value


# --- subject scope --------------------------------------------------------------------------


def _subject_set(agents: list[uuid.UUID], frm: datetime, to: datetime | None) -> str:
    return json.dumps(
        {
            "subject_set": {
                "agent_ids": [str(a) for a in agents],
                "window_from": frm.isoformat(),
                "window_to": None if to is None else to.isoformat(),
            }
        }
    )


def _agent_rows(admin: Conn, fx: TenantFixture, agent: uuid.UUID) -> dict[str, int]:
    return {
        t: admin.fetchval(
            f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1 AND agent_id = $2",
            fx.tenant_id,
            agent,
        )
        for t in ("events", "payload_refs", "checkpoint")
    }


def test_subject_erasure_deletes_the_resolved_objects_and_nothing_else(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-subject"))
    now = datetime.now(UTC)
    other_before = _agent_rows(admin, fx, fx.agent_b)
    agents_before = admin.fetchval(
        "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", fx.tenant_id
    )
    request = _executing(
        roles,
        fx,
        "subject",
        "sha256-of-subject",
        affected_objects=_subject_set([fx.agent_a], now - timedelta(hours=1), None),
    )
    counts = _run_phases(roles["sibyl_worker"], fx, request)
    assert counts[0]["events"] == 1 and counts[1] == {}
    assert _agent_rows(admin, fx, fx.agent_a) == {"events": 0, "payload_refs": 0, "checkpoint": 0}
    assert _agent_rows(admin, fx, fx.agent_b) == other_before
    assert (
        admin.fetchval("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", fx.tenant_id)
        == agents_before
    )
    with roles["sibyl_worker"].tx(fx.tenant_id, rollback=True):
        assert roles["sibyl_worker"].fetch("SELECT * FROM sibyl.erasure_residue($1)", request) == []


def test_subject_window_bounds_the_deletion(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, _slug("erase-subject-window"))
    now = datetime.now(UTC)
    before = _agent_rows(admin, fx, fx.agent_a)
    request = _executing(
        roles,
        fx,
        "subject",
        "sha256-of-subject",
        affected_objects=_subject_set(
            [fx.agent_a], now - timedelta(days=3), now - timedelta(days=2)
        ),
    )
    _run_phases(roles["sibyl_worker"], fx, request)
    assert _agent_rows(admin, fx, fx.agent_a) == before


def test_subject_erasure_without_a_resolved_set_is_refused(
    admin: Conn, roles: dict[str, Conn]
) -> None:
    fx = populate_tenant(admin, _slug("erase-subject-unresolved"))
    request = _executing(roles, fx, "subject", "sha256-of-subject")
    err = _error(
        roles["sibyl_worker"],
        fx.tenant_id,
        "SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')",
        request,
    )
    assert err.sqlstate == "SB031", err


# --- agent scope completeness (tests F3) -------------------------------------------------


def _agent_tables(admin: Conn) -> list[str]:
    tables = set(tenant_tables(admin)) - KEEP
    return sorted(
        r["relname"]
        for r in admin.fetch(
            "SELECT c.relname FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'sibyl' "
            "AND a.attname = 'agent_id' AND NOT a.attisdropped AND c.relkind IN ('r','p') "
            "AND NOT c.relispartition"
        )
        if r["relname"] in tables
    )


def _per_agent(
    admin: Conn, fx: TenantFixture, agent: uuid.UUID, tables: list[str]
) -> dict[str, int]:
    return {
        t: admin.fetchval(
            f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1 AND agent_id = $2",
            fx.tenant_id,
            agent,
        )
        for t in tables
    }


def test_every_agent_keyed_table_has_an_agent_predicate(admin: Conn) -> None:
    plan = {
        r["table_name"]: r["agent_predicate"]
        for r in admin.fetch("SELECT * FROM sibyl.erasure_cascade()")
    }
    assert [t for t in _agent_tables(admin) if plan.get(t) is None] == []


@pytest.mark.parametrize("victim", ["a", "b"])
def test_agent_erasure_removes_every_row_of_that_agent_and_nothing_of_the_other(
    admin: Conn, roles: dict[str, Conn], victim: str
) -> None:
    fx = populate_tenant(admin, _slug(f"erase-agent-{victim}"))
    gone, kept = (fx.agent_a, fx.agent_b) if victim == "a" else (fx.agent_b, fx.agent_a)
    tables = _agent_tables(admin)
    victim_before = _per_agent(admin, fx, gone, tables)
    other_before = _per_agent(admin, fx, kept, tables)
    for label, counts in (("victim", victim_before), ("bystander", other_before)):
        empty = sorted(t for t, n in counts.items() if not n)
        assert len(empty) <= 3, f"fixture lacks {label} rows in {empty}"
    request = _executing(roles, fx, "agent", str(gone))
    _run_phases(roles["sibyl_worker"], fx, request)
    assert {t: n for t, n in _per_agent(admin, fx, gone, tables).items() if n} == {}
    assert _per_agent(admin, fx, kept, tables) == other_before


def test_residue_reports_what_is_still_there(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, _slug("erase-residue-all"))
    request = _executing(roles, fx, "tenant", None)
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        residue = {
            r["table_name"]
            for r in worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request)
        }
    plan = [
        r["table_name"]
        for r in admin.fetch(
            "SELECT table_name FROM sibyl.erasure_cascade() "
            "WHERE action IN ('delete', 'routing_fn')"
        )
    ]
    populated = {
        t
        for t in plan
        if admin.fetchval(f"SELECT count(*) FROM sibyl.{t} WHERE tenant_id = $1", fx.tenant_id)
    }
    assert populated and residue >= populated


# --- the signed ledger (security H1) -----------------------------------------------------


def _entry(
    entries: tuple[Any, ...],
    tenant: uuid.UUID,
    scope: str,
    ref: str | None,
    subject_set: dict[str, Any] | None = None,
) -> tuple[Any, ...]:
    return ledger.append(
        entries,
        signing_key=SIGNING_KEY,
        tenant_id=str(tenant),
        erasure_request_id=str(uuid.uuid4()),
        scope_kind=scope,
        scope_ref=ref,
        key_ids=[],
        completed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        subject_set=subject_set,
    )


def _signed(*erasures: tuple[Any, ...]) -> tuple[Any, ...]:
    entries: tuple[Any, ...] = ()
    for erasure in erasures:
        entries = _entry(entries, *erasure)
    return entries


def test_python_ledger_round_trips_and_pins_the_head() -> None:
    entries = _signed((uuid.uuid4(), "tenant", None), (uuid.uuid4(), "agent", str(uuid.uuid4())))
    jsonl = ledger.to_jsonl(entries)
    count, head = ledger.head_of(entries)
    assert count == 2 and len(head) == 64
    assert ledger.verify(jsonl, PUBLIC_KEY, expected_count=2, expected_head=head) == entries
    assert (
        len(
            ledger.verify(
                jsonl, PUBLIC_KEY, expected_count=1, expected_head=ledger.head_of(entries[:1])[1]
            )
        )
        == 2
    )
    record = ledger.sign_head(entries, SIGNING_KEY, at="2026-10-10T00:00:00.000000Z")
    ledger.verify_head(record, entries, PUBLIC_KEY)


def test_python_ledger_refuses_forgery_truncation_and_reordering() -> None:
    entries = _signed(*((uuid.uuid4(), "tenant", None) for _ in range(3)))
    jsonl = ledger.to_jsonl(entries)
    count, head = ledger.head_of(entries)
    other = ledger.public_key_of(ledger.generate_signing_key())
    lines = jsonl.splitlines()
    forged_entries = ledger.append(
        entries[:2],
        signing_key=ledger.generate_signing_key(),
        tenant_id=str(uuid.uuid4()),
        erasure_request_id=str(uuid.uuid4()),
        scope_kind="tenant",
        scope_ref=None,
        key_ids=[],
        completed_at="2026-10-10T00:00:00.000000Z",
    )
    cases = {
        "wrong key": (jsonl, other, count, head),
        "truncated": ("\n".join(lines[:2]) + "\n", PUBLIC_KEY, count, head),
        "empty": ("", PUBLIC_KEY, count, head),
        "reordered": ("\n".join([lines[1], lines[0], lines[2]]) + "\n", PUBLIC_KEY, count, head),
        "edited": (jsonl.replace('"tenant"', '"agent"', 1), PUBLIC_KEY, count, head),
        "forged append": (ledger.to_jsonl(forged_entries), PUBLIC_KEY, 3, head),
        "wrong head": (jsonl, PUBLIC_KEY, count, "0" * 64),
    }
    for name, (text, key, n, h) in cases.items():
        with pytest.raises(ledger.LedgerError):
            ledger.verify(text, key, expected_count=n, expected_head=h)
            pytest.fail(name)


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- fixed interpreter and module
        [sys.executable, "-m", "sibyl_control.migrate", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_ledger_verify_and_head(tmp_path: Path) -> None:
    entries = _signed((uuid.uuid4(), "tenant", None), (uuid.uuid4(), "tenant", None))
    count, head = ledger.head_of(entries)
    good = tmp_path / "ledger.jsonl"
    good.write_text(ledger.to_jsonl(entries))
    pub = tmp_path / "ledger.pub"
    pub.write_bytes(ledger.public_key_pem(PUBLIC_KEY))
    common = ["--public-key", str(pub)]
    ok = _cli(
        "ledger-verify",
        "--ledger",
        str(good),
        *common,
        "--expected-head",
        head,
        "--expected-count",
        str(count),
    )
    assert ok.returncode == 0, ok.stderr
    printed = _cli("ledger-head", "--ledger", str(good), *common)
    assert printed.returncode == 0 and json.loads(printed.stdout) == {"count": 2, "head_hash": head}
    cut = tmp_path / "cut.jsonl"
    cut.write_text(ledger.to_jsonl(entries[:1]))
    bad = _cli(
        "ledger-verify",
        "--ledger",
        str(cut),
        *common,
        "--expected-head",
        head,
        "--expected-count",
        str(count),
    )
    assert bad.returncode != 0 and "ledger" in bad.stderr.lower()
    other = tmp_path / "other.pub"
    other.write_bytes(ledger.public_key_pem(ledger.public_key_of(ledger.generate_signing_key())))
    wrong = _cli(
        "ledger-verify",
        "--ledger",
        str(good),
        "--public-key",
        str(other),
        "--expected-head",
        head,
        "--expected-count",
        str(count),
    )
    assert wrong.returncode != 0


REAPPLY = "SELECT sibyl.erasure_reapply_from_ledger($1, $2, $3)"


def _reapply(
    admin: Conn, entries: tuple[Any, ...], count: int | None = None, head: str | None = None
) -> int:
    n, h = ledger.head_of(entries)
    return admin.fetchval(
        REAPPLY,
        ledger.to_jsonl(entries),
        n if count is None else count,
        h if head is None else head,
    )


def test_reapply_rechecks_count_and_head_in_the_database(admin: Conn) -> None:
    fx = populate_tenant(admin, _slug("reapply-head"))
    entries = _signed((uuid.uuid4(), "tenant", None), (fx.tenant_id, "agent", str(fx.agent_b)))
    count, head = ledger.head_of(entries)
    before = _held_counts(admin, fx)
    for text, n, h in (
        (ledger.to_jsonl(entries[:1]), count, head),  # truncated below the expected count
        (ledger.to_jsonl(entries), count, "0" * 64),  # wrong head
        (ledger.to_jsonl(entries), count + 1, head),  # count beyond the ledger
        ("", 1, head),  # empty ledger where one entry is expected
        (ledger.to_jsonl(entries).replace('"seq":1', '"seq":"one"'), count, head),
    ):
        with pytest.raises(asyncpg.PostgresError) as info:
            admin.fetchval(REAPPLY, text, n, h)
        assert info.value.sqlstate == "SB061" and "sibyl:ledger_invalid" in str(info.value)
    assert _held_counts(admin, fx) == before
    assert admin.fetchval(REAPPLY, "", 0, "0" * 64) == 0


def test_reapply_accepts_a_ledger_that_grew_after_the_backup(admin: Conn) -> None:
    fx = populate_tenant(admin, _slug("reapply-prefix"))
    entries = _signed((uuid.uuid4(), "tenant", None), (fx.tenant_id, "agent", str(fx.agent_b)))
    at_backup = ledger.head_of(entries[:1])
    assert admin.fetchval(REAPPLY, ledger.to_jsonl(entries), *at_backup) == 1
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            fx.agent_b,
        )
        == 0
    )


def test_reapply_includes_subject_erasures(admin: Conn) -> None:
    fx = populate_tenant(admin, _slug("reapply-subject"))
    now = datetime.now(UTC)
    subject_set = {
        "agent_ids": [str(fx.agent_a)],
        "window_from": (now - timedelta(hours=1)).isoformat(),
        "window_to": None,
    }
    entries = _signed((fx.tenant_id, "subject", "sha256-of-subject", subject_set))
    assert _reapply(admin, entries) == 1
    assert _agent_rows(admin, fx, fx.agent_a) == {"events": 0, "payload_refs": 0, "checkpoint": 0}
    assert (
        admin.fetchval("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", fx.tenant_id) == 2
    )


def test_reapply_restores_the_callers_tenant_context(admin: Conn) -> None:
    fx = populate_tenant(admin, _slug("reapply-context"))
    other = uuid.uuid4()
    entries = _signed((fx.tenant_id, "agent", str(fx.agent_b)))
    with admin.tx(rollback=True):
        admin.execute("SELECT set_config('app.tenant_id', $1, true)", str(other))
        _reapply(admin, entries)
        assert admin.fetchval("SELECT current_setting('app.tenant_id', true)") == str(other)
    with admin.tx(rollback=True):
        _reapply(admin, entries)
        assert admin.fetchval("SELECT coalesce(current_setting('app.tenant_id', true), '')") == ""
