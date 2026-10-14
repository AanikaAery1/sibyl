# ruff: noqa: S608 -- SQL identifiers here come from pg_catalog or fixed literals, never from input
"""(d) Erasure cascade: generated completeness (S13/X4) and end-to-end execution; R63 ledger
re-application after a restore."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import asyncpg
import pytest
from sibyl_control.core.problems import problem_from_db_error
from sibyl_control.migrate import ledger

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant, row_counts, tenant_tables

KEEP = {
    "audit_events",
    "audit_anchors",
    "audit_chain_head",
    "erasure_request",
    "legal_hold",
    "tenant_key",
    "tenant_pseudonym_key",
}
ANONYMISED = {"app_user", "oidc_issuer"}
# Wave 3 tenant tables keyed by agent; each later erasure_cascade() redefinition must carry them.
WAVE3_AGENT_TABLES = ("drift_baseline", "drift_report", "sentinel_finding")
# Wave 4 (D53) tenant tables keyed by agent.
WAVE4_AGENT_TABLES = ("external_finding", "webhook_delivery")


def test_cascade_covers_every_tenant_table(admin: Conn) -> None:
    plan = admin.fetch("SELECT table_name, phase, action FROM sibyl.erasure_cascade() ORDER BY ord")
    planned = [r["table_name"] for r in plan]
    assert len(planned) == len(set(planned)), "a table appears twice in the cascade"
    tables = set(tenant_tables(admin))
    assert set(planned) == tables, {
        "missing": sorted(tables - set(planned)),
        "unknown": sorted(set(planned) - tables),
    }
    assert {r["table_name"] for r in plan if r["action"] == "keep"} == KEEP
    assert {r["table_name"] for r in plan if r["action"] == "anonymise"} == ANONYMISED


def _transition(
    conn: Conn, tenant: uuid.UUID, request: uuid.UUID, state: str, extra: str = ""
) -> None:
    conn.execute("SET LOCAL app.transition_trigger = 'worker'")
    conn.execute(
        f"UPDATE sibyl.erasure_request SET state = $2 {extra} WHERE tenant_id = $1 AND id = $3",
        tenant,
        state,
        request,
    )


def _request(
    app: Conn, fx: TenantFixture, scope: str, scope_ref: str | None, basis: str
) -> uuid.UUID:
    with app.tx(fx.tenant_id):
        request = app.fetchval(
            "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, scope_ref, legal_basis, "
            "requested_by) "
            "VALUES ($1, $2, $3, $4, $5) RETURNING id",
            fx.tenant_id,
            scope,
            scope_ref,
            basis,
            fx.owner,
        )
        app.execute("SET LOCAL app.transition_trigger = 'approve'")
        app.execute(
            "UPDATE sibyl.erasure_request SET state = 'approved', approved_by = $3, approved_at = "
            "now() "
            "WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            request,
            fx.approver,
        )
    return request


def _assert_erased(admin: Conn, fx: TenantFixture) -> None:
    counts = row_counts(admin, fx.tenant_id, tenant_tables(admin))
    leftovers = {t: n for t, n in counts.items() if n and t not in KEEP | ANONYMISED}
    assert leftovers == {}
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.app_user WHERE tenant_id = $1 AND (status <> "
            "'deprovisioned' OR NOT sibyl.app_user_is_erased(email::text, subject, display_name, "
            "last_login_at))",
            fx.tenant_id,
        )
        == 0
    )
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.oidc_issuer WHERE tenant_id = $1 "
            "AND client_secret_ct IS NOT NULL",
            fx.tenant_id,
        )
        == 0
    )
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.tenant_key WHERE tenant_id = $1 AND (state <> 'shredded' "
            "OR wrapped_dek IS NOT NULL)",
            fx.tenant_id,
        )
        == 0
    )


def test_tenant_erasure_end_to_end(admin: Conn, roles: dict[str, Conn]) -> None:
    victim = populate_tenant(admin, "erase-victim")
    bystander = populate_tenant(admin, "erase-bystander")
    tables = tenant_tables(admin)
    bystander_before = row_counts(admin, bystander.tenant_id, tables)
    request = _request(roles["sibyl_app"], victim, "tenant", None, "tenant_offboarding")
    worker = roles["sibyl_worker"]
    with worker.tx(victim.tenant_id):
        _transition(worker, victim.tenant_id, request, "executing")
        worker.execute("UPDATE sibyl.tenant SET status = 'erasing' WHERE id = $1", victim.tenant_id)
        assert worker.fetchval("SELECT sibyl.tenant_key_shred($1)", request) == 3
        _transition(worker, victim.tenant_id, request, "keys_shredded")
        objects = worker.fetchval(
            "SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", request
        )
        _transition(worker, victim.tenant_id, request, "objects_deleted")
        derived = worker.fetchval(
            "SELECT sibyl.erasure_execute_phase($1, 'derived_purged')", request
        )
        _transition(worker, victim.tenant_id, request, "derived_purged")
        assert worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request) == []
        _transition(worker, victim.tenant_id, request, "verified")
        _transition(worker, victim.tenant_id, request, "completed", ", completed_at = now()")
    assert '"events": 2' in objects and '"agent": 2' in derived
    _assert_erased(admin, victim)
    assert row_counts(admin, bystander.tenant_id, tables) == bystander_before
    with admin.tx(victim.tenant_id, rollback=True):
        assert admin.fetchrow("SELECT * FROM sibyl.audit_verify($1)", victim.tenant_id)["ok"]


def test_agent_scope_erasure_keeps_the_rest(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, "erase-agent")
    request = _request(roles["sibyl_app"], fx, "agent", str(fx.agent_b), "gdpr_art17")
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _transition(worker, fx.tenant_id, request, "executing")
        worker.execute("SELECT sibyl.erasure_execute_phase($1, 'objects_deleted')", request)
        _transition(worker, fx.tenant_id, request, "objects_deleted")
        worker.execute("SELECT sibyl.erasure_execute_phase($1, 'derived_purged')", request)
        assert worker.fetch("SELECT * FROM sibyl.erasure_residue($1)", request) == []
    assert (
        admin.fetchval("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", fx.tenant_id) == 1
    )
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.routing_state WHERE tenant_id = $1", fx.tenant_id
        )
        == 1
    )
    assert (
        admin.fetchval("SELECT count(*) FROM sibyl.kill_switch WHERE tenant_id = $1", fx.tenant_id)
        == 0
    )
    assert (
        admin.fetchval(
            "SELECT count(*) FROM sibyl.tenant_key WHERE tenant_id = $1 AND state = 'active'",
            fx.tenant_id,
        )
        == 3
    )
    # Wave 3 and 4 per-agent tables (B27): the erased agent's drift, Sentinel and monitor rows
    # go, the other agent's survive.
    for table in WAVE3_AGENT_TABLES + WAVE4_AGENT_TABLES:
        remaining = admin.fetch(
            f"SELECT agent_id FROM sibyl.{table} WHERE tenant_id = $1 AND agent_id IS NOT NULL",
            fx.tenant_id,
        )
        assert {r["agent_id"] for r in remaining} == {fx.agent_a}, table


def _name_as_backup(admin: Conn, fx: TenantFixture, backup: uuid.UUID) -> uuid.UUID:
    """An approved chain of agent B whose first step fails over to ``backup``."""
    chain = uuid.uuid4()
    with admin.tx(fx.tenant_id):
        admin.execute(
            "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no, "
            "requested_by_user_id) VALUES ($1, $2, $3, 1, $4)",
            fx.tenant_id,
            chain,
            fx.agent_b,
            fx.owner,
        )
        for position, kind, agent in ((0, "backup_agent", backup), (1, "human_queue", None)):
            admin.execute(
                "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind, "
                "backup_agent_id) VALUES ($1, $2, $3, $4, $5)",
                fx.tenant_id,
                chain,
                position,
                kind,
                agent,
            )
        admin.execute(
            "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3, "
            "approved_at = now() WHERE tenant_id = $1 AND id = $2",
            fx.tenant_id,
            chain,
            fx.approver,
        )
    return chain


def test_agent_erasure_blocked_by_another_agents_chain(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, "erase-backup")
    # The request predates the chain (creation itself refuses once the chain is approved).
    request = _request(roles["sibyl_app"], fx, "agent", str(fx.agent_a), "gdpr_art17")
    chain = _name_as_backup(admin, fx, fx.agent_a)
    tables = tenant_tables(admin)
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id):
        _transition(worker, fx.tenant_id, request, "executing")
    before = row_counts(admin, fx.tenant_id, tables)
    for phase in ("objects_deleted", "derived_purged"):
        with pytest.raises(asyncpg.PostgresError, match="sibyl:erasure_blocked_by_chain") as caught:
            with worker.tx(fx.tenant_id, rollback=True):
                worker.execute("SELECT sibyl.erasure_execute_phase($1, $2)", request, phase)
        assert caught.value.sqlstate == "SB034"
        assert str(chain) in str(caught.value)
        problem = problem_from_db_error(caught.value)
        assert (problem.code, problem.status) == ("erasure_blocked_by_chain", 409)
    assert row_counts(admin, fx.tenant_id, tables) == before, "nothing is half-erased"


def test_active_legal_hold_blocks_shred(admin: Conn, roles: dict[str, Conn]) -> None:
    fx = populate_tenant(admin, "erase-held")
    with admin.tx(fx.tenant_id):
        admin.execute(
            "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, window_from, reason, placed_by) "
            "VALUES ($1, 'tenant', now() - interval '1 day', 'litigation', $2)",
            fx.tenant_id,
            fx.approver,
        )
    request = _request(roles["sibyl_app"], fx, "tenant", None, "gdpr_art17")
    worker = roles["sibyl_worker"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:legal_hold_active"):
        with worker.tx(fx.tenant_id, rollback=True):
            _transition(worker, fx.tenant_id, request, "executing")
            worker.fetchval("SELECT sibyl.tenant_key_shred($1)", request)


def test_shred_and_purge_refused_without_executing_request(
    roles: dict[str, Conn], admin: Conn
) -> None:
    fx = populate_tenant(admin, "erase-refused")
    request = _request(roles["sibyl_app"], fx, "tenant", None, "gdpr_art17")
    worker = roles["sibyl_worker"]
    for sql in (
        "SELECT sibyl.tenant_key_shred($1)",
        "SELECT sibyl.erasure_execute_phase($1, 'derived_purged')",
        "SELECT sibyl.erasure_purge_routing($1)",
    ):
        with pytest.raises(asyncpg.PostgresError, match="sibyl:erasure_refused"):
            with worker.tx(fx.tenant_id, rollback=True):
                worker.fetchval(sql, request)
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:erasure_refused"):
        with app.tx(fx.tenant_id, rollback=True):
            app.execute("SET LOCAL app.transition_trigger = 'shred'")
            app.execute(
                "UPDATE sibyl.tenant_key SET state = 'shredded' WHERE tenant_id = $1", fx.tenant_id
            )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        with worker.tx(fx.tenant_id, rollback=True):
            worker.execute(
                "UPDATE sibyl.tenant_key SET wrapped_dek = NULL WHERE tenant_id = $1", fx.tenant_id
            )


LEDGER_KEY = ledger.generate_signing_key()
LEDGER_PUB = ledger.public_key_of(LEDGER_KEY)


def _ledger_for(*erasures: tuple[uuid.UUID, str, str | None]) -> tuple:
    entries: tuple = ()
    for tenant, scope, ref in erasures:
        entries = ledger.append(
            entries,
            signing_key=LEDGER_KEY,
            tenant_id=str(tenant),
            erasure_request_id=str(uuid.uuid4()),
            scope_kind=scope,
            scope_ref=ref,
            key_ids=[],
            completed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
    return entries


REAPPLY = "SELECT sibyl.erasure_reapply_from_ledger($1, $2, $3)"


def test_restore_reapplies_the_ledger_with_zero_resurrected_rows(admin: Conn) -> None:
    """A restored pre-erasure state (the tenant's rows and live DEKs are back) is re-erased
    from the off-database ledger before the database opens (R63)."""
    restored = populate_tenant(admin, "restored-erased")
    partial = populate_tenant(admin, "restored-agent")
    survivor = populate_tenant(admin, "restored-survivor")
    tables = tenant_tables(admin)
    survivor_before = row_counts(admin, survivor.tenant_id, tables)
    entries = _ledger_for(
        (restored.tenant_id, "tenant", None),
        (partial.tenant_id, "agent", str(partial.agent_b)),
        (uuid.uuid4(), "tenant", None),
    )
    jsonl = ledger.to_jsonl(entries)
    head = ledger.head_of(entries)
    assert len(ledger.verify(jsonl, LEDGER_PUB, expected_count=3, expected_head=head[1])) == 3
    assert admin.fetchval(REAPPLY, jsonl, *head) == 2
    _assert_erased(admin, restored)
    assert (
        admin.fetchval("SELECT status FROM sibyl.tenant WHERE id = $1", restored.tenant_id)
        == "erased"
    )
    assert (
        admin.fetchval("SELECT count(*) FROM sibyl.agent WHERE tenant_id = $1", partial.tenant_id)
        == 1
    )
    assert row_counts(admin, survivor.tenant_id, tables) == survivor_before
    assert admin.fetchval(REAPPLY, jsonl, *head) == 2  # idempotent
    _assert_erased(admin, restored)
    with admin.tx(restored.tenant_id, rollback=True):
        assert admin.fetchrow("SELECT * FROM sibyl.audit_verify($1)", restored.tenant_id)["ok"]
        assert (
            admin.fetchval(
                "SELECT count(*) FROM sibyl.audit_events WHERE tenant_id = $1 "
                "AND action = 'erasure.reshredded_after_restore'",
                restored.tenant_id,
            )
            == 2
        )


def test_tampered_ledger_applies_nothing(admin: Conn) -> None:
    fx = populate_tenant(admin, "restored-tampered")
    tables = tenant_tables(admin)
    before = row_counts(admin, fx.tenant_id, tables)
    entries = _ledger_for((uuid.uuid4(), "tenant", None), (fx.tenant_id, "tenant", None))
    good = ledger.to_jsonl(entries)
    head = ledger.head_of(entries)
    lines = good.splitlines()
    lines[0] = lines[0].replace('"scope_kind":"tenant"', '"scope_kind":"agent"')
    for broken in ("\n".join(lines), "\n".join(reversed(good.splitlines())), "not json\n"):
        with pytest.raises(asyncpg.PostgresError, match="sibyl:ledger_invalid"):
            admin.fetchval(REAPPLY, broken, *head)
    assert row_counts(admin, fx.tenant_id, tables) == before
    with pytest.raises(ledger.LedgerError):
        ledger.verify("\n".join(lines), LEDGER_PUB)


def test_reapply_is_operator_only(roles: dict[str, Conn]) -> None:
    for conn in roles.values():
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            conn.fetchval(REAPPLY, "", 0, "0" * 64)
