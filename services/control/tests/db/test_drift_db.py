"""Lane DRIFT (D51) schema: drift_baseline / drift_report under RLS, the baseline lifecycle
guard, report immutability, the grant matrix and the catalogue rows (scopes, audit action)."""

from __future__ import annotations

import uuid

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant

TABLES = ("drift_baseline", "drift_report")


@pytest.fixture(scope="module")
def pair(admin: Conn) -> tuple[TenantFixture, TenantFixture]:
    return populate_tenant(admin, "drift-a"), populate_tenant(admin, "drift-b")


def _baseline(
    conn: Conn, fx: TenantFixture, *, state: str = "collecting", model: str = "m"
) -> uuid.UUID:
    extra = (
        ", window_end, frozen_at) VALUES ($1, $2, '', $3, 'frozen', now() - interval '2 hours',"
        " now() - interval '1 hour', now())"
        if state == "frozen"
        else ") VALUES ($1, $2, '', $3, 'collecting', now())"
    )
    return conn.fetchval(
        "INSERT INTO sibyl.drift_baseline (tenant_id, agent_id, provider, model, state,"
        " window_start" + extra + " RETURNING id",
        fx.tenant_id,
        fx.agent_a,
        model,
    )


@pytest.mark.parametrize("table", TABLES)
def test_rls_hides_and_protects_the_other_tenant(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], table: str
) -> None:
    a, b = pair
    for role in ("sibyl_app", "sibyl_worker"):
        conn = roles[role]
        with conn.tx(b.tenant_id, rollback=True):
            own = conn.fetchval(f"SELECT count(*) FROM sibyl.{table}")  # noqa: S608 - fixed
            foreign = conn.fetchval(
                f"SELECT count(*) FROM sibyl.{table} WHERE tenant_id = $1",  # noqa: S608
                a.tenant_id,
            )
            assert own == 2 and foreign == 0, (role, table)
        with conn.tx(rollback=True):
            assert conn.fetchval(f"SELECT count(*) FROM sibyl.{table}") == 0  # noqa: S608


def test_a_baseline_for_another_tenants_agent_is_refused(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, b = pair
    worker = roles["sibyl_worker"]
    with worker.tx(b.tenant_id, rollback=True), pytest.raises(asyncpg.PostgresError):
        worker.execute(
            "INSERT INTO sibyl.drift_baseline (tenant_id, agent_id, provider, model, window_start)"
            " VALUES ($1, $2, '', 'm', now())",
            a.tenant_id,
            a.agent_a,
        )


def test_lifecycle_guard(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], admin: Conn
) -> None:
    a, _ = pair
    worker = roles["sibyl_worker"]
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, state="frozen", model="guard")
        with pytest.raises(asyncpg.PostgresError, match="sibyl:immutable_row"):
            worker.execute(
                "UPDATE sibyl.drift_baseline SET features = '{\"x\": 1}' WHERE id = $1", baseline
            )
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, state="frozen", model="guard")
        with pytest.raises(asyncpg.PostgresError, match="sibyl:invalid_transition"):
            worker.execute(
                "UPDATE sibyl.drift_baseline SET state = 'collecting' WHERE id = $1", baseline
            )
    with admin.tx(a.tenant_id, rollback=True):
        baseline = _baseline(admin, a, state="frozen", model="guard")
        admin.execute(
            "UPDATE sibyl.drift_baseline SET drift_streak = 2, last_evaluated_at = now()"
            " WHERE id = $1",
            baseline,
        )
        admin.execute(
            "UPDATE sibyl.drift_baseline SET state = 'superseded', superseded_at = now()"
            " WHERE id = $1",
            baseline,
        )
        with pytest.raises(asyncpg.PostgresError, match="sibyl:invalid_transition"):
            admin.execute(
                "UPDATE sibyl.drift_baseline SET state = 'frozen' WHERE id = $1", baseline
            )


def test_collecting_freezes_and_one_current_baseline_per_key(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, _ = pair
    worker = roles["sibyl_worker"]
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, model="freeze")
        with pytest.raises(asyncpg.CheckViolationError):
            worker.execute(
                "UPDATE sibyl.drift_baseline SET state = 'frozen' WHERE id = $1", baseline
            )
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, model="freeze")
        worker.execute(
            "UPDATE sibyl.drift_baseline SET state = 'frozen', window_end = now(),"
            " frozen_at = now(), features = '{\"refusal\": {}}', sample_count = 600 WHERE id = $1",
            baseline,
        )
        with pytest.raises(asyncpg.UniqueViolationError):
            _baseline(worker, a, model="freeze")


def test_reports_are_immutable_and_written_by_the_worker_only(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], admin: Conn
) -> None:
    a, _ = pair
    app, worker = roles["sibyl_app"], roles["sibyl_worker"]
    insert = (
        "INSERT INTO sibyl.drift_report (tenant_id, baseline_id, agent_id, provider, model,"
        " window_start, window_end, sample_count, verdict, behaviour_evaluated, features,"
        " identity, identity_changed) VALUES ($1, $2, $3, '', 'm', now() - interval '1 hour',"
        " now(), 10, 'drift', true, '[]', $4::jsonb, $5) RETURNING id"
    )
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, state="frozen", model="report")
        report = worker.fetchval(insert, a.tenant_id, baseline, a.agent_a, "[]", False)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            worker.execute("UPDATE sibyl.drift_report SET verdict = 'none' WHERE id = $1", report)
    with admin.tx(a.tenant_id, rollback=True):
        baseline = _baseline(admin, a, state="frozen", model="report")
        report = admin.fetchval(insert, a.tenant_id, baseline, a.agent_a, "[]", False)
        with pytest.raises(asyncpg.PostgresError, match="sibyl:immutable_row"):
            admin.execute("UPDATE sibyl.drift_report SET verdict = 'none' WHERE id = $1", report)
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, state="frozen", model="report")
        with pytest.raises(asyncpg.CheckViolationError):  # identity_changed must match identity
            worker.fetchval(insert, a.tenant_id, baseline, a.agent_a, '[{"kind": "x"}]', False)
    with worker.tx(a.tenant_id, rollback=True):
        baseline = _baseline(worker, a, state="frozen", model="report")
        worker.fetchval(insert, a.tenant_id, baseline, a.agent_a, "[]", False)
        worker.execute("DELETE FROM sibyl.drift_report WHERE baseline_id = $1", baseline)
    with app.tx(a.tenant_id, rollback=True):
        baseline = app.fetchval(
            "SELECT id FROM sibyl.drift_baseline WHERE tenant_id = $1 LIMIT 1", a.tenant_id
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            app.fetchval(insert, a.tenant_id, baseline, a.agent_a, "[]", False)


def test_grant_matrix(admin: Conn) -> None:
    def has(role: str, table: str, privilege: str) -> bool:
        fn = "has_table_privilege" if privilege == "DELETE" else "has_any_column_privilege"
        return bool(admin.fetchval(f"SELECT {fn}($1, $2, $3)", role, f"sibyl.{table}", privilege))

    expected = {
        ("sibyl_app", "drift_baseline"): {"SELECT", "INSERT", "UPDATE"},
        ("sibyl_app", "drift_report"): {"SELECT"},
        ("sibyl_worker", "drift_baseline"): {"SELECT", "INSERT", "UPDATE", "DELETE"},
        ("sibyl_worker", "drift_report"): {"SELECT", "INSERT", "DELETE"},
        ("sibyl_ingest", "drift_baseline"): set(),
        ("sibyl_ingest", "drift_report"): set(),
    }
    for (role, table), privileges in expected.items():
        held = {p for p in ("SELECT", "INSERT", "UPDATE", "DELETE") if has(role, table, p)}
        assert held == privileges, (role, table)
    assert has("sibyl_worker", "alert_rule", "INSERT")
    assert not admin.fetchval(
        "SELECT has_column_privilege('sibyl_app', 'sibyl.drift_baseline', 'features', 'UPDATE')"
    )


def test_catalogue_rows(admin: Conn) -> None:
    rows = admin.fetch(
        "SELECT role_name, permission FROM sibyl.role_permission WHERE permission LIKE 'drift:%'"
    )
    by_scope: dict[str, set[str]] = {}
    for r in rows:
        by_scope.setdefault(r["permission"], set()).add(r["role_name"])
    assert by_scope["drift:write"] == {"owner", "admin", "security_admin"}
    assert len(by_scope["drift:read"]) == 7
    action = admin.fetchrow("SELECT * FROM sibyl.audit_action WHERE name = 'drift.baseline_reset'")
    assert action["actor_types"] == ["human"] and action["reason_required"]
