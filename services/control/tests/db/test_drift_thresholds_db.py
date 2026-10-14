"""Wave 4 HARDEN item 7 schema: tenant drift threshold overrides (``drift_thresholds``, one row
per tenant, every value nullable = deployment default) under RLS, its range and ordering
CHECKs, the grant matrix and the ``drift.thresholds_updated`` audit action. The populated
tenants carry one overrides row (``fixtures._drift_thresholds``); the api never deletes it (a
reset writes NULLs), so the checks below rewrite it inside rolled-back transactions."""

from __future__ import annotations

import uuid

import asyncpg
import pytest
from sibyl_schemas.models.drift import THRESHOLD_BOUNDS

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant

_RESET = "UPDATE sibyl.drift_thresholds SET " + ", ".join(  # noqa: S608 - fixed column names
    f"{name} = NULL" for name in sorted(THRESHOLD_BOUNDS)
)


@pytest.fixture(scope="module")
def pair(admin: Conn) -> tuple[TenantFixture, TenantFixture]:
    return populate_tenant(admin, "dthr-a"), populate_tenant(admin, "dthr-b")


def test_rls_hides_and_protects_the_other_tenant(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, b = pair
    for role in ("sibyl_app", "sibyl_worker"):
        conn = roles[role]
        with conn.tx(b.tenant_id, rollback=True):
            assert conn.fetchval("SELECT count(*) FROM sibyl.drift_thresholds") == 1, role
            foreign = conn.fetchval(
                "SELECT count(*) FROM sibyl.drift_thresholds WHERE tenant_id = $1", a.tenant_id
            )
            assert foreign == 0, role
        with conn.tx(rollback=True):
            assert conn.fetchval("SELECT count(*) FROM sibyl.drift_thresholds") == 0
    app = roles["sibyl_app"]
    with app.tx(b.tenant_id, rollback=True), pytest.raises(asyncpg.PostgresError):
        app.execute(
            "INSERT INTO sibyl.drift_thresholds (tenant_id, psi_watch, updated_by_user_id)"
            " VALUES ($1, 0.2, $2) ON CONFLICT (tenant_id) DO UPDATE SET psi_watch = 0.2",
            a.tenant_id,
            a.owner,
        )
    with app.tx(b.tenant_id, rollback=True):
        assert app.execute("UPDATE sibyl.drift_thresholds SET psi_drift = 0.5") == "UPDATE 1"
        assert app.fetchval("SELECT version FROM sibyl.drift_thresholds") == 1


@pytest.mark.parametrize("column", sorted(THRESHOLD_BOUNDS))
def test_every_value_is_range_checked(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], column: str
) -> None:
    _, b = pair
    low, high = THRESHOLD_BOUNDS[column]
    app = roles["sibyl_app"]
    sql = f"UPDATE sibyl.drift_thresholds SET {column} = $1"  # noqa: S608 - fixed names
    integral = isinstance(low, int)
    below = low - 1 if integral else low / 2
    above = high + 1 if integral else high * 2
    for bad in (below, above):
        with app.tx(b.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
            app.execute(_RESET)  # the other value of a pair stays NULL: only the range applies
            app.execute(sql, bad)
    for good in (low, high):
        with app.tx(b.tenant_id, rollback=True):
            app.execute(_RESET)
            app.execute(sql, good)


@pytest.mark.parametrize("stat", ["psi", "js_two_category", "js_many_category"])
def test_watch_must_be_below_drift_when_both_are_overridden(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn], stat: str
) -> None:
    _, b = pair
    app = roles["sibyl_app"]
    low, _ = THRESHOLD_BOUNDS[f"{stat}_watch"]
    sql = f"UPDATE sibyl.drift_thresholds SET {stat}_watch = $1, {stat}_drift = $2"  # noqa: S608
    for watch, drift in ((low * 2, low * 2), (low * 3, low * 2)):
        with app.tx(b.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
            app.execute(sql, watch, drift)
    with app.tx(b.tenant_id, rollback=True):
        app.execute(sql, low * 2, low * 3)


def test_updater_must_be_a_user_of_the_tenant(
    pair: tuple[TenantFixture, TenantFixture], roles: dict[str, Conn]
) -> None:
    a, b = pair
    app = roles["sibyl_app"]
    for stranger in (a.owner, uuid.uuid4()):
        with app.tx(b.tenant_id, rollback=True), pytest.raises(asyncpg.ForeignKeyViolationError):
            app.execute("UPDATE sibyl.drift_thresholds SET updated_by_user_id = $1", stranger)


def test_grant_matrix(admin: Conn) -> None:
    def has(role: str, privilege: str) -> bool:
        fn = "has_table_privilege" if privilege == "DELETE" else "has_any_column_privilege"
        return bool(
            admin.fetchval(f"SELECT {fn}($1, 'sibyl.drift_thresholds', $2)", role, privilege)
        )

    expected = {
        "sibyl_app": {"SELECT", "INSERT", "UPDATE"},
        "sibyl_worker": {"SELECT"},
        "sibyl_ingest": set(),
    }
    for role, privileges in expected.items():
        held = {p for p in ("SELECT", "INSERT", "UPDATE", "DELETE") if has(role, p)}
        assert held == privileges, role


def test_catalogue_row(admin: Conn) -> None:
    action = admin.fetchrow(
        "SELECT * FROM sibyl.audit_action WHERE name = 'drift.thresholds_updated'"
    )
    assert action is not None
    assert action["actor_types"] == ["human"] and action["reason_required"]
    assert action["resource_type"] == "drift_thresholds"
    assert set(action["required_fields"]) == {"before", "after"}
