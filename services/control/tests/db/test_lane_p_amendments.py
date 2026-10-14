"""Lane P change requests to INT-1 (wave 2): alert silences and the persisted per-agent breaker.

* ``alert.silenced_until`` / ``alert.silenced_by_user_id`` (FK to a user of the same tenant,
  partial index ``ix_alert_silenced``), writable by the api (silence) and the worker (expiry);
* ``agent.preemptive_breaker_tripped_at`` set by the worker; clearing it (with who and when) is a
  human api write; ``preemptive.breaker_tripped`` (system) and ``preemptive.breaker_cleared``
  (human, reason required) are declared audit actions.
"""

from __future__ import annotations

import uuid

import asyncpg
import pytest
from sibyl_schemas import values as sv

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "lane-p-amend")


def _alert(conn: Conn, fx: TenantFixture) -> uuid.UUID:
    return conn.fetchval("SELECT id FROM sibyl.alert WHERE tenant_id = $1 LIMIT 1", fx.tenant_id)


def test_api_silences_and_worker_expires_an_alert(
    fx: TenantFixture, roles: dict[str, Conn]
) -> None:
    app, worker = roles["sibyl_app"], roles["sibyl_worker"]
    with app.tx(fx.tenant_id, rollback=True):
        alert = _alert(app, fx)
        app.execute(
            "UPDATE sibyl.alert SET state = 'acked', silenced_until = now() + interval '1 hour',"
            " silenced_by_user_id = $2 WHERE id = $1",
            alert,
            fx.owner,
        )
        assert app.fetchval("SELECT silenced_by_user_id FROM sibyl.alert WHERE id = $1", alert)
    with worker.tx(fx.tenant_id, rollback=True):
        alert = _alert(worker, fx)
        worker.execute("UPDATE sibyl.alert SET silenced_until = NULL WHERE id = $1", alert)


def test_silencer_must_be_a_user_of_the_tenant(fx: TenantFixture, admin: Conn) -> None:
    other = populate_tenant(admin, "lane-p-other")
    with admin.tx(fx.tenant_id, rollback=True), pytest.raises(asyncpg.ForeignKeyViolationError):
        admin.execute(
            "UPDATE sibyl.alert SET silenced_until = now(), silenced_by_user_id = $2"
            " WHERE tenant_id = $1",
            fx.tenant_id,
            other.owner,
        )


def test_silence_index_is_partial(admin: Conn) -> None:
    definition = admin.fetchval("SELECT pg_get_indexdef('sibyl.ix_alert_silenced'::regclass)")
    assert "silenced_until IS NOT NULL" in definition


def test_worker_trips_the_breaker_but_cannot_clear_it(
    fx: TenantFixture, roles: dict[str, Conn]
) -> None:
    worker, app = roles["sibyl_worker"], roles["sibyl_app"]
    with worker.tx(fx.tenant_id, rollback=True):
        worker.execute(
            "UPDATE sibyl.agent SET preemptive_breaker_tripped_at = now() WHERE id = $1",
            fx.agent_a,
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            worker.execute(
                "UPDATE sibyl.agent SET preemptive_breaker_cleared_at = now() WHERE id = $1",
                fx.agent_a,
            )
    with app.tx(fx.tenant_id, rollback=True):
        app.execute(
            "UPDATE sibyl.agent SET preemptive_breaker_tripped_at = NULL,"
            " preemptive_breaker_cleared_at = now(), preemptive_breaker_cleared_by_user_id = $2"
            " WHERE id = $1",
            fx.agent_a,
            fx.owner,
        )


def test_a_clearer_needs_a_clearing_time(fx: TenantFixture, admin: Conn) -> None:
    with admin.tx(fx.tenant_id, rollback=True), pytest.raises(asyncpg.CheckViolationError):
        admin.execute(
            "UPDATE sibyl.agent SET preemptive_breaker_cleared_by_user_id = $2 WHERE id = $1",
            fx.agent_a,
            fx.owner,
        )


def test_breaker_audit_actions_are_declared(admin: Conn) -> None:
    tripped = sv.AUDIT_ACTIONS["preemptive.breaker_tripped"]
    cleared = sv.AUDIT_ACTIONS["preemptive.breaker_cleared"]
    assert {a.value for a in tripped.actor_types} == {"system"}
    assert {a.value for a in cleared.actor_types} == {"human"} and cleared.reason_required
    rows = {
        r["name"]: r
        for r in admin.fetch(
            "SELECT * FROM sibyl.audit_action WHERE name LIKE 'preemptive.breaker_%'"
        )
    }
    assert set(rows) == {"preemptive.breaker_tripped", "preemptive.breaker_cleared"}
    assert rows["preemptive.breaker_cleared"]["reason_required"]
