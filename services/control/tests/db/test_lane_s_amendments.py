"""Lane S change requests to INT-1: ``failover.kill_switch_id`` (FK + index), the ``drill`` saga
kind, ``handoff_task.rating`` (1-5), ``alert.hold_suppressed_at``, and an ``api_key`` actor on
``killswitch.applied``."""

from __future__ import annotations

import uuid

import asyncpg
import pytest
from sibyl_schemas import values as sv

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "lane-s-amend")


def _one(admin: Conn, tenant: uuid.UUID, table: str) -> uuid.UUID:
    return admin.fetchval(f"SELECT id FROM sibyl.{table} WHERE tenant_id = $1 LIMIT 1", tenant)  # noqa: S608


def test_a_failover_names_its_kill_switch(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        failover = _one(app, fx.tenant_id, "failover")
        switch = _one(app, fx.tenant_id, "kill_switch")
        app.execute("UPDATE sibyl.failover SET kill_switch_id = $2 WHERE id = $1", failover, switch)
        assert (
            app.fetchval("SELECT kill_switch_id FROM sibyl.failover WHERE id = $1", failover)
            == switch
        )
    with app.tx(fx.tenant_id, rollback=True), pytest.raises(asyncpg.ForeignKeyViolationError):
        app.execute(
            "UPDATE sibyl.failover SET kill_switch_id = $2 WHERE id = $1",
            _one(app, fx.tenant_id, "failover"),
            uuid.uuid4(),
        )


def test_drill_is_a_saga_kind(fx: TenantFixture, admin: Conn) -> None:
    assert sv.SagaKind.DRILL.value == "drill"
    with admin.tx(fx.tenant_id, rollback=True):
        failover = _one(admin, fx.tenant_id, "failover")
        admin.execute("UPDATE sibyl.failover SET kind = 'drill' WHERE id = $1", failover)


@pytest.mark.parametrize(
    ("rating", "ok"), [(1, True), (5, True), (None, True), (0, False), (6, False)]
)
def test_handoff_rating_is_one_to_five(
    fx: TenantFixture, roles: dict[str, Conn], rating: int | None, ok: bool
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        task = _one(app, fx.tenant_id, "handoff_task")
        if ok:
            app.execute("UPDATE sibyl.handoff_task SET rating = $2 WHERE id = $1", task, rating)
        else:
            with pytest.raises(asyncpg.CheckViolationError):
                app.execute("UPDATE sibyl.handoff_task SET rating = $2 WHERE id = $1", task, rating)


def test_alert_records_when_a_hold_suppressed_it(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        alert = _one(worker, fx.tenant_id, "alert")
        worker.execute(
            "UPDATE sibyl.alert SET hold_suppressed_at = now(),"
            " hold_suppressed_count = hold_suppressed_count + 1 WHERE id = $1",
            alert,
        )
        assert worker.fetchval(
            "SELECT hold_suppressed_at IS NOT NULL FROM sibyl.alert WHERE id = $1", alert
        )


def test_killswitch_applied_accepts_the_gateway_key_actor(admin: Conn) -> None:
    actors = admin.fetchval(
        "SELECT actor_types FROM sibyl.audit_action WHERE name = 'killswitch.applied'"
    )
    assert set(actors) == {"system", "api_key"}
    assert sv.AUDIT_ACTIONS["killswitch.applied"].actor_types == {
        sv.ActorType.SYSTEM,
        sv.ActorType.API_KEY,
    }
