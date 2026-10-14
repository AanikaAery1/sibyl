"""``sibyl.partition_retire_expired`` (lane U CR to INT-1, DATAMODEL §6.6 step 3).

Runs on its own throw-away database (it drops partitions). Called as ``sibyl_worker``: expired
partitions are detached and dropped, the registry says so and per-tenant row counts come back;
partitions within retention stay; ``audit_events`` is never touched; a ``payload_refs``
partition holding a row under an active legal hold stays; ``sibyl_app`` cannot call it.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, populate_tenant


@dataclass
class Rig:
    admin: Conn
    worker: Conn
    app: Conn
    a: TenantFixture
    b: TenantFixture


@pytest.fixture(scope="module")
def rig(database_factory: Any) -> Iterator[Rig]:
    db = database_factory()
    admin = db.connect(None)
    worker, app = db.connect("sibyl_worker"), db.connect("sibyl_app")
    try:
        yield Rig(
            admin,
            worker,
            app,
            populate_tenant(admin, "retire-a"),
            populate_tenant(admin, "retire-b"),
        )
    finally:
        for conn in (admin, worker, app):
            conn.close()


def _ensure(rig: Rig, table: str, days_ago: int) -> str:
    rig.admin.fetchval(
        f"SELECT sibyl.partition_ensure('{table}', now() - interval '{days_ago} days',"
        f" now() - interval '{days_ago} days' + interval '1 hour')"
    )
    name = rig.admin.fetchval(
        "SELECT partition_name FROM sibyl.partition_registry WHERE table_name = $1"
        " AND range_from <= now() - make_interval(days => $2)"
        " AND range_to > now() - make_interval(days => $2)",
        table,
        days_ago,
    )
    assert name is not None
    return str(name)


def _outbox(rig: Rig, tenant: uuid.UUID, days_ago: int, n: int = 1) -> None:
    with rig.admin.tx(tenant):
        for _ in range(n):
            rig.admin.execute(
                "INSERT INTO sibyl.outbox (tenant_id, created_at, topic, event_type,"
                " aggregate_kind, aggregate_id, payload, idempotency_key)"
                " VALUES ($1, now() - make_interval(days => $2),"
                " 'alert', 'alert.fired', 'alert', $3, '{}', $4)",
                tenant,
                days_ago,
                uuid.uuid4(),
                uuid.uuid4().hex,
            )


def _old_payload(rig: Rig, fx: TenantFixture, days_ago: int) -> uuid.UUID:
    ref = uuid.uuid4()
    with rig.admin.tx(fx.tenant_id):
        rig.admin.execute(
            "INSERT INTO sibyl.payload_refs (tenant_id, id, created_at, kind, uri, sha256,"
            " size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
            " redaction_profile_hash, agent_id, source_kind, expires_at)"
            " SELECT tenant_id, $2::uuid, now() - make_interval(days => $3), kind, uri || $5,"
            " sha256,"
            " size_bytes, stored_bytes, tenant_key_id, key_version, nonce, capture_mode,"
            " redaction_profile_hash, agent_id, source_kind, now() - make_interval(days => $3 - 1)"
            " FROM sibyl.payload_refs WHERE tenant_id = $1 AND agent_id = $4 LIMIT 1",
            fx.tenant_id,
            ref,
            days_ago,
            fx.agent_a,
            str(ref),
        )
    return ref


def _state(rig: Rig, partition: str) -> str:
    return str(
        rig.admin.fetchval(
            "SELECT state FROM sibyl.partition_registry WHERE partition_name = $1", partition
        )
    )


def _retire(rig: Rig) -> list[Any]:
    with rig.worker.tx():
        return rig.worker.fetch("SELECT * FROM sibyl.partition_retire_expired(now())")


def test_retire_drops_expired_keeps_fresh_held_and_audit(rig: Rig) -> None:
    expired = _ensure(rig, "outbox", 30)  # outbox retention: 7 days
    fresh = _ensure(rig, "outbox", 2)
    empty = _ensure(rig, "events_rejected", 20)  # retention 3 days, no rows
    _outbox(rig, rig.a.tenant_id, 30, n=2)
    _outbox(rig, rig.b.tenant_id, 30)
    _outbox(rig, rig.a.tenant_id, 2)
    held = _ensure(rig, "payload_refs", 500)  # retention 400 days
    free = _ensure(rig, "payload_refs", 520)
    held_ref = _old_payload(rig, rig.a, 500)
    _old_payload(rig, rig.b, 520)
    with rig.admin.tx(rig.a.tenant_id):
        rig.admin.execute(
            "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, window_from, reason)"
            " VALUES ($1, 'tenant', now() - interval '900 days',"
            " 'litigation hold for retire test')",
            rig.a.tenant_id,
        )
    audit = rig.admin.fetch(
        "SELECT partition_name FROM sibyl.partition_registry WHERE table_name = 'audit_events'"
    )

    rows = _retire(rig)

    got = {(r["table_name"], r["partition_name"], r["tenant_id"], r["rows"]) for r in rows}
    assert ("outbox", expired, rig.a.tenant_id, 2) in got
    assert ("outbox", expired, rig.b.tenant_id, 1) in got
    assert ("events_rejected", empty, None, 0) in got
    assert ("payload_refs", free, rig.b.tenant_id, 1) in got
    dropped = {r["partition_name"] for r in rows}
    assert fresh not in dropped and held not in dropped
    assert not any(r["table_name"] == "audit_events" for r in rows)
    for name in (expired, empty, free):
        assert _state(rig, name) == "dropped"
        assert rig.admin.fetchval("SELECT to_regclass('sibyl.' || $1::text)", name) is None
    assert _state(rig, fresh) == "attached" and _state(rig, held) == "attached"
    assert {_state(rig, r["partition_name"]) for r in audit} == {"attached"}
    with rig.admin.tx(rig.a.tenant_id):
        assert (
            rig.admin.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE id = $1", held_ref)
            == 1
        )
    assert _retire(rig) == []  # idempotent: nothing left to retire


def test_only_the_worker_may_retire(rig: Rig) -> None:
    with rig.app.tx(rollback=True), pytest.raises(asyncpg.InsufficientPrivilegeError):
        rig.app.fetch("SELECT * FROM sibyl.partition_retire_expired(now())")
