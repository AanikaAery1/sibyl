"""Migration 0021 (lane AG-LIVE) on PG17, as the service roles under RLS:

* ``action_policy.policy_id`` is derived (the scope's first version), never chosen and never
  changed, per tenant; ``approvals`` is the only new column the api may update;
* ``held_action``: ``on_behalf_of`` shapes, the bounded ``history``, the counter columns all or
  none; the worker may append history but not mark a counter applied;
* ``action_counter`` accepts a window past its cap (an approved escalation);
* RLS: another tenant's rows (and their new columns) stay invisible.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator

import asyncpg
import pytest

from .conftest import Conn
from .fixtures import TenantFixture, h32, populate_tenant


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "aglive-a")


@pytest.fixture(scope="module")
def fy(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "aglive-b")


def _policy(
    conn: Conn, fx: TenantFixture, *, scope: str, version: int, **cols: object
) -> uuid.UUID:
    values = {
        "tenant_id": fx.tenant_id,
        "id": uuid.uuid4(),
        "name": "p",
        "scope_kind": scope,
        "agent_id": fx.agent_a if scope == "agent" else None,
        "version_no": version,
        "document": json.dumps({"schema": "sibyl-action-policy/1"}),
        "document_sha256": h32(f"doc-{uuid.uuid4()}"),
        "default_effect": "escalate",
        "hold_timeout_s": 900,
        "rule_count": 0,
        "created_by_user_id": fx.owner,
        **cols,
    }
    names = ", ".join(values)
    marks = ", ".join(f"${i}" for i in range(1, len(values) + 1))
    return conn.fetchval(
        f"INSERT INTO sibyl.action_policy ({names}) VALUES ({marks}) RETURNING policy_id",  # noqa: S608
        *values.values(),
    )


def test_lineage_is_derived_per_scope_and_tenant(
    fx: TenantFixture, fy: TenantFixture, roles: dict[str, Conn]
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        first = _policy(app, fx, scope="tenant", version=10)
        chosen = uuid.uuid4()
        second = _policy(app, fx, scope="tenant", version=11, policy_id=chosen)
        assert second == first != chosen  # a given policy_id is ignored
        agent_scope = _policy(app, fx, scope="agent", version=10)
        assert agent_scope != first
    with app.tx(fy.tenant_id, rollback=True):
        other = _policy(app, fy, scope="tenant", version=10)
        assert other != first  # never another tenant's lineage


def test_policy_id_is_frozen_and_approvals_writable(
    fx: TenantFixture, roles: dict[str, Conn]
) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        lineage = _policy(app, fx, scope="tenant", version=20)
        app.execute(
            "UPDATE sibyl.action_policy SET approvals = $2::jsonb WHERE policy_id = $1",
            lineage,
            json.dumps([{"user_id": str(fx.owner), "at": "2026-10-12T00:00:00Z", "reason": None}]),
        )
    with pytest.raises(asyncpg.InsufficientPrivilegeError), app.tx(fx.tenant_id):
        app.execute(
            "UPDATE sibyl.action_policy SET policy_id = $1 WHERE tenant_id = $2",
            uuid.uuid4(),
            fx.tenant_id,
        )
    admin_like = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError), admin_like.tx(fx.tenant_id):
        admin_like.execute(
            "UPDATE sibyl.action_policy SET change_note = 'x' WHERE tenant_id = $1", fx.tenant_id
        )


def test_the_owner_cannot_rewrite_a_lineage(fx: TenantFixture, admin: Conn) -> None:
    with pytest.raises(asyncpg.PostgresError, match="immutable"), admin.tx(fx.tenant_id):
        admin.execute(
            "UPDATE sibyl.action_policy SET policy_id = $1 WHERE tenant_id = $2",
            uuid.uuid4(),
            fx.tenant_id,
        )


@pytest.fixture
def held(fx: TenantFixture, admin: Conn) -> Iterator[uuid.UUID]:
    with admin.tx(fx.tenant_id):
        held_id = admin.fetchval(
            "SELECT id FROM sibyl.held_action WHERE tenant_id = $1 ORDER BY created_at LIMIT 1",
            fx.tenant_id,
        )
    yield held_id


@pytest.mark.parametrize(
    ("kind", "user", "ref", "ok"),
    [
        ("user", True, None, True),
        ("external", False, "crm:42", True),
        ("user", False, None, False),
        ("user", True, "x", False),
        ("external", False, None, False),
        ("external", False, "a\nb", False),
        ("external", False, "x" * 129, False),
        ("robot", True, None, False),
    ],
)
def test_on_behalf_of_shapes(
    fx: TenantFixture,
    admin: Conn,
    held: uuid.UUID,
    kind: str,
    user: bool,
    ref: str | None,
    ok: bool,
) -> None:
    sql = (
        "UPDATE sibyl.held_action SET on_behalf_of_kind = $2, on_behalf_of_user_id = $3,"
        " on_behalf_of_ref = $4 WHERE id = $1"
    )
    args = (held, kind, fx.owner if user else None, ref)
    if ok:
        with admin.tx(fx.tenant_id, rollback=True):
            admin.execute(sql, *args)
    else:
        with pytest.raises(asyncpg.CheckViolationError), admin.tx(fx.tenant_id, rollback=True):
            admin.execute(sql, *args)


def test_history_is_bounded_and_counter_columns_go_together(
    fx: TenantFixture, admin: Conn, held: uuid.UUID
) -> None:
    entry = {"kind": "refused"}
    with admin.tx(fx.tenant_id, rollback=True):
        admin.execute(
            "UPDATE sibyl.held_action SET history = $2::jsonb WHERE id = $1",
            held,
            json.dumps([entry] * 64),
        )
    with pytest.raises(asyncpg.CheckViolationError), admin.tx(fx.tenant_id, rollback=True):
        admin.execute(
            "UPDATE sibyl.held_action SET history = $2::jsonb WHERE id = $1",
            held,
            json.dumps([entry] * 65),
        )
    with pytest.raises(asyncpg.CheckViolationError), admin.tx(fx.tenant_id, rollback=True):
        admin.execute(
            "UPDATE sibyl.held_action SET counter_key = 'k', counter_amount = 1 WHERE id = $1",
            held,
        )
    full = (
        "UPDATE sibyl.held_action SET counter_key = 'k', counter_amount = $2, counter_max = 10,"
        " counter_window_s = 60, counter_policy_id = policy_id WHERE id = $1"
    )
    with admin.tx(fx.tenant_id, rollback=True):
        admin.execute(full, held, 1)
    with pytest.raises(asyncpg.CheckViolationError), admin.tx(fx.tenant_id, rollback=True):
        admin.execute(full, held, None)  # every counter column or none


def test_worker_appends_history_but_cannot_apply_a_counter(
    fx: TenantFixture, roles: dict[str, Conn], held: uuid.UUID
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        worker.execute(
            'UPDATE sibyl.held_action SET history = history || \'[{"kind": "expired"}]\'::jsonb'
            " WHERE id = $1",
            held,
        )
    with pytest.raises(asyncpg.InsufficientPrivilegeError), worker.tx(fx.tenant_id):
        worker.execute(
            "UPDATE sibyl.held_action SET counter_applied_at = now() WHERE id = $1", held
        )


def test_a_counter_window_may_pass_its_cap(fx: TenantFixture, roles: dict[str, Conn]) -> None:
    app = roles["sibyl_app"]
    with app.tx(fx.tenant_id, rollback=True):
        app.execute(
            "INSERT INTO sibyl.action_counter (tenant_id, agent_id, counter_key, window_s,"
            " window_start, value, max_value, calls) VALUES ($1, $2, 'over', 60, now(), 150, 100,"
            " 2)",
            fx.tenant_id,
            fx.agent_a,
        )
    with pytest.raises(asyncpg.CheckViolationError), app.tx(fx.tenant_id, rollback=True):
        app.execute(
            "INSERT INTO sibyl.action_counter (tenant_id, agent_id, counter_key, window_s,"
            " window_start, value, max_value) VALUES ($1, $2, 'neg', 60, now(), -1, 100)",
            fx.tenant_id,
            fx.agent_a,
        )


def test_rls_hides_another_tenants_new_columns(
    fx: TenantFixture, fy: TenantFixture, roles: dict[str, Conn], admin: Conn
) -> None:
    with admin.tx(fy.tenant_id):
        admin.execute(
            "UPDATE sibyl.held_action SET on_behalf_of_kind = 'external', on_behalf_of_ref = 'b'"
            " WHERE tenant_id = $1",
            fy.tenant_id,
        )
    for role in ("sibyl_app", "sibyl_worker"):
        conn = roles[role]
        with conn.tx(fx.tenant_id, rollback=True):
            seen = conn.fetchval(
                "SELECT count(*) FROM sibyl.held_action WHERE on_behalf_of_ref = 'b'"
            )
            lineages = conn.fetchval(
                "SELECT count(*) FROM sibyl.action_policy WHERE tenant_id = $1", fy.tenant_id
            )
        assert (seen, lineages) == (0, 0)


def test_the_detail_agent_index_exists(admin: Conn) -> None:
    found = admin.fetchval(
        "SELECT count(*) FROM pg_indexes WHERE schemaname = 'sibyl'"
        " AND indexname = 'ix_audit_events_detail_agent'"
    )
    assert found == 1
