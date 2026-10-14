"""(c) routing_apply() accepts exactly the state_edge(machine='routing') set, plus its other
contract points: idempotency, stale precondition, D21 operator hold, human reason, one audit
row + one outbox row + one routing_version per transition, function-only writes (R1)."""

from __future__ import annotations

import itertools
import uuid
from typing import Any

import asyncpg
import pytest
from sibyl_schemas import values as sv

from .conftest import LOGIN_ROLES, Conn
from .fixtures import TenantFixture, populate_tenant

# Derived from the schemas value sets, so a new state or trigger joins the matrix (G0-tests F12).
STATES = tuple(str(s.value) for s in sv.RoutingState)
TRIGGERS = tuple(str(t.value) for t in sv.TransitionTrigger)
ACTOR_FOR_TRIGGER = {
    "rule": "rule",
    "policy": "policy",
    "operator": "human",
    "undo": "human",
    "approval": "human",
}

CALL = (
    "SELECT * FROM sibyl.routing_apply($1, $2, NULL, $3, $4, $5::jsonb, $6, $7, $8, NULL, NULL, "
    "NULL, NULL, $9, "
    "NULL, NULL, $10::smallint, $11, $12, 'route.changed', NULL, NULL, NULL, NULL)"
)


@pytest.fixture(scope="module")
def fx(admin: Conn) -> TenantFixture:
    return populate_tenant(admin, "routing")


def _approval(admin: Conn, fx: TenantFixture) -> uuid.UUID:
    return admin.fetchval(
        "SELECT id FROM sibyl.approval WHERE tenant_id = $1 LIMIT 1", fx.tenant_id
    )


def _force_state(admin: Conn, fx: TenantFixture, state: str) -> None:
    """Put agent B's routing_state into ``state`` (admin bypass; consistent with the CHECKs)."""
    if state == "":
        admin.execute(
            "DELETE FROM sibyl.routing_state WHERE tenant_id = $1 AND agent_id = $2",
            fx.tenant_id,
            fx.agent_b,
        )
        return
    target = (
        "primary"
        if state in ("active", "degraded", "quarantined", "killed", "awaiting_approval")
        else "model"
    )
    admin.execute(
        "UPDATE sibyl.routing_state SET state = $3, target_kind = $4, target_model_id = $5, "
        "approval_id = $6, "
        "canary_pct = $7, operator_hold_until = NULL WHERE tenant_id = $1 AND agent_id = $2",
        fx.tenant_id,
        fx.agent_b,
        state,
        target,
        fx.model_a if target == "model" else None,
        _approval(admin, fx) if state == "awaiting_approval" else None,
        50 if state == "failing_back" else 100,
    )


def _attempt(
    admin: Conn, fx: TenantFixture, from_state: str, to_state: str, trigger: str
) -> str | None:
    actor = ACTOR_FOR_TRIGGER.get(trigger, "system")
    target = (
        f'{{"kind": "model", "model_id": "{fx.model_a}"}}' if to_state == "failed_over" else None
    )
    with admin.tx(fx.tenant_id, rollback=True):
        _force_state(admin, fx, from_state)
        try:
            admin.execute("SAVEPOINT attempt")
            admin.fetchrow(
                CALL,
                fx.tenant_id,
                fx.agent_b,
                from_state or None,
                to_state,
                target,
                trigger,
                actor,
                fx.owner if actor == "human" else None,
                _approval(admin, fx) if to_state == "awaiting_approval" else None,
                50 if to_state == "failing_back" else None,
                "operator decision" if actor == "human" else None,
                f"t:{uuid.uuid4()}",
            )
            return None
        except asyncpg.PostgresError as exc:
            admin.execute("ROLLBACK TO SAVEPOINT attempt")
            return exc.sqlstate


def test_accepts_exactly_the_state_edge_set(admin: Conn, fx: TenantFixture) -> None:
    edges = {
        (r["from_state"], r["to_state"], r["trigger"])
        for r in admin.fetch(
            "SELECT from_state, to_state, trigger FROM sibyl.state_edge WHERE machine = 'routing'"
        )
    }
    assert len(edges) >= 40
    wrong: list[tuple[Any, ...]] = []
    for from_state, to_state, trigger in itertools.product(("", *STATES), STATES, TRIGGERS):
        outcome = _attempt(admin, fx, from_state, to_state, trigger)
        legal = (from_state, to_state, trigger) in edges
        if legal and outcome is not None:
            wrong.append(("rejected legal edge", from_state, to_state, trigger, outcome))
        if not legal and outcome != "SB010":
            wrong.append(
                ("accepted or misreported illegal edge", from_state, to_state, trigger, outcome)
            )
    assert wrong == [], "\n".join(map(str, wrong))


def test_every_edge_is_reachable_by_some_actor(admin: Conn) -> None:
    triggers = {
        r["trigger"]
        for r in admin.fetch("SELECT trigger FROM sibyl.state_edge WHERE machine = 'routing'")
    }
    assert triggers <= set(TRIGGERS)


def _degrade(
    conn: Conn, fx: TenantFixture, key: str, actor: str = "rule", reason: str | None = None
) -> Any:
    return conn.fetchrow(
        CALL,
        fx.tenant_id,
        fx.agent_a,
        "active",
        "degraded",
        None,
        "rule" if actor == "rule" else "operator",
        actor,
        fx.owner if actor == "human" else None,
        None,
        None,
        reason,
        key,
    )


def test_transition_effects_and_idempotency(
    roles: dict[str, Conn], fx: TenantFixture, admin: Conn
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        before = worker.fetchrow(
            "SELECT (SELECT routing_version FROM sibyl.tenant WHERE id = $1) AS v, "
            "(SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1) AS s, "
            "(SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1) AS o",
            fx.tenant_id,
        )
        first = _degrade(worker, fx, "idem-1")
        again = _degrade(worker, fx, "idem-1")
        after = worker.fetchrow(
            "SELECT (SELECT routing_version FROM sibyl.tenant WHERE id = $1) AS v, "
            "(SELECT max(seq) FROM sibyl.audit_events WHERE tenant_id = $1) AS s, "
            "(SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1) AS o",
            fx.tenant_id,
        )
        assert dict(first) == dict(again)
        assert (after["v"] - before["v"], after["s"] - before["s"], after["o"] - before["o"]) == (
            1,
            1,
            1,
        )
        state = worker.fetchrow(
            "SELECT state, routing_version, last_transition_id FROM sibyl.routing_state "
            "WHERE tenant_id = $1 AND agent_id = $2",
            fx.tenant_id,
            fx.agent_a,
        )
        assert (
            state["state"] == "degraded" and state["last_transition_id"] == first["transition_id"]
        )
        audit = worker.fetchrow(
            "SELECT action, detail->>'transition_id' AS t FROM sibyl.audit_events "
            "WHERE tenant_id = $1 AND seq = $2",
            fx.tenant_id,
            first["audit_seq"],
        )
        assert audit["action"] == "route.changed" and audit["t"] == str(first["transition_id"])
        topic = worker.fetchval(
            "SELECT topic FROM sibyl.outbox WHERE tenant_id = $1 ORDER BY xid DESC, id DESC "
            "LIMIT 1",
            fx.tenant_id,
        )
        assert topic == "policy"


def test_stale_precondition(roles: dict[str, Conn], fx: TenantFixture) -> None:
    worker = roles["sibyl_worker"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:stale_precondition"):
        with worker.tx(fx.tenant_id, rollback=True):
            worker.fetchrow(
                CALL,
                fx.tenant_id,
                fx.agent_a,
                "degraded",
                "active",
                None,
                "rule",
                "rule",
                None,
                None,
                None,
                None,
                "stale-1",
            )


def test_operator_hold_blocks_rules_not_humans(
    roles: dict[str, Conn], fx: TenantFixture, admin: Conn
) -> None:
    worker = roles["sibyl_worker"]
    with worker.tx(fx.tenant_id, rollback=True):
        _degrade(worker, fx, "hold-0")
        worker.fetchrow(
            CALL,
            fx.tenant_id,
            fx.agent_a,
            "degraded",
            "active",
            None,
            "undo",
            "human",
            fx.owner,
            None,
            None,
            "undo automated degrade",
            "hold-1",
        )
        hold = worker.fetchval(
            "SELECT operator_hold_until FROM sibyl.routing_state WHERE tenant_id = $1 "
            "AND agent_id = $2",
            fx.tenant_id,
            fx.agent_a,
        )
        assert (
            hold is None
        )  # undo without an explicit hold argument leaves it unset; the api passes now()+30m
    with worker.tx(fx.tenant_id, rollback=True):
        worker.fetchrow(
            "SELECT * FROM sibyl.routing_apply($1, $2, NULL, 'active', 'degraded', NULL, "
            "'operator', "
            "'human', $3, NULL, NULL, NULL, NULL, NULL, NULL, now() + interval '30 minutes', NULL, "
            "'hold', 'hold-2', 'override.by_human', NULL, NULL, NULL, NULL)",
            fx.tenant_id,
            fx.agent_a,
            fx.owner,
        )
        worker.fetchrow(
            CALL,
            fx.tenant_id,
            fx.agent_a,
            "degraded",
            "active",
            None,
            "operator",
            "human",
            fx.owner,
            None,
            None,
            "back",
            "hold-3",
        )
        worker.execute("SAVEPOINT s")
        with pytest.raises(asyncpg.PostgresError, match="sibyl:operator_hold"):
            _degrade(worker, fx, "hold-4")
        worker.execute("ROLLBACK TO SAVEPOINT s")
        assert _degrade(worker, fx, "hold-5", actor="human", reason="human may act")[
            "transition_id"
        ]


def test_human_needs_reason(roles: dict[str, Conn], fx: TenantFixture) -> None:
    app = roles["sibyl_app"]
    with pytest.raises(asyncpg.PostgresError, match="sibyl:reason_required"):
        with app.tx(fx.tenant_id, rollback=True):
            _degrade(app, fx, "reason-1", actor="human", reason=None)


@pytest.mark.parametrize("role", LOGIN_ROLES)
def test_routing_tables_are_function_only(
    roles: dict[str, Conn], fx: TenantFixture, role: str
) -> None:
    conn = roles[role]
    for sql in (
        "UPDATE sibyl.routing_state SET state = 'killed'",
        "DELETE FROM sibyl.routing_state",
        "DELETE FROM sibyl.routing_transition",
        "UPDATE sibyl.routing_transition SET reason = 'x'",
        "INSERT INTO sibyl.routing_state (tenant_id, agent_id, routing_version) "
        "SELECT tenant_id, agent_id, 0 FROM sibyl.routing_state LIMIT 1",
    ):
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            with conn.tx(fx.tenant_id, rollback=True):
                conn.execute(sql)
