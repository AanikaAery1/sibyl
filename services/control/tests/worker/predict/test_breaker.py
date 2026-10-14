"""The persisted per-agent pre-emptive breaker (sre guard rail 5, ML.md §4.6 item 5), on PG17.

Two automated transitions undone, or verdicted ``fp``, within 7 days trip it: the worker sets
``agent.preemptive_breaker_tripped_at`` and appends ``preemptive.breaker_tripped`` (system) in
the same transaction. A tripped breaker forces ``approval`` on every predicted failover of that
agent, whatever the window or a worker restart does, until a human clears it
(``preemptive.breaker_cleared``, reason required); only automations after the clear count again.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.audit import AuditActor
from sibyl_control.core.settings import Settings
from sibyl_control.worker.predict.breaker import (
    BREAKER_WINDOW,
    BreakerCleared,
    clear_breaker,
    trip_breakers,
)
from sibyl_control.worker.predict.writer import PredictResult, reset_cursors, write_predictions

from .p_breaker import replica, undone_automated_transition
from .p_sim import FakeSaga
from .test_writer import TWO_FAMILIES, snapshot

NOW = datetime.now(UTC).replace(microsecond=0) - timedelta(minutes=5)


@pytest.fixture
def agent(kit: Any) -> tuple[UUID, UUID]:
    kit.ensure_partitions("prediction", NOW - timedelta(days=1), NOW + timedelta(days=2))
    t = kit.tenant()
    return t, kit.agent(t, tier=3)


def offer(kit: Any, t: UUID, a: UUID, at: datetime) -> list[str]:
    """One gate crossing at ``at`` (after a calm row) and the modes S was asked for."""
    saga = FakeSaga()
    snapshot(kit, t, a, at - timedelta(seconds=10))
    snapshot(kit, t, a, at, band15="0.90", conf="high", rules=TWO_FAMILIES)

    async def go() -> PredictResult:
        async with kit.worker.tenant_tx(t) as conn:
            return await write_predictions(
                conn,
                t,
                at + timedelta(seconds=1),
                settings=Settings(predicted_automation_band="0.90"),
                since=at - timedelta(seconds=11),
                requester=saga,
            )

    kit.run(go())
    return [c["mode"] for c in saga.calls]


def tripped_at(kit: Any, a: UUID) -> datetime | None:
    return kit.val(  # type: ignore[no-any-return]
        "SELECT preemptive_breaker_tripped_at FROM sibyl.agent WHERE id = $1", a
    )


def audits(kit: Any, t: UUID, action: str) -> list[Any]:
    found: list[Any] = kit.q(
        "SELECT actor_type, actor_id, resource_type, resource_id, reason, detail"
        " FROM sibyl.audit_events WHERE tenant_id = $1 AND action = $2 ORDER BY seq",
        t,
        action,
    )
    return found


def human(kit: Any, t: UUID) -> UUID:
    """The tenant's operator (created on first use)."""
    found = kit.val("SELECT id FROM sibyl.app_user WHERE tenant_id = $1 LIMIT 1", t)
    if found is not None:
        return found  # type: ignore[no-any-return]
    issuer, user = uuid4(), uuid4()
    kit.in_tenant(
        t,
        "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id)"
        " VALUES ($1, $2, $3, 'sibyl')",
        t,
        issuer,
        f"https://dex.example/{t}",
    )
    kit.in_tenant(
        t,
        "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email, display_name,"
        " status) VALUES ($1, $2, $3, 'operator', $4, 'Operator', 'active')",
        t,
        user,
        issuer,
        f"operator@{t.hex[:8]}.example",
    )
    return user


def clear(kit: Any, app_db: Any, t: UUID, a: UUID, reason: str) -> BreakerCleared | None:
    user = human(kit, t)

    async def go() -> BreakerCleared | None:
        async with app_db.tenant_tx(t) as conn:
            actor = AuditActor("human", user, None, None)
            return await clear_breaker(conn, t, a, actor=actor, reason=reason)

    return kit.run(go())


def test_two_undone_automations_trip_once_with_a_system_audit(
    kit: Any, agent: tuple[UUID, UUID]
) -> None:
    t, a = agent
    for n in range(2):
        undone_automated_transition(kit, t, a, n, NOW - timedelta(days=2))
    assert offer(kit, t, a, NOW) == ["approval"]
    assert tripped_at(kit, a) == NOW + timedelta(seconds=1)
    rows = audits(kit, t, "preemptive.breaker_tripped")
    assert len(rows) == 1
    row = rows[0]
    assert (row["actor_type"], row["resource_type"], row["resource_id"]) == ("system", "agent", a)
    assert row["detail"] == {
        "agent_id": str(a),
        "trips": 2,
        "window_s": int(BREAKER_WINDOW.total_seconds()),
    }
    assert offer(kit, t, a, NOW + timedelta(minutes=1)) == ["approval"]
    assert len(audits(kit, t, "preemptive.breaker_tripped")) == 1, "trips once"


@pytest.mark.parametrize("tier", [1, 3])
def test_one_undone_automation_or_tier_1_never_trips(kit: Any, tier: int) -> None:
    kit.ensure_partitions("prediction", NOW - timedelta(days=1), NOW + timedelta(days=2))
    t = kit.tenant()
    a = kit.agent(t, tier=tier)
    for n in range(1 if tier == 3 else 2):
        undone_automated_transition(kit, t, a, n, NOW - timedelta(days=2))
    offer(kit, t, a, NOW)
    assert tripped_at(kit, a) is None
    assert audits(kit, t, "preemptive.breaker_tripped") == []


def test_a_tripped_breaker_outlives_the_window_and_a_restart(
    kit: Any, agent: tuple[UUID, UUID]
) -> None:
    t, a = agent
    for n in range(2):
        undone_automated_transition(kit, t, a, n, NOW - timedelta(days=6))
    assert offer(kit, t, a, NOW) == ["approval"]
    reset_cursors()  # a worker restart: nothing is held in memory
    later = NOW + timedelta(days=2)  # both automations are now older than 7 days
    kit.ensure_partitions("prediction", later - timedelta(days=1), later + timedelta(days=1))
    assert offer(kit, t, a, later) == ["approval"]
    assert tripped_at(kit, a) == NOW + timedelta(seconds=1)


def test_fp_verdicts_on_automated_failovers_count(kit: Any, agent: tuple[UUID, UUID]) -> None:
    t, a = agent
    rule = kit.val(
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'error_rate'", t
    )
    for n in range(2):
        replica(
            kit,
            t,
            "WITH al AS (INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity,"
            " state, dedupe_key, what_to_do, summary, verdict, verdict_label_id, resolved_at,"
            " updated_at) VALUES ($1, $2, 'agent', $3, 'warning', 'resolved', $4, 'x', 'x', 'fp',"
            " gen_random_uuid(), $5, $5) RETURNING id)"
            " INSERT INTO sibyl.failover (tenant_id, agent_id, kind, state, step, actor_kind,"
            " from_state, idempotency_key, trigger_alert_id) SELECT $1, $3, 'failover', 'done',"
            " 'done', 'rule', 'active', $4, al.id FROM al",
            t,
            rule,
            a,
            f"fp-{n}-{a}",
            NOW - timedelta(days=1),
        )
    assert offer(kit, t, a, NOW) == ["approval"]
    assert audits(kit, t, "preemptive.breaker_tripped")[0]["detail"]["trips"] == 2


def test_a_human_clear_rearms_it_and_only_later_automations_count(
    kit: Any, app_db: Any, agent: tuple[UUID, UUID]
) -> None:
    t, a = agent
    now = datetime.now(UTC).replace(microsecond=0)
    for n in range(2):
        undone_automated_transition(kit, t, a, n, now - timedelta(days=1))
    assert offer(kit, t, a, now) == ["approval"]
    was = tripped_at(kit, a)

    cleared = clear(kit, app_db, t, a, "two undos were drills, not false positives")
    assert cleared is not None and cleared.tripped_at == was and cleared.agent_id == a
    row = kit.q(
        "SELECT preemptive_breaker_tripped_at, preemptive_breaker_cleared_at,"
        " preemptive_breaker_cleared_by_user_id FROM sibyl.agent WHERE id = $1",
        a,
    )[0]
    user = human(kit, t)
    assert row["preemptive_breaker_tripped_at"] is None
    assert row["preemptive_breaker_cleared_at"] == cleared.cleared_at
    assert row["preemptive_breaker_cleared_by_user_id"] == user
    audit = audits(kit, t, "preemptive.breaker_cleared")
    assert [(r["actor_type"], r["actor_id"], r["resource_id"]) for r in audit] == [
        ("human", user, a)
    ]
    assert audit[0]["reason"] == "two undos were drills, not false positives"
    assert audit[0]["detail"] == {"agent_id": str(a), "tripped_at": was.isoformat()}

    assert offer(kit, t, a, now + timedelta(minutes=1)) == ["auto"], "old undos do not re-trip"
    for n in range(2, 4):
        undone_automated_transition(kit, t, a, n, cleared.cleared_at + timedelta(seconds=n))
    assert offer(kit, t, a, now + timedelta(minutes=2)) == ["approval"]
    assert len(audits(kit, t, "preemptive.breaker_tripped")) == 2


def test_clearing_needs_a_reason_and_a_tripped_breaker(
    kit: Any, app_db: Any, agent: tuple[UUID, UUID]
) -> None:
    t, a = agent
    assert clear(kit, app_db, t, a, "nothing tripped") is None
    assert audits(kit, t, "preemptive.breaker_cleared") == []
    with pytest.raises(ValueError, match="reason"):
        clear(kit, app_db, t, a, "   ")


def test_trip_breakers_is_flat_in_agents(kit: Any) -> None:
    """One statement finds every agent to trip; tripping is one update and one audit each."""
    t = kit.tenant()
    agents = [kit.agent(t, tier=2) for _ in range(3)]
    for i, a in enumerate(agents[:2]):
        for n in range(2):
            undone_automated_transition(kit, t, a, 10 * i + n, NOW - timedelta(hours=3))

    async def go() -> Any:
        async with kit.worker.tenant_tx(t) as conn:
            return await trip_breakers(conn, t, NOW)

    trips = kit.run(go())
    assert sorted(x.agent_id for x in trips) == sorted(agents[:2])
    assert tripped_at(kit, agents[2]) is None
    assert len(audits(kit, t, "preemptive.breaker_tripped")) == 2
