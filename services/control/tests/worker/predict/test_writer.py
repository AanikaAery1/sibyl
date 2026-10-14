"""Sparse prediction rows, idempotent rescans, the gate's rising edge, guard rails and
outcomes, on PG17 with hand-written health snapshots (ML.md §4.5-§4.6, §7.3, R49)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from sibyl_control.core.settings import Settings
from sibyl_control.worker.predict.outcomes import fill_outcomes
from sibyl_control.worker.predict.writer import PredictResult, write_predictions

from .p_breaker import replica, undone_automated_transition
from .p_sim import FakeSaga

CLOSED = Settings(predicted_automation_band="0.90")
T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=3)
TWO_FAMILIES = ["ratelimit_proximity", "provider_status"]


def horizon(
    band: str = "0.05", conf: str = "low", rules: list[str] | None = None
) -> dict[str, Any]:
    return {
        "probability_band": band,
        "source": "rules/v1",
        "confidence": conf,
        "contributing_rules": rules or [],
        "predicted_failure_mode": "provider_outage" if rules else None,
    }


def snapshot(
    kit: Any,
    t: UUID,
    a: UUID,
    at: datetime,
    *,
    band15: str = "0.05",
    conf: str = "low",
    rules: list[str] | None = None,
    health: str = "watch",
    provisional: bool = False,
    feature: bool = False,
) -> UUID:
    doc = {"15m": horizon(band15, conf, rules), "1h": horizon(), "24h": horizon()}
    config = kit.in_tenant(
        t, "SELECT id FROM sibyl.scoring_config WHERE tenant_id = $1 LIMIT 1", t
    )[0]["id"]
    fs = None
    if feature:
        fs = kit.in_tenant(
            t,
            "INSERT INTO sibyl.feature_snapshot (tenant_id, agent_id, as_of, feature_set, reason,"
            " observation_coverage, summary) VALUES ($1, $2, $3, 'features/v1', 'alert', 1, '{}')"
            " RETURNING id",
            t,
            a,
            at,
        )[0]["id"]
    return kit.in_tenant(  # type: ignore[no-any-return]
        t,
        "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
        " provisional, events_seen, observation_coverage, factors, horizons, scoring_config_id,"
        " policy_version, routing_state_at, window_start, window_end, grain_s, feature_snapshot_id)"
        " VALUES ($1, $2::timestamptz, $3, 80, $4, $5, 100, 1, $6::jsonb, $7::jsonb, $8, 0,"
        " 'active', $2::timestamptz - interval '5 minutes', $2::timestamptz, 300, $9) RETURNING id",
        t,
        at,
        a,
        health,
        provisional,
        json.dumps([{"rule": "ratelimit_proximity", "penalty": 20}]),
        json.dumps(doc),
        config,
        fs,
    )[0]["id"]


def write(
    kit: Any,
    t: UUID,
    now: datetime,
    saga: Any = None,
    since: datetime | None = None,
    settings: Settings = CLOSED,
) -> PredictResult:
    async def go() -> PredictResult:
        async with kit.worker.tenant_tx(t) as conn:
            return await write_predictions(
                conn,
                t,
                now,
                settings=settings,
                since=since or T0 - timedelta(seconds=1),
                requester=saga,
            )

    return kit.run(go())  # type: ignore[no-any-return]


def rows(kit: Any, t: UUID, a: UUID, horizon_s: int = 900) -> list[Any]:
    return kit.q(
        "SELECT * FROM sibyl.prediction WHERE tenant_id = $1 AND agent_id = $2 AND horizon_s = $3"
        " ORDER BY predicted_at",
        t,
        a,
        horizon_s,
    )


@pytest.fixture
def world(kit: Any) -> tuple[UUID, UUID]:
    kit.ensure_partitions("prediction", T0 - timedelta(days=1), T0 + timedelta(days=2))
    t = kit.tenant()
    return t, kit.agent(t, tier=1)


def test_sparse_rule_band_changes_raised_bands_frozen_ticks_and_hourly_heartbeat(
    kit: Any, world: tuple[UUID, UUID]
) -> None:
    t, a = world
    at = [T0 + timedelta(seconds=60 * i) for i in range(6)]
    snapshot(kit, t, a, at[0])  # first row: written
    snapshot(kit, t, a, at[1])  # unchanged 0.05: skipped
    snapshot(kit, t, a, at[2], band15="0.25", rules=["ratelimit_proximity"])  # change
    snapshot(kit, t, a, at[3], band15="0.25", rules=["ratelimit_proximity"])  # >= 0.25
    snapshot(kit, t, a, at[4])  # back down: change
    snapshot(kit, t, a, at[5], feature=True)  # froze a feature snapshot
    snapshot(kit, t, a, at[5] + timedelta(minutes=30))  # skipped
    snapshot(kit, t, a, at[5] + timedelta(minutes=61))  # hourly heartbeat
    result = write(kit, t, T0 + timedelta(hours=2))
    got = [r["predicted_at"] for r in rows(kit, t, a)]
    assert got == [at[0], at[2], at[3], at[4], at[5], at[5] + timedelta(minutes=61)]
    assert result.written == 3 * 2 + len(got)  # 1h/24h: first row, frozen tick, heartbeat
    one = rows(kit, t, a)[1]
    assert one["probability_band"] == "0.25" and one["source"] == "rules/v1"
    assert one["contributions"] == [
        {"rule": "ratelimit_proximity", "family": "rate_limit_headroom", "penalty": 20}
    ]
    assert one["predicted_failure_mode"] == "provider_outage"


def test_rescans_are_idempotent(kit: Any, world: tuple[UUID, UUID]) -> None:
    t, a = world
    snapshot(kit, t, a, T0, band15="0.25", rules=["ratelimit_proximity"])
    snapshot(kit, t, a, T0 + timedelta(seconds=10), band15="0.25", rules=["ratelimit_proximity"])
    first = write(kit, t, T0 + timedelta(minutes=1))
    again = write(kit, t, T0 + timedelta(minutes=1))
    assert first.written == 4 and again.written == 0 and again.skipped_existing == 4
    assert len(rows(kit, t, a)) == 2


def test_gate_fires_once_per_rising_edge(kit: Any, world: tuple[UUID, UUID]) -> None:
    t, a = world
    saga = FakeSaga()
    s = [T0 + timedelta(seconds=10 * i) for i in range(5)]
    snapshot(kit, t, a, s[0], band15="0.60", conf="medium", rules=TWO_FAMILIES)
    snapshot(kit, t, a, s[1], band15="0.60", conf="medium", rules=TWO_FAMILIES)
    snapshot(kit, t, a, s[2], band15="0.25", conf="medium", rules=TWO_FAMILIES)
    snapshot(kit, t, a, s[3], band15="0.60", conf="high", rules=TWO_FAMILIES)
    write(kit, t, s[3] + timedelta(seconds=1), saga)
    assert [c["mode"] for c in saga.calls] == ["approval", "approval"]
    assert [c["confidence"] for c in saga.calls] == ["medium", "high"]
    # one family or low confidence never crosses
    snapshot(kit, t, a, s[4], band15="0.60", conf="low", rules=TWO_FAMILIES)
    write(kit, t, s[4] + timedelta(seconds=1), saga, since=s[3])
    assert len(saga.calls) == 2


@pytest.mark.parametrize(
    ("health", "provisional"), [("failed", False), ("watch", True)], ids=["detected", "provisional"]
)
def test_detected_and_provisional_snapshots_are_not_offered(
    kit: Any, world: tuple[UUID, UUID], health: str, provisional: bool
) -> None:
    t, a = world
    saga = FakeSaga()
    snapshot(
        kit,
        t,
        a,
        T0,
        band15="0.90",
        conf="high",
        rules=TWO_FAMILIES,
        health=health,
        provisional=provisional,
    )
    result = write(kit, t, T0 + timedelta(seconds=1), saga)
    assert result.written == 3 and saga.calls == []


def test_operator_hold_blocks_the_offer_and_counts_it(kit: Any, world: tuple[UUID, UUID]) -> None:
    t, a = world
    saga = FakeSaga()
    rule = kit.in_tenant(
        t,
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'ratelimit_proximity'",
        t,
    )[0]["id"]
    alert = kit.in_tenant(
        t,
        "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, dedupe_key,"
        " what_to_do, summary) VALUES ($1, $2, 'agent', $3, 'warning', $4, 'x', 'x') RETURNING id",
        t,
        rule,
        a,
        f"ratelimit_proximity:agent:{a}",
    )[0]["id"]
    now = T0 + timedelta(seconds=1)
    replica(
        kit,
        t,
        "UPDATE sibyl.routing_state SET operator_hold_until = $3 WHERE tenant_id = $1 AND agent_id"
        " = $2",
        t,
        a,
        now + timedelta(minutes=30),
    )
    snapshot(kit, t, a, T0, band15="0.60", conf="medium", rules=TWO_FAMILIES)
    result = write(kit, t, now, saga)
    assert saga.calls == [] and result.gate_blocked == [(a, "operator_hold")]
    held = kit.in_tenant(t, "SELECT hold_suppressed_count FROM sibyl.alert WHERE id = $1", alert)
    assert held[0]["hold_suppressed_count"] == 1


def _held(kit: Any, t: UUID, alert: UUID) -> tuple[int, datetime | None]:
    row = kit.in_tenant(
        t, "SELECT hold_suppressed_count, hold_suppressed_at FROM sibyl.alert WHERE id = $1", alert
    )[0]
    return row["hold_suppressed_count"], row["hold_suppressed_at"]


def test_hold_suppression_is_stamped_and_counted_once_per_evaluation(
    kit: Any, world: tuple[UUID, UUID]
) -> None:
    """Lane S CR: like ``saga.engine.suppress_for_hold``, P stamps ``hold_suppressed_at`` and
    counts only when the alert was evaluated again since the last suppression."""
    t, a = world
    rule = kit.in_tenant(
        t,
        "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = 'ratelimit_proximity'",
        t,
    )[0]["id"]
    alert = kit.in_tenant(
        t,
        "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, severity, dedupe_key,"
        " what_to_do, summary) VALUES ($1, $2, 'agent', $3, 'warning', $4, 'x', 'x') RETURNING id",
        t,
        rule,
        a,
        f"ratelimit_proximity:agent:{a}",
    )[0]["id"]
    replica(
        kit,
        t,
        "UPDATE sibyl.routing_state SET operator_hold_until = $3 WHERE tenant_id = $1 AND agent_id"
        " = $2",
        t,
        a,
        T0 + timedelta(hours=1),
    )

    def crossing(at: datetime) -> PredictResult:
        snapshot(kit, t, a, at - timedelta(seconds=5))
        snapshot(kit, t, a, at, band15="0.60", conf="medium", rules=TWO_FAMILIES)
        return write(kit, t, at + timedelta(seconds=1), since=at - timedelta(seconds=6))

    assert crossing(T0).gate_blocked == [(a, "operator_hold")]
    count, stamped = _held(kit, t, alert)
    assert count == 1 and stamped is not None
    assert crossing(T0 + timedelta(minutes=1)).gate_blocked == [(a, "operator_hold")]
    assert _held(kit, t, alert) == (1, stamped), "no new evaluation: not counted again"
    kit.in_tenant(t, "UPDATE sibyl.alert SET last_evaluated_at = now() WHERE id = $1", alert)
    crossing(T0 + timedelta(minutes=2))
    count, again = _held(kit, t, alert)
    assert count == 2 and again is not None and again > stamped


@pytest.mark.parametrize(("undone", "mode"), [(1, "auto"), (2, "approval")])
def test_per_agent_breaker_forces_approval_after_two_undone_automations(
    kit: Any, undone: int, mode: str
) -> None:
    kit.ensure_partitions("prediction", T0 - timedelta(days=1), T0 + timedelta(days=2))
    t = kit.tenant()
    a = kit.agent(t, tier=3)
    for n in range(undone):
        undone_automated_transition(kit, t, a, n, T0 - timedelta(days=2))
    undone_automated_transition(kit, t, a, 9, T0 - timedelta(days=9))  # outside 7 d
    saga = FakeSaga()
    snapshot(kit, t, a, T0, band15="0.90", conf="high", rules=TWO_FAMILIES)
    write(kit, t, T0 + timedelta(seconds=1), saga)
    assert [c["mode"] for c in saga.calls] == [mode]


def test_outcomes_are_point_in_time_with_lead_times(kit: Any, world: tuple[UUID, UUID]) -> None:
    t, a = world
    snapshot(kit, t, a, T0, band15="0.25", rules=["ratelimit_proximity"])
    snapshot(
        kit,
        t,
        a,
        T0 + timedelta(minutes=7),
        band15="0.90",
        conf="high",
        rules=["error_rate"],
        health="failed",
    )
    snapshot(kit, t, a, T0 + timedelta(minutes=20), health="failed")  # after the horizon
    write(kit, t, T0 + timedelta(minutes=21))

    async def go() -> dict[str, int]:
        async with kit.worker.tenant_tx(t) as conn:
            return await fill_outcomes(conn, t, T0 + timedelta(hours=2))

    counts = kit.run(go())
    assert counts.get("failed", 0) >= 1
    first = rows(kit, t, a)[0]
    assert first["outcome"] == "failed"
    assert first["lead_time_s"] == 420
    assert first["outcome_at"] == T0 + timedelta(minutes=7)
    day = rows(kit, t, a, 86400)[0]
    assert day["outcome"] is None, "the 24 h horizon has not passed"
    hour = rows(kit, t, a, 3600)[0]
    assert (hour["outcome"], hour["lead_time_s"]) == ("failed", 420)
    last = rows(kit, t, a)[-1]  # predicted at +20 min; nothing failed in the 15 min after it
    assert last["predicted_at"] == T0 + timedelta(minutes=20)
    assert (last["outcome"], last["lead_time_s"]) == ("no_event", None)


def test_loop_tick_writes_predictions_and_resumes(kit: Any, world: tuple[UUID, UUID]) -> None:
    import logging

    from sibyl_control.worker.loops import LoopContext
    from sibyl_control.worker.predict import LOOP, tick

    t, a = world
    saga = FakeSaga()
    from sibyl_control.worker.predict.gate import set_failover_requester

    set_failover_requester(saga)
    at = datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=20)
    kit.ensure_partitions("prediction", at - timedelta(days=1), at + timedelta(days=1))
    snapshot(kit, t, a, at, band15="0.60", conf="medium", rules=TWO_FAMILIES)
    ctx = LoopContext(LOOP, kit.worker, CLOSED, logging.getLogger("t"))
    kit.run(tick(ctx))
    kit.run(tick(ctx))  # the overlap rescan writes nothing twice and calls S once
    assert [r["probability_band"] for r in rows(kit, t, a)] == ["0.60"]
    assert [(c["agent_id"], c["mode"]) for c in saga.calls] == [(a, "approval")]
    assert saga.calls[0]["automation_band"] == "0.90", "the tick hands ctx.settings on"


@pytest.mark.parametrize(("band", "calls"), [("0.90", []), ("0.60", ["degrade_then_auto"])])
def test_tier2_060_crossing_is_offered_only_when_the_setting_opens_the_gate(
    kit: Any, band: str, calls: list[str]
) -> None:
    """B20: the writer's D36 gate is ``Settings.predicted_automation_band``, never the tenant's
    scoring config, and S's entry receives the same Settings."""
    kit.ensure_partitions("prediction", T0 - timedelta(days=1), T0 + timedelta(days=2))
    t = kit.tenant()
    a = kit.agent(t, tier=2)
    saga = FakeSaga()
    snapshot(kit, t, a, T0)
    snapshot(
        kit, t, a, T0 + timedelta(seconds=10), band15="0.60", conf="medium", rules=TWO_FAMILIES
    )
    write(
        kit, t, T0 + timedelta(minutes=1), saga, settings=Settings(predicted_automation_band=band)
    )
    assert [c["mode"] for c in saga.calls] == calls
    assert all(c["automation_band"] == band for c in saga.calls)
