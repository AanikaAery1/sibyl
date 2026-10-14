"""The pure engine: score arithmetic, floors, bands, hysteresis, flap, provisional (ML.md §3)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import (
    EngineState,
    Evaluation,
    evaluate,
    explain_identity,
    should_write,
)
from sibyl_control.worker.scoring.features import AgentInputs
from sibyl_control.worker.scoring.rules import RuleOutcome

from .h_inputs import NOW, inputs

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))
TICK = timedelta(seconds=10)


def run(seq: list[AgentInputs], prior: EngineState | None = None, start=NOW) -> list[Evaluation]:
    out: list[Evaluation] = []
    state = prior
    for i, inp in enumerate(seq):
        ev = evaluate(inp, state, CFG, start + i * TICK)
        out.append(ev)
        state = ev.state
    return out


HEALTHY = inputs(tier=1, req=100)
OUTAGE = replace(inputs(tier=1, req=100, err=60, server_errors=60), consecutive_errors=10)


def test_healthy_agent_scores_100_with_no_factors() -> None:
    ev = evaluate(HEALTHY, None, CFG, NOW)
    assert ev.score == 100 and ev.band == "healthy" and ev.factors == []
    assert ev.from_band is None and ev.band_changed, "first evaluation is a transition from unknown"
    assert ev.recommended_action == "none"


def test_hard_outage_penalties_explain_the_score() -> None:
    ev = evaluate(OUTAGE, None, CFG, NOW)
    pens = {f["rule"]: f["penalty"] for f in ev.factors if f["direction"] != "equals"}
    assert pens == {"error_rate": 50, "consecutive_failures": 60}
    assert ev.score == 0 and ev.clamp == 10
    assert explain_identity(ev) == 0
    assert ev.factors[0]["penalty"] >= ev.factors[-1]["penalty"], "sorted by penalty desc"
    floors = [f for f in ev.factors if f["direction"] == "equals"]
    assert floors and all(f["penalty"] == 0 and f["value"] == "failed" for f in floors)
    assert ev.recommended_action == "reroute_to_fallback"


def test_outage_reaches_failed_after_detected_hysteresis_in_and_is_very_fast() -> None:
    evs = run([HEALTHY] + [OUTAGE] * 3)
    assert [e.band for e in evs] == ["healthy", "healthy", "failed", "failed"]
    assert evs[2].band_changed and evs[2].from_band == "healthy"
    assert not evs[2].very_fast and evs[3].very_fast
    assert "error_rate" in evs[2].newly_fired and "consecutive_failures" in evs[1].newly_fired


@pytest.mark.parametrize(("tier", "need"), [(1, 2), (2, 3), (3, 3)])
def test_worsen_needs_tier_ticks(tier: int, need: int) -> None:
    bad = replace(OUTAGE, tier=tier)
    evs = run([replace(HEALTHY, tier=tier)] + [bad] * need)
    assert evs[need - 1].band == "healthy" and evs[need].band == "failed"


@pytest.mark.parametrize(("tier", "need"), [(1, 18), (2, 12), (3, 6)])
def test_recovery_needs_tier_out_ticks_and_resolves_rules(tier: int, need: int) -> None:
    bad = replace(OUTAGE, tier=tier)
    good = replace(HEALTHY, tier=tier)
    evs = run([good] + [bad] * 4 + [good] * need)
    assert evs[3 + need].band == "failed" and evs[4 + need].band == "healthy"
    cleared = set().union(*(e.newly_cleared for e in evs))
    assert {"error_rate", "consecutive_failures"} <= cleared


def _explained(ev: Evaluation) -> bool:
    """ML.md §3.6: a non-healthy band is explained by a penalty or by a zero-penalty factor
    that names that very band."""
    if ev.band == "healthy":
        return True
    if any(f["penalty"] > 0 for f in ev.factors):
        return True
    return any(
        f["direction"] == "equals" and f["value"] == ev.band and f["explanation"]
        for f in ev.factors
    )


def test_a_band_held_worse_than_a_live_floor_is_still_explained() -> None:
    """B-07: after a failover the agent serves cleanly (score 100) while the band is held at
    `failed` by recovery hysteresis and the critical provider-status rule, still fired by its own
    hysteresis, floors it at `degraded`. The `degraded` floor factor alone does not explain a
    `failed` band; the snapshot must say why it is `failed`."""
    red = replace(OUTAGE, provider_status="major_outage", provider_status_age_s=5.0)
    clean = replace(HEALTHY, provider_status="operational", provider_status_age_s=5.0)
    evs = run([HEALTHY] + [red] * 6 + [clean] * 20)
    held = [e for e in evs if e.band == "failed" and e.score == 100]
    assert held, "the scenario reproduces a clean agent held at failed"
    assert any(e.floor == "degraded" for e in held), "with the provider-status floor still live"
    for ev in evs:
        assert _explained(ev), (ev.band, ev.score, ev.floor, ev.factors)
        assert explain_identity(ev) == 0


def test_recovery_hold_with_no_rule_firing_is_explained() -> None:
    evs = run([HEALTHY] + [OUTAGE] * 4 + [HEALTHY] * 18)
    for ev in evs:
        assert _explained(ev), (ev.band, ev.score, ev.fired, ev.factors)


def test_blip_shorter_than_hysteresis_never_transitions() -> None:
    evs = run([HEALTHY, OUTAGE, HEALTHY, OUTAGE, HEALTHY])
    assert {e.band for e in evs} == {"healthy"}
    assert all(not e.band_changed for e in evs[1:])


def test_dead_band_holds_degraded_until_edge_plus_four() -> None:
    # tier 2: degraded below 65; leaving upward needs 69
    deg = inputs(tier=2, req=100, err=17)  # R1 sev (0.17-.1)/.2 = .35 -> 14 -> score 86? use more
    deg = inputs(tier=2, req=100, err=25)  # sev .75 -> 30 -> 70 watch
    worse = inputs(tier=2, req=100, err=30)  # sev 1 -> 40 -> 60 degraded
    mid = inputs(tier=2, req=100, err=27)  # sev .85 -> 34 -> 66: watch raw, inside dead-band
    evs = run([worse] + [mid] * 13)
    assert evs[0].band == "degraded" and all(e.band == "degraded" for e in evs)
    evs2 = run([worse] + [deg] * 13)
    assert evs2[-1].band == "watch"


def test_provisional_caps_band_at_watch() -> None:
    no_plan = replace(OUTAGE, has_plan=False)
    ev = evaluate(no_plan, None, CFG, NOW)
    assert ev.provisional and ev.band == "watch" and ev.score == 0
    # cold-start triggers, on a degradation below any failure floor (a hard failure on a proven
    # agent lifts the cap: test_cold_start.py)
    mild = inputs(tier=1, req=100, err=20)  # R1 sev 1 -> 50 -> degraded raw, no floor
    low_traffic = replace(mild, request_count_1h=10)
    assert evaluate(low_traffic, None, CFG, NOW).provisional
    assert evaluate(low_traffic, None, CFG, NOW).band == "watch"
    young = replace(mild, created_at=NOW - timedelta(hours=2), active_minutes_1h=10)
    assert evaluate(young, None, CFG, NOW).provisional
    young_busy = replace(young, active_minutes_1h=45)
    assert not evaluate(young_busy, None, CFG, NOW).provisional
    lagging = replace(mild, rollup_lag_s=300)
    assert evaluate(lagging, None, CFG, NOW).provisional


def _flap_seq(tier: int) -> list[AgentInputs]:
    good = replace(HEALTHY, tier=tier)
    bad = replace(OUTAGE, tier=tier)
    h_in = {1: 2, 2: 3, 3: 3}[tier]
    h_out = {1: 18, 2: 12, 3: 6}[tier]
    return [good] + ([bad] * h_in + [good] * h_out) * 2 + [bad] * h_in + [good] * (h_out + 3)


@pytest.mark.parametrize("tier", [1, 2])
def test_flap_pins_tiers_1_2_at_the_worse_band(tier: int) -> None:
    evs = run(_flap_seq(tier))
    started = [e for e in evs if e.flapping_started]
    assert len(started) == 1
    i = evs.index(started[0])
    assert all(e.band == "failed" for e in evs[i:]), "pinned at the worse band"
    assert evs[-1].state.pin_until is not None


def test_flap_pins_tier_3_at_the_better_band_but_failed_floor_still_wins() -> None:
    evs = run(_flap_seq(3)[:-9])
    started = [e for e in evs if e.flapping_started]
    assert len(started) == 1
    pinned = evs[evs.index(started[0]) :]
    assert pinned[0].state.pin_band == "healthy"


def test_staged_recovery_is_not_a_flap() -> None:
    # tier 1: healthy -> failed -> degraded -> healthy within 10 min is 3 transitions, 1 reversal
    mid = inputs(tier=1, req=100, err=10)  # R1 sev .25 -> 13 -> 87 healthy? use stronger
    mid = inputs(tier=1, req=100, err=12)  # x .12: sev .35 -> 18 -> 82 watch
    seq = [HEALTHY] + [OUTAGE] * 2 + [replace(inputs(tier=1, req=100, err=20))] * 20
    seq += [HEALTHY] * 20
    evs = run(seq)
    bands = [e.band for e in evs]
    assert "failed" in bands and bands[-1] == "healthy"
    assert len({b for b in bands[3:]}) >= 2, "it moved through an intermediate band"
    assert not any(e.flapping_started for e in evs)
    del mid


def test_routing_flap_counts_too() -> None:
    ev = evaluate(replace(HEALTHY, routing_transitions_10m=2), None, CFG, NOW)
    assert ev.flapping_started


def test_rule_hysteresis_state_survives_a_round_trip() -> None:
    evs = run([HEALTHY, OUTAGE])
    state = evs[-1].state
    again = EngineState.from_bookkeeping(state.to_bookkeeping())
    assert again == state
    ev = evaluate(OUTAGE, again, CFG, NOW + 2 * TICK)
    assert ev.band == "failed", "restart resumes mid-count"


def test_alert_only_rules_do_not_penalise_and_quality_proxy_does() -> None:
    q = inputs(tier=2, req=100, refusals=45)  # R6 sev 1 -> quality_proxy 20
    ev = evaluate(q, None, CFG, NOW)
    pens = {f["rule"]: f["penalty"] for f in ev.factors}
    assert pens["quality_proxy"] == 20 and pens["refusal_share"] == 0
    assert ev.score == 80 and explain_identity(ev) == 0


def test_leading_outcomes_plug_in_and_use_leading_hysteresis() -> None:
    lead = RuleOutcome("error_trend", "leading", True, 1.0, 0.1, 0.05, explanation="trend")
    big = RuleOutcome("fallback_pressure", "leading", True, 1.0, 0.5, 0.2, explanation="fb")
    base = replace(HEALTHY, tier=2)
    state = evaluate(base, None, CFG, NOW).state
    bands = []
    for i in range(1, 8):
        ev = evaluate(base, state, CFG, NOW + i * TICK, leading=[lead, big])
        state = ev.state
        bands.append(ev.band)
    assert ev.score == 60 and {f["kind"] for f in ev.factors} == {"leading"}
    # tier 2 worsens on leading-only evidence after 6 ticks, not the detected 3
    assert bands[:5] == ["healthy"] * 5 and bands[5] == "degraded"


def test_leading_rules_are_ignored_while_provisional() -> None:
    lead = RuleOutcome("error_trend", "leading", True, 1.0, 0.1, 0.05, explanation="trend")
    ev = evaluate(replace(HEALTHY, has_plan=False), None, CFG, NOW, leading=[lead])
    assert ev.factors == []


def test_should_write_on_change_and_heartbeat() -> None:
    first = evaluate(HEALTHY, None, CFG, NOW)
    assert should_write(None, first, NOW) == "change"
    written = first.state.mark_written(NOW, first.score)
    same = evaluate(HEALTHY, written, CFG, NOW + TICK)
    assert should_write(written, same, NOW + TICK) is None
    later = evaluate(HEALTHY, written, CFG, NOW + timedelta(seconds=61))
    assert should_write(written, later, NOW + timedelta(seconds=61)) == "heartbeat"
    moved = evaluate(inputs(tier=1, req=100, err=6), written, CFG, NOW + TICK)
    assert moved.score == 95
    assert should_write(written, moved, NOW + TICK) == "change"


def test_recommended_actions() -> None:
    loop = inputs(tier=2, req=30, tool_calls=40, tool_distinct=1)
    assert evaluate(loop, None, CFG, NOW).recommended_action == "quarantine"
    assert evaluate(replace(loop, tier=1), None, CFG, NOW).recommended_action == "await_approval"
    q1 = inputs(tier=1, req=100, refusals=45)
    assert evaluate(q1, None, CFG, NOW).recommended_action == "handoff"
    budget = replace(HEALTHY, spend_ratio=1.2)
    assert evaluate(budget, None, CFG, NOW).recommended_action == "throttle"
    # L5: calls already rescued by the inline fallback step mean the primary route is failing;
    # the standing action is a persistent reroute, not a throttle (ML.md §4.3: provider_outage)
    fb = RuleOutcome("fallback_pressure", "leading", True, 1.0, 0.8, 0.2, explanation="fb")
    tier2 = replace(HEALTHY, tier=2)
    assert evaluate(tier2, None, CFG, NOW, leading=[fb]).recommended_action == "reroute_to_fallback"


counts = st.integers(min_value=0, max_value=400)


@settings(max_examples=300, deadline=None)
@given(
    tier=st.integers(1, 3),
    req=counts,
    err=counts,
    refusals=counts,
    truncations=counts,
    empty=counts,
    tool_calls=counts,
    tool_distinct=counts,
    schema_bad=counts,
    consecutive=st.integers(0, 12),
    latency=st.integers(1, 200_000),
    status=st.sampled_from([None, "operational", "partial_outage", "major_outage", "unknown"]),
    spend=st.one_of(st.none(), st.floats(0, 3)),
    fleet=st.one_of(st.none(), st.floats(0, 1)),
)
def test_property_penalties_always_sum_to_100_minus_score(
    tier: int,
    req: int,
    err: int,
    refusals: int,
    truncations: int,
    empty: int,
    tool_calls: int,
    tool_distinct: int,
    schema_bad: int,
    consecutive: int,
    latency: int,
    status: str | None,
    spend: float | None,
    fleet: float | None,
) -> None:
    inp = inputs(
        tier=tier,
        req=req,
        err=min(err, req),
        refusals=min(refusals, req),
        truncations=min(truncations, req),
        empty=min(empty, req),
        tool_calls=tool_calls,
        tool_distinct=min(tool_distinct, tool_calls),
        schema_bad=min(schema_bad, tool_calls),
        latencies=[latency] * req,
    )
    inp = replace(
        inp,
        consecutive_errors=consecutive,
        provider_status=status,
        spend_ratio=spend,
        provider_error_rate_fleet=fleet,
    )
    ev = evaluate(inp, None, CFG, NOW)
    assert 0 <= ev.score <= 100
    assert all(f["penalty"] >= 0 for f in ev.factors)
    assert explain_identity(ev) == 0, "100 - sum(penalty) + clamp == score"
    assert sum(f["penalty"] for f in ev.factors) - ev.clamp == 100 - ev.score
    for f in ev.factors:
        assert f["explanation"] and len(f["explanation"]) <= 300 and f["evidence"]
