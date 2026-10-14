"""Cold start vs hard failures (ML.md §3.8; the live detection gap, wave 3 lane HARNESS).

Live finding (demo stack, 2026-10-11): tier-3 ``kb-summarizer`` was created at 06:43:15, served
148 healthy calls, then hit a 100 % 503 outage at 06:46. Both ``error_rate`` and
``consecutive_failures`` fired and set the ``failed`` floor, but the agent was still provisional
(under a day old, under 30 active minutes), so the band was clamped to ``watch`` (score 30),
alerts were capped at ``warning`` and the saga never saw a ``failed`` band.

The cap exists to keep a genuinely new agent's teething noise out of automation. A detected
failure floor on an agent that has *proven* a working baseline is not noise: these tests pin the
boundary between the two.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.engine import EngineState, Evaluation, evaluate, explain_identity
from sibyl_control.worker.scoring.features import AgentInputs

from .h_inputs import NOW, inputs

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))
TICK = timedelta(seconds=10)

# 60 % 5xx over 100 calls in 5 minutes and 10 consecutive failures: both failed floors.
OUTAGE = replace(inputs(tier=3, req=100, err=60, server_errors=60), consecutive_errors=10)
HEALTHY = inputs(tier=3, req=100)


def young(inp: AgentInputs, *, minutes: int = 3, ok_1h: int, err_1h: int) -> AgentInputs:
    """An agent created ``minutes`` ago with ``ok_1h`` healthy and ``err_1h`` failed calls."""
    return replace(
        inp,
        created_at=NOW - timedelta(minutes=minutes),
        active_minutes_1h=5,
        request_count_1h=ok_1h + err_1h,
        error_count_1h=err_1h,
    )


def run(seq: list[AgentInputs], prior: EngineState | None = None) -> list[Evaluation]:
    out: list[Evaluation] = []
    state = prior
    for i, inp in enumerate(seq):
        ev = evaluate(inp, state, CFG, NOW + i * TICK)
        out.append(ev)
        state = ev.state
    return out


def floors(ev: Evaluation) -> list[dict]:
    return [f for f in ev.factors if f["direction"] == "equals"]


def test_live_replay_hard_outage_after_proven_traffic_reaches_failed() -> None:
    # the demo numbers: 148 healthy calls, then 280 failures, three minutes after creation
    outage = young(OUTAGE, ok_1h=148, err_1h=280)
    evs = run([young(HEALTHY, ok_1h=148, err_1h=0)] + [outage] * 3)
    assert evs[0].provisional, "a 3-minute-old agent is in cold start while it is healthy"
    assert [e.band for e in evs] == ["healthy", "healthy", "healthy", "failed"]
    last = evs[-1]
    assert not last.provisional, "a proven agent's hard failure is not cold-start noise"
    assert last.floor == "failed" and last.score == 30
    assert last.recommended_action == "reroute_to_fallback"
    assert any("cold-start cap lifted" in f["explanation"] for f in floors(last))
    assert explain_identity(last) == 0


def test_agent_failing_since_its_first_call_stays_capped_at_watch() -> None:
    # never served a healthy call: a misconfigured new deployment, not an outage to fail over
    broken = young(OUTAGE, ok_1h=0, err_1h=120)
    evs = run([broken] * 5)
    assert all(e.provisional and e.band == "watch" for e in evs)
    assert evs[-1].floor == "failed", "the evidence is still shown"


def test_too_little_healthy_traffic_keeps_the_cap() -> None:
    thin = young(OUTAGE, ok_1h=49, err_1h=200)
    assert run([thin] * 4)[-1].band == "watch"
    proven = young(OUTAGE, ok_1h=50, err_1h=200)
    assert run([proven] * 4)[-1].band == "failed"


def test_young_agent_with_errors_below_the_failure_floor_stays_capped() -> None:
    # 40 % errors on tier 3: R1 penalises (score 70 -> degraded raw) but no failed floor
    noisy = young(inputs(tier=3, req=100, err=40, server_errors=40), ok_1h=300, err_1h=40)
    evs = run([noisy] * 5)
    assert evs[-1].floor is None
    assert all(e.provisional and e.band in ("healthy", "watch") for e in evs)


def test_established_low_volume_agent_is_not_held_by_the_volume_gate() -> None:
    # 30 days old, a quiet hour (40 calls) and a hard outage: request_count_1h < 50 alone used
    # to cap it at watch forever
    quiet = replace(OUTAGE, request_count_1h=40, error_count_1h=30)
    evs = run([replace(HEALTHY, request_count_1h=40)] + [quiet] * 3)
    assert evs[0].provisional
    assert evs[-1].band == "failed" and not evs[-1].provisional


def test_no_plan_keeps_the_cap_even_for_an_old_proven_agent() -> None:
    no_plan = replace(OUTAGE, has_plan=False)
    evs = run([no_plan] * 4)
    assert all(e.provisional and e.band == "watch" for e in evs)


def test_rollup_lag_keeps_the_cap() -> None:
    stale = replace(young(OUTAGE, ok_1h=148, err_1h=280), rollup_lag_s=300)
    assert all(e.provisional and e.band == "watch" for e in run([stale] * 4))


def test_lift_is_sticky_while_the_failure_floor_holds() -> None:
    # a long outage ages the healthy calls out of the hour: the failed band must not fall back
    # to watch (and flap) while the agent is still failing
    start = young(OUTAGE, ok_1h=148, err_1h=280)
    later = young(OUTAGE, minutes=70, ok_1h=0, err_1h=900)
    evs = run([start] * 3 + [later] * 4)
    assert evs[2].band == "failed"
    assert all(e.band == "failed" and not e.provisional for e in evs[3:])


def test_cap_returns_once_the_failure_clears() -> None:
    evs = run([young(OUTAGE, ok_1h=148, err_1h=280)] * 3 + [young(HEALTHY, ok_1h=200, err_1h=280)])
    assert evs[2].band == "failed"
    assert evs[3].provisional and evs[3].floor is None


def test_aged_agent_with_traffic_is_never_provisional() -> None:
    assert not evaluate(OUTAGE, None, CFG, NOW).provisional
    assert not evaluate(HEALTHY, None, CFG, NOW).provisional


# ------------------------------------------------- band held by recovery hysteresis (S-22)


def test_band_held_by_recovery_hysteresis_is_explained() -> None:
    # S-22: tier-1 billing-agent fails over, serves clean on the fallback, and its band stays
    # degraded for 18 clean ticks with score 100: the snapshot must still say why
    bad = replace(OUTAGE, tier=1)
    good = replace(HEALTHY, tier=1)
    evs = run([good] + [bad] * 3 + [good] * 5)
    held = evs[-1]
    assert held.score == 100 and held.band == "failed"
    assert [f["penalty"] for f in held.factors] == [0] * len(held.factors) and held.factors
    f = held.factors[0]
    assert f["direction"] == "equals" and f["value"] == "failed" and f["threshold"] == "healthy"
    assert f["rule"] in held.fired and "5 of 18 clean ticks" in f["explanation"]
    assert explain_identity(held) == 0


def test_healthy_or_penalised_snapshots_carry_no_hold_factor() -> None:
    evs = run([HEALTHY, HEALTHY])
    assert evs[-1].factors == []
    out = run([OUTAGE] * 4)[-1]
    assert all("held" not in f["explanation"] for f in out.factors)
