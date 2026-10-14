"""Deterministic PG17 scenarios with lead times (ML.md §8.2 S-02/S-03/S-04/S-05/S-06-like).

Every scenario drives real events through the rollup, the trend state, the health engine with
lane P's extensions and the prediction writer. Lead time is reported two ways: from the first
leading-rule fire (after hysteresis) and from the first 15-minute (or 1-hour) band rise, to the
failure the scenario injects. The ML.md §8.3 gate is ">= 5 min on ramps".
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

import pytest

from .p_sim import FakeSaga, PSim, request, spread

RAMP_GATE = timedelta(minutes=5)
LEADS: dict[str, dict[str, float | None]] = {}


def _minutes(a: datetime | None, b: datetime | None) -> float | None:
    return None if a is None or b is None else round((b - a).total_seconds() / 60, 2)


def report(name: str, **leads: float | None) -> None:
    LEADS[name] = leads
    print(f"\nLEAD {name}: " + ", ".join(f"{k}={v}" for k, v in leads.items()))


def ramp(
    agent: UUID,
    t0: datetime,
    *,
    warm_s: int,
    ramp_s: int,
    n: int = 6,
    start: float = 0.6,
    end: float = 0.02,
) -> Callable[[datetime, datetime], Sequence[dict[str, Any]]]:
    """Headroom ``start -> end`` over ``ramp_s`` after ``warm_s``; then 60 % of calls get 429."""

    def gen(lo: datetime, hi: datetime) -> list[dict[str, Any]]:
        out = []
        for i, ts in enumerate(spread(lo, hi, n)):
            el = (ts - t0).total_seconds()
            if el < warm_s:
                head = start
            elif el < warm_s + ramp_s:
                head = start - (start - end) * (el - warm_s) / ramp_s
            else:
                head = 0.0
            limited = head <= 0.0 and i % 5 < 3
            out.append(
                request(
                    agent,
                    ts,
                    headroom=head,
                    status="error" if limited else "ok",
                    error_class="rate_limit" if limited else None,
                    http_status=429 if limited else 200,
                )
            )
        return out

    return gen


def steady(
    agent: UUID, n: int = 6, *, cost: Callable[[datetime], Decimal] | None = None, **kw: Any
) -> Callable[[datetime, datetime], Sequence[dict[str, Any]]]:
    def gen(lo: datetime, hi: datetime) -> list[dict[str, Any]]:
        return [
            request(agent, ts, cost=cost(ts) if cost else Decimal("0.0001"), **kw)
            for ts in spread(lo, hi, n)
        ]

    return gen


# ---- S-02-like: rate-limit ramp, tiers 2 and 3 ---------------------------------------------------


@pytest.mark.parametrize("tier", [2, 3])
def test_rate_limit_ramp_leads_the_first_429(kit: Any, tier: int) -> None:
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=tier)
    sim = PSim(kit, t, minutes=25)
    t0 = sim.now
    warm, length = 300, 720
    sim.run(warm + length + 360, ramp(a, t0, warm_s=warm, ramp_s=length))
    first_429 = t0 + timedelta(seconds=warm + length)

    l3 = sim.fired_at(a, "ratelimit_proximity")
    rise = sim.band_rise_at(a)
    r1 = sim.fired_at(a, "error_rate")
    report(
        f"rate_limit_ramp_t{tier}",
        l3_fire_min=_minutes(l3, first_429),
        band_025_min=_minutes(rise, first_429),
        detected_r1_after_429_min=_minutes(first_429, r1),
    )
    assert l3 is not None and first_429 - l3 >= RAMP_GATE
    if tier == 2:  # tier 3's L3 cap (15) puts a lone rule at the 0.15 cut only at full severity
        assert rise is not None and first_429 - rise >= timedelta(minutes=2)
    assert r1 is not None and r1 > first_429
    # leading-only evidence never puts the agent past watch before the 429s start
    before = [p for p in sim.points[a] if p.at < first_429]
    assert all(p.band in ("healthy", "watch") for p in before)
    # the detected failure carries "0.90" into the 15-minute horizon with high confidence
    assert any(p.h15 == "0.90" and p.conf15 == "high" for p in sim.points[a])
    # gate closed at "0.60" by default and the detected path owns band "failed": no S call
    assert sim.gate_calls() == []
    rows = sim.predictions_for(a)
    assert rows, "sparse rows written"
    assert {r["source"] for r in rows} == {"rules/v1"}
    assert all(r["probability"] is None for r in rows)


# ---- S-03-like: tier 1 ramp during a provider partial outage -> approval only -------------------


def _ramp_with_partial_outage(kit: Any, tier: int, *, release: bool = False) -> tuple[PSim, UUID]:
    t = kit.tenant()
    pid = kit.provider(t)
    a = kit.agent(t, tier=tier)
    saga = FakeSaga()
    sim = PSim(kit, t, minutes=14, requester=saga)
    if release:
        sim.open_release_gate()
    t0 = sim.now
    warm, length = 180, 600
    traffic = ramp(a, t0, warm_s=warm, ramp_s=length, start=0.4, end=0.02)
    sim.run(warm, traffic)
    sim.provider_status(pid, "partial_outage")
    sim.run(length, traffic)
    return sim, a


def test_tier1_prediction_requests_approval_and_never_auto_acts(kit: Any) -> None:
    sim, a = _ramp_with_partial_outage(kit, tier=1)
    saga = sim.requester
    assert len(saga.calls) == 1, "one call per gate crossing (rising edge)"
    call = saga.calls[0]
    assert call["mode"] == "approval"
    assert call["horizon"] == "15m" and call["band"] in ("0.60", "0.90")
    assert call["confidence"] in ("medium", "high")
    assert all(c["mode"] == "approval" for c in saga.calls)
    crossing = sim.first(a, lambda p: p.h15 in ("0.60", "0.90"))
    report(
        "tier1_partial_outage_ramp",
        gate_crossed_min_after_start=_minutes(sim.points[a][0].at, crossing),
    )
    rows = sim.predictions_for(a)
    called = next(r for r in rows if r["id"] == call["prediction_id"])
    families = {c["family"] for c in called["contributions"]}
    assert len(families) >= 2


def test_tier2_060_band_stays_off_by_default(kit: Any) -> None:
    sim, a = _ramp_with_partial_outage(kit, tier=2)
    assert any(p.h15 == "0.60" for p in sim.points[a]), "the band itself is reported"
    assert sim.requester.calls == []


def test_tier2_with_the_release_gate_open_degrades_then_autos(kit: Any) -> None:
    sim, _ = _ramp_with_partial_outage(kit, tier=2, release=True)
    assert [c["mode"] for c in sim.requester.calls] == ["degrade_then_auto"]


# ---- S-04-like: latency creep on a small model, tier 2 -------------------------------------------


def test_latency_creep_leads_the_detected_p95_rule(kit: Any) -> None:
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=2)
    sim = PSim(kit, t, minutes=38)
    t0 = sim.now
    warm = 600

    def latency(ts: datetime) -> int:  # +35 % per 5-minute window
        el = (ts - t0).total_seconds()
        if el < warm:
            return 1200
        return int(1200 * 1.35 ** (1 + (el - warm) // 300))

    def gen(lo: datetime, hi: datetime) -> list[dict[str, Any]]:
        return [
            request(a, ts, model="gpt-mini", latency_ms=latency(ts)) for ts in spread(lo, hi, 6)
        ]

    sim.run(warm + 1800, gen)
    l2 = sim.fired_at(a, "latency_trend")
    r2 = sim.fired_at(a, "p95_latency")
    report(
        "latency_creep_t2",
        l2_fire_min=_minutes(l2, r2),
        band_025_min=_minutes(sim.band_rise_at(a), r2),
    )
    assert r2 is not None, "the creep crosses the small-model threshold"
    assert l2 is not None and r2 - l2 >= RAMP_GATE


# ---- S-05-like: cost spike, tier 3 ---------------------------------------------------------------


def test_cost_spike_leads_the_budget_breach_by_over_30_minutes(kit: Any) -> None:
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=3, budget=Decimal("100"))
    sim = PSim(kit, t, minutes=52, tick_s=30)
    sim.seed_spend(a, Decimal("50"))
    t0 = sim.now
    warm = 300

    def cost(ts: datetime) -> Decimal:
        return Decimal("0.0005") if (ts - t0).total_seconds() < warm else Decimal("0.035")

    sim.run(warm + 2700, steady(a, 18, cost=cost))
    l4 = sim.fired_at(a, "budget_proximity")
    r5 = sim.fired_at(a, "budget_breach")
    report(
        "cost_spike_t3",
        l4_fire_min=_minutes(l4, r5),
        band_1h_025_min=_minutes(sim.band_rise_at(a, "1h"), r5),
        band_24h_025_min=_minutes(sim.band_rise_at(a, "24h"), r5),
    )
    assert l4 is not None and l4 - t0 <= timedelta(minutes=8), (
        "L4 fires within minutes of the spike"
    )
    assert r5 is not None and r5 - l4 >= timedelta(minutes=30)
    assert sim.points[a][-1].h1h in ("0.25", "0.60", "0.90")


# ---- S-06-like: budget exhaustion mid-month, tier 1 ----------------------------------------------


def test_budget_exhaustion_tier1_fires_l4_at_once_then_r5(kit: Any) -> None:
    t = kit.tenant()
    kit.provider(t)
    a = kit.agent(t, tier=1, budget=Decimal("100"))
    saga = FakeSaga()
    sim = PSim(kit, t, minutes=16, tick_s=30, requester=saga)
    sim.seed_spend(a, Decimal("97"))
    t0 = sim.now
    sim.run(900, steady(a, 15, cost=lambda _ts: Decimal("0.01")))
    l4 = sim.fired_at(a, "budget_proximity")
    r5 = sim.fired_at(a, "budget_breach")
    report(
        "budget_exhaustion_t1", l4_fire_min=_minutes(l4, r5), l4_after_start_min=_minutes(t0, l4)
    )
    # as soon as the agent leaves provisional (50 requests in the hour)
    assert l4 is not None and l4 - t0 <= timedelta(minutes=3)
    assert r5 is not None and r5 > l4
    assert saga.calls == [], "one family (budget) never crosses the gate"
