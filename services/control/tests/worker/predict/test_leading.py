"""Leading rules L1-L5 and the provider-status facet as pure functions (ML.md §4.3)."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sibyl_control.worker.predict.feed import EMPTY_FEED
from sibyl_control.worker.predict.leading import (
    budget_facets,
    budget_proximity,
    cusum_severity,
    error_trend,
    evaluate_leading,
    fallback_pressure,
    latency_trend,
    lsq_slope,
    provider_facet,
    ratelimit_proximity,
    rising,
    time_to_exhaustion_s,
)

from .p_inputs import NOW, feed, headroom_ramp, inputs, seed_config

CFG = seed_config()


def test_rising_needs_three_positive_deltas() -> None:
    assert rising([0.01, 0.02, 0.03, 0.04])
    assert not rising([0.01, 0.02, 0.02, 0.04])
    assert not rising([0.02, 0.03, 0.04])
    assert not rising([0.01, None, 0.03, 0.04])


def test_lsq_slope_and_time_to_exhaustion() -> None:
    assert lsq_slope([(0, 1.0), (1, 2.0), (2, 3.0)]) == pytest.approx(1.0)
    assert lsq_slope([(0, 1.0), (1, 2.0)]) is None
    f = feed(headroom=headroom_ramp(0.30, 0.03))  # 0.03 per minute lost
    assert time_to_exhaustion_s(f, 0.30) == pytest.approx(600, rel=0.01)
    assert time_to_exhaustion_s(feed(headroom=headroom_ramp(0.3, -0.01)), 0.3) is None


def test_cusum_severity_is_the_drift_curve() -> None:
    assert cusum_severity(5.0, 5.0) == 0
    assert cusum_severity(7.5, 5.0) == pytest.approx(0.25)
    assert cusum_severity(20.0, 5.0) == pytest.approx(0.5)


# ---- L1 -----------------------------------------------------------------------------------------


def test_l1_fires_on_three_rising_windows_above_half_the_detected_threshold() -> None:
    inp = inputs(tier=2)  # R1 threshold tier 2 = 0.10
    f = feed(error_series=(0.02, 0.04, 0.06, 0.08), error_ewma=0.075)
    out = error_trend(inp, f, CFG, NOW)
    assert out.evaluated and out.kind == "leading"
    assert out.severity == pytest.approx((0.075 / 0.10 - 0.5) / 0.5)
    assert out.hint == "provider_outage"
    assert "rising" in out.explanation and out.evidence.startswith("/api/v1/events")


def test_l1_stays_quiet_below_the_arming_level_or_without_a_rise() -> None:
    low = feed(error_series=(0.01, 0.02, 0.03, 0.04), error_ewma=0.04)
    flat = feed(error_series=(0.08, 0.08, 0.08, 0.08), error_ewma=0.08)
    assert error_trend(inputs(), low, CFG, NOW).severity == 0
    assert error_trend(inputs(), flat, CFG, NOW).severity == 0


def test_l1_cusum_alarm_fires_even_when_the_level_is_low() -> None:
    f = feed(error_series=(0.01,) * 4, error_ewma=0.03, error_cusum=7.5)
    out = error_trend(inputs(), f, CFG, NOW)
    assert out.severity == pytest.approx(0.25)
    assert "CUSUM" in out.explanation


def test_l1_needs_samples_and_trend_state() -> None:
    assert not error_trend(inputs(), feed(closed_requests=5, error_ewma=0.1), CFG, NOW).evaluated
    assert not error_trend(inputs(), feed(), CFG, NOW).evaluated
    assert not error_trend(inputs(), EMPTY_FEED, CFG, NOW).evaluated


def test_l1_failure_mode_follows_the_dominant_error_class() -> None:
    f = feed(error_series=(0.02, 0.04, 0.06, 0.08), error_ewma=0.08)
    assert error_trend(inputs(timeouts=5, err=5), f, CFG, NOW).hint == "latency_degradation"


# ---- L2 -----------------------------------------------------------------------------------------


def test_l2_fires_near_the_model_class_threshold_when_rising() -> None:
    inp = inputs(model_class="small")  # R2 small = 5000 ms, arm 0.8 -> 4000
    f = feed(p95_series=(2000.0, 3000.0, 4000.0, 4600.0), p95_ewma=4500.0)
    out = latency_trend(inp, f, CFG, NOW)
    assert out.severity == pytest.approx((4500 / 5000 - 0.8) / 0.2)
    assert out.hint == "latency_degradation"


def test_l2_relative_path_needs_an_own_baseline() -> None:
    f = feed(p95_series=(1000.0, 1000.0, 1200.0, 1800.0), p95_ewma=1300.0)
    seed = inputs(baselines={"latency_p95_ms": 1000.0}, baseline_ref="seed/v1")
    own = inputs(baselines={"latency_p95_ms": 1000.0}, baseline_ref="own/how4w")
    assert latency_trend(seed, f, CFG, NOW).severity == 0
    assert latency_trend(own, f, CFG, NOW).severity == pytest.approx((1.8 - 1.5) / 0.5)


# ---- L3 -----------------------------------------------------------------------------------------


def test_l3_headroom_below_the_tier_threshold() -> None:
    out = ratelimit_proximity(inputs(tier=2, headroom=0.05), EMPTY_FEED, CFG, NOW)
    assert out.severity == pytest.approx((0.10 - 0.05) / 0.10)
    assert out.direction == "below"


def test_l3_time_to_exhaustion_fires_before_the_level_does() -> None:
    f = feed(headroom=headroom_ramp(0.40, 0.05))  # 8 minutes left
    out = ratelimit_proximity(inputs(tier=2), f, CFG, NOW)
    assert out.severity == pytest.approx((900 - 480) / 900, rel=0.02)
    assert "exhaustion" in out.explanation


def test_l3_429_share() -> None:
    out = ratelimit_proximity(inputs(req=100, rate_limited=9, err=9), EMPTY_FEED, CFG, NOW)
    assert out.severity == pytest.approx(0.09 / 0.15)


def test_l3_without_any_signal_is_not_evaluated() -> None:
    assert not ratelimit_proximity(inputs(req=2), EMPTY_FEED, CFG, NOW).evaluated


def test_l3_comfortable_headroom_is_zero() -> None:
    f = feed(headroom=headroom_ramp(0.8, 0.0))
    assert ratelimit_proximity(inputs(), f, CFG, NOW).severity == 0


# ---- L4 -----------------------------------------------------------------------------------------


def test_l4_projects_one_hour_and_one_day_ahead() -> None:
    rule = CFG.rule("budget_proximity")
    f = feed(budget=100.0, mtd=50.0, rate_s=45.0 / 3600)  # +45 USD per hour
    facets = budget_facets(inputs(), f, rule)
    assert facets is not None
    assert facets.projected_1h == pytest.approx(0.95)
    assert facets.severity_1h == pytest.approx(0.5)
    assert facets.severity_24h == 1.0
    assert budget_proximity(inputs(), f, CFG, NOW).hint == "cost_runaway"


def test_l4_slow_burn_only_trips_the_24h_facet() -> None:
    rule = CFG.rule("budget_proximity")
    f = feed(budget=100.0, mtd=50.0, rate_s=3.0 / 3600)  # 72 USD a day
    facets = budget_facets(inputs(), f, rule)
    assert facets is not None and facets.severity_1h == 0 and facets.severity_24h == 1.0


def test_l4_falls_back_to_the_spend_level_and_skips_without_a_budget() -> None:
    out = budget_proximity(inputs(spend_ratio=0.97), EMPTY_FEED, CFG, NOW)
    assert out.severity == pytest.approx(0.7)
    assert not budget_proximity(inputs(), EMPTY_FEED, CFG, NOW).evaluated


@given(
    st.floats(min_value=0, max_value=200),
    st.floats(min_value=0, max_value=0.05),
    st.floats(min_value=0, max_value=0.05),
)
def test_l4_severity_is_monotone_in_the_burn_rate(mtd: float, rate: float, more: float) -> None:
    rule = CFG.rule("budget_proximity")
    a = budget_facets(inputs(), feed(budget=100.0, mtd=mtd, rate_s=rate), rule)
    b = budget_facets(inputs(), feed(budget=100.0, mtd=mtd, rate_s=rate + more), rule)
    assert a is not None and b is not None
    assert b.severity_1h >= a.severity_1h and b.severity_24h >= a.severity_24h


# ---- provider facet -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "severity"),
    [
        ("maintenance", 0.15),
        ("degraded_performance", 0.33),
        ("partial_outage", 0.58),
        ("major_outage", 0.0),
        ("operational", 0.0),
        (None, 0.0),
    ],
)
def test_provider_facet_ordinal(status: str | None, severity: float) -> None:
    assert provider_facet(inputs(provider_status=status), CFG) == pytest.approx(severity)


def test_provider_facet_steps_aside_once_the_agent_errors() -> None:
    inp = inputs(provider_status="partial_outage", req=100, err=20, server_errors=20)
    assert provider_facet(inp, CFG) == 0


def test_evaluate_leading_returns_the_phase1_rules_in_order() -> None:
    codes = [o.code for o in evaluate_leading(inputs(), EMPTY_FEED, CFG, NOW)]
    assert codes == [
        "error_trend",
        "latency_trend",
        "ratelimit_proximity",
        "budget_proximity",
        "fallback_pressure",
    ]


# ------------------------------------------------------------------------------- L5


def rescued(tier: int, req: int, inline: int, breaker: int = 0):  # type: ignore[no-untyped-def]
    """``req`` calls in the open 5 minutes, ``inline`` of them served by the inline fallback."""
    inp = inputs(tier=tier, req=req)
    w5 = replace(inp.w5, inline_fallback_count=inline, breaker_open_count=breaker)
    return replace(inp, w5=w5, w1=w5)


@pytest.mark.parametrize(
    ("tier", "share", "severity"),
    [
        (2, 0.2, 0.0),  # at the tier-2 threshold: quiet
        (2, 0.4, 0.5),  # (0.4 - 0.2) / 0.4
        (2, 1.0, 1.0),  # saturated: every call needed the fallback
        (1, 0.3, 0.5),  # tier 1 threshold 0.10
        (3, 0.45, 0.5),  # tier 3 threshold 0.25
    ],
)
def test_l5_severity_is_the_share_above_the_tier_threshold(
    tier: int, share: float, severity: float
) -> None:
    out = fallback_pressure(rescued(tier, 100, round(share * 100)), EMPTY_FEED, CFG, NOW)
    assert out.evaluated and out.kind == "leading"
    assert out.severity == pytest.approx(severity)
    assert out.value == pytest.approx(share) and out.threshold == CFG.rule(out.code).threshold(tier)
    assert out.hint == "provider_outage", "ML.md §4.3: L5 predicts a provider outage"
    assert "inline fallback" in out.explanation and "/api/v1/events" in out.evidence


def test_l5_counts_open_breakers_too() -> None:
    out = fallback_pressure(rescued(2, 100, 20, breaker=20), EMPTY_FEED, CFG, NOW)
    assert out.value == pytest.approx(0.4) and out.severity == pytest.approx(0.5)
    assert "breaker" in out.explanation


def test_l5_needs_min_samples() -> None:
    out = fallback_pressure(rescued(2, 19, 19), EMPTY_FEED, CFG, NOW)
    assert not out.evaluated and out.severity == 0 and "needs 20" in out.explanation


@given(st.integers(20, 400), st.integers(0, 400), st.integers(0, 400))
def test_l5_severity_is_bounded_and_monotone(req: int, a: int, b: int) -> None:
    lo, hi = sorted((min(a, req), min(b, req)))
    s_lo = fallback_pressure(rescued(2, req, lo), EMPTY_FEED, CFG, NOW).severity
    s_hi = fallback_pressure(rescued(2, req, hi), EMPTY_FEED, CFG, NOW).severity
    assert 0 <= s_lo <= s_hi <= 1
