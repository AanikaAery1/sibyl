"""The rules/v1 horizon predictor on real engine evaluations (ML.md §4.2, §4.4)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sibyl_control.core.risk import RiskDocument
from sibyl_control.worker.predict import horizons_extension, leading_extension
from sibyl_control.worker.predict.bands import BAND_RANK
from sibyl_control.worker.predict.feed import AgentFeed, Feed, install, reset
from sibyl_control.worker.predict.horizons import predict_horizons
from sibyl_control.worker.predict.leading import evaluate_leading
from sibyl_control.worker.scoring.engine import evaluate
from sibyl_schemas.models.health import Horizons

from .p_inputs import AGENT, NOW, feed, headroom_ramp, inputs, run_ticks, seed_config

CFG = seed_config()
LEAD_TICKS = 13  # past every leading hysteresis_in (6 on tiers 1-2, 12 on tier 3)


def horizons_for(inp: Any, f: AgentFeed, ticks: int = LEAD_TICKS) -> tuple[dict[str, Any], Any]:
    ev = run_ticks(inp, CFG, lambda i, c, n: evaluate_leading(i, f, c, n), ticks)
    doc, mode = predict_horizons(inp, ev, CFG, NOW, f)
    return doc, (ev, mode)


def test_quiet_agent_is_005_low_everywhere_and_valid_sibyl_health() -> None:
    doc, (_, mode) = horizons_for(inputs(), feed())
    assert {k: v["probability_band"] for k, v in doc.items()} == {
        "15m": "0.05",
        "1h": "0.05",
        "24h": "0.05",
    }
    assert all(v["confidence"] == "low" and v["source"] == "rules/v1" for v in doc.values())
    assert mode is None
    Horizons.model_validate(doc)


def test_rate_limit_ramp_lifts_15m_and_1h_but_not_24h() -> None:
    f = feed(headroom=headroom_ramp(0.10, 0.06))  # ~100 s to exhaustion
    doc, (ev, mode) = horizons_for(inputs(tier=1, headroom=0.10), f)
    assert "ratelimit_proximity" in ev.fired
    assert doc["15m"]["probability_band"] == "0.25"
    assert doc["15m"]["contributing_rules"] == ["ratelimit_proximity"]
    assert doc["1h"]["probability_band"] == "0.25"
    assert doc["24h"]["probability_band"] == "0.05"
    assert mode == "provider_outage"


def test_leading_rules_count_only_after_their_hysteresis() -> None:
    f = feed(headroom=headroom_ramp(0.10, 0.06))
    doc, (ev, _) = horizons_for(inputs(tier=2, headroom=0.10), f, ticks=3)
    assert "ratelimit_proximity" not in ev.fired
    assert doc["15m"]["probability_band"] == "0.05"


@pytest.mark.parametrize(("coverage", "confidence"), [(1.0, "high"), (0.9, "medium")])
def test_two_families_reach_060(coverage: float, confidence: str) -> None:
    """L3 near exhaustion plus a provider partial outage: two strong rules, two SLI families.

    Both severities are >= 0.5, so full coverage makes it ``high`` (§4.4); below 0.95 it is the
    single-strong-rule ``medium``.
    """
    f = feed(headroom=headroom_ramp(0.05, 0.05))
    inp = inputs(
        tier=1,
        headroom=0.05,
        provider_status="partial_outage",
        provider_status_age_s=30,
        coverage=coverage,
    )
    doc, _ = horizons_for(inp, f)
    assert doc["15m"]["probability_band"] == "0.60"
    assert doc["15m"]["confidence"] == confidence
    assert set(doc["15m"]["contributing_rules"]) == {"ratelimit_proximity", "provider_status"}


def test_failed_band_carries_090_high_into_15m_and_1h() -> None:
    doc, (ev, mode) = horizons_for(inputs(req=100, err=60, server_errors=60), feed(), ticks=4)
    assert ev.band == "failed" and ev.floor == "failed"
    assert doc["15m"]["probability_band"] == "0.90" and doc["15m"]["confidence"] == "high"
    assert doc["1h"]["probability_band"] == "0.90"
    assert doc["24h"]["probability_band"] == "0.05"
    assert doc["15m"]["contributing_rules"][0] == "error_rate"
    assert mode == "provider_outage"


def test_budget_facets_feed_1h_and_24h_only() -> None:
    f = feed(budget=100.0, mtd=50.0, rate_s=45.0 / 3600)
    doc, (_, mode) = horizons_for(inputs(), f)
    assert doc["15m"]["probability_band"] == "0.05"
    assert doc["1h"]["contributing_rules"] == ["budget_proximity"]
    assert doc["24h"]["contributing_rules"] == ["budget_proximity"]
    assert doc["24h"]["confidence"] == "low"
    # 1 h: 15 % cap x 0.5 = 0.075 -> "0.05"; 24 h: 15 % cap x 1.0 = 0.15 -> "0.25", nearest
    # horizon at or above 0.15 names the document's failure mode
    assert doc["1h"]["probability_band"] == "0.05"
    assert doc["24h"]["probability_band"] == "0.25"
    assert mode == "cost_runaway"


def test_provisional_agents_predict_nothing() -> None:
    f = feed(headroom=headroom_ramp(0.05, 0.05))
    doc, (ev, _) = horizons_for(
        inputs(plan=False, headroom=0.05, provider_status="partial_outage"), f
    )
    assert ev.provisional
    assert all(v["probability_band"] == "0.05" for v in doc.values())


def test_reads_shape_is_a_valid_risk_document() -> None:
    """What ``GET /agents/{id}/risk`` serves from these horizons (projected to RiskHorizon)."""
    f = feed(headroom=headroom_ramp(0.10, 0.06))
    doc, (ev, mode) = horizons_for(inputs(tier=1, headroom=0.10), f)
    risk = RiskDocument(
        agent_id=AGENT,
        horizons={
            k: {
                "horizon_s": s,
                "probability_band": v["probability_band"],
                "confidence": v["confidence"],
                "contributing_rules": tuple(v["contributing_rules"]),
            }
            for (k, v), s in zip(doc.items(), (900, 3600, 86400), strict=True)
        },
        predicted_failure_mode=mode,
        recommended_action=ev.recommended_action,
        rules_source="rules/v1",
    )
    assert risk.horizons["15m"].probability is None


def test_registered_extensions_read_the_installed_feed() -> None:
    f = feed(headroom=headroom_ramp(0.10, 0.06))
    inp = inputs(tier=1, headroom=0.10)
    token = install(Feed(inp.agent_id, NOW, {AGENT: f}))
    try:
        state = None
        for _ in range(LEAD_TICKS):
            ev = evaluate(inp, state, CFG, NOW, leading=leading_extension(inp, CFG, NOW))
            state = ev.state
        doc, _ = horizons_extension(inp, ev, CFG, NOW)
    finally:
        reset(token)
    assert doc["15m"]["probability_band"] == "0.25"


severity = st.floats(min_value=0.0, max_value=1.0)


@settings(max_examples=60, deadline=None)
@given(st.floats(min_value=0.0, max_value=0.09), st.floats(min_value=0.0, max_value=0.04))
def test_15m_band_is_monotone_in_headroom_pressure(head: float, extra: float) -> None:
    """Less headroom (more pressure) never lowers the 15-minute band."""

    def band(h: float) -> int:
        f = feed(headroom=((0.0, h),))
        doc, _ = horizons_for(inputs(tier=1, headroom=h), f)
        return BAND_RANK[doc["15m"]["probability_band"]]

    lower = max(0.0, head - extra)
    assert band(lower) >= band(head)


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_tier1_is_never_critical_from_leading_rules_alone(tier: int) -> None:
    f = feed(headroom=headroom_ramp(0.01, 0.05), budget=100.0, mtd=99.0, rate_s=0.01)
    _, (ev, _) = horizons_for(inputs(tier=tier, headroom=0.01), f)
    assert all(f["kind"] == "leading" for f in ev.factors if f["penalty"] > 0)
    assert ev.band != "failed"
