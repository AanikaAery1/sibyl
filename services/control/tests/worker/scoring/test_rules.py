"""Severity curves and the detected rules R1-R9, tool_loop and quality_proxy (ML.md §3.2-§3.3)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig
from sibyl_control.worker.scoring.features import (
    AgentInputs,
    WindowStats,
    hist_quantile,
    latency_hist,
    model_class,
)
from sibyl_control.worker.scoring.rules import (
    above,
    below,
    count_curve,
    evaluate_detected,
)

from .h_inputs import NOW, inputs

CFG = EngineConfig.from_seed(load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml"))


def by_code(inp: AgentInputs) -> dict:
    return {o.code: o for o in evaluate_detected(inp, CFG, NOW)}


def test_curves() -> None:
    assert above(0.1, 0.1, 0.3) == 0
    assert above(0.2, 0.1, 0.3) == pytest.approx(0.5)
    assert above(0.9, 0.1, 0.3) == 1
    assert below(0.05, 0.1) == pytest.approx(0.5)
    assert below(0.2, 0.1) == 0
    assert count_curve(2, 3) == 0
    assert count_curve(3, 3) == pytest.approx(1 / 3)
    assert count_curve(5, 3) == 1


def test_hist_quantile_matches_sql_helper() -> None:
    hist = latency_hist([100] * 95 + [9000] * 5)
    assert hist_quantile(hist, 0.5) == 90  # bucket 13 midpoint, as sibyl.hist_quantile
    assert hist_quantile(hist, 0.99) > 7000
    assert hist_quantile((0,) * 40, 0.95) is None


@pytest.mark.parametrize(
    ("name", "cls"),
    [
        ("gpt-4o-mini", "small"),
        ("claude-haiku", "small"),
        ("o3", "reasoning"),
        ("deepseek-r1", "reasoning"),
        ("large-1", "large"),
        (None, "large"),
    ],
)
def test_model_class(name: str | None, cls: str) -> None:
    assert model_class(name) == cls


def test_r1_error_rate_scales_between_threshold_and_three_times() -> None:
    out = by_code(inputs(tier=2, req=100, err=20))["error_rate"]
    assert out.severity == pytest.approx(0.5)  # t=0.1, s=0.3, x=0.2
    assert out.value == pytest.approx(0.2) and out.threshold == 0.1
    assert "20%" in out.explanation and out.evidence.startswith("/api/v1/events?")


def test_r1_needs_min_samples() -> None:
    out = by_code(inputs(tier=2, req=10, err=10))["error_rate"]
    assert not out.evaluated and out.severity == 0


def test_r1_floor_failed_at_half_errors() -> None:
    assert by_code(inputs(tier=3, req=100, err=50))["error_rate"].floor == "failed"
    assert by_code(inputs(tier=3, req=100, err=49))["error_rate"].floor is None


def test_r2_latency_by_model_class_and_relative_baseline() -> None:
    slow = inputs(tier=2, req=50, latencies=[30000] * 50)
    r2 = by_code(slow)["p95_latency"]
    assert r2.threshold == 20000 and 0 < r2.severity <= 1
    small = replace(slow, model="gpt-4o-mini", model_class="small")
    assert by_code(small)["p95_latency"].severity == 1
    rel = inputs(tier=2, req=50, latencies=[3000] * 50)
    rel = replace(rel, baselines={"latency_p95_ms": 1000.0}, baseline_ref="own/how4w")
    out = by_code(rel)["p95_latency"]
    assert out.severity > 0 and "baseline" in out.explanation


def test_r3_consecutive_failures_full_forces_failed_floor() -> None:
    out = by_code(replace(inputs(tier=1, req=5, err=5), consecutive_errors=5))[
        "consecutive_failures"
    ]
    assert out.severity == 1 and out.floor == "failed"
    part = by_code(replace(inputs(tier=1, req=5, err=3), consecutive_errors=3))[
        "consecutive_failures"
    ]
    assert part.severity == pytest.approx(1 / 3) and part.floor is None


def test_r4_major_outage_detected_and_corroborated_floor() -> None:
    # too little own traffic to judge the page: the status is all the evidence there is
    inp = replace(inputs(tier=2, req=5), provider_status="major_outage", request_count_1h=5)
    out = by_code(inp)["provider_status"]
    assert out.severity == 1 and out.floor is None and out.kind == "detected"
    corroborated = replace(inp, provider_error_rate_fleet=0.4)
    assert by_code(corroborated)["provider_status"].floor == "failed"
    partial = replace(inp, provider_status="partial_outage")
    assert by_code(partial)["provider_status"].severity == 0, "leading facet is lane P"
    erroring = replace(inputs(tier=2, req=50, err=10), provider_status="major_outage")
    assert by_code(erroring)["provider_status"].kind == "detected", "own errors agree"


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_r4_major_outage_contradicted_by_clean_own_traffic_is_leading(tier: int) -> None:
    """S-16 (ML §8.2): the page says major_outage while the agent's own calls are clean.

    The status still costs points, at the leading facet's strongest ordinal (partial_outage,
    ML §3.2/§4.3 "agent not yet erroring"), but it is not a detected fact: no failure floor and
    no critical-rule degraded floor, so status alone never fails an agent over."""
    inp = replace(inputs(tier=tier, req=50), provider_status="major_outage")
    out = by_code(inp)["provider_status"]
    assert out.kind == "leading" and out.floor is None
    assert out.severity == CFG.provider_status_ordinal("partial_outage")
    assert out.hint == "provider_outage"
    assert "own traffic" in out.explanation
    # a masked outage (B35) is not clean traffic: every call needed the inline fallback
    masked = replace(inp, w5=replace(inp.w5, inline_fallback_count=50))
    assert by_code(masked)["provider_status"].kind == "detected"
    assert by_code(masked)["provider_status"].severity == 1
    # fleet errors corroborate the page whatever this agent sees
    fleet = replace(inp, provider_error_rate_fleet=0.4)
    assert by_code(fleet)["provider_status"].floor == "failed"


def test_r4_low_traffic_agent_counts_its_clean_last_hour() -> None:
    """A quiet agent (8 calls in 5 minutes) with a clean last hour contradicts the page too;
    a quiet agent whose hour was failing, or with no call at all now, does not."""
    quiet = replace(inputs(tier=1, req=8), provider_status="major_outage")
    assert quiet.request_count_1h >= 20 and quiet.error_count_1h == 0
    assert by_code(quiet)["provider_status"].kind == "leading"
    bad_hour = replace(quiet, error_count_1h=quiet.request_count_1h // 2)
    assert by_code(bad_hour)["provider_status"].kind == "detected"
    idle = replace(inputs(tier=1, req=0), provider_status="major_outage", request_count_1h=90)
    assert by_code(idle)["provider_status"].kind == "detected"
    erroring_now = replace(inputs(tier=1, req=8, err=4), provider_status="major_outage")
    assert by_code(erroring_now)["provider_status"].kind == "detected"


def test_r5_budget_breach_is_boolean_on_spend_ratio() -> None:
    assert by_code(replace(inputs(), spend_ratio=0.99))["budget_breach"].severity == 0
    assert by_code(replace(inputs(), spend_ratio=1.0))["budget_breach"].severity == 1
    assert not by_code(inputs())["budget_breach"].evaluated


def test_r6_to_r8_and_quality_proxy_takes_the_max() -> None:
    inp = inputs(tier=2, req=100, refusals=30, truncations=10, tool_calls=40, schema_bad=20)
    out = by_code(inp)
    assert out["refusal_share"].severity == pytest.approx(0.5)  # t .15 s .45 x .30
    assert out["truncation_share"].severity == 0  # 0.10 < 0.25
    assert out["schema_fail_share"].severity == pytest.approx(1.0)  # .5 vs t .15 s .45
    q = out["quality_proxy"]
    assert q.severity == pytest.approx(1.0) and "schema_fail_share" in q.explanation
    for code in ("refusal_share", "truncation_share", "schema_fail_share"):
        assert out[code].alert_only


def test_r7_truncation_needs_twice_the_baseline_when_one_exists() -> None:
    inp = inputs(tier=2, req=100, truncations=50)
    assert by_code(inp)["truncation_share"].severity > 0
    with_base = replace(inp, baselines={"finish_length_ratio": 0.4}, baseline_ref="own/7d")
    assert by_code(with_base)["truncation_share"].severity == 0


def test_empty_output_feeds_quality_proxy() -> None:
    q = by_code(inputs(tier=2, req=100, empty=10))["quality_proxy"]
    assert q.severity == pytest.approx(0.5)  # t .05 s .15 x .10


def test_r9_heartbeat_missing_only_with_declared_cadence() -> None:
    silent = inputs(tier=2, req=0)
    assert not by_code(silent)["heartbeat_missing"].evaluated
    declared = replace(silent, cadence_s=60, last_request_at=NOW.replace(microsecond=0) - _s(180))
    assert by_code(declared)["heartbeat_missing"].severity == 1
    recent = replace(declared, last_request_at=NOW - _s(30))
    assert by_code(recent)["heartbeat_missing"].severity == 0


def test_tool_loop_on_repeated_tools() -> None:
    loop = inputs(tier=2, req=30, tool_calls=40, tool_distinct=2)
    assert by_code(loop)["tool_loop"].severity > 0.5
    varied = inputs(tier=2, req=30, tool_calls=40, tool_distinct=30)
    assert by_code(varied)["tool_loop"].severity == 0
    few = inputs(tier=2, req=30, tool_calls=15, tool_distinct=1)
    assert by_code(few)["tool_loop"].severity == 0


def test_disabled_rule_is_not_evaluated() -> None:
    seed = load(Path(__file__).resolve().parents[5] / "rules/v1/defaults.yaml")
    rows = [dict(r, enabled=(r["code"] != "error_rate")) for r in seed.rules]
    import json

    cfg = EngineConfig.from_rows(
        json.loads(seed.scoring_canonical), rows, scoring_config_id=None, defaults=seed.rules
    )
    codes = {o.code for o in evaluate_detected(inputs(req=100, err=50), cfg, NOW)}
    assert "error_rate" not in codes and "p95_latency" in codes


def test_window_stats_ratios_are_none_without_denominator() -> None:
    w = WindowStats()
    assert w.ratio("error_count") is None
    assert w.p95_ms is None


def _s(seconds: int):
    from datetime import timedelta

    return timedelta(seconds=seconds)
