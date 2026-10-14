"""Pure detection: freezing, comparing, identity findings and hysteresis (no database)."""

from __future__ import annotations

import random
from dataclasses import replace

import pytest
from sibyl_control.worker.drift import features as fx
from sibyl_control.worker.drift import hysteresis as hy
from sibyl_control.worker.drift import identity as idn
from sibyl_control.worker.drift.config import DriftConfig, Thresholds
from sibyl_control.worker.drift.features import CallSample, ToolSample, Window
from sibyl_schemas.values import DriftFeature, DriftIdentityChange, DriftVerdict

F = DriftFeature
CFG = DriftConfig(eval_min_samples=100, tool_min_samples=30, baseline_min_samples=100)


def calls(
    n: int,
    *,
    seed: int,
    out_mu: float = 300,
    refusal: float = 0.01,
    trunc: float = 0.02,
    errors: float = 0.02,
    model: str = "gpt-4o-2024-08-06",
    fingerprint: str | None = "fp_a",
) -> tuple[CallSample, ...]:
    rng = random.Random(seed)  # noqa: S311 (reproducible test data)
    out = []
    for _ in range(n):
        failed = rng.random() < errors
        out.append(
            CallSample(
                tokens_out=max(1, int(rng.gauss(out_mu, out_mu / 5))),
                tokens_in=max(1, int(rng.gauss(1200, 200))),
                latency_ms=max(1.0, rng.gauss(900, 150)),
                status="error" if failed else "ok",
                error_class="timeout" if failed else None,
                refusal=rng.random() < refusal,
                truncated=rng.random() < trunc,
                tool_call=rng.random() < 0.3,
                response_model=model,
                fingerprint=fingerprint,
            )
        )
    return tuple(out)


def tools(
    n_tasks: int,
    *,
    seed: int,
    order: tuple[str, ...] = ("search", "fetch", "answer"),
    schema_fail: float = 0.0,
) -> tuple[ToolSample, ...]:
    rng = random.Random(seed)  # noqa: S311 (reproducible test data)
    out = []
    for t in range(n_tasks):
        for name in order:
            out.append(ToolSample(f"task-{seed}-{t}", name, rng.random() < schema_fail))
    return tuple(out)


BASE = Window(calls(800, seed=1), tools(100, seed=1))
FROZEN = fx.freeze(BASE, CFG)


def by_feature(results: list[fx.FeatureResult]) -> dict[DriftFeature, fx.FeatureResult]:
    return {r.feature: r for r in results}


def test_freeze_is_deterministic_and_complete() -> None:
    assert fx.freeze(BASE, CFG) == FROZEN
    assert set(FROZEN) == {f.value for f in DriftFeature}
    out = FROZEN["output_tokens"]
    assert out["kind"] == "numeric" and out["statistic"] == "psi" and out["n"] == 800
    assert len(out["probs"]) == len(out["edges"]) + 1 == 10
    assert sum(out["probs"]) == pytest.approx(1.0)
    refusal = FROZEN["refusal"]
    assert refusal["kind"] == "categorical" and refusal["statistic"] == "js"
    assert set(refusal["probs"]) <= {"yes", "no"}
    assert FROZEN["tool_bigram"]["probs"] == {"fetch>answer": 0.5, "search>fetch": 0.5}


def test_same_distribution_reads_none() -> None:
    results = fx.compare(FROZEN, Window(calls(400, seed=2), tools(60, seed=2)), CFG)
    assert fx.evaluated(results)
    assert fx.overall(results) is DriftVerdict.NONE, [r.as_json() for r in results]
    assert all(r.status == "ok" for r in results)


def test_longer_outputs_drift_on_psi_with_contributors() -> None:
    window = Window(calls(400, seed=3, out_mu=600), tools(60, seed=3))
    results = by_feature(fx.compare(FROZEN, window, CFG))
    out = results[F.OUTPUT_TOKENS]
    assert out.verdict is DriftVerdict.DRIFT and out.value is not None and out.value > 0.25
    assert out.contributors and out.contributors[0][0].startswith(">")
    assert results[F.INPUT_TOKENS].verdict is DriftVerdict.NONE
    assert fx.overall(list(results.values())) is DriftVerdict.DRIFT
    assert fx.drift_ratio(list(results.values())) > 1.0


def test_refusal_share_rise_drifts_on_js() -> None:
    window = Window(calls(400, seed=4, refusal=0.12), tools(60, seed=4))
    result = by_feature(fx.compare(FROZEN, window, CFG))[F.REFUSAL]
    assert result.statistic.value == "js"
    assert result.verdict is DriftVerdict.DRIFT
    assert result.as_json()["contributors"][0]["label"] in {"yes", "no"}


def test_new_tool_sequence_and_schema_failures_drift() -> None:
    window = Window(
        calls(400, seed=5),
        tools(60, seed=5, order=("search", "delete", "answer"), schema_fail=0.3),
    )
    results = by_feature(fx.compare(FROZEN, window, CFG))
    assert results[F.TOOL_BIGRAM].verdict is DriftVerdict.DRIFT
    assert results[F.SCHEMA_FAIL].verdict is DriftVerdict.DRIFT
    labels = {c[0] for c in results[F.TOOL_BIGRAM].contributors}
    assert "__other__" in labels


def test_error_mix_shift() -> None:
    window = Window(calls(400, seed=6, errors=0.3), tools(60, seed=6))
    assert by_feature(fx.compare(FROZEN, window, CFG))[F.ERROR_CLASS].verdict is (
        DriftVerdict.DRIFT
    )


def test_minimum_samples_gate_every_feature() -> None:
    small = Window(calls(50, seed=7, out_mu=900), tools(5, seed=7))
    results = fx.compare(FROZEN, small, CFG)
    assert not fx.evaluated(results)
    assert {r.status for r in results} == {"insufficient_samples"}
    assert fx.overall(results) is DriftVerdict.NONE
    assert fx.drift_ratio(results) == 0.0
    missing = fx.compare_feature(F.OUTPUT_TOKENS, None, BASE, CFG)
    assert missing.status == "insufficient_samples" and missing.value is None


def test_malformed_baseline_never_fakes_a_verdict() -> None:
    broken = {**FROZEN["latency_ms"], "probs": [1.0]}
    result = fx.compare_feature(F.LATENCY_MS, broken, BASE, CFG)
    assert result.status == "invalid_baseline" and result.verdict is DriftVerdict.NONE


def test_watch_band_and_custom_thresholds() -> None:
    loose = replace(CFG, thresholds={**CFG.thresholds, F.OUTPUT_TOKENS: Thresholds(0.01, 5.0)})
    window = Window(calls(400, seed=8, out_mu=360), tools(60, seed=8))
    result = by_feature(fx.compare(FROZEN, window, loose))[F.OUTPUT_TOKENS]
    assert result.verdict is DriftVerdict.WATCH
    with pytest.raises(ValueError):
        Thresholds(0.3, 0.2)
    with pytest.raises(ValueError):
        DriftConfig(thresholds={F.OUTPUT_TOKENS: Thresholds(0.1, 0.2)})
    with pytest.raises(ValueError):
        DriftConfig(raise_after=0)
    with pytest.raises(ValueError):
        DriftConfig(eval_min_samples=0)


def test_categorical_values_reject_numeric() -> None:
    with pytest.raises(ValueError):
        fx.categorical_values(F.OUTPUT_TOKENS, BASE)
    assert fx.bigrams([ToolSample(None, "x"), ToolSample("t", "a"), ToolSample("t", "b")]) == [
        "a>b"
    ]


# ------------------------------------------------------------------------------- identity


@pytest.mark.parametrize(
    ("requested", "served", "ok"),
    [
        ("gpt-4o", "gpt-4o", True),
        ("gpt-4o", "gpt-4o-2024-08-06", True),
        ("GPT-4o", "gpt-4o-2024-08-06", True),
        ("gemini-1.5-pro", "models/gemini-1.5-pro-002", True),
        ("claude-sonnet-4", "claude-sonnet-4@20250514", True),
        ("gpt-4o", "gpt-4o-mini", False),  # a sibling model sharing the prefix
        ("gpt-4o", "gpt-4o-mini-2024-07-18", False),
        ("gpt-3.5-turbo", "gpt-3.5-turbo-0125", True),
        ("gpt-4o", "gpt-4o-latest", True),
        ("claude-3-5-sonnet", "claude-3-5-sonnet-20241022", True),
        ("claude-sonnet-4", "claude-sonnet-4-5", False),
        ("gpt-4o", "gpt-3.5-turbo", False),
        ("", "gpt-4o", False),
    ],
)
def test_served_matches(requested: str, served: str, ok: bool) -> None:
    assert idn.served_matches(requested, served) is ok


def test_identity_findings() -> None:
    window = calls(20, seed=9, model="gpt-3.5-turbo-0125", fingerprint="fp_new")
    found = idn.changes("gpt-4o", window, ["gpt-4o-2024-08-06"], ["fp_a"], 3)
    kinds = {(f.kind, f.value) for f in found}
    assert kinds == {
        (DriftIdentityChange.SERVED_MODEL_MISMATCH, "gpt-3.5-turbo-0125"),
        (DriftIdentityChange.NEW_FINGERPRINT, "fp_new"),
    }
    assert found[0].as_json()["requested_model"] == "gpt-4o"


def test_identity_snapshot_rollover_and_quiet_cases() -> None:
    rolled = calls(10, seed=10, model="gpt-4o-2024-11-20")
    found = idn.changes("gpt-4o", rolled, ["gpt-4o-2024-08-06"], ["fp_a"], 3)
    assert [(f.kind, f.value) for f in found] == [
        (DriftIdentityChange.NEW_SERVED_MODEL, "gpt-4o-2024-11-20")
    ]
    same = calls(10, seed=11)
    assert idn.changes("gpt-4o", same, ["gpt-4o-2024-08-06"], ["fp_a"], 3) == []
    # baseline without response models or fingerprints: only a real mismatch speaks
    assert idn.changes("gpt-4o", rolled, [], [], 3) == []
    assert len(idn.changes("gpt-4o", calls(5, seed=12, model="o3"), [], [], 3)) == 1
    # fewer than min_count calls never alert
    assert idn.changes("gpt-4o", calls(2, seed=13, model="o3"), [], [], 3) == []


def test_top_values() -> None:
    assert idn.top_values(["b", "a", "a", None, "", "c" * 300], 2) == ["a", "b"]
    assert len(idn.top_values(["c" * 300], 2)[0]) == idn.MAX_VALUE


# ----------------------------------------------------------------------------- hysteresis


def test_behaviour_hysteresis() -> None:
    cfg = DriftConfig(raise_after=2, clear_after=3)
    s = hy.Streaks()
    s, a = hy.behaviour(s, DriftVerdict.DRIFT, False, cfg, evaluated=True)
    assert a is hy.Action.NONE and s.drift == 1
    s, a = hy.behaviour(s, DriftVerdict.DRIFT, False, cfg, evaluated=True)
    assert a is hy.Action.RAISE
    s, a = hy.behaviour(s, DriftVerdict.DRIFT, True, cfg, evaluated=True)
    assert a is hy.Action.REFRESH
    s, a = hy.behaviour(s, DriftVerdict.WATCH, True, cfg, evaluated=True)
    assert a is hy.Action.NONE and s == hy.Streaks(0, 1, 0)  # watch is not drift
    same, a = hy.behaviour(s, DriftVerdict.NONE, True, cfg, evaluated=False)
    assert same == s and a is hy.Action.NONE
    for expected in (hy.Action.NONE, hy.Action.RESOLVE):
        s, a = hy.behaviour(s, DriftVerdict.NONE, True, cfg, evaluated=True)
        assert a is expected
    s, a = hy.behaviour(hy.Streaks(), DriftVerdict.WATCH, False, cfg, evaluated=True)
    assert a is hy.Action.NONE
    s, a = hy.behaviour(hy.Streaks(1, 0, 0), DriftVerdict.WATCH, False, cfg, evaluated=True)
    assert s.drift == 0  # a watch breaks a drift run


def test_identity_hysteresis() -> None:
    cfg = DriftConfig(identity_clear_after=2)
    s, a = hy.identity(hy.Streaks(), True, False, cfg)
    assert a is hy.Action.RAISE
    s, a = hy.identity(s, True, True, cfg)
    assert a is hy.Action.REFRESH
    s, a = hy.identity(s, False, True, cfg)
    assert a is hy.Action.NONE and s.identity_clear == 1
    s, a = hy.identity(s, False, True, cfg)
    assert a is hy.Action.RESOLVE
    _, a = hy.identity(s, False, False, cfg)
    assert a is hy.Action.NONE


def test_drift_cusum_is_visible_score_only_and_never_alerts() -> None:
    """B23: the factor shows on the health document with penalty 0 and the engine never fires
    a drift_cusum alert, however long the drift lasts."""
    from datetime import UTC, datetime, timedelta
    from uuid import UUID

    from sibyl_control.migrate.rules_seed import load
    from sibyl_control.worker.drift import factor
    from sibyl_control.worker.scoring.config import EngineConfig
    from sibyl_control.worker.scoring.engine import evaluate
    from sibyl_control.worker.scoring.features import AgentInputs, WindowStats, latency_hist

    cfg = EngineConfig.from_seed(load())
    now = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
    w5 = WindowStats(request_count=100, latency_hist=latency_hist([500] * 100))
    inp = AgentInputs(
        agent_id=UUID(int=1),
        tier=1,
        created_at=now - timedelta(days=30),
        provider="p",
        provider_id=UUID(int=2),
        model="large-1",
        model_class="large",
        w5=w5,
        w1=w5,
        request_count_1h=1200,
        active_minutes_1h=60,
        has_plan=True,
    )
    drift = factor.AgentDrift("drift", 0.5, 1.8, "openai", "gpt-4o", now)
    lead = factor.outcome(drift, cfg)
    assert lead is not None and lead.score_only and lead.alert_only
    state = None
    for i in range(40):  # far beyond drift_cusum's hysteresis_in of 6 ticks
        ev = evaluate(inp, state, cfg, now + i * timedelta(seconds=10), leading=[lead])
        state = ev.state
        assert "drift_cusum" not in ev.newly_fired and "drift_cusum" not in ev.fired
    [visible] = [f for f in ev.factors if f["rule"] == "drift_cusum"]
    assert visible["penalty"] == 0 and ev.score == 100 and ev.band == "healthy"
