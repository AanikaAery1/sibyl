"""Tenant-tunable drift thresholds (wave 4 HARDEN item 7): a tenant's overrides replace the
deployment defaults value by value (null = default), the drift tick judges that tenant's
verdicts and minimum samples with them, and every other tenant keeps the defaults."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from sibyl_control.worker.drift.config import (
    DEFAULT_CONFIG,
    TUNABLE_FEATURES,
    DriftConfig,
    TenantThresholds,
    Thresholds,
)
from sibyl_drift_kit import CFG, Profile, Traffic, make_traffic
from sibyl_lane_s_world import SWorld
from sibyl_schemas.models.drift import THRESHOLD_BOUNDS
from sibyl_schemas.values import DriftFeature

F = DriftFeature
H = timedelta(hours=1)
MILD = Profile(out_mu=330)


# --- pure resolution -------------------------------------------------------------------------


def test_no_override_is_the_deployment_config() -> None:
    assert TenantThresholds().apply(DEFAULT_CONFIG) == DEFAULT_CONFIG
    assert TenantThresholds().apply(CFG) == CFG
    assert TenantThresholds().overridden == ()


def test_overrides_replace_only_their_own_values() -> None:
    tuned = TenantThresholds(psi_drift=0.4, js_two_category_watch=0.001, min_samples_tools=80)
    cfg = tuned.apply(DEFAULT_CONFIG)
    for feature in TUNABLE_FEATURES["psi"]:
        assert cfg.threshold(feature) == Thresholds(0.10, 0.4)
    for feature in TUNABLE_FEATURES["js_two_category"]:
        assert cfg.threshold(feature) == Thresholds(0.001, 0.02)
    for feature in TUNABLE_FEATURES["js_many_category"]:
        assert cfg.threshold(feature) == DEFAULT_CONFIG.threshold(feature)
    assert cfg.eval_min_samples == DEFAULT_CONFIG.eval_min_samples
    assert cfg.tool_min_samples == 80
    assert tuned.overridden == ("psi_drift", "js_two_category_watch", "min_samples_tools")


def test_every_feature_belongs_to_exactly_one_tunable_statistic() -> None:
    grouped = [f for features in TUNABLE_FEATURES.values() for f in features]
    assert sorted(grouped) == sorted(DriftFeature)
    assert set(THRESHOLD_BOUNDS) == {
        *(f"{stat}_{level}" for stat in TUNABLE_FEATURES for level in ("watch", "drift")),
        "min_samples_calls",
        "min_samples_tools",
    }


def test_deployment_defaults_sit_inside_the_tunable_bounds() -> None:
    effective = TenantThresholds().effective(DEFAULT_CONFIG)
    for name, (low, high) in THRESHOLD_BOUNDS.items():
        assert low <= effective[name] <= high, name


def test_an_inconsistent_pair_falls_back_to_the_defaults_of_that_statistic() -> None:
    # The API refuses watch >= drift; if a deployment default moved under a stored override the
    # tick must not crash or judge with an inverted pair: that statistic uses its defaults.
    stale = TenantThresholds(psi_watch=0.3, js_many_category_drift=0.2)
    cfg = stale.apply(DEFAULT_CONFIG)
    assert cfg.threshold(F.OUTPUT_TOKENS) == DEFAULT_CONFIG.threshold(F.OUTPUT_TOKENS)
    assert cfg.threshold(F.ERROR_CLASS) == Thresholds(0.05, 0.2)


def test_from_row_reads_the_columns() -> None:
    row: dict[str, Any] = {name: None for name in THRESHOLD_BOUNDS}
    row.update(psi_watch=0.05, min_samples_calls=400)
    tuned = TenantThresholds.from_row(row)
    assert tuned == TenantThresholds(psi_watch=0.05, min_samples_calls=400)
    assert TenantThresholds.from_row(None) == TenantThresholds()


# --- the tick on PG17 ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def traffic_a(sworld: SWorld) -> Traffic:
    return make_traffic(sworld)


@pytest.fixture(scope="module")
def traffic_b(sworld: SWorld) -> Traffic:
    return make_traffic(sworld, on_b=True)


@pytest.fixture
def override_a(sworld: SWorld) -> Iterator[Any]:
    """Store tenant A's overrides (``set(**values)``); removed afterwards."""

    def put(**values: Any) -> None:
        cols = ", ".join(values)
        marks = ", ".join(f"${i}" for i in range(3, len(values) + 3))
        sworld.admin.execute("DELETE FROM sibyl.drift_thresholds WHERE tenant_id = $1", sworld.a.id)
        sworld.admin.execute(
            f"INSERT INTO sibyl.drift_thresholds (tenant_id, updated_by_user_id, {cols})"  # noqa: S608
            f" VALUES ($1, $2, {marks})",
            sworld.a.id,
            sworld.a.users["owner"],
            *values.values(),
        )

    try:
        yield put
    finally:
        sworld.admin.execute("DELETE FROM sibyl.drift_thresholds WHERE tenant_id = $1", sworld.a.id)


def _evaluate_once(t: Traffic, cfg: DriftConfig = CFG) -> dict[str, Any]:
    """A fresh agent: frozen baseline, then one window of mildly longer outputs, evaluated."""
    agent = t.agent()
    t0 = t.now() - 3 * H
    t.period(agent, t0 - H, t0, 400, seed=41, tasks=60)
    t.period(agent, t0, t0 + H, 200, MILD, seed=42, tasks=40)
    t.run(t0, cfg)
    t.run(t0 + H, cfg)
    [report] = t.reports(agent)
    return dict(report)


def _features(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["feature"]: f for f in json.loads(report["features"])}


def test_a_tenant_override_changes_its_verdict_and_not_the_other_tenants(
    traffic_a: Traffic, traffic_b: Traffic, override_a: Any
) -> None:
    override_a(psi_watch=0.01, psi_drift=0.02)
    tuned = _evaluate_once(traffic_a)
    default = _evaluate_once(traffic_b)

    a_out = _features(tuned)["output_tokens"]
    assert (a_out["watch"], a_out["drift"]) == (0.01, 0.02)
    assert a_out["verdict"] == "drift" and tuned["verdict"] == "drift"
    b_out = _features(default)["output_tokens"]
    assert (b_out["watch"], b_out["drift"]) == (0.10, 0.25)
    assert b_out["verdict"] != "drift"
    # same traffic, same statistic: only the thresholds differ
    assert abs(a_out["value"] - b_out["value"]) < 0.05

    config_a = json.loads(tuned["config"])
    assert config_a["overrides"] == ["psi_watch", "psi_drift"]
    assert config_a["thresholds"]["psi_drift"] == 0.02
    config_b = json.loads(default["config"])
    assert config_b["overrides"] == []
    assert config_b["thresholds"]["psi_drift"] == 0.25


def test_a_tenant_minimum_samples_override_gates_its_features(
    traffic_a: Traffic, traffic_b: Traffic, override_a: Any
) -> None:
    override_a(min_samples_calls=5000, min_samples_tools=10)
    tuned = _features(_evaluate_once(traffic_a))
    default = _features(_evaluate_once(traffic_b))
    assert tuned["output_tokens"]["status"] == "insufficient_samples"
    assert tuned["refusal"]["status"] == "insufficient_samples"
    assert tuned["tool_bigram"]["status"] == "ok"
    assert default["output_tokens"]["status"] == "ok"
    assert default["refusal"]["status"] == "ok"
