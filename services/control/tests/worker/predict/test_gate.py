"""Tier gating (D13, D36/R41, D39/R40) and the effective preemptive mode, as pure functions."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sibyl_control.core.settings import Settings
from sibyl_control.worker.predict.bands import CONFIDENCES, PROBABILITY_BANDS
from sibyl_control.worker.predict.gate import (
    effective_mode,
    failover_requester,
    gate_config,
    min_band,
    qualifies,
    set_failover_requester,
)

from .p_inputs import config, seed_config

OPEN = {
    "predicted_failover_min_band_tiers_2_3": "0.60",
    "harness_precision": 0.78,
    "harness_recall": 0.64,
}
CLOSED_SETTINGS = Settings(predicted_automation_band="0.90")
OPEN_SETTINGS = Settings(predicted_automation_band="0.60")


def test_the_060_band_is_off_by_default_on_tiers_2_and_3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SIBYL_PREDICTED_AUTOMATION_BAND", raising=False)
    gc = gate_config(seed_config().scoring, Settings())
    assert not gc.release_open
    assert min_band(2, gc) == min_band(3, gc) == "0.90"
    assert not qualifies(2, "0.60", "high", 3, gc)
    assert qualifies(2, "0.90", "medium", 2, gc)


def test_only_the_deployment_setting_opens_060() -> None:
    gc = gate_config(seed_config().scoring, OPEN_SETTINGS)
    assert gc.release_open
    assert min_band(2, gc) == min_band(3, gc) == "0.60"


def test_the_setting_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_PREDICTED_AUTOMATION_BAND", "0.60")
    assert min_band(3, gate_config(seed_config().scoring, Settings())) == "0.60"


@pytest.mark.parametrize(
    "automation",
    [
        OPEN,
        {**OPEN, "harness_precision": 0.99, "harness_recall": 0.99},
        {"predicted_failover_min_band_tiers_2_3": "0.60"},
        {"predicted_failover_min_band_tiers_2_3": "0.25"},
    ],
)
def test_the_scoring_config_never_opens_the_release_gate(automation: dict[str, object]) -> None:
    """B20: the D36 gate is a release criterion, never tenant-tunable via ``scoring_config``."""
    gc = gate_config(config(**automation).scoring, CLOSED_SETTINGS)
    assert not gc.release_open
    assert min_band(2, gc) == min_band(3, gc) == "0.90"


def test_tier1_approval_gate_is_060_regardless_of_the_release_gate() -> None:
    assert min_band(1, gate_config(seed_config().scoring, CLOSED_SETTINGS)) == "0.60"
    assert min_band(1, gate_config(seed_config().scoring, OPEN_SETTINGS)) == "0.60"


def test_confidence_and_family_floors() -> None:
    gc = gate_config(seed_config().scoring, OPEN_SETTINGS)
    assert not qualifies(2, "0.60", "low", 2, gc)
    assert not qualifies(2, "0.60", "medium", 1, gc)
    assert qualifies(2, "0.60", "medium", 2, gc)


@given(
    st.integers(min_value=1, max_value=3),
    st.sampled_from(PROBABILITY_BANDS),
    st.sampled_from(PROBABILITY_BANDS),
    st.sampled_from(CONFIDENCES),
    st.integers(min_value=0, max_value=4),
    st.booleans(),
)
def test_gate_is_monotone_in_the_band(
    tier: int, a: str, b: str, conf: str, fams: int, release: bool
) -> None:
    gc = gate_config(seed_config().scoring, OPEN_SETTINGS if release else CLOSED_SETTINGS)
    lo, hi = sorted((a, b), key=PROBABILITY_BANDS.index)
    if qualifies(tier, lo, conf, fams, gc):
        assert qualifies(tier, hi, conf, fams, gc)


@pytest.mark.parametrize("plan_mode", ["auto", "degrade_then_auto", "approval", None])
@pytest.mark.parametrize("breaker", [False, True])
def test_tier1_predictions_never_auto_act(plan_mode: str | None, breaker: bool) -> None:
    assert effective_mode(1, plan_mode, breaker) == "approval"


def test_tiers_2_3_follow_the_plan_unless_the_breaker_trips() -> None:
    assert effective_mode(2, "degrade_then_auto", False) == "degrade_then_auto"
    assert effective_mode(3, "auto", False) == "auto"
    assert effective_mode(2, None, False) == "degrade_then_auto"
    assert effective_mode(3, "auto", True) == "approval"


def test_requester_resolution_is_lazy_and_overridable() -> None:
    async def fake(*_a: object, **_k: object) -> None:
        return None

    set_failover_requester(fake)
    try:
        assert failover_requester() is fake
    finally:
        set_failover_requester(None)
