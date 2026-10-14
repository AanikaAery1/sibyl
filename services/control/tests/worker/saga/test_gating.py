"""Tier gating (ML §4.5, API §6.5): approval-gating correctness is a CRITICAL gate (M3 3.8)."""

from __future__ import annotations

import itertools

import pytest
from sibyl_control.worker.saga.gating import (
    approval_for,
    decide_predicted,
    effective_mode,
    families,
)

STEP_KINDS = (
    "retry",
    "alt_model_same_provider",
    "alt_provider",
    "backup_agent",
    "degraded_safe_mode",
    "human_queue",
)


@pytest.mark.parametrize(
    ("tier", "trigger", "actor"),
    list(itertools.product((1, 2, 3), ("detected", "operator"), ("rule",))),
)
def test_detected_failure_is_automatic_except_tier1_backup_agent(tier, trigger, actor) -> None:
    for kind in STEP_KINDS:
        need = approval_for(tier=tier, trigger=trigger, actor_kind=actor, step_kind=kind)
        if tier == 1 and kind == "backup_agent":
            assert need == "backup_agent_failover"
        else:
            assert need is None, (tier, kind)


@pytest.mark.parametrize("tier", (1, 2, 3))
def test_human_initiated_backup_agent_on_tier1_needs_four_eyes(tier) -> None:
    need = approval_for(tier=tier, trigger="operator", actor_kind="human", step_kind="backup_agent")
    assert need == ("backup_agent_failover" if tier == 1 else None)
    for kind in ("alt_provider", "alt_model_same_provider", "human_queue"):
        assert (
            approval_for(tier=tier, trigger="operator", actor_kind="human", step_kind=kind) is None
        )


def test_predicted_tier1_needs_approval_except_same_provider_model_and_humans() -> None:
    assert (
        approval_for(tier=1, trigger="predicted", actor_kind="rule", step_kind="alt_provider")
        == "alt_provider_failover"
    )
    for kind in ("alt_model_same_provider", "human_queue", "degraded_safe_mode"):
        assert approval_for(tier=1, trigger="predicted", actor_kind="rule", step_kind=kind) is None


def test_predicted_tier2_auto_unless_plan_or_breaker_asks() -> None:
    kw = {"tier": 2, "trigger": "predicted", "actor_kind": "rule", "step_kind": "alt_provider"}
    assert approval_for(**kw, preemptive_mode="degrade_then_auto") is None
    assert approval_for(**kw, preemptive_mode="approval") == "alt_provider_failover"
    assert approval_for(**kw, breaker_open=True) == "alt_provider_failover"


def test_families_map_leading_rules() -> None:
    assert families(["ratelimit_proximity", "fallback_pressure"]) == {"capacity"}
    assert len(families(["error_trend", "provider_status"])) == 2
    assert families(["unknown_rule"]) == {"unknown_rule"}


def test_effective_mode_defaults_by_tier_and_breaker() -> None:
    assert effective_mode(1, "auto", False) == "approval"
    assert effective_mode(2, None, False) == "degrade_then_auto"
    assert effective_mode(3, None, False) == "auto"
    assert effective_mode(3, "auto", True) == "approval"


STRONG = {
    "band": "0.90",
    "confidence": "medium",
    "contributing_rules": ("error_trend", "latency_trend"),
}


def _decide(**kw):
    base = {"tier": 2, "horizon_s": 900, "preemptive_mode": None, **STRONG}
    base.update(kw)
    return decide_predicted(**base).action


def test_only_15m_horizon_opens_a_saga() -> None:
    assert _decide(horizon_s=3600) == "none"
    assert _decide(horizon_s=86400, tier=1) == "none"


def test_tier1_strong_prediction_asks_for_approval_even_at_060() -> None:
    assert _decide(tier=1, band="0.60") == "approval"
    assert _decide(tier=1, band="0.60", confidence="low") == "watch"
    assert _decide(tier=1, contributing_rules=("error_trend",)) == "watch"
    assert _decide(tier=1, band="0.05") == "none"


def test_d39_tier2_degrade_then_auto_and_tier3_auto() -> None:
    assert _decide(tier=2) == "degrade_then_auto"
    assert _decide(tier=3) == "saga"
    assert _decide(tier=3, preemptive_mode="approval") == "approval"
    assert _decide(tier=2, preemptive_mode="auto") == "saga"


def test_d36_gate_holds_060_back_until_released() -> None:
    assert _decide(tier=3, band="0.60") == "degrade"
    assert _decide(tier=3, band="0.60", automation_band="0.60") == "saga"
    assert _decide(tier=2, band="0.60", automation_band="0.60") == "degrade_then_auto"


def test_weak_evidence_degrades_only_and_watch_band_watches() -> None:
    assert _decide(tier=3, confidence="low") == "degrade"
    assert _decide(tier=3, contributing_rules=("error_trend",)) == "degrade"
    assert _decide(tier=2, band="0.25") == "watch"
    assert _decide(tier=3, band="0.05") == "none"


def test_breaker_forces_approval_on_tiers_2_3() -> None:
    assert _decide(tier=3, breaker_open=True) == "approval"
    assert _decide(tier=2, breaker_open=True) == "approval"
