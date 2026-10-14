"""EngineConfig is built from the tenant's active scoring_config plus its alert_rule copies."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from sibyl_control.migrate.rules_seed import load
from sibyl_control.worker.scoring.config import EngineConfig, RuleSpec, band_for_score

ROOT = Path(__file__).resolve().parents[5]
SEED = load(ROOT / "rules" / "v1" / "defaults.yaml")


def seed_config() -> EngineConfig:
    return EngineConfig.from_seed(SEED)


def test_seed_yaml_builds_every_rule_with_per_tier_values() -> None:
    cfg = seed_config()
    r1 = cfg.rule("error_rate")
    assert (r1.cap(1), r1.cap(2), r1.cap(3)) == (50, 40, 30)
    assert (r1.threshold(1), r1.threshold(2), r1.threshold(3)) == (0.05, 0.1, 0.2)
    assert (r1.h_in(1), r1.h_out(1), r1.cooldown(3)) == (2, 18, 900)
    assert cfg.rule("p95_latency").threshold_by_model_class["reasoning"] == 60000
    assert cfg.rule("quality_proxy").score_only
    assert cfg.rule("provider_status").collapses_to_provider
    assert cfg.has_rule("drift_cusum") and cfg.rule("drift_cusum").kind == "leading"


def _row(code: str, **over: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": UUID(int=len(code)),
        "code": code,
        "kind": "detected",
        "scope": "agent",
        "severity": "warning",
        "enabled": True,
        "min_samples": 20,
        "window_s": 300,
        "collapses_to_provider": False,
        "escalate_after_fires": 3,
        "escalate_window_s": 3600,
        "what_to_do_template": "t",
        "thresholds": {"tiers": {}},
    }
    row.update(over)
    return row


def test_db_rows_override_seed_thresholds_and_disable_rules() -> None:
    tiers = {
        "1": {"cap": 1, "threshold": 0.5, "hysteresis_in": 4, "hysteresis_out": 5, "cooldown_s": 60}
    }
    rows = [
        _row("error_rate", min_samples=5, thresholds={"tiers": tiers}),
        _row("p95_latency", enabled=False),
    ]
    cfg = EngineConfig.from_rows(
        json.loads(SEED.scoring_canonical), rows, scoring_config_id=None, defaults=SEED.rules
    )
    r1 = cfg.rule("error_rate")
    assert r1.threshold(1) == 0.5 and r1.h_in(1) == 4 and r1.min_samples == 5
    assert r1.cap(1) == 50, "caps come from scoring_config, not alert_rule"
    assert r1.threshold(2) == 0.1, "a tier missing from the row falls back to the seed"
    assert not cfg.has_rule("p95_latency"), "a disabled rule is not evaluated"
    assert r1.rule_id == UUID(int=len("error_rate"))


def test_rows_for_unknown_codes_are_ignored() -> None:
    cfg = EngineConfig.from_rows(
        json.loads(SEED.scoring_canonical),
        [_row("not_a_rule")],
        scoring_config_id=None,
        defaults=SEED.rules,
    )
    assert not cfg.has_rule("not_a_rule")


@pytest.mark.parametrize(
    ("tier", "score", "band"),
    [
        (1, 85, "healthy"),
        (1, 84, "watch"),
        (1, 70, "watch"),
        (1, 69, "degraded"),
        (1, 45, "degraded"),
        (1, 44, "failed"),
        (2, 80, "healthy"),
        (2, 64, "degraded"),
        (2, 39, "failed"),
        (3, 75, "healthy"),
        (3, 55, "watch"),
        (3, 29, "failed"),
    ],
)
def test_band_edges_per_tier(tier: int, score: int, band: str) -> None:
    assert band_for_score(seed_config(), tier, score) == band


def test_upward_dead_band_needs_edge_plus_four() -> None:
    cfg = seed_config()
    assert band_for_score(cfg, 1, 73, current="degraded") == "degraded"
    assert band_for_score(cfg, 1, 74, current="degraded") == "watch"
    assert band_for_score(cfg, 1, 88, current="watch") == "watch"
    assert band_for_score(cfg, 1, 89, current="watch") == "healthy"
    assert band_for_score(cfg, 1, 95, current="failed") == "healthy"
    assert band_for_score(cfg, 1, 48, current="failed") == "failed"
    assert band_for_score(cfg, 1, 49, current="failed") == "degraded"
    # worsening is immediate on the edge (no dead-band downwards)
    assert band_for_score(cfg, 1, 84, current="healthy") == "watch"


def test_rule_spec_is_immutable() -> None:
    r1 = seed_config().rule("error_rate")
    assert isinstance(r1, RuleSpec)
    with pytest.raises(AttributeError):
        r1.code = "x"  # type: ignore[misc]
