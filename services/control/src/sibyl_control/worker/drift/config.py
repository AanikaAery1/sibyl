"""Drift detection settings (D51). ``DEFAULT_CONFIG`` holds the deployment defaults: the
textbook PSI cut-offs and Jensen-Shannon cut-offs calibrated so that a refusal share moving from
1 % to about 3 % reads ``watch`` and to about 8 % reads ``drift``.

Wave 4 HARDEN: a tenant may override the watch / drift pair of each statistic (PSI, JS on two
categories, JS on many categories) and the two window minimums (``drift_thresholds``, one row per
tenant, NULL = default). ``TenantThresholds.apply`` resolves them value by value onto the
deployment config the tick runs with.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import timedelta
from types import MappingProxyType
from typing import Any

from sibyl_schemas.values import DriftFeature

F = DriftFeature
log = logging.getLogger("sibyl.drift")


@dataclass(frozen=True)
class Thresholds:
    watch: float
    drift: float

    def __post_init__(self) -> None:
        if not 0 < self.watch <= self.drift:
            raise ValueError("thresholds need 0 < watch <= drift")


PSI = Thresholds(0.10, 0.25)
JS_SHARE = Thresholds(0.005, 0.02)  # two-category features (a share)
JS_MIX = Thresholds(0.05, 0.10)  # many-category features (error mix, tool bigrams)

DEFAULT_THRESHOLDS: Mapping[DriftFeature, Thresholds] = MappingProxyType(
    {
        F.OUTPUT_TOKENS: PSI,
        F.INPUT_TOKENS: PSI,
        F.LATENCY_MS: PSI,
        F.REFUSAL: JS_SHARE,
        F.TRUNCATION: JS_SHARE,
        F.TOOL_CALL: JS_SHARE,
        F.SCHEMA_FAIL: JS_SHARE,
        F.ERROR_CLASS: JS_MIX,
        F.TOOL_BIGRAM: JS_MIX,
    }
)


@dataclass(frozen=True)
class DriftConfig:
    """Windows, minimum sample sizes, hysteresis and thresholds of one drift tick."""

    baseline_min_samples: int = 500
    baseline_min_span: timedelta = timedelta(hours=6)
    baseline_max_span: timedelta = timedelta(days=7)
    eval_window: timedelta = timedelta(hours=1)
    eval_every: timedelta = timedelta(minutes=10)
    eval_min_samples: int = 200
    tool_min_samples: int = 50
    identity_min_count: int = 3
    max_samples: int = 5000
    max_tool_samples: int = 20000
    numeric_bins: int = 10
    top_categories: int = 20
    served_set_limit: int = 64
    raise_after: int = 2  # consecutive drift verdicts before silent_drift is raised
    clear_after: int = 3  # consecutive clean verdicts before it resolves
    identity_clear_after: int = 3  # clean evaluations before model_change resolves
    report_retention: timedelta = timedelta(days=30)
    baseline_retention: timedelta = timedelta(days=30)  # after supersession (B24)
    retention_batch: int = 1000
    max_keys_per_tick: int = 200
    thresholds: Mapping[DriftFeature, Thresholds] = field(
        default_factory=lambda: DEFAULT_THRESHOLDS
    )
    overrides: tuple[str, ...] = ()  # tunable values a tenant override set (TenantThresholds)

    def __post_init__(self) -> None:
        if min(self.baseline_min_samples, self.eval_min_samples, self.tool_min_samples) < 1:
            raise ValueError("minimum sample sizes must be positive")
        if min(self.raise_after, self.clear_after, self.identity_clear_after) < 1:
            raise ValueError("hysteresis counts must be positive")
        if set(self.thresholds) != set(DriftFeature):
            raise ValueError("every drift feature needs thresholds")

    def threshold(self, feature: DriftFeature) -> Thresholds:
        return self.thresholds[feature]


DEFAULT_CONFIG = DriftConfig()

TUNABLE_FEATURES: Mapping[str, tuple[DriftFeature, ...]] = MappingProxyType(
    {
        "psi": (F.OUTPUT_TOKENS, F.INPUT_TOKENS, F.LATENCY_MS),
        "js_two_category": (F.REFUSAL, F.TRUNCATION, F.TOOL_CALL, F.SCHEMA_FAIL),
        "js_many_category": (F.ERROR_CLASS, F.TOOL_BIGRAM),
    }
)
"""The features each tunable statistic judges (``<statistic>_watch`` / ``<statistic>_drift``);
keyed like ``sibyl_schemas.models.drift.THRESHOLD_STATISTICS``."""


@dataclass(frozen=True)
class TenantThresholds:
    """One tenant's overrides; ``None`` is the deployment default (names = THRESHOLD_BOUNDS)."""

    psi_watch: float | None = None
    psi_drift: float | None = None
    js_two_category_watch: float | None = None
    js_two_category_drift: float | None = None
    js_many_category_watch: float | None = None
    js_many_category_drift: float | None = None
    min_samples_calls: int | None = None
    min_samples_tools: int | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any] | None) -> TenantThresholds:
        if row is None:
            return cls()
        return cls(**{f.name: row[f.name] for f in fields(cls)})

    @property
    def overridden(self) -> tuple[str, ...]:
        return tuple(f.name for f in fields(self) if getattr(self, f.name) is not None)

    def as_dict(self) -> dict[str, float | int | None]:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def effective(self, base: DriftConfig) -> dict[str, float | int]:
        """Every tunable value as ``base`` resolves it with these overrides (pairs that would
        be inconsistent fall back to ``base``'s pair, see ``apply``)."""
        return tunable_values(self.apply(base))

    def apply(self, base: DriftConfig) -> DriftConfig:
        """``base`` with these overrides. Fails safe: a pair whose effective watch is not below
        its drift (only possible if a deployment default moved under a stored override; the API
        refuses it) keeps ``base``'s pair for that statistic and logs it."""
        if not self.overridden:
            return base
        thresholds = dict(base.thresholds)
        for stat, features in TUNABLE_FEATURES.items():
            pair = self._pair(stat, base.threshold(features[0]))
            for feature in features:
                thresholds[feature] = pair
        return replace(
            base,
            thresholds=MappingProxyType(thresholds),
            eval_min_samples=self.min_samples_calls or base.eval_min_samples,
            tool_min_samples=self.min_samples_tools or base.tool_min_samples,
            overrides=self.overridden,
        )

    def _pair(self, stat: str, default: Thresholds) -> Thresholds:
        watch, drift = getattr(self, f"{stat}_watch"), getattr(self, f"{stat}_drift")
        if watch is None and drift is None:
            return default
        resolved = resolve_pair(watch, drift, default)
        if resolved is None:
            log.warning("drift: inconsistent %s override ignored (watch must be < drift)", stat)
            return default
        return resolved


def tunable_values(cfg: DriftConfig) -> dict[str, float | int]:
    """The tenant-tunable values of ``cfg`` by name (``THRESHOLD_BOUNDS`` keys)."""
    out: dict[str, float | int] = {}
    for stat, features in TUNABLE_FEATURES.items():
        pair = cfg.threshold(features[0])
        out[f"{stat}_watch"], out[f"{stat}_drift"] = pair.watch, pair.drift
    out["min_samples_calls"] = cfg.eval_min_samples
    out["min_samples_tools"] = cfg.tool_min_samples
    return out


def resolve_pair(
    watch: float | None, drift: float | None, default: Thresholds
) -> Thresholds | None:
    """The effective pair (override else default), or ``None`` unless ``0 < watch < drift``."""
    effective_watch = default.watch if watch is None else float(watch)
    effective_drift = default.drift if drift is None else float(drift)
    if not 0 < effective_watch < effective_drift:
        return None
    return Thresholds(effective_watch, effective_drift)
