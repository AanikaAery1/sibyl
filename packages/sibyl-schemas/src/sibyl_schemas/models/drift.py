"""Model drift API documents (D51): baselines, reports, the fleet summary and the reset body.

Responses are open to additive fields like every Sibyl resource; the reset body is closed
(unknown members are a 422). Every report carries each feature's numbers (statistic, value,
noise floor, excess, thresholds, sample counts, top movers) so a verdict can always be
explained without re-running anything. Detection is deterministic (PSI / Jensen-Shannon and
model-identity checks), never an LLM.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sibyl_schemas._enums_drift import (
    DriftBaselineState,
    DriftFeature,
    DriftIdentityChange,
    DriftStatistic,
    DriftVerdict,
)

MAX_PROVIDER = 64
MAX_MODEL = 256


class _Doc(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True)


class DriftContributor(_Doc):
    """A bin (numeric) or category whose share moved most."""

    label: str
    baseline: float
    window: float


class DriftFeatureResult(_Doc):
    feature: DriftFeature
    statistic: DriftStatistic
    status: str = Field(description="ok | insufficient_samples | invalid_baseline")
    value: float | None
    noise_floor: float = 0.0
    excess: float | None = None
    watch: float
    drift: float
    verdict: DriftVerdict
    n_baseline: int
    n_window: int
    contributors: list[DriftContributor] = Field(default_factory=list)


class DriftIdentityFinding(_Doc):
    kind: DriftIdentityChange
    value: str
    count: int
    requested_model: str


class DriftReportSummary(_Doc):
    id: UUID
    baseline_id: UUID
    evaluated_at: datetime
    verdict: DriftVerdict
    behaviour_evaluated: bool
    identity_changed: bool
    max_ratio: float
    sample_count: int


class DriftReport(DriftReportSummary):
    agent_id: UUID
    provider: str
    model: str
    window_start: datetime
    window_end: datetime
    tool_sample_count: int
    features: list[DriftFeatureResult]
    identity: list[DriftIdentityFinding]
    config: dict[str, Any] = Field(default_factory=dict)


class DriftBaseline(_Doc):
    id: UUID
    agent_id: UUID
    provider: str
    model: str
    state: DriftBaselineState
    window_start: datetime
    window_end: datetime | None
    sample_count: int
    tool_sample_count: int
    frozen_at: datetime | None
    served_models: list[str]
    fingerprints: list[str]
    features: dict[str, Any] = Field(
        description="frozen distributions per feature (numeric: edges + probs; categorical:"
        " probs), empty while collecting"
    )
    reset_by_user_id: UUID | None = None
    reset_reason: str | None = None
    supersedes: UUID | None = None
    superseded_by: UUID | None = None
    superseded_at: datetime | None = None
    last_evaluated_at: datetime | None = None
    created_at: datetime


class DriftAlertRef(_Doc):
    id: UUID
    rule: str
    severity: str
    state: str
    first_fired_at: datetime
    summary: str


class DriftKeySummary(_Doc):
    """One current baseline in the fleet view, with its latest evaluation."""

    baseline_id: UUID
    agent_id: UUID
    agent_name: str
    provider: str
    model: str
    state: DriftBaselineState
    frozen_at: datetime | None
    sample_count: int
    report_id: UUID | None
    evaluated_at: datetime | None
    verdict: DriftVerdict | None
    identity_changed: bool
    max_ratio: float | None
    drifting_features: list[str]
    created_at: datetime


class FleetDriftSummary(_Doc):
    baselines: int
    collecting: int
    frozen: int
    drift: int
    watch: int
    identity_changed: int
    open_alerts: int


class AgentDrift(_Doc):
    agent_id: UUID
    baselines: list[DriftBaseline]
    latest: list[DriftReport]
    history: list[DriftReportSummary]
    open_alerts: list[DriftAlertRef]


class DriftBaselineReset(BaseModel):
    """``POST /agents/{agent_id}/drift/baseline``: supersede the agent's current baselines (or
    the one for ``provider`` / ``model``) and start collecting again from ``since`` (default now;
    a past ``since`` re-freezes on recent traffic at the next drift tick)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    provider: str | None = Field(default=None, max_length=MAX_PROVIDER)
    model: str | None = Field(default=None, min_length=1, max_length=MAX_MODEL)
    since: datetime | None = None
    reason: str = Field(min_length=10, max_length=2000)

    @model_validator(mode="after")
    def _aware(self) -> DriftBaselineReset:
        if self.since is not None and self.since.tzinfo is None:
            raise ValueError("since needs a time zone (RFC 3339)")
        return self


class DriftBaselineResetResult(_Doc):
    agent_id: UUID
    superseded: list[UUID]
    baselines: list[DriftBaseline]


# --- tenant-tunable thresholds (wave 4 HARDEN) ---------------------------------------------------

THRESHOLD_BOUNDS: Mapping[str, tuple[float, float] | tuple[int, int]] = MappingProxyType(
    {
        # PSI: below 0.01 is sampling noise on decile bins; above 2.0 no realistic shift reads.
        "psi_watch": (0.01, 2.0),
        "psi_drift": (0.01, 2.0),
        # JS (base 2) on a share: 0.0005 is about a 1 % -> 1.5 % move; 0.5 is a full flip.
        "js_two_category_watch": (0.0005, 0.5),
        "js_two_category_drift": (0.0005, 0.5),
        # JS on a mix (error classes, tool bigrams): bounded by 1.0.
        "js_many_category_watch": (0.005, 1.0),
        "js_many_category_drift": (0.005, 1.0),
        # Window minimums: at most the samples a window can hold (5,000 calls, 20,000 tools).
        "min_samples_calls": (50, 5000),
        "min_samples_tools": (10, 20000),
    }
)
"""Inclusive bounds of every tenant-tunable drift value (API, OpenAPI and DB CHECKs)."""

THRESHOLD_STATISTICS = ("psi", "js_two_category", "js_many_category")


def _bounded(name: str) -> Any:
    """Strict (a JSON string is refused), inclusive bounds from ``THRESHOLD_BOUNDS``."""
    low, high = THRESHOLD_BOUNDS[name]
    return Field(default=None, ge=low, le=high, strict=True)


class DriftThresholdsPut(BaseModel):
    """``PUT /drift/thresholds``: the tenant's whole override set. A null or omitted value
    uses the deployment default, so a body with only ``reason`` resets every value."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    psi_watch: float | None = _bounded("psi_watch")
    psi_drift: float | None = _bounded("psi_drift")
    js_two_category_watch: float | None = _bounded("js_two_category_watch")
    js_two_category_drift: float | None = _bounded("js_two_category_drift")
    js_many_category_watch: float | None = _bounded("js_many_category_watch")
    js_many_category_drift: float | None = _bounded("js_many_category_drift")
    min_samples_calls: int | None = _bounded("min_samples_calls")
    min_samples_tools: int | None = _bounded("min_samples_tools")
    reason: str = Field(min_length=10, max_length=2000)

    def overrides(self) -> dict[str, float | int | None]:
        return {name: getattr(self, name) for name in THRESHOLD_BOUNDS}


class DriftThresholdValue(_Doc):
    value: float
    default: float
    source: str = Field(description="tenant | default")
    minimum: float
    maximum: float


class DriftThresholds(_Doc):
    values: dict[str, DriftThresholdValue]
    version: int
    updated_at: datetime | None = None
    updated_by_user_id: UUID | None = None
    watch_only: bool = True


__all__ = [
    "THRESHOLD_BOUNDS",
    "THRESHOLD_STATISTICS",
    "AgentDrift",
    "DriftAlertRef",
    "DriftBaseline",
    "DriftBaselineReset",
    "DriftBaselineResetResult",
    "DriftContributor",
    "DriftFeatureResult",
    "DriftIdentityFinding",
    "DriftKeySummary",
    "DriftReport",
    "DriftReportSummary",
    "DriftThresholdValue",
    "DriftThresholds",
    "DriftThresholdsPut",
    "FleetDriftSummary",
]
