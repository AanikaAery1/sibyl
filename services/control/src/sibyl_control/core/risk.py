"""Frozen ``RiskDocument`` and ``Prediction`` types (ROADMAP W0-KER; ML §4) so lane S does not
wait for lane P. Mirrors the OpenAPI ``RiskDocument`` component; the contract test keeps the two
in step. ``rules/v1`` never emits a numeric ``probability`` (model sources only, Phase 2).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from types import MappingProxyType
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

ProbabilityBand = Literal["0.05", "0.25", "0.60", "0.90"]
Confidence = Literal["low", "medium", "high"]
HorizonKey = Literal["15m", "1h", "24h"]
RecommendedAction = Literal[
    "none",
    "watch",
    "throttle",
    "trim_context",
    "reroute_to_fallback",
    "quarantine",
    "await_approval",
    "handoff",
]
FailureMode = Literal[
    "provider_outage",
    "latency_degradation",
    "quality_collapse",
    "prompt_injection",
    "policy_violation",
    "tool_failure",
    "data_source_failure",
    "infinite_loop",
    "cost_runaway",
    "permission_error",
    "model_deprecation",
    "silent_drift",
]
HORIZON_SECONDS: Mapping[str, int] = MappingProxyType({"15m": 900, "1h": 3600, "24h": 86400})
RULES_SOURCE_PATTERN = r"^(rules/v\d+|model/.+)$"


class RiskHorizon(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    horizon_s: int
    probability_band: ProbabilityBand
    probability: float | None = None
    confidence: Confidence
    contributing_rules: tuple[str, ...] = ()
    abstained: bool = False


class RiskDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID
    evaluated_at: datetime | None = None
    horizons: dict[HorizonKey, RiskHorizon]
    predicted_failure_mode: FailureMode | None = None
    recommended_action: RecommendedAction
    leading_rules_firing: tuple[str, ...] = ()
    rules_source: str = Field(pattern=RULES_SOURCE_PATTERN)

    @model_validator(mode="after")
    def _all_horizons(self) -> RiskDocument:
        if set(self.horizons) != set(HORIZON_SECONDS):
            raise ValueError("horizons must be exactly 15m, 1h and 24h")
        if self.rules_source.startswith("rules/") and any(
            h.probability is not None for h in self.horizons.values()
        ):
            raise ValueError("rules sources never emit a numeric probability")
        return self


class Prediction(BaseModel):
    """One sparse ``prediction`` row (ML §9, R49) as lanes P and S exchange it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: UUID
    agent_id: UUID
    predicted_at: datetime
    horizon_s: int
    source: str = Field(pattern=RULES_SOURCE_PATTERN)
    probability_band: ProbabilityBand
    probability: float | None = None
    confidence: Confidence
    predicted_failure_mode: FailureMode | None = None
    health_snapshot_id: UUID | None = None
    feature_snapshot_id: UUID | None = None
    abstained: bool = False
