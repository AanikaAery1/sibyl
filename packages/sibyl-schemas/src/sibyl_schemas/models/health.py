"""`sibyl-health/1`, `sibyl-feature-snapshot/1` and `sibyl-label/1`."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import MISSING, ConfigDict, Field, StringConstraints, model_validator

from sibyl_schemas._enums import (
    BreakerState,
    Confidence,
    FactorDirection,
    FailMode,
    FailureMode,
    HandoffEventOutcome,
    HealthBand,
    JudgesKind,
    LabelKind,
    LabellerKind,
    ProbabilityBand,
    ProviderStatus,
    RecommendedAction,
    RoutingState,
    RuleKind,
    TaskOutcome,
    Verdict,
    WindowGrainS,
)
from sibyl_schemas.models._base import (
    FeatureSnapshotRef,
    Lax,
    NonNegInt,
    OpenWireModel,
    PosInt,
    RuleIdStr,
    TierInt,
    Timestamp,
    UnitInterval,
    Uuid,
    UuidV7,
    WireModel,
    inline_local_refs,
)

PREDICTION_SOURCE_PATTERN = r"^(rules/v\d+|model/[a-z0-9_-]+:[A-Za-z0-9._-]+)$"
FEATURE_KEY_PATTERN = r"^[a-z][a-z0-9_]{1,60}$"

FactorValue = float | str | bool


class Factor(WireModel):
    rule: RuleIdStr
    weight: UnitInterval
    penalty: Annotated[float, Field(ge=0, le=100)] | MISSING = MISSING
    value: FactorValue
    threshold: FactorValue
    direction: Lax[FactorDirection]
    explanation: Annotated[str, Field(max_length=300)]
    evidence: str | MISSING = MISSING
    kind: Lax[RuleKind] | MISSING = MISSING
    horizon_s: int | MISSING = MISSING


class Prediction(WireModel):
    probability_band: Lax[ProbabilityBand]
    probability: UnitInterval | MISSING = MISSING
    predicted_failure_mode: Lax[FailureMode] | MISSING | None = MISSING
    source: Annotated[str, StringConstraints(pattern=PREDICTION_SOURCE_PATTERN)]
    confidence: Lax[Confidence]
    contributing_rules: list[RuleIdStr] | MISSING = MISSING
    abstained: bool | MISSING = MISSING


class Horizons(WireModel):
    m15: Prediction = Field(alias="15m")
    h1: Prediction = Field(alias="1h")
    h24: Prediction = Field(alias="24h")


class HealthWindow(WireModel):
    start: Timestamp
    end: Timestamp
    grain_s: Lax[WindowGrainS]


class Provisional(WireModel):
    flag: bool
    events_seen: NonNegInt
    events_needed: PosInt
    observation_coverage: UnitInterval | MISSING = MISSING


class HealthDocument(WireModel):
    """`GET /api/v1/agents/{id}/health` (ML §3)."""

    schema_: Literal["sibyl-health/1"] = Field(alias="schema")
    health_snapshot_id: UuidV7
    tenant_id: Uuid
    agent_id: Uuid
    computed_at: Timestamp
    window: HealthWindow
    score: Annotated[int, Field(ge=0, le=100)]
    status: Lax[HealthBand]
    provisional: Provisional
    factors: list[Factor]
    horizons: Horizons
    predicted_failure_mode: Lax[FailureMode] | None
    recommended_action: Lax[RecommendedAction] | MISSING | None = MISSING
    feature_snapshot_ref: FeatureSnapshotRef
    policy_version: NonNegInt
    routing_state: Lax[RoutingState] | MISSING = MISSING


FeatureKey = Annotated[str, StringConstraints(pattern=FEATURE_KEY_PATTERN)]
FeatureGrainMap = Annotated[
    dict[FeatureKey, float | None], Field(json_schema_extra={"additionalProperties": False})
]
"""`patternProperties` alone would admit non-matching keys; pin them shut."""


class Grains(WireModel):
    m1: FeatureGrainMap = Field(alias="1m")
    m5: FeatureGrainMap = Field(alias="5m")
    m15: FeatureGrainMap = Field(alias="15m")
    h1: FeatureGrainMap = Field(alias="1h")


class StaticFeatures(WireModel):
    tier: TierInt
    provider: str
    model: str
    fail_mode: Lax[FailMode]
    routing_state: Lax[RoutingState] | MISSING = MISSING
    breaker_state: Lax[BreakerState] | MISSING = MISSING
    provider_status: Lax[ProviderStatus] | MISSING = MISSING
    budget_headroom: float | MISSING = MISSING
    model_context_limit: int | MISSING = MISSING
    days_to_model_deprecation: int | MISSING | None = MISSING
    days_to_credential_expiry: int | MISSING | None = MISSING
    hour_of_day_utc: Annotated[int, Field(ge=0, le=23)]
    day_of_week_utc: Annotated[int, Field(ge=0, le=6)]
    agent_age_days: float | MISSING = MISSING
    peer_group: str | MISSING = MISSING


class FeatureSnapshot(WireModel):
    """Frozen feature vector a health computation used (immutable, replayable)."""

    schema_: Literal["sibyl-feature-snapshot/1"] = Field(alias="schema")
    feature_snapshot_ref: FeatureSnapshotRef
    tenant_id: Uuid
    agent_id: Uuid
    as_of: Timestamp
    feature_set: Annotated[str, StringConstraints(pattern=r"^features/v\d+$")]
    grains: Grains
    static: StaticFeatures
    observation_coverage: UnitInterval
    baseline_ref: str | MISSING = MISSING


# ------------------------------------------------------------------------- labels


class JudgedWindow(OpenWireModel):
    start: Timestamp
    end: Timestamp


class Judges(WireModel):
    kind: Lax[JudgesKind]
    id: str
    window: JudgedWindow | MISSING = MISSING
    feature_snapshot_ref: FeatureSnapshotRef | MISSING = MISSING


class Labeller(OpenWireModel):
    kind: Lax[LabellerKind]
    ref: str | MISSING = MISSING


class _AlertVerdictValue(OpenWireModel):
    verdict: Lax[Verdict]
    actual_failure_mode: Lax[FailureMode] | MISSING | None = MISSING
    lead_time_s: int | MISSING | None = MISSING


class _TaskOutcomeValue(OpenWireModel):
    outcome: Lax[TaskOutcome]
    rework: bool | MISSING = MISSING


class _FeedbackValue(OpenWireModel):
    score: Annotated[float, Field(ge=-1, le=1)]
    scale: str | MISSING = MISSING


class _FailoverOutcomeValue(OpenWireModel):
    fallback_succeeded: bool
    time_to_recover_s: int | MISSING = MISSING
    failback_verified: bool | MISSING = MISSING
    undone_by_operator: bool | MISSING = MISSING


class _HandoffOutcomeValue(OpenWireModel):
    outcome: Lax[HandoffEventOutcome]
    rework: bool | MISSING = MISSING
    rating: Annotated[int, Field(ge=1, le=5)] | MISSING = MISSING
    packet_useful: bool | MISSING = MISSING


class _ProviderIncidentValue(OpenWireModel):
    provider: str
    status: str
    incident_id: str | MISSING = MISSING
    rule_fired_before: bool
    lead_time_s: int | MISSING | None = MISSING


_LABEL_VALUE_MODELS: dict[LabelKind, type[OpenWireModel]] = {
    LabelKind.ALERT_VERDICT: _AlertVerdictValue,
    LabelKind.TASK_OUTCOME: _TaskOutcomeValue,
    LabelKind.FEEDBACK: _FeedbackValue,
    LabelKind.FAILOVER_OUTCOME: _FailoverOutcomeValue,
    LabelKind.HANDOFF_OUTCOME: _HandoffOutcomeValue,
    LabelKind.PROVIDER_INCIDENT: _ProviderIncidentValue,
}


def _label_schema_extra(schema: dict[str, Any], cls: type) -> None:
    """Export the per-kind `value` rules exactly as the hand-written schema states them."""
    rules: list[dict[str, Any]] = []
    for kind, model in _LABEL_VALUE_MODELS.items():
        value_schema = inline_local_refs(model.model_json_schema())
        value_schema.pop("title", None)
        rules.append(
            {
                "if": {"properties": {"kind": {"const": kind.value}}},
                "then": {"properties": {"value": value_schema}},
            }
        )
    schema["allOf"] = rules


class Label(WireModel):
    """A verdict or outcome judging exactly one thing (ML §5.2, D24)."""

    model_config = ConfigDict(json_schema_extra=_label_schema_extra)

    schema_: Literal["sibyl-label/1"] = Field(alias="schema")
    label_id: UuidV7
    tenant_id: Uuid
    agent_id: Uuid
    kind: Lax[LabelKind]
    judges: Judges
    judged_as_of: Timestamp
    labelled_at: Timestamp
    labeller: Labeller
    value: dict[str, Any]
    reason: Annotated[str, Field(max_length=500)] | MISSING = MISSING

    @model_validator(mode="after")
    def _value_matches_kind(self) -> Label:
        _LABEL_VALUE_MODELS[self.kind].model_validate(self.value)
        return self
