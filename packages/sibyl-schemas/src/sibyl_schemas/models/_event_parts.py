"""`sibyl-event/1` building blocks: shared `$defs` and the per-type `attrs` models."""

from __future__ import annotations

from typing import Annotated

from pydantic import MISSING, AfterValidator, Field, StringConstraints

from sibyl_schemas._enums import (
    AssembledBy,
    BreakerState,
    CallStatus,
    DiscoveredVia,
    EventStatus,
    FailMode,
    FailureMode,
    FeedbackRater,
    FeedbackTargetKind,
    Fidelity,
    GapCause,
    GapStatus,
    GenAiOperation,
    HandoffEventOutcome,
    HandoffTrigger,
    HealthBand,
    InvokePhase,
    MergeState,
    OutcomeDeclaredBy,
    OutputType,
    PayloadEncoding,
    PayloadPart,
    PolicyDecisionAction,
    PolicyDecisionState,
    PolicyState,
    PriorHealthBand,
    ProviderStatus,
    ProviderStatusFeed,
    RouteDecision,
    SideEffectClass,
    TaskOutcome,
    TelemetrySource,
    ToolType,
    UsageSource,
)
from sibyl_schemas._enums_action import ToolActionEffect
from sibyl_schemas.models._base import (
    FeatureSnapshotRef,
    Lax,
    NonNegInt,
    NonNegNum,
    OpenWireModel,
    PosInt,
    RuleIdStr,
    Sha256Hex,
    SpanId,
    Timestamp,
    TraceId,
    UnitInterval,
    Uuid,
    UuidV7,
    WireModel,
)

AgentRef = Annotated[str, Field(min_length=1, max_length=256)]
"""Run tree (D50): an agent slug, uuid or framework agent name."""
Fingerprint = Annotated[str, Field(max_length=128)]
ActionRuleRef = Annotated[str, Field(min_length=1, max_length=128)]
"""Action Gate rule id on a tool call (`<rule_id>` or a `sibyl:` built-in such as
`sibyl:tool_allowlist`)."""
BLOB_REF_PATTERN = r"^blob://[0-9a-f-]{36}/\d{4}-\d{2}-\d{2}/[A-Za-z0-9_./-]+$"
PAYLOAD_INLINE_MAX_CHARS = 4 * 1024 * 1024


def _unique[T](items: list[T]) -> list[T]:
    if len(set(items)) != len(items):
        raise ValueError("items must be unique")
    return items


class RedactionRecord(WireModel):
    """`$defs/redaction_profile`: the profile applied to an event or stored object."""

    id: str
    version: PosInt
    rules_fired: list[str] | MISSING = MISSING
    secrets_scrubbed: NonNegInt
    fields_redacted: list[str] | MISSING = MISSING
    profile_hash: Sha256Hex | MISSING = MISSING
    emitter_profile_hash: Sha256Hex | MISSING = MISSING
    late_hits: NonNegInt | MISSING = MISSING


class PolicyStateInfo(WireModel):
    state: Lax[PolicyState]
    policy_version: NonNegInt | MISSING | None = MISSING
    fail_mode: Lax[FailMode] | MISSING | None = MISSING
    snapshot_age_s: NonNegNum | MISSING = MISSING


class PayloadRef(WireModel):
    ref: Annotated[str, StringConstraints(pattern=BLOB_REF_PATTERN)]
    sha256: Sha256Hex
    bytes: NonNegInt
    content_type: str
    parts: list[Lax[PayloadPart]] | MISSING = MISSING
    redaction_profile: RedactionRecord | MISSING = MISSING
    truncated: bool | MISSING = MISSING
    bytes_original: NonNegInt | MISSING = MISSING


class PayloadInline(WireModel):
    """Wire-only body that ingest turns into a `PayloadRef` (`sibyl-event-wire/1`)."""

    encoding: Lax[PayloadEncoding]
    data: Annotated[str, Field(max_length=PAYLOAD_INLINE_MAX_CHARS)]
    content_type: Annotated[str, Field(min_length=1, max_length=128)]
    parts: list[Lax[PayloadPart]] | MISSING = MISSING


class RawSpanRef(OpenWireModel):
    source: Lax[TelemetrySource]
    trace_id: TraceId
    span_id: SpanId
    ref: str


class IngestInfo(WireModel):
    normaliser_version: str | MISSING = MISSING
    semconv_version: str | MISSING = MISSING
    instrumentor: str | MISSING = MISSING
    raw_span_refs: list[RawSpanRef] | MISSING = MISSING
    warnings: list[str] | MISSING = MISSING
    sdk_version: str | MISSING = MISSING


class Target(WireModel):
    provider: str
    model: str
    base_url_hash: str | MISSING = MISSING
    agent_id: Uuid | MISSING = MISSING


class Usage(WireModel):
    input_tokens: NonNegInt | MISSING = MISSING
    output_tokens: NonNegInt | MISSING = MISSING
    cached_input_tokens: NonNegInt | MISSING = MISSING
    cache_creation_input_tokens: NonNegInt | MISSING = MISSING
    reasoning_tokens: NonNegInt | MISSING = MISSING
    source: Lax[UsageSource] | MISSING = MISSING


class RequestParams(WireModel):
    temperature: float | MISSING = MISSING
    top_p: float | MISSING = MISSING
    top_k: int | MISSING = MISSING
    max_tokens: int | MISSING = MISSING
    seed: int | MISSING = MISSING
    stop_sequences: list[str] | MISSING = MISSING
    frequency_penalty: float | MISSING = MISSING
    presence_penalty: float | MISSING = MISSING
    choice_count: int | MISSING = MISSING
    output_type: Lax[OutputType] | MISSING = MISSING
    service_tier: str | MISSING = MISSING
    tool_definitions_count: NonNegInt | MISSING = MISSING


class ToolCallRequested(OpenWireModel):
    id: str | MISSING = MISSING
    name: str


class ContextInfo(WireModel):
    model_context_limit: PosInt | MISSING = MISSING
    utilisation: UnitInterval | MISSING = MISSING


class RateLimitInfo(WireModel):
    limit_requests: int | MISSING = MISSING
    remaining_requests: int | MISSING = MISSING
    reset_requests_ms: int | MISSING = MISSING
    limit_tokens: int | MISSING = MISSING
    remaining_tokens: int | MISSING = MISSING
    reset_tokens_ms: int | MISSING = MISSING
    headroom: UnitInterval | MISSING = MISSING


class RetryInfo(WireModel):
    attempt: PosInt
    inline_fallback_used: bool | MISSING = MISSING
    fallback_target: Target | MISSING = MISSING
    breaker_state: Lax[BreakerState] | MISSING = MISSING


class RouteInfo(WireModel):
    decision: Lax[RouteDecision]
    reason: str | MISSING = MISSING
    from_: Target | MISSING = Field(default=MISSING, alias="from")
    to: Target | MISSING = MISSING
    transition_id: Uuid | MISSING = MISSING


class ServerInfo(OpenWireModel):
    address: str | MISSING = MISSING
    port: int | MISSING = MISSING


class ContentHashes(OpenWireModel):
    input: Sha256Hex | MISSING = MISSING
    output: Sha256Hex | MISSING = MISSING
    system: Sha256Hex | MISSING = MISSING


Contributions = Annotated[
    list[Lax[TelemetrySource]],
    Field(min_length=1, json_schema_extra={"uniqueItems": True}),
    AfterValidator(_unique),
]


class GenAiRequestAttrs(WireModel):
    operation: Lax[GenAiOperation]
    provider: str
    request_model: str
    response_model: str | MISSING = MISSING
    response_id: str | MISSING = MISSING
    status: Lax[CallStatus]
    error_type: str | MISSING = MISSING
    http_status: Annotated[int, Field(ge=100, le=599)] | MISSING = MISSING
    latency_ms: NonNegNum
    ttfb_ms: NonNegNum | MISSING = MISSING
    streamed: bool | MISSING = MISSING
    usage: Usage | MISSING = MISSING
    cost_usd: NonNegNum | MISSING = MISSING
    cost_source: str | MISSING = MISSING
    finish_reasons: list[str] | MISSING = MISSING
    request: RequestParams | MISSING = MISSING
    tool_calls_requested: list[ToolCallRequested] | MISSING = MISSING
    context: ContextInfo | MISSING = MISSING
    ratelimit: RateLimitInfo | MISSING = MISSING
    retry: RetryInfo | MISSING = MISSING
    route: RouteInfo | MISSING = MISSING
    server: ServerInfo | MISSING = MISSING
    conversation_id: str | MISSING = MISSING
    prompt_version: str | MISSING = MISSING
    data_source_ids: list[str] | MISSING = MISSING
    payload: PayloadRef | MISSING = MISSING
    content_hashes: ContentHashes | MISSING = MISSING
    output_chars: NonNegInt | MISSING = MISSING
    eval_sample: bool | MISSING = MISSING
    contributions: Contributions
    merge_state: Lax[MergeState]
    policy_sdk_version: NonNegInt | MISSING = MISSING
    cost_unpriced: bool | MISSING = MISSING
    capture_override_rejected: bool | MISSING = MISSING
    system_fingerprint: Fingerprint | MISSING = MISSING
    parent_run_id: Uuid | MISSING = MISSING
    step_index: NonNegInt | MISSING = MISSING


class ToolCallAttrs(WireModel):
    tool_name: str
    tool_type: Lax[ToolType]
    tool_call_id: str | MISSING = MISSING
    mcp_server: str | MISSING = MISSING
    status: Lax[CallStatus]
    error_type: str | MISSING = MISSING
    latency_ms: NonNegNum
    side_effect_class: Lax[SideEffectClass] | MISSING = MISSING
    args_bytes: NonNegInt | MISSING = MISSING
    result_bytes: NonNegInt | MISSING = MISSING
    payload: PayloadRef | MISSING = MISSING
    parent_run_id: Uuid | MISSING = MISSING
    step_index: NonNegInt | MISSING = MISSING
    handoff_to_agent: AgentRef | MISSING = MISSING
    action_effect: Lax[ToolActionEffect] | MISSING = MISSING
    action_rule_id: ActionRuleRef | MISSING = MISSING
    held_action_id: Uuid | MISSING = MISSING


class A2AInfo(OpenWireModel):
    remote_task_id: str | MISSING = MISSING
    state: str | MISSING = MISSING
    callee_agent_id: Uuid | MISSING = MISSING


class AgentInvokeAttrs(WireModel):
    phase: Lax[InvokePhase]
    agent_name: str
    parent_task_id: Uuid | MISSING = MISSING
    status: Lax[EventStatus] | MISSING = MISSING
    error_type: str | MISSING = MISSING
    duration_ms: NonNegNum | MISSING = MISSING
    steps: NonNegInt | MISSING = MISSING
    tool_calls: NonNegInt | MISSING = MISSING
    model_calls: NonNegInt | MISSING = MISSING
    cost_usd: NonNegNum | MISSING = MISSING
    a2a: A2AInfo | MISSING = MISSING
    parent_run_id: Uuid | MISSING = MISSING
    step_index: NonNegInt | MISSING = MISSING
    handoff_to_agent: AgentRef | MISSING = MISSING


class CheckpointAttrs(WireModel):
    checkpoint_id: UuidV7
    seq: PosInt
    step_index: NonNegInt
    step_name: str | MISSING = MISSING
    state_bytes: NonNegInt
    state_ref: PayloadRef | MISSING = MISSING
    state_schema: str | MISSING = MISSING
    completed_count: NonNegInt
    pending_count: NonNegInt
    side_effects_count: NonNegInt | MISSING = MISSING
    prev_checkpoint_id: UuidV7 | MISSING = MISSING


class HandoffRequestedAttrs(WireModel):
    packet_id: UuidV7
    trigger: Lax[HandoffTrigger]
    rule_id: RuleIdStr | MISSING = MISSING
    alert_id: Uuid | MISSING = MISSING
    transition_id: Uuid | MISSING = MISSING
    fidelity: Lax[Fidelity]
    assembled_by: Lax[AssembledBy]
    failure_mode: Lax[FailureMode]
    checkpoint_seq: NonNegInt | MISSING = MISSING
    packet_ref: PayloadRef | MISSING = MISSING
    reason_preview: Annotated[str, Field(max_length=280)] | MISSING = MISSING


class HandoffResolvedAttrs(WireModel):
    packet_id: UuidV7
    outcome: Lax[HandoffEventOutcome]
    operator_ref: Uuid
    claimed_at: Timestamp
    resolved_at: Timestamp
    time_to_claim_s: NonNegNum | MISSING = MISSING
    rework: bool | MISSING = MISSING
    rating: Annotated[int, Field(ge=1, le=5)] | MISSING = MISSING
    returned_to_agent_id: Uuid | MISSING = MISSING
    note_ref: PayloadRef | MISSING = MISSING


class FeedbackTarget(OpenWireModel):
    kind: Lax[FeedbackTargetKind]
    id: str


class FeedbackAttrs(WireModel):
    feedback_id: UuidV7
    target: FeedbackTarget
    score: Annotated[float, Field(ge=-1, le=1)]
    scale: str
    raw_value: float | str | MISSING = MISSING
    rater: Lax[FeedbackRater]
    comment_ref: PayloadRef | MISSING = MISSING
    tags: list[str] | MISSING = MISSING


class TaskMetrics(OpenWireModel):
    steps: int | MISSING = MISSING
    tool_calls: int | MISSING = MISSING
    model_calls: int | MISSING = MISSING
    cost_usd: NonNegNum | MISSING = MISSING
    duration_ms: float | MISSING = MISSING


class TaskOutcomeAttrs(WireModel):
    outcome: Lax[TaskOutcome]
    declared_by: Lax[OutcomeDeclaredBy]
    reason: Annotated[str, Field(max_length=500)] | MISSING = MISSING
    rework: bool | MISSING = MISSING
    metrics: TaskMetrics | MISSING = MISSING


class AgentDiscoveredAttrs(WireModel):
    discovered_via: Lax[DiscoveredVia]
    candidate: Annotated[str, Field(max_length=256)]
    candidate_hash: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
    resolved_agent_id: Uuid
    fail_mode_applied: Lax[FailMode]
    first_call_id: Uuid | MISSING = MISSING
    first_trace_id: TraceId | MISSING = MISSING
    server_address: str | MISSING = MISSING


class PolicyDecisionAttrs(WireModel):
    action: Lax[PolicyDecisionAction]
    state: Lax[PolicyDecisionState]
    fail_mode: Lax[FailMode]
    reason: Annotated[str, Field(max_length=200)]
    snapshot_issued_at: Timestamp | MISSING = MISSING
    from_target: Target | MISSING = MISSING
    to_target: Target | MISSING = MISSING
    attempt: PosInt | MISSING = MISSING
    http_status_returned: int | MISSING = MISSING


class ObservationGapAttrs(WireModel):
    emitter_id: str
    gap_start: Timestamp
    gap_end: Timestamp | MISSING = MISSING
    cause: Lax[GapCause]
    status: Lax[GapStatus]
    events_replayed: NonNegInt | MISSING = MISSING
    events_dropped: NonNegInt | MISSING = MISSING
    affected_agent_ids: list[Uuid] | MISSING = MISSING


class ProviderStatusAttrs(WireModel):
    provider: str
    component: str | MISSING = MISSING
    status: Lax[ProviderStatus]
    feed: Lax[ProviderStatusFeed]
    incident_id: str | MISSING = MISSING
    incident_url: str | MISSING = MISSING
    started_at: Timestamp | MISSING = MISSING
    resolved_at: Timestamp | MISSING = MISSING
    probe_latency_ms: NonNegNum | MISSING = MISSING


class HealthTransitionAttrs(WireModel):
    from_status: Lax[PriorHealthBand]
    to_status: Lax[HealthBand]
    score: Annotated[int, Field(ge=0, le=100)]
    health_snapshot_id: UuidV7
    feature_snapshot_ref: FeatureSnapshotRef
    rules_fired: list[RuleIdStr]
    alert_id: Uuid | MISSING = MISSING
    recommended_action: str | MISSING = MISSING


# Wire variants: `payload_inline` allowed where the canonical attrs carry a PayloadRef.


class GenAiRequestWireAttrs(GenAiRequestAttrs):
    payload_inline: PayloadInline | MISSING = MISSING


class ToolCallWireAttrs(ToolCallAttrs):
    payload_inline: PayloadInline | MISSING = MISSING


class CheckpointWireAttrs(CheckpointAttrs):
    payload_inline: PayloadInline | MISSING = MISSING


class HandoffRequestedWireAttrs(HandoffRequestedAttrs):
    payload_inline: PayloadInline | MISSING = MISSING


class HandoffResolvedWireAttrs(HandoffResolvedAttrs):
    payload_inline: PayloadInline | MISSING = MISSING


class FeedbackWireAttrs(FeedbackAttrs):
    payload_inline: PayloadInline | MISSING = MISSING
