"""`sibyl-checkpoint/1` and `sibyl-handoff/1` (API §9) with their shared step models."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import MISSING, ConfigDict, Field, model_validator

from sibyl_schemas._enums import (
    INLINE_STATE_MAX_BYTES,
    AssembledBy,
    CaptureMode,
    DeadlineSource,
    FailureMode,
    Fidelity,
    HandoffTrigger,
    SideEffectKind,
)
from sibyl_schemas.models._base import (
    Lax,
    NonNegInt,
    NonNegNum,
    OpenWireModel,
    PosInt,
    RuleIdStr,
    Sha256Hex,
    SpanId,
    TierInt,
    Timestamp,
    TraceId,
    Uuid,
    UuidV7,
    WireModel,
)
from sibyl_schemas.models._event_parts import PayloadRef, RedactionRecord, Target
from sibyl_schemas.models.health import Factor


class OutputRef(WireModel):
    preview: Annotated[str, Field(max_length=4096)] | MISSING = MISSING
    ref: PayloadRef | MISSING = MISSING
    content_type: str | MISSING = MISSING


class CompletedStep(WireModel):
    index: NonNegInt
    step: Annotated[str, Field(max_length=128)]
    started_at: Timestamp
    ended_at: Timestamp
    tool_name: str | MISSING = MISSING
    call_id: Uuid | MISSING = MISSING
    span_id: SpanId | MISSING = MISSING
    output: OutputRef | MISSING = MISSING
    assumed: bool


class PendingStep(WireModel):
    index: NonNegInt
    step: Annotated[str, Field(max_length=128)]
    description: Annotated[str, Field(max_length=1000)] | MISSING = MISSING
    inputs_needed: list[str] | MISSING = MISSING
    blocked_on: str | MISSING = MISSING


class SideEffect(WireModel):
    kind: Lax[SideEffectKind]
    target: Annotated[str, Field(max_length=256)] | MISSING = MISSING
    at: Timestamp
    idempotency_key: Annotated[str, Field(max_length=256)] | MISSING = MISSING
    reversible: bool | MISSING = MISSING
    idempotent: bool | MISSING = MISSING
    """A-4: only an explicit `true` lets in-flight work resume automatically."""
    assumed: bool
    evidence_span_id: SpanId | MISSING = MISSING


class RedactionState(WireModel):
    capture_mode: Lax[CaptureMode]
    profile: RedactionRecord
    fields_redacted: list[str] | MISSING = MISSING


class CheckpointProvenance(WireModel):
    sdk_version: str
    trace_id: TraceId
    span_id: SpanId
    prev_checkpoint_id: UuidV7 | MISSING = MISSING
    framework_checkpoint_id: str | MISSING = MISSING


_CHECKPOINT_STATE_RULE: dict[str, Any] = {
    "allOf": [
        {
            "if": {"properties": {"state_bytes": {"maximum": INLINE_STATE_MAX_BYTES}}},
            "then": {"required": ["state"]},
            "else": {"required": ["state_ref"], "not": {"required": ["state"]}},
        }
    ]
}


class Checkpoint(WireModel):
    """Resumable task state; inline up to 64 KiB post-scrub, otherwise a `state_ref`."""

    model_config = ConfigDict(json_schema_extra=_CHECKPOINT_STATE_RULE)

    schema_: Literal["sibyl-checkpoint/1"] = Field(alias="schema")
    checkpoint_id: UuidV7
    tenant_id: Uuid
    agent_id: Uuid
    task_id: Uuid
    seq: PosInt
    step_index: NonNegInt
    step_name: Annotated[str, Field(max_length=128)] | MISSING = MISSING
    created_at: Timestamp
    goal: Annotated[str, Field(max_length=2000)] | MISSING = MISSING
    state: dict[str, Any] | MISSING = MISSING
    state_ref: PayloadRef | MISSING = MISSING
    state_bytes: NonNegInt
    state_sha256: Sha256Hex | MISSING = MISSING
    state_schema: str
    completed_steps: list[CompletedStep]
    pending_steps: list[PendingStep]
    side_effects: list[SideEffect]
    redaction: RedactionState
    provenance: CheckpointProvenance

    @model_validator(mode="after")
    def _inline_or_ref(self) -> Checkpoint:
        if self.state_bytes <= INLINE_STATE_MAX_BYTES:
            if self.state is MISSING:
                raise ValueError("state_bytes <= 65536 requires inline state")
        else:
            if self.state_ref is MISSING:
                raise ValueError("state_bytes > 65536 requires state_ref")
            if self.state is not MISSING:
                raise ValueError("state_bytes > 65536 forbids inline state")
        return self


class Trigger(WireModel):
    kind: Lax[HandoffTrigger]
    rule_id: RuleIdStr | MISSING = MISSING
    alert_id: Uuid | MISSING = MISSING
    health_snapshot_id: UuidV7 | MISSING = MISSING
    factors: list[Factor] | MISSING = MISSING
    span_ids: list[SpanId] | MISSING = MISSING
    call_ids: list[Uuid] | MISSING = MISSING


class HandoffReason(WireModel):
    plain_language: Annotated[str, Field(min_length=20, max_length=1000)]
    failure_mode: Lax[FailureMode]
    trigger: Trigger


class Deadline(WireModel):
    at: Timestamp
    derived_from: Lax[DeadlineSource]
    tier: TierInt | MISSING = MISSING
    rto_s: NonNegInt | MISSING = MISSING


class Accountability(WireModel):
    owner: str
    on_call: str | MISSING = MISSING
    escalation: str | MISSING = MISSING
    business_process: str | MISSING = MISSING
    line: Annotated[str, Field(max_length=300)]


class HandoffProvenance(WireModel):
    assembled_by: Lax[AssembledBy]
    sdk_version: str | MISSING = MISSING
    checkpoint_id: UuidV7 | MISSING = MISSING
    checkpoint_seq: NonNegInt | MISSING = MISSING
    checkpoint_age_s: NonNegNum | MISSING = MISSING
    trace_ids: list[TraceId]
    policy_version: NonNegInt
    transition_id: Uuid | MISSING = MISSING
    normaliser_version: str | MISSING = MISSING


class RouteHistoryItem(OpenWireModel):
    at: Timestamp
    to: Target
    decision: str | MISSING = MISSING


class Sidecar(WireModel):
    route_history: list[RouteHistoryItem] | MISSING = MISSING
    cost_so_far_usd: NonNegNum | MISSING = MISSING
    attempts: NonNegInt | MISSING = MISSING
    model_calls: NonNegInt | MISSING = MISSING
    tool_calls: NonNegInt | MISSING = MISSING


_HANDOFF_RULES: dict[str, Any] = {
    "allOf": [
        {
            "if": {"properties": {"fidelity": {"const": "request_only"}}},
            "then": {"properties": {"pending_steps": {"maxItems": 0}}},
        },
        {
            "if": {
                "properties": {
                    "provenance": {
                        "properties": {"assembled_by": {"const": "sdk"}},
                        "required": ["assembled_by"],
                    }
                }
            },
            "then": {
                "properties": {
                    "reason": {
                        "properties": {
                            "trigger": {"properties": {"kind": {"const": "sdk_explicit"}}}
                        }
                    }
                }
            },
        },
    ]
}


class HandoffPacket(WireModel):
    """What a human needs to finish a task the agent could not (`sibyl-handoff/1`)."""

    model_config = ConfigDict(json_schema_extra=_HANDOFF_RULES)

    schema_: Literal["sibyl-handoff/1"] = Field(alias="schema")
    packet_id: UuidV7
    tenant_id: Uuid
    agent_id: Uuid
    agent_name: Annotated[str, Field(max_length=128)] | MISSING = MISSING
    task_id: Uuid
    created_at: Timestamp
    fidelity: Lax[Fidelity]
    goal: Annotated[str, Field(min_length=1, max_length=2000)]
    original_input: OutputRef
    completed_steps: list[CompletedStep]
    pending_steps: list[PendingStep]
    side_effects: list[SideEffect] | MISSING = MISSING
    reason: HandoffReason
    next_action: Annotated[str, Field(min_length=5, max_length=300)]
    deadline: Deadline
    accountability: Accountability
    redaction: RedactionState
    provenance: HandoffProvenance
    sidecar: Sidecar | MISSING = MISSING
    summary: Annotated[str, Field(max_length=500)] | MISSING = MISSING

    @model_validator(mode="after")
    def _fidelity_and_author_rules(self) -> HandoffPacket:
        if self.fidelity is Fidelity.REQUEST_ONLY and self.pending_steps:
            raise ValueError("request_only packets carry no pending steps")
        if (
            self.provenance.assembled_by is AssembledBy.SDK
            and self.reason.trigger.kind is not HandoffTrigger.SDK_EXPLICIT
        ):
            raise ValueError("SDK-assembled packets must use trigger kind sdk_explicit")
        return self
