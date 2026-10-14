"""`sibyl-event/1` envelopes, the discriminated `Event` union, and the wire variant.

`Event` validates stored/normalised events; `WireEvent` validates what clients POST to
`/v1/events` (no `observed_at`/`ingest`, `attrs.payload_inline` allowed); `EventBatch` is
that request body. `agent_id` is nullable only on `provider.status` and `observation.gap`.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import MISSING, Field

from sibyl_schemas._enums import CaptureMode, EventSource
from sibyl_schemas.models._base import (
    Lax,
    NonNegInt,
    SpanId,
    Timestamp,
    TraceId,
    Uuid,
    UuidV7,
    WireModel,
)
from sibyl_schemas.models._event_parts import (
    AgentDiscoveredAttrs,
    AgentInvokeAttrs,
    CheckpointAttrs,
    CheckpointWireAttrs,
    FeedbackAttrs,
    FeedbackWireAttrs,
    GenAiRequestAttrs,
    GenAiRequestWireAttrs,
    HandoffRequestedAttrs,
    HandoffRequestedWireAttrs,
    HandoffResolvedAttrs,
    HandoffResolvedWireAttrs,
    HealthTransitionAttrs,
    IngestInfo,
    ObservationGapAttrs,
    PolicyDecisionAttrs,
    PolicyStateInfo,
    ProviderStatusAttrs,
    RedactionRecord,
    TaskOutcomeAttrs,
    ToolCallAttrs,
    ToolCallWireAttrs,
)

EVENT_SCHEMA = "sibyl-event/1"


class _EnvelopeCore(WireModel):
    """Fields a client sends; `agent_id` is narrowed per event type below."""

    schema_: Literal["sibyl-event/1"] = Field(alias="schema")
    event_id: UuidV7
    tenant_id: Uuid
    agent_id: Uuid
    task_id: Uuid | MISSING | None = MISSING
    call_id: Uuid | MISSING | None = MISSING
    trace_id: TraceId | MISSING = MISSING
    span_id: SpanId | MISSING = MISSING
    parent_span_id: SpanId | MISSING = MISSING
    ts: Timestamp
    source: Lax[EventSource]
    emitter_id: Annotated[str, Field(max_length=128)]
    seq: NonNegInt
    capture_mode: Lax[CaptureMode]
    redaction_profile: RedactionRecord
    policy_state: PolicyStateInfo


class _Envelope(_EnvelopeCore):
    """Stored form: adds the ingest-authored fields."""

    observed_at: Timestamp
    ingest: IngestInfo | MISSING = MISSING


# --------------------------------------------------------------------- canonical


class GenAiRequestEvent(_Envelope):
    type: Literal["gen_ai.request"]
    attrs: GenAiRequestAttrs


class ToolCallEvent(_Envelope):
    type: Literal["tool.call"]
    attrs: ToolCallAttrs


class AgentInvokeEvent(_Envelope):
    type: Literal["agent.invoke"]
    attrs: AgentInvokeAttrs


class CheckpointEvent(_Envelope):
    type: Literal["checkpoint"]
    attrs: CheckpointAttrs


class HandoffRequestedEvent(_Envelope):
    type: Literal["handoff.requested"]
    attrs: HandoffRequestedAttrs


class HandoffResolvedEvent(_Envelope):
    type: Literal["handoff.completed", "handoff.returned"]
    attrs: HandoffResolvedAttrs


class FeedbackEvent(_Envelope):
    type: Literal["feedback"]
    attrs: FeedbackAttrs


class TaskOutcomeEvent(_Envelope):
    type: Literal["task.outcome"]
    attrs: TaskOutcomeAttrs


class AgentDiscoveredEvent(_Envelope):
    type: Literal["agent.discovered"]
    attrs: AgentDiscoveredAttrs


class PolicyDecisionEvent(_Envelope):
    type: Literal["policy.decision"]
    attrs: PolicyDecisionAttrs


class ObservationGapEvent(_Envelope):
    type: Literal["observation.gap"]
    agent_id: Uuid | None  # type: ignore[assignment]
    attrs: ObservationGapAttrs


class ProviderStatusEvent(_Envelope):
    type: Literal["provider.status"]
    agent_id: Uuid | None  # type: ignore[assignment]
    attrs: ProviderStatusAttrs


class HealthTransitionEvent(_Envelope):
    type: Literal["health.transition"]
    attrs: HealthTransitionAttrs


Event = Annotated[
    GenAiRequestEvent
    | ToolCallEvent
    | AgentInvokeEvent
    | CheckpointEvent
    | HandoffRequestedEvent
    | HandoffResolvedEvent
    | FeedbackEvent
    | TaskOutcomeEvent
    | AgentDiscoveredEvent
    | PolicyDecisionEvent
    | ObservationGapEvent
    | ProviderStatusEvent
    | HealthTransitionEvent,
    Field(discriminator="type"),
]
"""Any canonical `sibyl-event/1` document; validate with `TypeAdapter(Event)`."""


# -------------------------------------------------------------------------- wire


class GenAiRequestWireEvent(_EnvelopeCore):
    type: Literal["gen_ai.request"]
    attrs: GenAiRequestWireAttrs


class ToolCallWireEvent(_EnvelopeCore):
    type: Literal["tool.call"]
    attrs: ToolCallWireAttrs


class AgentInvokeWireEvent(_EnvelopeCore):
    type: Literal["agent.invoke"]
    attrs: AgentInvokeAttrs


class CheckpointWireEvent(_EnvelopeCore):
    type: Literal["checkpoint"]
    attrs: CheckpointWireAttrs


class HandoffRequestedWireEvent(_EnvelopeCore):
    type: Literal["handoff.requested"]
    attrs: HandoffRequestedWireAttrs


class HandoffResolvedWireEvent(_EnvelopeCore):
    type: Literal["handoff.completed", "handoff.returned"]
    attrs: HandoffResolvedWireAttrs


class FeedbackWireEvent(_EnvelopeCore):
    type: Literal["feedback"]
    attrs: FeedbackWireAttrs


class TaskOutcomeWireEvent(_EnvelopeCore):
    type: Literal["task.outcome"]
    attrs: TaskOutcomeAttrs


class AgentDiscoveredWireEvent(_EnvelopeCore):
    type: Literal["agent.discovered"]
    attrs: AgentDiscoveredAttrs


class PolicyDecisionWireEvent(_EnvelopeCore):
    type: Literal["policy.decision"]
    attrs: PolicyDecisionAttrs


class ObservationGapWireEvent(_EnvelopeCore):
    type: Literal["observation.gap"]
    agent_id: Uuid | None  # type: ignore[assignment]
    attrs: ObservationGapAttrs


class ProviderStatusWireEvent(_EnvelopeCore):
    type: Literal["provider.status"]
    agent_id: Uuid | None  # type: ignore[assignment]
    attrs: ProviderStatusAttrs


class HealthTransitionWireEvent(_EnvelopeCore):
    type: Literal["health.transition"]
    attrs: HealthTransitionAttrs


WireEvent = Annotated[
    GenAiRequestWireEvent
    | ToolCallWireEvent
    | AgentInvokeWireEvent
    | CheckpointWireEvent
    | HandoffRequestedWireEvent
    | HandoffResolvedWireEvent
    | FeedbackWireEvent
    | TaskOutcomeWireEvent
    | AgentDiscoveredWireEvent
    | PolicyDecisionWireEvent
    | ObservationGapWireEvent
    | ProviderStatusWireEvent
    | HealthTransitionWireEvent,
    Field(discriminator="type"),
]
"""One element of a `POST /v1/events` batch (`sibyl-event-wire/1`)."""


class EventBatch(WireModel):
    """`POST /v1/events` body: `{"schema": "sibyl-event/1", "events": [...]}`."""

    schema_: Literal["sibyl-event/1"] = Field(alias="schema")
    events: Annotated[list[WireEvent], Field(min_length=1, max_length=1000)]
