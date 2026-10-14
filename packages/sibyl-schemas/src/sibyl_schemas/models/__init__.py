"""Pydantic v2 models for every `sibyl-schemas` document.

Each model accepts and rejects exactly what the hand-written JSON Schema in
`sibyl_schemas.jsonschema` does (proved over the golden corpus by
`tests/test_models.py`). Event unions are `Annotated` discriminated unions: validate them
with `pydantic.TypeAdapter(Event)` / `TypeAdapter(WireEvent)`.
"""

from __future__ import annotations

from sibyl_schemas.models._event_parts import (
    GenAiRequestAttrs,
    PayloadInline,
    PayloadRef,
    PolicyStateInfo,
    RedactionRecord,
    Target,
)
from sibyl_schemas.models.action_policy import (
    ActionPolicy,
    ActionRule,
    CumulativeCap,
    DataClassRule,
    Predicate,
)
from sibyl_schemas.models.event import (
    AgentDiscoveredEvent,
    AgentInvokeEvent,
    CheckpointEvent,
    Event,
    EventBatch,
    FeedbackEvent,
    GenAiRequestEvent,
    HandoffRequestedEvent,
    HandoffResolvedEvent,
    HealthTransitionEvent,
    ObservationGapEvent,
    PolicyDecisionEvent,
    ProviderStatusEvent,
    TaskOutcomeEvent,
    ToolCallEvent,
    WireEvent,
)
from sibyl_schemas.models.handoff import (
    Checkpoint,
    CompletedStep,
    HandoffPacket,
    PendingStep,
    SideEffect,
)
from sibyl_schemas.models.health import (
    Factor,
    FeatureSnapshot,
    HealthDocument,
    Label,
    Prediction,
)
from sibyl_schemas.models.ingest import IngestResponse, Rejection
from sibyl_schemas.models.snapshot import (
    PolicySnapshot,
    SignedPolicySnapshot,
    SigningKey,
    SigningKeySet,
    SigningKeySetBody,
    SnapshotAgent,
    TenantBlock,
    parse_signed_snapshot,
    parse_signing_key_set,
)

__all__ = [
    "ActionPolicy",
    "ActionRule",
    "AgentDiscoveredEvent",
    "AgentInvokeEvent",
    "Checkpoint",
    "CheckpointEvent",
    "CompletedStep",
    "CumulativeCap",
    "DataClassRule",
    "Event",
    "EventBatch",
    "Factor",
    "FeatureSnapshot",
    "FeedbackEvent",
    "GenAiRequestAttrs",
    "GenAiRequestEvent",
    "HandoffPacket",
    "HandoffRequestedEvent",
    "HandoffResolvedEvent",
    "HealthDocument",
    "HealthTransitionEvent",
    "IngestResponse",
    "Label",
    "ObservationGapEvent",
    "PayloadInline",
    "PayloadRef",
    "PendingStep",
    "PolicyDecisionEvent",
    "PolicySnapshot",
    "PolicyStateInfo",
    "Predicate",
    "Prediction",
    "ProviderStatusEvent",
    "RedactionRecord",
    "Rejection",
    "SideEffect",
    "SignedPolicySnapshot",
    "SigningKey",
    "SigningKeySet",
    "SigningKeySetBody",
    "SnapshotAgent",
    "Target",
    "TaskOutcomeEvent",
    "TenantBlock",
    "ToolCallEvent",
    "WireEvent",
    "parse_signed_snapshot",
    "parse_signing_key_set",
]
