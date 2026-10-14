"""Request bodies of the lane S routes (OpenAPI ``components.schemas``, ``additionalProperties:
false``): IncidentCreate, IncidentAction, KillSwitchCreate, ReasonBody, KillSwitchAckCreate,
HandoffTaskAction."""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Reason = Field(min_length=10, max_length=2000)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentTarget(_Body):
    step_id: UUID | None = None
    kind: Literal["model", "agent"] | None = None
    provider_id: UUID | None = None
    model_id: UUID | None = None
    agent_id: UUID | None = None


class EvidenceRefs(_Body):
    alert_ids: list[UUID] = Field(default_factory=list, max_length=50)
    health_snapshot_id: UUID | None = None


class IncidentCreate(_Body):
    agent_id: UUID
    action: Literal["failover", "degrade", "recover", "handoff", "quarantine", "kill"]
    target: IncidentTarget | None = None
    reason: str = Reason
    evidence_refs: EvidenceRefs | None = None


class IncidentAction(_Body):
    action: Literal["approve", "deny", "undo", "clear_hold", "release", "fail_back", "cancel"]
    reason: str = Reason
    expected_routing_version: int | None = None


class KillSwitchCreate(_Body):
    scope_kind: Literal["tenant", "agent", "provider"]
    scope_id: UUID | None = None
    reason: str = Field(min_length=20, max_length=2000)


class ReasonBody(_Body):
    reason: str = Reason


class KillSwitchAckCreate(_Body):
    gateway_id: str = Field(min_length=1, max_length=128)
    snapshot_version: int = Field(ge=0)


class HandoffTaskAction(_Body):
    action: Literal["claim", "extend_lock", "release_claim", "complete", "return", "reassign"]
    outcome: Literal["resolved", "escalated", "abandoned"] | None = None
    outcome_note: str | None = Field(default=None, max_length=4000)
    next_action: str | None = Field(default=None, max_length=2000)
    rating: int | None = Field(default=None, ge=1, le=5)
    accountable_user_id: UUID | None = None
    reason: str | None = Field(default=None, max_length=2000)


class PreemptiveBreakerClear(_Body):
    """B19: clearing a tripped pre-emptive breaker is deliberate and needs a reason."""

    reason: str = Reason
