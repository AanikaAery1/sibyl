"""Request bodies of the human Action Gate routes (OpenAPI ``components.schemas``, closed
objects). The enforcement-point bodies are AG-ENFORCE's wire models, used as they are:
``sibyl_schemas.action_gate.HeldActionRequest`` and ``ActionDecisionRequest``."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

Reason = Field(min_length=10, max_length=2000)


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionPolicyCreate(_Body):
    name: str = Field(min_length=1, max_length=200)
    scope_kind: Literal["tenant", "agent_group", "agent"]
    scope_id: UUID | None = None
    document: dict[str, Any]
    four_eyes: bool = False
    reason: str | None = Field(default=None, min_length=10, max_length=2000)
    change_note: str | None = Field(default=None, min_length=1, max_length=2000)
    based_on_id: UUID | None = None


class ReasonBody(_Body):
    reason: str = Reason


class ActionSimulate(_Body):
    tool: str = Field(min_length=1, max_length=256)
    args: dict[str, Any]
    agent_id: UUID | None = None
    counters: dict[str, int | float | str] | None = None


class ActionPolicyDraftSimulate(_Body):
    """An unsaved document; with ``agent_id`` it takes its scope's place among the agent's
    approved policies (``scope_kind`` defaults to ``agent``)."""

    document: dict[str, Any]
    scope_kind: Literal["tenant", "agent_group", "agent"] | None = None
    scope_id: UUID | None = None
    tool: str = Field(min_length=1, max_length=256)
    args: dict[str, Any]
    agent_id: UUID | None = None
    counters: dict[str, int | float | str] | None = None


class HeldActionAction(_Body):
    action: Literal["approve", "deny"]
    reason: str = Reason
