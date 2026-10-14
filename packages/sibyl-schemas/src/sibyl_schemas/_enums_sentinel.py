"""Sibyl Sentinel value sets (D52): the single source for migration 0019's CHECKs, the API
contract and ``sibyl_schemas.models.sentinel``."""

from __future__ import annotations

from enum import StrEnum


class SentinelProvider(StrEnum):
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"


class SentinelTask(StrEnum):
    """What a tenant switches on; each task writes findings of the same kind."""

    INCIDENT_EXPLANATION = "incident_explanation"
    HELD_ACTION_REVIEW = "held_action_review"
    SEMANTIC_DRIFT = "semantic_drift"
    FLEET_SUMMARY = "fleet_summary"


class SentinelSubjectKind(StrEnum):
    INCIDENT = "incident"
    HELD_ACTION = "held_action"
    AGENT = "agent"
    FLEET = "fleet"


class SentinelSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class SentinelFeedback(StrEnum):
    USEFUL = "useful"
    NOT_USEFUL = "not_useful"
    WRONG = "wrong"


class SentinelTrigger(StrEnum):
    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"
