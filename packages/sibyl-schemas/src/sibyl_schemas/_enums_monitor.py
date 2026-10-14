"""External monitor value sets (D53): the single source for migration 0025's CHECKs, the API
contract, ``sibyl_schemas.models.monitor``, the webhooks worker, the SDK and the MCP server."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class MonitorKind(StrEnum):
    """How the monitor observes the fleet (informational; every kind may use every surface)."""

    MCP = "mcp"
    WEBHOOK = "webhook"
    API = "api"


class MonitorState(StrEnum):
    """``paused`` stops findings and webhook deliveries (reads keep working); ``revoked`` is
    terminal: its keys are revoked and its webhooks disabled."""

    ACTIVE = "active"
    PAUSED = "paused"
    REVOKED = "revoked"


class WebhookState(StrEnum):
    """``disabled`` stops deliveries (the monitor was revoked, or deliveries kept dying)."""

    ENABLED = "enabled"
    DISABLED = "disabled"


class WebhookEventType(StrEnum):
    """Events a monitor webhook can subscribe to. Payloads are references and states only
    (never content); the receiver fetches details with its monitor key."""

    ALERT_FIRED = "alert.fired"
    ALERT_UPDATED = "alert.updated"
    ALERT_RESOLVED = "alert.resolved"
    INCIDENT_UPDATED = "incident.updated"
    ACTION_HELD = "action.held"
    ACTION_DECIDED = "action.decided"
    ACTION_EXPIRED = "action.expired"
    DRIFT_DETECTED = "drift.detected"
    """An ``alert.fired`` / ``alert.updated`` of a drift rule (``silent_drift``,
    ``model_change``)."""
    RUN_FAILED = "run.failed"
    """A run (D50) that ended with a non-ok status."""
    PING = "ping"
    """The test delivery (``POST /monitors/{id}/webhooks/{wid}/test``); never subscribed."""


SUBSCRIBABLE_EVENTS: Final = tuple(e for e in WebhookEventType if e is not WebhookEventType.PING)

OUTBOX_WEBHOOK_EVENTS: Final = MappingProxyType(
    {
        "alert.fired": WebhookEventType.ALERT_FIRED,
        "alert.updated": WebhookEventType.ALERT_UPDATED,
        "alert.resolved": WebhookEventType.ALERT_RESOLVED,
        "incident.updated": WebhookEventType.INCIDENT_UPDATED,
        "action.held": WebhookEventType.ACTION_HELD,
        "action.decided": WebhookEventType.ACTION_DECIDED,
        "action.expired": WebhookEventType.ACTION_EXPIRED,
    }
)
"""Outbox ``event_type`` -> the webhook event it is delivered as."""

DRIFT_ALERT_RULES: Final = frozenset({"silent_drift", "model_change"})


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    RETRYING = "retrying"
    DEAD = "dead"


class FindingSource(StrEnum):
    SENTINEL = "sentinel"
    EXTERNAL = "external"


class ExternalFindingKind(StrEnum):
    """Sentinel's four kinds (same subject rules) plus open kinds for external monitors."""

    INCIDENT_EXPLANATION = "incident_explanation"
    HELD_ACTION_REVIEW = "held_action_review"
    SEMANTIC_DRIFT = "semantic_drift"
    FLEET_SUMMARY = "fleet_summary"
    ANOMALY = "anomaly"
    SAFETY = "safety"
    QUALITY = "quality"
    COST = "cost"
    OTHER = "other"


class ExternalSubjectKind(StrEnum):
    INCIDENT = "incident"
    HELD_ACTION = "held_action"
    AGENT = "agent"
    RUN = "run"
    FLEET = "fleet"


class HeldActionAdvice(StrEnum):
    """A monitor's advice on a held action (advisory: never decides the hold)."""

    APPROVE = "approve"
    DENY = "deny"
    NEEDS_MORE_INFO = "needs_more_info"


FIXED_SUBJECT_OF_KIND: Final = MappingProxyType(
    {
        ExternalFindingKind.INCIDENT_EXPLANATION: ExternalSubjectKind.INCIDENT,
        ExternalFindingKind.HELD_ACTION_REVIEW: ExternalSubjectKind.HELD_ACTION,
        ExternalFindingKind.SEMANTIC_DRIFT: ExternalSubjectKind.AGENT,
        ExternalFindingKind.FLEET_SUMMARY: ExternalSubjectKind.FLEET,
    }
)
"""Kinds shared with Sentinel keep Sentinel's subject (the other kinds take any subject)."""

EXTERNAL_FINDING_ALERT_RULE: Final = "external_finding"
"""The watch-only alert rule code external findings raise (never seeded, never automated)."""

SIGNATURE_HEADER: Final = "Sibyl-Signature"
EVENT_ID_HEADER: Final = "Sibyl-Event-Id"
EVENT_TYPE_HEADER: Final = "Sibyl-Event-Type"
DELIVERY_ID_HEADER: Final = "Sibyl-Delivery-Id"
SIGNATURE_TOLERANCE_S: Final = 300
"""Receivers reject a signature whose timestamp is more than five minutes off."""
