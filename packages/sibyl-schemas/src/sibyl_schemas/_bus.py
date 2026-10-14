"""Outbox topics, NOTIFY channels and SSE event types (R58 X1/X2, API §7)."""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Final


class OutboxTopic(StrEnum):
    """14 coarse topics (R58 X1, B14 ``job``, D48 ``action``); the fine name is `event_type`."""

    POLICY = "policy"
    KILLSWITCH = "killswitch"
    GRAPH = "graph"
    HEALTH = "health"
    ALERT = "alert"
    PROVIDER_INCIDENT = "provider_incident"
    INCIDENT = "incident"
    APPROVAL = "approval"
    HANDOFF = "handoff"
    ERASURE = "erasure"
    AUDIT = "audit"
    AGENT = "agent"
    JOB = "job"
    """B14: ``job.requested`` wakes the jobs worker loop; never streamed."""
    ACTION = "action"
    """D48 Action Gate: held actions created, decided and expired."""


class NotifyChannel(StrEnum):
    """Exactly two LISTEN/NOTIFY channels with a constant payload (R58 X2)."""

    POLICY = "sibyl_policy"
    OUTBOX = "sibyl_outbox"


TOPIC_CHANNEL: Final = MappingProxyType(
    {
        topic: (
            NotifyChannel.POLICY
            if topic in (OutboxTopic.POLICY, OutboxTopic.KILLSWITCH)
            else NotifyChannel.OUTBOX
        )
        for topic in OutboxTopic
    }
)


class SseEventType(StrEnum):
    POLICY_CHANGED = "policy_changed"
    SNAPSHOT_ISSUED = "snapshot.issued"
    GRAPH_CHANGED = "graph.changed"
    HEALTH_TRANSITION = "health.transition"
    ALERT_FIRED = "alert.fired"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_UPDATED = "alert.updated"
    PROVIDER_INCIDENT_OPENED = "provider_incident.opened"
    PROVIDER_INCIDENT_RESOLVED = "provider_incident.resolved"
    INCIDENT_UPDATED = "incident.updated"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_DECIDED = "approval.decided"
    APPROVAL_EXPIRED = "approval.expired"
    HANDOFF_QUEUED = "handoff.queued"
    HANDOFF_CLAIMED = "handoff.claimed"
    HANDOFF_COMPLETED = "handoff.completed"
    HANDOFF_RETURNED = "handoff.returned"
    HANDOFF_EXPIRED = "handoff.expired"
    KILLSWITCH_PULLED = "killswitch.pulled"
    KILLSWITCH_RELEASED = "killswitch.released"
    KILLSWITCH_APPLIED = "killswitch.applied"
    ERASURE_STEP = "erasure.step"
    ACTION_HELD = "action.held"
    ACTION_DECIDED = "action.decided"
    ACTION_EXPIRED = "action.expired"
    RESET = "reset"
    """Control event emitted by the api; never an outbox row."""


_SSE_PREFIX_TOPIC: Final = MappingProxyType(
    {
        "policy_changed": OutboxTopic.POLICY,
        "snapshot": OutboxTopic.POLICY,
        "graph": OutboxTopic.GRAPH,
        "health": OutboxTopic.HEALTH,
        "alert": OutboxTopic.ALERT,
        "provider_incident": OutboxTopic.PROVIDER_INCIDENT,
        "incident": OutboxTopic.INCIDENT,
        "approval": OutboxTopic.APPROVAL,
        "handoff": OutboxTopic.HANDOFF,
        "killswitch": OutboxTopic.KILLSWITCH,
        "erasure": OutboxTopic.ERASURE,
        "action": OutboxTopic.ACTION,
    }
)

SSE_EVENT_TOPIC: Final = MappingProxyType(
    {
        event: _SSE_PREFIX_TOPIC[event.value.split(".")[0]]
        for event in SseEventType
        if event is not SseEventType.RESET
    }
)
"""Every SSE `event:` maps to exactly one outbox topic (freeze checklist item 6)."""

OUTBOX_EVENT_TOPIC: Final = MappingProxyType(
    {
        **{event.value: topic for event, topic in SSE_EVENT_TOPIC.items()},
        "audit.anchor_now": OutboxTopic.AUDIT,
        "agent.discovered": OutboxTopic.AGENT,
        "job.requested": OutboxTopic.JOB,
    }
)
"""All fine-grained outbox `event_type`s. `audit.anchor_now` is the single spelling (X1);
it, `agent.discovered` and `job.requested` (B14) are worker-facing and never streamed."""

KEY_VISIBLE_SSE_EVENTS: Final = frozenset(
    {
        SseEventType.POLICY_CHANGED,
        SseEventType.SNAPSHOT_ISSUED,
        SseEventType.KILLSWITCH_PULLED,
        SseEventType.KILLSWITCH_RELEASED,
        SseEventType.KILLSWITCH_APPLIED,
    }
)
"""What an API-key principal with `routing:read` sees on the stream (API §7)."""
