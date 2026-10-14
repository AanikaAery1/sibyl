"""D53 external monitor schemas (WAVE4.md): monitors, their webhooks, and findings from every
source. Enumerations render the ``sibyl_schemas`` value sets (single source); key and webhook
secrets appear once, in the 201 response, and never again."""

from __future__ import annotations

from enum import Enum

from sibyl_schemas import values as sv
from sibyl_schemas.models.monitor import MAX_BODY_BYTES, MAX_WATCHED_GROUPS

from .dsl import (
    Schema,
    array,
    body_obj,
    boolean,
    enum,
    free_object,
    integer,
    nullable,
    obj,
    ref,
    string,
)

# Fresh dicts per use: a shared object would become a YAML anchor and renumber the others.


def _uuid() -> Schema:
    return ref("Uuid")


def _n_uuid() -> Schema:
    return ref("NullableUuid")


def _ts() -> Schema:
    return ref("Timestamp")


def _n_ts() -> Schema:
    return ref("NullableTimestamp")


def _reason() -> Schema:
    return ref("Reason")


def _enum(values: type[Enum]) -> Schema:
    return enum(*(str(m.value) for m in values))


def _name() -> Schema:
    return string(minLength=1, maxLength=128, pattern=r"^[^\x00-\x1f\x7f]{1,128}$")


def _groups() -> Schema:
    return array(_uuid(), maxItems=MAX_WATCHED_GROUPS, uniqueItems=True)


def _events() -> Schema:
    return array(
        _enum_values(sv.SUBSCRIBABLE_EVENTS),
        minItems=1,
        maxItems=len(sv.SUBSCRIBABLE_EVENTS),
        uniqueItems=True,
    )


def _enum_values(values: tuple[Enum, ...]) -> Schema:
    return enum(*(str(v.value) for v in values))


def _key_ref() -> Schema:
    return obj(
        {
            "id": _uuid(),
            "name": string(),
            "prefix": string(minLength=12, maxLength=12),
            "env": ref("ApiKeyEnv"),
            "status": ref("ApiKeyStatus"),
            "expires_at": _ts(),
            "last_used_at": _n_ts(),
            "created_at": _ts(),
        },
        ("id", "name", "prefix", "env", "status", "expires_at", "created_at"),
    )


def _webhook() -> Schema:
    return obj(
        {
            "id": _uuid(),
            "monitor_id": _uuid(),
            "url": string(maxLength=2048),
            "event_types": _events(),
            "state": _enum(sv.WebhookState),
            "consecutive_failures": integer(minimum=0),
            "last_delivery_at": _n_ts(),
            "last_delivery_status": nullable(enum("delivered", "retrying", "dead")),
            "last_response_code": {"type": ["integer", "null"]},
            "disabled_reason": nullable(string(maxLength=500)),
            "created_at": _ts(),
            "updated_at": _ts(),
        },
        ("id", "monitor_id", "url", "event_types", "state", "created_at"),
        description="The signing secret is never returned after creation.",
    )


def _monitor() -> Schema:
    return obj(
        {
            "id": _uuid(),
            "name": string(maxLength=128),
            "kind": _enum(sv.MonitorKind),
            "description": nullable(string(maxLength=2000)),
            "owner_user_id": _uuid(),
            "all_groups": boolean(),
            "group_ids": _groups(),
            "state": _enum(sv.MonitorState),
            "rate_limit_per_min": integer(minimum=1, maximum=600),
            "version": integer(minimum=1),
            "keys": array(_key_ref(), description="active and rotating keys (metadata only)"),
            "webhooks": array(_webhook()),
            "findings_24h": integer(minimum=0),
            "last_finding_at": _n_ts(),
            "created_by_user_id": _uuid(),
            "revoked_at": _n_ts(),
            "revoke_reason": nullable(string(maxLength=2000)),
            "created_at": _ts(),
            "updated_at": _ts(),
            "advisory": boolean(description="always true: a monitor never enforces"),
        },
        (
            "id",
            "name",
            "kind",
            "owner_user_id",
            "all_groups",
            "group_ids",
            "state",
            "rate_limit_per_min",
            "keys",
            "webhooks",
            "created_at",
            "advisory",
        ),
    )


def _money() -> Schema:
    return string(pattern=r"^[0-9]{1,30}(\.[0-9]{1,18})?$", description="USD, decimal string")


def monitor_schemas() -> dict[str, Schema]:
    return {
        "Monitor": _monitor(),
        "MonitorCreated": {
            "allOf": [
                ref("Monitor"),
                obj(
                    {
                        "api_key": nullable(
                            ref("ApiKeyCreated"),
                        )
                    },
                    ("api_key",),
                    description="the first key (null when issue_key was false); its secret is"
                    " shown exactly once and is null on an Idempotency-Key replay",
                ),
            ]
        },
        "MonitorCreate": body_obj(
            {
                "name": _name(),
                "kind": _enum(sv.MonitorKind),
                "description": nullable(string(maxLength=2000)),
                "owner_user_id": {**_uuid(), "description": "default: the caller"},
                "all_groups": boolean(default=True),
                "group_ids": _groups(),
                "rate_limit_per_min": integer(minimum=1, maximum=600, default=60),
                "issue_key": boolean(default=True),
                "key_env": ref("ApiKeyEnv"),
                "key_expires_at": {**_ts(), "description": "default now+365 d, max now+400 d"},
                "reason": _reason(),
            },
            ("name", "kind"),
        ),
        "MonitorPatch": body_obj(
            {
                "name": _name(),
                "description": nullable(string(maxLength=2000)),
                "state": enum("active", "paused"),
                "owner_user_id": _uuid(),
                "all_groups": boolean(),
                "group_ids": _groups(),
                "rate_limit_per_min": integer(minimum=1, maximum=600),
                "reason": _reason(),
            },
            minProperties=1,
            description="all_groups and group_ids change together",
        ),
        "MonitorRevoke": body_obj(
            {"reason": string(minLength=10, maxLength=2000)},
            ("reason",),
        ),
        "MonitorKeyCreate": body_obj(
            {
                "name": string(minLength=1, maxLength=80),
                "env": ref("ApiKeyEnv"),
                "expires_at": {**_ts(), "description": "default now+365 d, max now+400 d"},
                "reason": _reason(),
            },
        ),
        "MonitorWebhook": _webhook(),
        "MonitorWebhookCreated": {
            "allOf": [
                ref("MonitorWebhook"),
                obj(
                    {
                        "secret": {
                            "type": ["string", "null"],
                            "pattern": r"^whsec_[A-Za-z0-9_-]{43}$",
                            "description": "the HMAC signing secret, shown exactly once; null on"
                            " an Idempotency-Key replay",
                        }
                    },
                    ("secret",),
                ),
            ]
        },
        "WebhookCreate": body_obj(
            {
                "url": string(minLength=8, maxLength=2048, description="https only"),
                "event_types": _events(),
                "reason": _reason(),
            },
            ("url", "event_types"),
        ),
        "WebhookTestResult": obj(
            {
                "ok": boolean(),
                "http_status": integer(minimum=0),
                "error": nullable(string(maxLength=64)),
                "latency_ms": integer(minimum=0),
                "delivery_id": _uuid(),
            },
            ("ok", "http_status", "latency_ms", "delivery_id"),
        ),
        "FindingSubmit": body_obj(
            {
                "kind": _enum(sv.ExternalFindingKind),
                "subject_kind": _enum(sv.ExternalSubjectKind),
                "subject_id": nullable(_uuid()),
                "severity": _enum(sv.SentinelSeverity),
                "summary": string(minLength=1, maxLength=2000),
                "body": free_object(f"structured detail, plain JSON, at most {MAX_BODY_BYTES} B"),
                "recommendation": nullable(string(maxLength=2000)),
                "advice": nullable(_enum(sv.HeldActionAdvice)),
                "confidence": nullable(enum("low", "medium", "high")),
                "provider": nullable(string(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")),
                "model": nullable(string(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")),
                "raise_alert": nullable(boolean()),
            },
            ("kind", "subject_kind", "severity", "summary"),
            description=(
                "incident_explanation, held_action_review, semantic_drift and fleet_summary"
                " keep Sentinel's subject (incident, held_action, agent, fleet); `advice` is for"
                " held_action_review only; a fleet finding has no subject_id."
            ),
        ),
        "Finding": obj(
            {
                "id": _uuid(),
                "source": _enum(sv.FindingSource),
                "monitor_id": _n_uuid(),
                "monitor_name": nullable(string(maxLength=128)),
                "kind": _enum(sv.ExternalFindingKind),
                "subject_kind": _enum(sv.ExternalSubjectKind),
                "subject_id": _n_uuid(),
                "agent_id": _n_uuid(),
                "severity": _enum(sv.SentinelSeverity),
                "summary": string(maxLength=2000),
                "body": free_object("structured detail (untrusted model output)"),
                "recommendation": nullable(string(maxLength=2000)),
                "advice": nullable(_enum(sv.HeldActionAdvice)),
                "confidence": nullable(enum("low", "medium", "high")),
                "provider": nullable(string(maxLength=64)),
                "model": nullable(string(maxLength=128)),
                "trigger": nullable(
                    enum("scheduled", "on_demand", "external"),
                ),
                "tokens_in": {"type": ["integer", "null"], "minimum": 0},
                "tokens_out": {"type": ["integer", "null"], "minimum": 0},
                "cost_usd": nullable(_money()),
                "alert_id": _n_uuid(),
                "feedback": nullable(_enum(sv.SentinelFeedback)),
                "feedback_by_user_id": _n_uuid(),
                "feedback_at": _n_ts(),
                "created_at": _ts(),
                "advisory": boolean(description="always true: a finding never decides anything"),
            },
            (
                "id",
                "source",
                "kind",
                "subject_kind",
                "severity",
                "summary",
                "created_at",
                "advisory",
            ),
            description="Sentinel-only fields (tokens, cost) are null for external findings;"
            " monitor fields are null for Sentinel's.",
        ),
        "FindingFeedback": body_obj({"feedback": _enum(sv.SentinelFeedback)}, ("feedback",)),
        "WebhookEvent": obj(
            {
                "id": _uuid(),
                "type": _enum(sv.WebhookEventType),
                "created_at": _ts(),
                "tenant_id": _uuid(),
                "monitor_id": _uuid(),
                "data": free_object(
                    "references and states only, never content: alert.* {alert_id, rule,"
                    " severity, scope, state, agent_id}; incident.updated {failover_id, agent_id,"
                    " state, ...}; action.* {held_action_id, agent_id, tool, state, decision};"
                    " drift.detected (an alert.fired/updated of silent_drift or model_change);"
                    " run.failed {run_id, agent_id, status, error_type, ended_at, trace_id};"
                    " ping {message, webhook_id}"
                ),
                "advisory": boolean(),
            },
            ("id", "type", "created_at", "tenant_id", "monitor_id", "data", "advisory"),
            description=(
                "The JSON body of a webhook delivery. Headers: Sibyl-Signature"
                " (t=<unix>,v1=<hex HMAC-SHA256(secret, t + '.' + raw body)>), Sibyl-Event-Id"
                " (stable across retries: de-duplicate on it), Sibyl-Event-Type,"
                " Sibyl-Delivery-Id."
            ),
        ),
    }
