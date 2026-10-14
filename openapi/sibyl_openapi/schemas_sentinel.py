"""D52 Sibyl Sentinel schemas (WAVE3.md): the advisory monitoring agent's config, findings and
feedback. Enumerations render the ``sibyl_schemas`` value sets (single source); the API key is
write-only (never in a response)."""

from __future__ import annotations

from enum import Enum

from sibyl_schemas import values as sv

from .dsl import (
    N_TS,
    N_UUID,
    REASON,
    TS,
    UUID,
    Schema,
    array,
    body_obj,
    boolean,
    enum,
    free_object,
    integer,
    nullable,
    obj,
    string,
)

# Fresh dicts per use: a shared object would become a YAML anchor and renumber the others.


def _money() -> Schema:
    return string(pattern=r"^[0-9]{1,30}(\.[0-9]{1,18})?$", description="USD, decimal string")


def _model_id() -> Schema:
    return string(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _rate() -> Schema:
    return {"type": "number", "minimum": 0, "maximum": 1}


def _enum(values: type[Enum]) -> Schema:
    return enum(*(str(m.value) for m in values))


def sentinel_schemas() -> dict[str, Schema]:
    usage = obj(
        {
            "day": string(format="date"),
            "spent_usd": _money(),
            "calls": integer(minimum=0),
            "findings": integer(minimum=0),
            "failures": integer(minimum=0),
            "skipped_budget": integer(minimum=0),
            "skipped_sampling": integer(minimum=0),
            "exhausted": boolean(),
        },
        ("day", "spent_usd", "calls", "findings", "skipped_budget", "skipped_sampling"),
    )
    return {
        "SentinelConfig": obj(
            {
                "configured": boolean(),
                "enabled": boolean(),
                "provider": nullable(_enum(sv.SentinelProvider)),
                "model": nullable(_model_id()),
                "base_url": nullable(string(maxLength=2048)),
                "has_key": boolean(description="a key is vaulted (the key is never returned)"),
                "key_hint": nullable(string(maxLength=8)),
                "key_updated_at": N_TS,
                "daily_budget_usd": nullable(_money()),
                "sampling_rate": nullable(_rate()),
                "tasks": array(_enum(sv.SentinelTask)),
                "price_in_usd_per_mtok": nullable(_money()),
                "price_out_usd_per_mtok": nullable(_money()),
                "version": integer(minimum=0),
                "updated_at": N_TS,
                "usage_today": nullable(usage),
                "advisory": boolean(description="always true: Sentinel never enforces"),
            },
            ("configured", "enabled", "has_key", "tasks", "version", "advisory"),
        ),
        "SentinelConfigPut": body_obj(
            {
                "enabled": boolean(),
                "provider": _enum(sv.SentinelProvider),
                "model": nullable(_model_id()),
                "api_key": {
                    **string(minLength=8, maxLength=4096),
                    "writeOnly": True,
                    "description": "the tenant's own provider key; omit to keep the vaulted one",
                },
                "base_url": nullable(string(minLength=8, maxLength=2048)),
                "daily_budget_usd": _money(),
                "sampling_rate": _rate(),
                "tasks": array(_enum(sv.SentinelTask), maxItems=4, uniqueItems=True),
                "price_in_usd_per_mtok": nullable(_money()),
                "price_out_usd_per_mtok": nullable(_money()),
                "reason": REASON,
            },
            ("enabled", "provider", "daily_budget_usd", "sampling_rate"),
        ),
        "SentinelConfigTestResult": obj(
            {
                "ok": boolean(),
                "provider": _enum(sv.SentinelProvider),
                "model": _model_id(),
                "latency_ms": integer(minimum=0),
                "http_status": integer(
                    minimum=0, description="the provider's HTTP status; 0 without a response"
                ),
                "error": nullable(
                    string(
                        maxLength=64,
                        description="null when ok; else http_error, transport, timeout,"
                        " egress_refused, refused, bad_output, malformed_response, config or"
                        " llm_error",
                    )
                ),
                "cost_usd": _money(),
            },
            ("ok", "provider", "model", "latency_ms", "http_status"),
        ),
        "SentinelFinding": obj(
            {
                "id": UUID,
                "kind": _enum(sv.SentinelTask),
                "subject_kind": _enum(sv.SentinelSubjectKind),
                "subject_id": N_UUID,
                "agent_id": N_UUID,
                "severity": _enum(sv.SentinelSeverity),
                "summary": string(maxLength=2000),
                "body": free_object("the model's validated structured output and input metadata"),
                "recommendation": nullable(string(maxLength=2000)),
                "provider": _enum(sv.SentinelProvider),
                "model": string(maxLength=128),
                "prompt_sha256": string(pattern=r"^[0-9a-f]{64}$"),
                "tokens_in": integer(minimum=0),
                "tokens_out": integer(minimum=0),
                "cost_usd": _money(),
                "cost_estimated": boolean(),
                "calls": integer(minimum=1),
                "trigger": _enum(sv.SentinelTrigger),
                "requested_by_user_id": N_UUID,
                "alert_id": N_UUID,
                "feedback": nullable(_enum(sv.SentinelFeedback)),
                "feedback_by_user_id": N_UUID,
                "feedback_at": N_TS,
                "created_at": TS,
                "advisory": boolean(description="always true: a finding never decides anything"),
            },
            (
                "id",
                "kind",
                "subject_kind",
                "severity",
                "summary",
                "provider",
                "model",
                "prompt_sha256",
                "cost_usd",
                "trigger",
                "created_at",
                "advisory",
            ),
        ),
        "SentinelFeedback": body_obj({"feedback": _enum(sv.SentinelFeedback)}, ("feedback",)),
        "SentinelExplain": body_obj(
            {
                "subject_kind": enum("incident", "held_action"),
                "subject_id": UUID,
            },
            ("subject_kind", "subject_id"),
        ),
    }
