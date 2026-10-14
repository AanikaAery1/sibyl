"""D52 Sibyl Sentinel routes (WAVE3.md): the opt-in advisory monitoring agent.

Readers (``sentinel:read``) list findings and rate them; tenant-wide admins
(``sentinel:admin``) configure Sentinel (step-up: the body may carry the tenant's provider key),
test connectivity and ask for an on-demand explanation. No Sentinel route can allow, block,
approve, fail over or change policy.
"""

from __future__ import annotations

from sibyl_schemas import values as sv

from .dsl import UUID, Op, Q, enum
from .params import AGENT_ID_Q, SINCE_Q

READ = "sentinel:read"
ADMIN = "sentinel:admin"
BASE = "/sentinel"


def _enum(values: type) -> dict[str, object]:
    return enum(*(str(m.value) for m in values))


SENTINEL_OPS: tuple[Op, ...] = (
    Op(
        "get",
        BASE + "/config",
        "getSentinelConfig",
        "sentinel",
        "Sentinel configuration (the API key is never returned) and today's usage",
        scope=READ,
        ok=((200, "SentinelConfig", "Sentinel configuration"),),
        etag_out=True,
        description='The ETag is "<version>", or "0" before the first save, so a client can'
        " always send it back as If-Match.",
    ),
    Op(
        "put",
        BASE + "/config",
        "putSentinelConfig",
        "sentinel",
        "Turn Sentinel on or off and set provider, model, vaulted key, budget and tasks",
        scope=ADMIN,
        step_up="always",
        step_up_note="the body may carry the tenant's provider API key",
        if_match="required_or_star",
        etag_out=True,
        audit=("sentinel.config_changed",),
        body="SentinelConfigPut",
        ok=((200, "SentinelConfig", "Saved"),),
        problems={422: ("base_url_not_allowlisted",), 503: ("service_unavailable",)},
        description=(
            "The key is sealed under the tenant credential key and is write-only. If-Match is"
            ' the ETag from GET ("0" before the first save; * is also accepted for the first'
            " write)."
        ),
    ),
    Op(
        "post",
        BASE + "/config/test",
        "testSentinelConfig",
        "sentinel",
        "Connectivity check: one tiny call with the vaulted key (counted in today's usage)",
        scope=ADMIN,
        idem=True,
        audit=("sentinel.config_tested",),
        ok=((200, "SentinelConfigTestResult", "Result (ok true or false)"),),
        problems={409: ("not_active",), 503: ("service_unavailable",)},
        description=(
            "A provider-side failure is still 200: `ok` false, `http_status` the provider's"
            " status (0 when no HTTP response arrived) and `error` one of `http_error`,"
            " `transport`, `timeout`, `egress_refused`, `refused`, `bad_output`,"
            " `malformed_response`, `config`, `llm_error`; `latency_ms` and `cost_usd` are"
            " still reported and the attempt counts in today's usage. 409 `not_active` when"
            " Sentinel has no configuration or no vaulted key; 503 when the vault is not"
            " configured."
        ),
    ),
    Op(
        "get",
        BASE + "/findings",
        "listSentinelFindings",
        "sentinel",
        "Sentinel findings (advisory), newest first",
        scope=READ,
        paged=True,
        query=(
            Q("kind", _enum(sv.SentinelTask)),
            Q("subject_kind", _enum(sv.SentinelSubjectKind)),
            Q("subject_id", UUID),
            AGENT_ID_Q,
            Q("severity", _enum(sv.SentinelSeverity)),
            Q("trigger", _enum(sv.SentinelTrigger)),
            SINCE_Q,
        ),
        ok=((200, "SentinelFinding", "Page of findings"),),
    ),
    Op(
        "get",
        BASE + "/findings/{finding_id}",
        "getSentinelFinding",
        "sentinel",
        "One Sentinel finding",
        scope=READ,
        ok=((200, "SentinelFinding", "Finding"),),
    ),
    Op(
        "post",
        BASE + "/findings/{finding_id}/feedback",
        "recordSentinelFeedback",
        "sentinel",
        "Rate a finding (useful, not_useful, wrong); the latest rating wins",
        scope=READ,
        idem=True,
        audit=("sentinel.feedback_recorded",),
        body="SentinelFeedback",
        ok=((200, "SentinelFinding", "Rated"),),
    ),
    Op(
        "post",
        BASE + "/explain",
        "explainWithSentinel",
        "sentinel",
        "On-demand explanation of an incident or held action (budget-checked, advisory)",
        scope=ADMIN,
        idem=True,
        audit=("sentinel.finding_created", "sentinel.budget_exhausted"),
        audit_note="sentinel.budget_exhausted (with 409 conflict) when today's budget is spent",
        body="SentinelExplain",
        ok=((201, "SentinelFinding", "Finding created"),),
        problems={
            404: ("not_found",),
            409: ("not_active", "conflict"),
            503: ("service_unavailable",),
        },
    ),
)
