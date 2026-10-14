"""D53 external monitor routes (WAVE4.md): monitors, their keys and webhooks (``monitors``),
and findings from every source (``findings``).

Tenant-wide admins (``monitors:admin``) register monitors, issue monitor-bound keys and signed
webhooks, pause, resume and revoke them; Sentinel readers (``sentinel:read``) see monitors and
every finding. A monitor-bound key holds ``monitor:read`` (metadata reads within its watched
agent groups, on the existing read routes) and ``findings:write`` (``POST /findings``, rate
limited per monitor). Findings are advisory: no route here can allow, block, approve, fail over
or change policy.
"""

from __future__ import annotations

from sibyl_schemas import values as sv

from .dsl import Op, Q, enum, ref
from .params import AGENT_ID_Q, SINCE_Q

ADMIN = "monitors:admin"
SENTINEL_READ = "sentinel:read"
MONITOR_READ = "monitor:read"
FINDINGS_WRITE = "findings:write"
BASE = "/monitors"
ONE = BASE + "/{monitor_id}"


def _enum(values: type) -> dict[str, object]:
    return enum(*(str(m.value) for m in values))


MONITOR_OPS: tuple[Op, ...] = (
    Op(
        "post",
        BASE,
        "createMonitor",
        "monitors",
        "Register an external monitor (and issue its first key; the secret is shown once)",
        scope=ADMIN,
        idem=True,
        rate="apikeys_create",
        audit=("monitor.registered", "api_key.created"),
        audit_when="conditional",
        audit_note="api_key.created as well when issue_key is true (the default)",
        body="MonitorCreate",
        ok=((201, "MonitorCreated", "Registered"),),
        problems={409: ("conflict",)},
        description=(
            "A monitor watches `all_groups` or the listed `group_ids` (descendants included)."
            " Its key carries `monitor:read` and `findings:write` only; an Idempotency-Key"
            " replay returns `api_key.secret: null`. 409 `conflict` when an unrevoked monitor"
            " already has the name."
        ),
    ),
    Op(
        "get",
        BASE,
        "listMonitors",
        "monitors",
        "External monitors, newest first",
        scope=ADMIN,
        scope_any=(SENTINEL_READ,),
        paged=True,
        query=(
            Q("state", _enum(sv.MonitorState)),
            Q("kind", _enum(sv.MonitorKind)),
        ),
        ok=((200, "Monitor", "Page of monitors"),),
    ),
    Op(
        "get",
        BASE + "/self",
        "getMonitorSelf",
        "monitors",
        "The monitor a monitor key is bound to (its watched groups, state and rate limit)",
        scope=MONITOR_READ,
        key_only=True,
        key_scopes=(MONITOR_READ,),
        ok=((200, "Monitor", "Monitor"),),
    ),
    Op(
        "get",
        ONE,
        "getMonitor",
        "monitors",
        "One monitor with its keys (metadata) and webhooks",
        scope=ADMIN,
        scope_any=(SENTINEL_READ,),
        ok=((200, "Monitor", "Monitor"),),
        etag_out=True,
        description='The ETag is "<version>"; send it back as If-Match to update.',
    ),
    Op(
        "patch",
        ONE,
        "updateMonitor",
        "monitors",
        "Pause or resume, rename, change watched groups, owner or rate limit",
        scope=ADMIN,
        if_match="required",
        etag_out=True,
        audit=("monitor.updated",),
        body="MonitorPatch",
        ok=((200, "Monitor", "Updated"),),
        problems={409: ("invalid_transition", "conflict")},
        description="A revoked monitor is terminal (409 `invalid_transition`).",
    ),
    Op(
        "post",
        ONE + "/revoke",
        "revokeMonitor",
        "monitors",
        "Revoke a monitor: its keys are revoked and its webhooks disabled (terminal)",
        scope=ADMIN,
        idem=True,
        audit=("monitor.revoked",),
        body="MonitorRevoke",
        ok=((200, "Monitor", "Revoked"),),
        problems={409: ("invalid_transition",)},
    ),
    Op(
        "post",
        ONE + "/keys",
        "issueMonitorKey",
        "monitors",
        "Issue another key bound to the monitor (monitor:read + findings:write; shown once)",
        scope=ADMIN,
        idem=True,
        rate="apikeys_create",
        audit=("api_key.created",),
        body="MonitorKeyCreate",
        body_required=False,
        ok=((201, "ApiKeyCreated", "Issued"),),
        problems={409: ("not_active",)},
        description="409 `not_active` for a revoked monitor. Rotate and revoke monitor keys"
        " with the `/api-keys` routes.",
    ),
    Op(
        "post",
        ONE + "/webhooks",
        "createMonitorWebhook",
        "monitors",
        "Add a signed webhook (https, egress-allowlisted); the signing secret is shown once",
        scope=ADMIN,
        idem=True,
        audit=("monitor.updated",),
        body="WebhookCreate",
        ok=((201, "MonitorWebhookCreated", "Created"),),
        problems={
            409: ("not_active",),
            422: ("base_url_not_allowlisted",),
            503: ("service_unavailable",),
        },
        description=(
            "Deliveries carry `Sibyl-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t + '.' +"
            " body)>`, `Sibyl-Event-Id`, `Sibyl-Event-Type` and `Sibyl-Delivery-Id`; payloads"
            " are references and states only. A non-2xx response is retried with exponential"
            " backoff and dead-lettered after the last attempt. The URL must be https, on a"
            " public address (checked again at connect time) and, when the deployment sets"
            " SIBYL_WEBHOOK_ALLOWED_HOSTS, on that allowlist."
        ),
    ),
    Op(
        "post",
        ONE + "/webhooks/{webhook_id}/test",
        "testMonitorWebhook",
        "monitors",
        "Send a signed `ping` delivery now and report the receiver's answer",
        scope=ADMIN,
        idem=True,
        audit=("webhook.tested",),
        ok=((200, "WebhookTestResult", "Result (ok true or false)"),),
        problems={409: ("not_active",), 503: ("service_unavailable",)},
        description="A receiver-side failure is still 200 with `ok` false, `http_status` (0"
        " without a response) and `error` (`http_error`, `timeout`, `transport`,"
        " `egress_refused`).",
    ),
)

FINDING_OPS: tuple[Op, ...] = (
    Op(
        "post",
        "/findings",
        "submitFinding",
        "findings",
        "Submit an advisory finding (monitor key; rate-limited per monitor)",
        scope=FINDINGS_WRITE,
        key_only=True,
        key_scopes=(FINDINGS_WRITE,),
        rules=("group",),
        idem=True,
        audit=("finding.submitted",),
        body="FindingSubmit",
        ok=((201, "Finding", "Recorded"),),
        problems={404: ("not_found",), 409: ("not_active",)},
        description=(
            "Same shape as a Sentinel finding. The subject must exist within the monitor's"
            " watched groups (404 otherwise; a fleet finding needs an all-groups monitor). A"
            " critical finding (or a warning with `raise_alert: true`) about an agent opens a"
            " watch-only `external_finding` alert; a `held_action_review` attaches its `advice`"
            " to the held action. A finding never allows, blocks, approves, fails over or"
            " changes policy. 409 `not_active` while the monitor is paused; 429 past the"
            " monitor's `rate_limit_per_min`."
        ),
    ),
    Op(
        "get",
        "/findings",
        "listFindings",
        "findings",
        "Findings from Sentinel and external monitors, newest first",
        scope=SENTINEL_READ,
        scope_any=(MONITOR_READ,),
        key_scopes=(MONITOR_READ,),
        rules=("group",),
        paged=True,
        query=(
            Q("source", _enum(sv.FindingSource)),
            Q("monitor_id", ref("Uuid")),
            Q("kind", _enum(sv.ExternalFindingKind)),
            Q("subject_kind", _enum(sv.ExternalSubjectKind)),
            Q("subject_id", ref("Uuid")),
            AGENT_ID_Q,
            Q("severity", _enum(sv.SentinelSeverity)),
            SINCE_Q,
        ),
        ok=((200, "Finding", "Page of findings"),),
        description="A monitor key sees findings about agents in its watched groups (fleet"
        " findings only with all groups).",
    ),
    Op(
        "get",
        "/findings/{finding_id}",
        "getFinding",
        "findings",
        "One finding (either source)",
        scope=SENTINEL_READ,
        scope_any=(MONITOR_READ,),
        key_scopes=(MONITOR_READ,),
        rules=("group",),
        ok=((200, "Finding", "Finding"),),
    ),
    Op(
        "post",
        "/findings/{finding_id}/feedback",
        "recordFindingFeedback",
        "findings",
        "Rate a finding of either source (useful, not_useful, wrong); the latest rating wins",
        scope=SENTINEL_READ,
        idem=True,
        audit=("finding.feedback_recorded", "sentinel.feedback_recorded"),
        audit_when="conditional",
        audit_note="sentinel.feedback_recorded for a Sentinel finding",
        body="FindingFeedback",
        ok=((200, "Finding", "Rated"),),
    ),
)

MONITOR_READ_OPS: frozenset[str] = frozenset(
    {
        "listAgents",
        "getAgent",
        "getFleetHealth",
        "getAgentHealth",
        "listRuns",
        "getRun",
        "getAgentDrift",
        "listAlerts",
        "getAlert",
        "listIncidents",
        "getIncident",
        "listHeldActions",
        "getHeldAction",
    }
)
"""Existing read routes a ``monitor:read`` key may call (metadata only, watched groups only)."""
