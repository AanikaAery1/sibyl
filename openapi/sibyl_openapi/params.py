"""Reusable parameter declarations."""

from __future__ import annotations

from .dsl import TS, UUID, Q, boolean, integer, ref, string

AGENT_ID_Q = Q("agent_id", UUID)
FROM_Q = Q("from", TS)
TO_Q = Q("to", TS)
SINCE_Q = Q("since", TS)
SEARCH_Q = Q("q", string(maxLength=120))
REASON_Q = Q("reason", string(minLength=10, maxLength=2000), required=True)
OPEN_Q = Q("open", boolean())
STATUS_KEY_Q = Q("status", ref("ApiKeyStatus"))
ENV_Q = Q("env", ref("ApiKeyEnv"))
TIER_Q = Q("tier", integer(minimum=1, maximum=3))
GROUP_Q = Q("group_id", UUID)
BAND_Q = Q("band", ref("Band"))
PROVIDER_ID_Q = Q("provider_id", UUID)
IF_NONE_MATCH = Q("If-None-Match", string(), location="header")
REVEAL_REASON = Q(
    "X-Sibyl-Reveal-Reason",
    string(minLength=10, maxLength=500),
    location="header",
    description="required with payloads:reveal (428 reveal_reason_required); audited data.revealed",
)
LAST_EVENT_ID = Q(
    "Last-Event-ID",
    string(pattern=r"^(\d{1,20}|\d{4}-\d{2}-\d{2}T[^|]+Z)\|[0-9a-f-]{36}$", maxLength=128),
    location="header",
    description="<xid>|<uuid> as sent in the SSE id: field (legacy <timestamp>|<uuid> accepted)",
)
SEAL_KEY = Q(
    "X-Sibyl-Seal-Key",
    string(pattern=r"^[A-Za-z0-9_-]{43}$"),
    required=True,
    location="header",
    description=(
        "the gateway's X25519 public key (raw, base64url unpadded); secrets are sealed to it"
        " (sibyl-seal/1). Missing or unusable is 422 validation_failed"
    ),
)
BATCH_ID = Q("X-Sibyl-Batch-Id", UUID, location="header", description="recommended; 24 h replay")
SCHEMA_HDR = Q("X-Sibyl-Schema", string(const="sibyl-event/1"), location="header")
AGENT_HDR = Q("X-Sibyl-Agent", string(maxLength=200), location="header")
CAPTURE_OWNER_HDR = Q("X-Sibyl-Capture-Owner", string(enum=["sdk", "gateway"]), location="header")

PATH_PARAM_SCHEMAS = {
    "purpose": ref("TenantKeyPurpose"),
    "version_no": integer(minimum=1),
    "seq": integer(minimum=0, format="int64"),
    "node_kind": ref("NodeKind"),
    "trace_id": string(pattern=r"^[0-9a-f]{32}$"),
}
