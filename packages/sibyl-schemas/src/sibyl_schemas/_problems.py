"""Problem codes (RFC 9457, API §2.3) and gateway error codes (OpenAI envelope, API §3.5)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

PROBLEM_TYPE_BASE: Final = "https://sibyl.dev/problems/"


class ProblemCode(StrEnum):
    # 400
    BATCH_TOO_LARGE = "batch_too_large"
    CREDENTIAL_IN_URL = "credential_in_url"
    CURSOR_FILTER_MISMATCH = "cursor_filter_mismatch"
    INVALID_CURSOR = "invalid_cursor"
    INVALID_SCOPE = "invalid_scope"
    UNSUPPORTED_SCHEMA = "unsupported_schema"
    # 401
    UNAUTHENTICATED = "unauthenticated"
    OIDC_FAILED = "oidc_failed"
    # 403
    FORBIDDEN = "forbidden"
    AGENT_BINDING_VIOLATION = "agent_binding_violation"
    STEP_UP_REQUIRED = "step_up_required"
    KEY_FROM_BROWSER = "key_from_browser"
    AGENT_NOT_PERMITTED = "agent_not_permitted"
    BREAK_GLASS_KEY_MISUSE = "break_glass_key_misuse"
    CREDENTIAL_NOT_IN_SNAPSHOT = "credential_not_in_snapshot"
    IDENTITY_WIDEN_FORBIDDEN = "identity_widen_forbidden"
    TIER1_INLINE_FALLBACK_NEEDS_APPROVER = "tier1_inline_fallback_needs_approver"
    # 404
    NOT_FOUND = "not_found"
    BOM_NOT_GENERATED = "bom_not_generated"
    NO_SNAPSHOT_YET = "no_snapshot_yet"
    PACKET_SHREDDED = "packet_shredded"
    PAYLOAD_SWEPT = "payload_swept"
    PLAN_MISSING = "plan_missing"
    TENANT_UNKNOWN = "tenant_unknown"
    # 405
    METHOD_NOT_ALLOWED = "method_not_allowed"
    # 409
    ALREADY_PULLED = "already_pulled"
    ALREADY_RESOLVED = "already_resolved"
    ALREADY_REVOKED = "already_revoked"
    ALREADY_UNDONE = "already_undone"
    ACTION_NOT_PENDING = "action_not_pending"
    APPROVAL_NOT_PENDING = "approval_not_pending"
    CAPTURE_POLICY_MISSING = "capture_policy_missing"
    CHAIN_IMMUTABLE = "chain_immutable"
    CLAIMED_BY_OTHER = "claimed_by_other"
    CODE_EXISTS = "code_exists"
    CONFLICT = "conflict"
    CUSTOM_RULE = "custom_rule"
    DEMO_MODE = "demo_mode"
    DUPLICATE_APPROVER = "duplicate_approver"
    EDGE_EXISTS = "edge_exists"
    ERASURE_BLOCKED_BY_CHAIN = "erasure_blocked_by_chain"
    ERASURE_IN_PROGRESS = "erasure_in_progress"
    GROUP_CYCLE = "group_cycle"
    HOLD_BLOCKED = "hold_blocked"
    IDEMPOTENCY_IN_PROGRESS = "idempotency_in_progress"
    IDEMPOTENT_REPLAY_UNAVAILABLE = "idempotent_replay_unavailable"
    ERASURE_NOT_APPROVED = "erasure_not_approved"
    KEY_FIELD_IMMUTABLE = "key_field_immutable"
    INVALID_TRANSITION = "invalid_transition"
    ISSUER_EXISTS = "issuer_exists"
    KEY_NOT_ACTIVE = "key_not_active"
    LAST_ACTIVE_ISSUER = "last_active_issuer"
    LAST_OWNER = "last_owner"
    LOCK_LAPSED = "lock_lapsed"
    MEMBERSHIP_EXISTS = "membership_exists"
    MODEL_EXISTS = "model_exists"
    NOT_ACTIVE = "not_active"
    NOT_COMPLETED = "not_completed"
    NOT_PROVISIONAL = "not_provisional"
    NOT_PULLED = "not_pulled"
    NOTHING_TO_UNDO = "nothing_to_undo"
    OPERATOR_HOLD = "operator_hold"
    PROVIDER_IN_USE = "provider_in_use"
    SAGA_IN_FLIGHT = "saga_in_flight"
    SECOND_OWNER_REQUIRED = "second_owner_required"
    SELF_APPROVAL = "self_approval"
    SLUG_EXISTS = "slug_exists"
    STALE_PRECONDITION = "stale_precondition"
    TARGET_NOT_VIABLE = "target_not_viable"
    TIER1_REQUIRES_BOUND_KEY = "tier1_requires_bound_key"
    USER_EXISTS = "user_exists"
    # 410
    PAYLOAD_SHREDDED = "payload_shredded"
    # 412
    PRECONDITION_FAILED = "precondition_failed"
    # 413
    PAYLOAD_TOO_LARGE = "payload_too_large"
    # 415
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    # 422
    VALIDATION_FAILED = "validation_failed"
    AGENT_POLICY_LOOSER_THAN_TENANT = "agent_policy_looser_than_tenant"
    ALT_PROVIDER_REQUIRES_CREDENTIAL = "alt_provider_requires_credential"
    BACKUP_IS_SELF = "backup_is_self"
    BASE_URL_NOT_ALLOWLISTED = "base_url_not_allowlisted"
    BELOW_SECRETS_BASELINE = "below_secrets_baseline"
    BREAK_GLASS_SCOPE_EXCLUSIVE = "break_glass_scope_exclusive"
    CAPTURE_MODE_REQUIRED = "capture_mode_required"
    CHAIN_AGENT_MISMATCH = "chain_agent_mismatch"
    CHAIN_NOT_APPROVED = "chain_not_approved"
    CODE_PATTERN = "code_pattern"
    EXPIRES_AT_OUT_OF_RANGE = "expires_at_out_of_range"
    FAIL_MODE_REQUIRED = "fail_mode_required"
    FAIL_SAFE_FORBIDDEN = "fail_safe_forbidden"
    GRAIN_RANGE = "grain_range"
    HEADER_FORBIDDEN = "header_forbidden"
    IDEMPOTENCY_KEY_REUSE = "idempotency_key_reuse"
    JIT_ROLE_FORBIDDEN = "jit_role_forbidden"
    MAX_AGENTS_REACHED = "max_agents_reached"
    NODE_UNKNOWN = "node_unknown"
    RANGE_TOO_WIDE = "range_too_wide"
    REFERENCE_UNKNOWN = "reference_unknown"
    ROLE_REQUIRES_TENANT_SCOPE = "role_requires_tenant_scope"
    SCOPE_MISMATCH = "scope_mismatch"
    SCOPE_REF_REQUIRED = "scope_ref_required"
    STEP_AFTER_HUMAN_QUEUE = "step_after_human_queue"
    STEP_RANK_ORDER = "step_rank_order"
    VERDICT_REQUIRED = "verdict_required"
    # 428
    IDEMPOTENCY_KEY_REQUIRED = "idempotency_key_required"
    PRECONDITION_REQUIRED = "precondition_required"
    REVEAL_REASON_REQUIRED = "reveal_reason_required"
    # 429
    RATE_LIMITED = "rate_limited"
    TENANT_ERASING = "tenant_erasing"
    BREAK_GLASS_RATE_LIMITED = "break_glass_rate_limited"
    STREAM_LIMIT = "stream_limit"
    TENANT_RATE_LIMIT = "tenant_rate_limit"
    INGEST_SATURATED = "ingest_saturated"
    # 5xx
    INTERNAL_ERROR = "internal_error"
    NOT_IMPLEMENTED = "not_implemented"
    SERVICE_UNAVAILABLE = "service_unavailable"
    SNAPSHOT_UNAVAILABLE = "snapshot_unavailable"
    DATABASE_UNAVAILABLE = "database_unavailable"
    SERIALIZATION_FAILURE = "serialization_failure"
    DATABASE_TIMEOUT = "database_timeout"


_BY_STATUS: Final[dict[int, tuple[ProblemCode, ...]]] = {
    400: (
        ProblemCode.BATCH_TOO_LARGE,
        ProblemCode.CREDENTIAL_IN_URL,
        ProblemCode.CURSOR_FILTER_MISMATCH,
        ProblemCode.INVALID_CURSOR,
        ProblemCode.INVALID_SCOPE,
        ProblemCode.UNSUPPORTED_SCHEMA,
    ),
    401: (
        ProblemCode.UNAUTHENTICATED,
        ProblemCode.OIDC_FAILED,
    ),
    403: (
        ProblemCode.FORBIDDEN,
        ProblemCode.AGENT_BINDING_VIOLATION,
        ProblemCode.STEP_UP_REQUIRED,
        ProblemCode.KEY_FROM_BROWSER,
        ProblemCode.AGENT_NOT_PERMITTED,
        ProblemCode.BREAK_GLASS_KEY_MISUSE,
        ProblemCode.CREDENTIAL_NOT_IN_SNAPSHOT,
        ProblemCode.IDENTITY_WIDEN_FORBIDDEN,
        ProblemCode.TIER1_INLINE_FALLBACK_NEEDS_APPROVER,
    ),
    404: (
        ProblemCode.NOT_FOUND,
        ProblemCode.BOM_NOT_GENERATED,
        ProblemCode.NO_SNAPSHOT_YET,
        ProblemCode.PACKET_SHREDDED,
        ProblemCode.PAYLOAD_SWEPT,
        ProblemCode.PLAN_MISSING,
        ProblemCode.TENANT_UNKNOWN,
    ),
    405: (ProblemCode.METHOD_NOT_ALLOWED,),
    409: (
        ProblemCode.ALREADY_PULLED,
        ProblemCode.ALREADY_RESOLVED,
        ProblemCode.ALREADY_REVOKED,
        ProblemCode.ALREADY_UNDONE,
        ProblemCode.ACTION_NOT_PENDING,
        ProblemCode.APPROVAL_NOT_PENDING,
        ProblemCode.CAPTURE_POLICY_MISSING,
        ProblemCode.CHAIN_IMMUTABLE,
        ProblemCode.CLAIMED_BY_OTHER,
        ProblemCode.CODE_EXISTS,
        ProblemCode.CONFLICT,
        ProblemCode.CUSTOM_RULE,
        ProblemCode.DEMO_MODE,
        ProblemCode.DUPLICATE_APPROVER,
        ProblemCode.EDGE_EXISTS,
        ProblemCode.ERASURE_BLOCKED_BY_CHAIN,
        ProblemCode.ERASURE_IN_PROGRESS,
        ProblemCode.GROUP_CYCLE,
        ProblemCode.HOLD_BLOCKED,
        ProblemCode.IDEMPOTENCY_IN_PROGRESS,
        ProblemCode.IDEMPOTENT_REPLAY_UNAVAILABLE,
        ProblemCode.ERASURE_NOT_APPROVED,
        ProblemCode.KEY_FIELD_IMMUTABLE,
        ProblemCode.INVALID_TRANSITION,
        ProblemCode.ISSUER_EXISTS,
        ProblemCode.KEY_NOT_ACTIVE,
        ProblemCode.LAST_ACTIVE_ISSUER,
        ProblemCode.LAST_OWNER,
        ProblemCode.LOCK_LAPSED,
        ProblemCode.MEMBERSHIP_EXISTS,
        ProblemCode.MODEL_EXISTS,
        ProblemCode.NOT_ACTIVE,
        ProblemCode.NOT_COMPLETED,
        ProblemCode.NOT_PROVISIONAL,
        ProblemCode.NOT_PULLED,
        ProblemCode.NOTHING_TO_UNDO,
        ProblemCode.OPERATOR_HOLD,
        ProblemCode.PROVIDER_IN_USE,
        ProblemCode.SAGA_IN_FLIGHT,
        ProblemCode.SECOND_OWNER_REQUIRED,
        ProblemCode.SELF_APPROVAL,
        ProblemCode.SLUG_EXISTS,
        ProblemCode.STALE_PRECONDITION,
        ProblemCode.TARGET_NOT_VIABLE,
        ProblemCode.TIER1_REQUIRES_BOUND_KEY,
        ProblemCode.USER_EXISTS,
    ),
    410: (ProblemCode.PAYLOAD_SHREDDED,),
    412: (ProblemCode.PRECONDITION_FAILED,),
    413: (ProblemCode.PAYLOAD_TOO_LARGE,),
    415: (ProblemCode.UNSUPPORTED_MEDIA_TYPE,),
    422: (
        ProblemCode.VALIDATION_FAILED,
        ProblemCode.AGENT_POLICY_LOOSER_THAN_TENANT,
        ProblemCode.ALT_PROVIDER_REQUIRES_CREDENTIAL,
        ProblemCode.BACKUP_IS_SELF,
        ProblemCode.BASE_URL_NOT_ALLOWLISTED,
        ProblemCode.BELOW_SECRETS_BASELINE,
        ProblemCode.BREAK_GLASS_SCOPE_EXCLUSIVE,
        ProblemCode.CAPTURE_MODE_REQUIRED,
        ProblemCode.CHAIN_AGENT_MISMATCH,
        ProblemCode.CHAIN_NOT_APPROVED,
        ProblemCode.CODE_PATTERN,
        ProblemCode.EXPIRES_AT_OUT_OF_RANGE,
        ProblemCode.FAIL_MODE_REQUIRED,
        ProblemCode.FAIL_SAFE_FORBIDDEN,
        ProblemCode.GRAIN_RANGE,
        ProblemCode.HEADER_FORBIDDEN,
        ProblemCode.IDEMPOTENCY_KEY_REUSE,
        ProblemCode.JIT_ROLE_FORBIDDEN,
        ProblemCode.MAX_AGENTS_REACHED,
        ProblemCode.NODE_UNKNOWN,
        ProblemCode.RANGE_TOO_WIDE,
        ProblemCode.REFERENCE_UNKNOWN,
        ProblemCode.ROLE_REQUIRES_TENANT_SCOPE,
        ProblemCode.SCOPE_MISMATCH,
        ProblemCode.SCOPE_REF_REQUIRED,
        ProblemCode.STEP_AFTER_HUMAN_QUEUE,
        ProblemCode.STEP_RANK_ORDER,
        ProblemCode.VERDICT_REQUIRED,
    ),
    428: (
        ProblemCode.IDEMPOTENCY_KEY_REQUIRED,
        ProblemCode.PRECONDITION_REQUIRED,
        ProblemCode.REVEAL_REASON_REQUIRED,
    ),
    429: (
        ProblemCode.RATE_LIMITED,
        ProblemCode.TENANT_ERASING,
        ProblemCode.BREAK_GLASS_RATE_LIMITED,
        ProblemCode.STREAM_LIMIT,
        ProblemCode.TENANT_RATE_LIMIT,
        ProblemCode.INGEST_SATURATED,
    ),
    500: (ProblemCode.INTERNAL_ERROR,),
    501: (ProblemCode.NOT_IMPLEMENTED,),
    503: (
        ProblemCode.SERVICE_UNAVAILABLE,
        ProblemCode.SNAPSHOT_UNAVAILABLE,
        ProblemCode.DATABASE_UNAVAILABLE,
        ProblemCode.SERIALIZATION_FAILURE,
        ProblemCode.DATABASE_TIMEOUT,
    ),
}


def _status_table() -> dict[ProblemCode, int]:
    table: dict[ProblemCode, int] = {}
    for status, codes in _BY_STATUS.items():
        table.update(dict.fromkeys(codes, status))
    return table


PROBLEM_STATUS: Final = MappingProxyType(_status_table())
"""Primary HTTP status per problem code."""

PROBLEM_ALT_STATUSES: Final = MappingProxyType({ProblemCode.CAPTURE_POLICY_MISSING: (403, 404)})
"""Codes the API document uses with more than one status (ingest 403, reads 404)."""


def problem_type_uri(code: ProblemCode) -> str:
    """RFC 9457 `type` member for a problem code."""
    return f"{PROBLEM_TYPE_BASE}{code.value}"


def problem_statuses(code: ProblemCode) -> tuple[int, ...]:
    """Every HTTP status a code may carry, the primary status first."""
    return (PROBLEM_STATUS[code], *PROBLEM_ALT_STATUSES.get(code, ()))


_C = ProblemCode

# fmt: off
PROBLEM_TITLE: Final[Mapping[ProblemCode, str]] = MappingProxyType({
    _C.BATCH_TOO_LARGE: "Batch exceeds the item limit",
    _C.CREDENTIAL_IN_URL: "Credentials must not be sent in the URL",
    _C.CURSOR_FILTER_MISMATCH: "Cursor was issued for different filters",
    _C.INVALID_CURSOR: "Cursor is not valid",
    _C.INVALID_SCOPE: "Scope cannot be granted to an API key",
    _C.UNSUPPORTED_SCHEMA: "Unsupported document schema",
    _C.UNAUTHENTICATED: "Authentication required",
    _C.OIDC_FAILED: "Sign-in failed",
    _C.FORBIDDEN: "Not allowed",
    _C.AGENT_BINDING_VIOLATION: "Key is bound to another agent",
    _C.STEP_UP_REQUIRED: "Recent re-authentication required",
    _C.KEY_FROM_BROWSER: "API keys are not accepted from a browser",
    _C.AGENT_NOT_PERMITTED: "Key may not act as this agent",
    _C.BREAK_GLASS_KEY_MISUSE: "Break-glass key used outside its route",
    _C.CREDENTIAL_NOT_IN_SNAPSHOT: "Credential is not referenced by the snapshot",
    _C.IDENTITY_WIDEN_FORBIDDEN: "Only narrowing changes are allowed",
    _C.TIER1_INLINE_FALLBACK_NEEDS_APPROVER: "Tier-1 inline fallback needs an approver",
    _C.NOT_FOUND: "Not found",
    _C.BOM_NOT_GENERATED: "AI-BOM not generated yet",
    _C.NO_SNAPSHOT_YET: "No health snapshot yet",
    _C.PACKET_SHREDDED: "Packet was crypto-shredded",
    _C.PAYLOAD_SWEPT: "Payload was swept by retention",
    _C.PLAN_MISSING: "Continuity plan missing",
    _C.TENANT_UNKNOWN: "Unknown tenant",
    _C.METHOD_NOT_ALLOWED: "Method not allowed",
    _C.ALREADY_PULLED: "Kill switch already pulled",
    _C.ALREADY_RESOLVED: "Alert already resolved",
    _C.ALREADY_REVOKED: "Already revoked",
    _C.ALREADY_UNDONE: "Already undone",
    _C.ACTION_NOT_PENDING: "Held action is not pending",
    _C.APPROVAL_NOT_PENDING: "Approval is not pending",
    _C.CAPTURE_POLICY_MISSING: "Tenant capture policy missing",
    _C.CHAIN_IMMUTABLE: "Chain is immutable",
    _C.CLAIMED_BY_OTHER: "Claimed by another operator",
    _C.CODE_EXISTS: "Rule code exists",
    _C.CONFLICT: "Conflict",
    _C.CUSTOM_RULE: "Custom rules cannot be reset",
    _C.DEMO_MODE: "Not allowed in demo mode",
    _C.DUPLICATE_APPROVER: "Second approval must come from another person",
    _C.EDGE_EXISTS: "Edge exists",
    _C.ERASURE_BLOCKED_BY_CHAIN: "Agent is a backup in another agent's fallback chain",
    _C.ERASURE_IN_PROGRESS: "Erasure in progress",
    _C.GROUP_CYCLE: "Agent group cycle",
    _C.HOLD_BLOCKED: "Blocked by a legal hold",
    _C.IDEMPOTENCY_IN_PROGRESS: "Request with this Idempotency-Key in progress",
    _C.IDEMPOTENT_REPLAY_UNAVAILABLE: "Stored response too large to replay",
    _C.ERASURE_NOT_APPROVED: "Erasure request is not approved",
    _C.KEY_FIELD_IMMUTABLE: "API key field cannot be changed",
    _C.INVALID_TRANSITION: "Transition not allowed",
    _C.ISSUER_EXISTS: "Issuer exists",
    _C.KEY_NOT_ACTIVE: "Key is not active",
    _C.LAST_ACTIVE_ISSUER: "Cannot disable the last active issuer",
    _C.LAST_OWNER: "Cannot remove the last owner",
    _C.LOCK_LAPSED: "Claim lock lapsed",
    _C.MEMBERSHIP_EXISTS: "Membership exists",
    _C.MODEL_EXISTS: "Model exists",
    _C.NOT_ACTIVE: "Not active",
    _C.NOT_COMPLETED: "Not completed",
    _C.NOT_PROVISIONAL: "Agent is not provisional",
    _C.NOT_PULLED: "Kill switch not pulled",
    _C.NOTHING_TO_UNDO: "Nothing to undo",
    _C.OPERATOR_HOLD: "Automation paused by operator hold",
    _C.PROVIDER_IN_USE: "Provider in use",
    _C.SAGA_IN_FLIGHT: "Another incident is in flight",
    _C.SECOND_OWNER_REQUIRED: "A second owner is required",
    _C.SELF_APPROVAL: "Requester cannot approve",
    _C.SLUG_EXISTS: "Slug exists",
    _C.STALE_PRECONDITION: "State changed; re-read and retry",
    _C.TARGET_NOT_VIABLE: "Target not viable",
    _C.TIER1_REQUIRES_BOUND_KEY: "Tier-1 agents need an agent-bound key",
    _C.USER_EXISTS: "User exists",
    _C.PAYLOAD_SHREDDED: "Payload was crypto-shredded",
    _C.PRECONDITION_FAILED: "Precondition failed",
    _C.PAYLOAD_TOO_LARGE: "Payload too large",
    _C.UNSUPPORTED_MEDIA_TYPE: "Unsupported media type",
    _C.VALIDATION_FAILED: "Request is not valid",
    _C.AGENT_POLICY_LOOSER_THAN_TENANT: "Agent policy looser than tenant policy",
    _C.ALT_PROVIDER_REQUIRES_CREDENTIAL: "Alternate provider needs a credential",
    _C.BACKUP_IS_SELF: "Backup agent is the agent itself",
    _C.BASE_URL_NOT_ALLOWLISTED: "base_url not allowlisted",
    _C.BELOW_SECRETS_BASELINE: "Profile below the secrets baseline",
    _C.BREAK_GLASS_SCOPE_EXCLUSIVE: "Break-glass keys carry only killswitch:pull",
    _C.CAPTURE_MODE_REQUIRED: "capture_mode is required",
    _C.CHAIN_AGENT_MISMATCH: "Chain belongs to another agent",
    _C.CHAIN_NOT_APPROVED: "Chain not approved",
    _C.CODE_PATTERN: "Rule code pattern",
    _C.EXPIRES_AT_OUT_OF_RANGE: "expires_at out of range",
    _C.FAIL_MODE_REQUIRED: "fail_mode is required",
    _C.FAIL_SAFE_FORBIDDEN: "fail_safe forbidden for this agent",
    _C.GRAIN_RANGE: "Grain and range mismatch",
    _C.HEADER_FORBIDDEN: "Header may not be captured",
    _C.IDEMPOTENCY_KEY_REUSE: "Idempotency-Key reused with a different request",
    _C.JIT_ROLE_FORBIDDEN: "JIT role not allowed",
    _C.MAX_AGENTS_REACHED: "Agent limit reached",
    _C.NODE_UNKNOWN: "Graph node unknown",
    _C.RANGE_TOO_WIDE: "Range too wide",
    _C.REFERENCE_UNKNOWN: "Referenced object unknown",
    _C.ROLE_REQUIRES_TENANT_SCOPE: "Role requires tenant scope",
    _C.SCOPE_MISMATCH: "Scope mismatch",
    _C.SCOPE_REF_REQUIRED: "scope_ref required",
    _C.STEP_AFTER_HUMAN_QUEUE: "No step may follow human_queue",
    _C.STEP_RANK_ORDER: "Fallback steps out of rank order",
    _C.VERDICT_REQUIRED: "Verdict required",
    _C.IDEMPOTENCY_KEY_REQUIRED: "Idempotency-Key required",
    _C.PRECONDITION_REQUIRED: "If-Match required",
    _C.REVEAL_REASON_REQUIRED: "X-Sibyl-Reveal-Reason required",
    _C.RATE_LIMITED: "Too many requests",
    _C.TENANT_ERASING: "Tenant is being erased",
    _C.BREAK_GLASS_RATE_LIMITED: "Break-glass rate limit reached",
    _C.STREAM_LIMIT: "Too many open streams",
    _C.TENANT_RATE_LIMIT: "Tenant ingest rate limit reached",
    _C.INGEST_SATURATED: "Ingest is saturated",
    _C.INTERNAL_ERROR: "Internal error",
    _C.NOT_IMPLEMENTED: "Not implemented yet",
    _C.SERVICE_UNAVAILABLE: "Service unavailable",
    _C.SNAPSHOT_UNAVAILABLE: "Policy snapshot unavailable",
    _C.DATABASE_UNAVAILABLE: "Database unavailable",
    _C.SERIALIZATION_FAILURE: "Concurrent update; retry",
    _C.DATABASE_TIMEOUT: "Database timeout",
})
"""Default RFC 9457 `title` per problem code."""

DB_ERROR_PREFIX: Final = "sibyl:"
"""Every Sibyl database raise uses SQLSTATE class `SB` and a message `sibyl:<code>[: detail]`."""

DB_ERROR_SQLSTATE_CLASS: Final = "SB"

DB_ERROR_PROBLEM: Final[Mapping[str, ProblemCode]] = MappingProxyType({
    "tenant_not_set": _C.INTERNAL_ERROR,
    "tenant_mismatch": _C.INTERNAL_ERROR,
    "invalid_transition": _C.INVALID_TRANSITION,
    "stale_precondition": _C.STALE_PRECONDITION,
    "operator_hold": _C.OPERATOR_HOLD,
    "reason_required": _C.VALIDATION_FAILED,
    "routing_arguments": _C.INTERNAL_ERROR,
    "audit_action_unknown": _C.INTERNAL_ERROR,
    "audit_actor_not_allowed": _C.INTERNAL_ERROR,
    "audit_field_missing": _C.INTERNAL_ERROR,
    "audit_detail_invalid": _C.INTERNAL_ERROR,
    "audit_canonical_mismatch": _C.INTERNAL_ERROR,
    "audit_chain_genesis": _C.INTERNAL_ERROR,
    "immutable_row": _C.INTERNAL_ERROR,
    "erasure_refused": _C.CONFLICT,
    "legal_hold_active": _C.HOLD_BLOCKED,
    "tenant_erasing": _C.TENANT_ERASING,
    "erasure_blocked_by_chain": _C.ERASURE_BLOCKED_BY_CHAIN,
    "fallback_chain_invalid": _C.CHAIN_IMMUTABLE,
    "self_approval": _C.SELF_APPROVAL,
    "owner_required": _C.LAST_OWNER,
    "capture_policy_looser": _C.AGENT_POLICY_LOOSER_THAN_TENANT,
    "graph_node_missing": _C.NODE_UNKNOWN,
    "fail_mode_required": _C.FAIL_MODE_REQUIRED,
    "breakglass_limit": _C.BREAK_GLASS_SCOPE_EXCLUSIVE,
    "continuity_plan_invalid": _C.VALIDATION_FAILED,
    "tenant_create_invalid": _C.VALIDATION_FAILED,
    "partition_policy_unknown": _C.INTERNAL_ERROR,
    "ledger_invalid": _C.INTERNAL_ERROR,
    "idempotency_key_reuse": _C.IDEMPOTENCY_KEY_REUSE,
    "erasure_not_approved": _C.ERASURE_NOT_APPROVED,
    "key_field_immutable": _C.KEY_FIELD_IMMUTABLE,
    "agent_unconfirmed": _C.CONFLICT,  # 0020 PLUG: discovered agents are never routed
})
"""Problem code per database error code (chair ruling G0-1).

The keys are exactly the codes `sibyl_control.migrate.errcodes` allocates SQLSTATEs for; a
drift test holds the two together. Programming errors (tenant context, audit arguments)
surface as `internal_error` so nothing about the database leaks to the caller.
"""
# fmt: on

_DB_CODE = re.compile(r"[a-z][a-z0-9_]*")


def parse_db_error_code(message: str) -> str | None:
    """`<code>` from a `sibyl:<code>[: detail]` database message, or None."""
    if not message.startswith(DB_ERROR_PREFIX):
        return None
    code = message[len(DB_ERROR_PREFIX) :].split(":", 1)[0].strip()
    return code if _DB_CODE.fullmatch(code) else None


class GatewayErrorCode(StrEnum):
    """`error.code` in the OpenAI error envelope and `X-Sibyl-Error` (API §3.5)."""

    SIBYL_HEADER_NOT_ALLOWED = "sibyl_header_not_allowed"
    SIBYL_BAD_REQUEST = "sibyl_bad_request"
    SIBYL_KEY_INVALID = "sibyl_key_invalid"
    SIBYL_KEY_REVOKED = "sibyl_key_revoked"
    SIBYL_KEY_EXPIRED = "sibyl_key_expired"
    SIBYL_AGENT_MISMATCH = "sibyl_agent_mismatch"
    SIBYL_SCOPE_MISSING = "sibyl_scope_missing"
    SIBYL_AGENT_KILLED = "sibyl_agent_killed"
    SIBYL_AGENT_QUARANTINED = "sibyl_agent_quarantined"
    SIBYL_POLICY_BLOCKED = "sibyl_policy_blocked"
    SIBYL_MODEL_NOT_ALLOWED = "sibyl_model_not_allowed"
    SIBYL_AGENT_UNKNOWN = "sibyl_agent_unknown"
    SIBYL_RATE_LIMITED = "sibyl_rate_limited"
    SIBYL_INFLIGHT_LIMIT = "sibyl_inflight_limit"
    SIBYL_BUDGET_EXHAUSTED = "sibyl_budget_exhausted"
    UPSTREAM_RATE_LIMITED = "upstream_rate_limited"
    UPSTREAM_ERROR = "upstream_error"
    SIBYL_POLICY_EXPIRED = "sibyl_policy_expired"
    SIBYL_NO_SNAPSHOT = "sibyl_no_snapshot"
    SIBYL_AGENT_HANDED_OFF = "sibyl_agent_handed_off"
    SIBYL_AGENT_QUEUED = "sibyl_agent_queued"
    SIBYL_BREAKER_OPEN = "sibyl_breaker_open"
    UPSTREAM_TIMEOUT = "upstream_timeout"


def _gateway_table() -> dict[GatewayErrorCode, tuple[int, str]]:
    g = GatewayErrorCode
    rows: list[tuple[int, str, tuple[GatewayErrorCode, ...]]] = [
        (400, "invalid_request_error", (g.SIBYL_HEADER_NOT_ALLOWED, g.SIBYL_BAD_REQUEST)),
        (
            401,
            "authentication_error",
            (g.SIBYL_KEY_INVALID, g.SIBYL_KEY_REVOKED, g.SIBYL_KEY_EXPIRED),
        ),
        (
            403,
            "permission_error",
            (
                g.SIBYL_AGENT_MISMATCH,
                g.SIBYL_SCOPE_MISSING,
                g.SIBYL_AGENT_KILLED,
                g.SIBYL_AGENT_QUARANTINED,
                g.SIBYL_POLICY_BLOCKED,
                g.SIBYL_MODEL_NOT_ALLOWED,
            ),
        ),
        (404, "not_found_error", (g.SIBYL_AGENT_UNKNOWN,)),
        (
            429,
            "rate_limit_error",
            (
                g.SIBYL_RATE_LIMITED,
                g.SIBYL_INFLIGHT_LIMIT,
                g.SIBYL_BUDGET_EXHAUSTED,
                g.UPSTREAM_RATE_LIMITED,
            ),
        ),
        (502, "api_error", (g.UPSTREAM_ERROR,)),
        (
            503,
            "api_error",
            (
                g.SIBYL_POLICY_EXPIRED,
                g.SIBYL_NO_SNAPSHOT,
                g.SIBYL_AGENT_HANDED_OFF,
                g.SIBYL_AGENT_QUEUED,
                g.SIBYL_BREAKER_OPEN,
            ),
        ),
        (504, "api_error", (g.UPSTREAM_TIMEOUT,)),
    ]
    return {code: (status, kind) for status, kind, codes in rows for code in codes}


GATEWAY_ERROR_STATUS: Final = MappingProxyType(_gateway_table())
"""`(http_status, openai error.type)` per gateway error code."""
