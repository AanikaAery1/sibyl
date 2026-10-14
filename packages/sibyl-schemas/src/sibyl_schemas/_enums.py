"""Frozen value sets (DATAMODEL §4.0 plus Step 3-5 wire enums).

Every string here is part of the frozen contract `contracts-v1.0.0`. Additions are
additive-only contract changes; renames and removals are breaking. Import these through
`sibyl_schemas.values`.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final

from sibyl_schemas._enums_health import (
    HORIZON_SECONDS as HORIZON_SECONDS,
)
from sibyl_schemas._enums_health import (
    RULE_ID_PATTERN as RULE_ID_PATTERN,
)
from sibyl_schemas._enums_health import (
    RULE_KIND as RULE_KIND,
)
from sibyl_schemas._enums_health import (
    RULE_SHORT_CODES as RULE_SHORT_CODES,
)
from sibyl_schemas._enums_health import (  # re-exported
    AlertSeverity as AlertSeverity,
)
from sibyl_schemas._enums_health import (
    AlertState as AlertState,
)
from sibyl_schemas._enums_health import (
    AuditSeverity as AuditSeverity,
)
from sibyl_schemas._enums_health import (
    Confidence as Confidence,
)
from sibyl_schemas._enums_health import (
    FactorDirection as FactorDirection,
)
from sibyl_schemas._enums_health import (
    FailureMode as FailureMode,
)
from sibyl_schemas._enums_health import (
    FeatureGrain as FeatureGrain,
)
from sibyl_schemas._enums_health import (
    HealthBand as HealthBand,
)
from sibyl_schemas._enums_health import (
    Horizon as Horizon,
)
from sibyl_schemas._enums_health import (
    JudgesKind as JudgesKind,
)
from sibyl_schemas._enums_health import (
    LabelKind as LabelKind,
)
from sibyl_schemas._enums_health import (
    LabellerKind as LabellerKind,
)
from sibyl_schemas._enums_health import (
    PriorHealthBand as PriorHealthBand,
)
from sibyl_schemas._enums_health import (
    ProbabilityBand as ProbabilityBand,
)
from sibyl_schemas._enums_health import (
    RecommendedAction as RecommendedAction,
)
from sibyl_schemas._enums_health import (
    RuleId as RuleId,
)
from sibyl_schemas._enums_health import (
    RuleKind as RuleKind,
)
from sibyl_schemas._enums_health import (
    SliFamily as SliFamily,
)
from sibyl_schemas._enums_health import (
    Verdict as Verdict,
)
from sibyl_schemas._enums_health import (
    WindowGrainS as WindowGrainS,
)
from sibyl_schemas._enums_registry import (  # re-exported
    AgentKind as AgentKind,
)
from sibyl_schemas._enums_registry import (
    ApiKeyEnv as ApiKeyEnv,
)
from sibyl_schemas._enums_registry import (
    ApiKeyStatus as ApiKeyStatus,
)
from sibyl_schemas._enums_registry import (
    Dialect as Dialect,
)
from sibyl_schemas._enums_registry import (
    ErasureState as ErasureState,
)
from sibyl_schemas._enums_registry import (
    FailMode as FailMode,
)
from sibyl_schemas._enums_registry import (
    HoldState as HoldState,
)
from sibyl_schemas._enums_registry import (
    Lifecycle as Lifecycle,
)
from sibyl_schemas._enums_registry import (
    ProviderKind as ProviderKind,
)
from sibyl_schemas._enums_registry import (
    RiskClass as RiskClass,
)
from sibyl_schemas._enums_registry import (
    TenantKeyPurpose as TenantKeyPurpose,
)
from sibyl_schemas._enums_registry import (
    TenantKeyState as TenantKeyState,
)

# --------------------------------------------------------------------------- events


class EventType(StrEnum):
    GEN_AI_REQUEST = "gen_ai.request"
    TOOL_CALL = "tool.call"
    AGENT_INVOKE = "agent.invoke"
    CHECKPOINT = "checkpoint"
    HANDOFF_REQUESTED = "handoff.requested"
    HANDOFF_COMPLETED = "handoff.completed"
    HANDOFF_RETURNED = "handoff.returned"
    FEEDBACK = "feedback"
    TASK_OUTCOME = "task.outcome"
    AGENT_DISCOVERED = "agent.discovered"
    POLICY_DECISION = "policy.decision"
    OBSERVATION_GAP = "observation.gap"
    PROVIDER_STATUS = "provider.status"
    HEALTH_TRANSITION = "health.transition"


AGENT_OPTIONAL_EVENT_TYPES: Final = frozenset(
    {EventType.PROVIDER_STATUS, EventType.OBSERVATION_GAP}
)
"""Only these event types may carry `agent_id = null` (API §12 item 6, U1)."""

PLATFORM_TENANT_ID: Final = "00000000-0000-7000-8000-000000000000"
"""Reserved tenant that stores platform-scoped `provider.status` events."""


class EventSource(StrEnum):
    SDK = "sdk"
    GATEWAY = "gateway"
    INGEST = "ingest"
    WORKER = "worker"
    API = "api"


class TelemetrySource(StrEnum):
    """`contributions[]` and `raw_span_refs[].source`."""

    SDK = "sdk"
    GATEWAY = "gateway"
    OTEL = "otel"


class EventStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    HANDED_OFF = "handed_off"
    CANCELLED = "cancelled"


class CallStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


class ErrorClass(StrEnum):
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    CLIENT_ERROR = "client_error"
    BLOCKED = "blocked"
    OTHER = "other"


class PolicyState(StrEnum):
    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"


class PolicyDecisionState(StrEnum):
    """`policy.decision.attrs.state` (Step 3 spelling: `none`, not `not_applicable`)."""

    FRESH = "fresh"
    STALE = "stale"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"
    NONE = "none"


class RouteDecision(StrEnum):
    PRIMARY = "primary"
    FAILOVER = "failover"
    INLINE_FALLBACK = "inline_fallback"
    CANARY = "canary"
    STALE_PRIMARY = "stale_primary"


class CaptureMode(StrEnum):
    """D12; restrictiveness order `metadata < redacted < full`."""

    FULL = "full"
    REDACTED = "redacted"
    METADATA = "metadata"

    @property
    def openness(self) -> int:
        return _CAPTURE_OPENNESS[self]

    @classmethod
    def most_restrictive(cls, *modes: CaptureMode) -> CaptureMode:
        if not modes:
            raise ValueError("most_restrictive() needs at least one capture mode")
        return min(modes, key=lambda m: m.openness)


_CAPTURE_OPENNESS: Final = MappingProxyType(
    {CaptureMode.METADATA: 0, CaptureMode.REDACTED: 1, CaptureMode.FULL: 2}
)


class RedactionProfile(StrEnum):
    """System redaction profiles; tenants may add custom profiles on top of the floor."""

    SECRETS_ONLY = "secrets_only"
    PII_STANDARD = "pii_standard"


class PayloadKind(StrEnum):
    SPAN_CONTENT = "span_content"
    RAW_BATCH = "raw_batch"
    PROMPT = "prompt"
    CHECKPOINT_STATE = "checkpoint_state"
    HANDOFF_PACKET = "handoff_packet"
    FEATURE_SNAPSHOT = "feature_snapshot"
    BOM_EXPORT = "bom_export"
    ANCHOR_EXPORT = "anchor_export"
    COMMENT = "comment"
    ACTION_ARGS = "action_args"
    """D48: the scrubbed arguments of a held action (sealed like every payload)."""


class PayloadState(StrEnum):
    STORED = "stored"
    SWEPT = "swept"
    SHREDDED = "shredded"


class PayloadPart(StrEnum):
    INPUT_MESSAGES = "input_messages"
    OUTPUT_MESSAGES = "output_messages"
    SYSTEM_INSTRUCTIONS = "system_instructions"
    TOOL_DEFINITIONS = "tool_definitions"
    TOOL_ARGS = "tool_args"
    TOOL_RESULT = "tool_result"
    STATE = "state"
    RAW_SPAN = "raw_span"
    COMMENT = "comment"
    ORIGINAL_INPUT = "original_input"


class PayloadEncoding(StrEnum):
    """`attrs.payload_inline.encoding` on the wire variant only."""

    UTF8 = "utf8"
    BASE64 = "base64"


PAYLOAD_INLINE_CONTENT_TYPES: Final = MappingProxyType(
    {
        "checkpoint": "application/vnd.sibyl.checkpoint+json",
        "handoff": "application/vnd.sibyl.handoff+json",
        "genai": "application/vnd.sibyl.genai-content+json",
    }
)
INLINE_STATE_MAX_BYTES: Final = 65_536
PAYLOAD_INLINE_MAX_BYTES: Final = 4 * 1024 * 1024


class GenAiOperation(StrEnum):
    CHAT = "chat"
    TEXT_COMPLETION = "text_completion"
    EMBEDDINGS = "embeddings"
    GENERATE_CONTENT = "generate_content"


class OutputType(StrEnum):
    TEXT = "text"
    JSON = "json"
    IMAGE = "image"
    SPEECH = "speech"


class UsageSource(StrEnum):
    PROVIDER = "provider"
    ESTIMATED = "estimated"


class BreakerState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class MergeState(StrEnum):
    PARTIAL = "partial"
    COMPLETE = "complete"


class ToolType(StrEnum):
    FUNCTION = "function"
    MCP = "mcp"
    A2A = "a2a"
    HTTP = "http"
    RETRIEVAL = "retrieval"
    CODE = "code"
    EXTENSION = "extension"
    DATASTORE = "datastore"


class SideEffectClass(StrEnum):
    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class InvokePhase(StrEnum):
    START = "start"
    END = "end"


class HandoffTrigger(StrEnum):
    SDK_EXPLICIT = "sdk_explicit"
    RULE = "rule"
    A2A_STATE = "a2a_state"
    OPERATOR = "operator"
    APPROVAL_TIMEOUT = "approval_timeout"


class AssembledBy(StrEnum):
    SDK = "sdk"
    CONTROL_PLANE = "control_plane"


class Fidelity(StrEnum):
    CHECKPOINT = "checkpoint"
    REQUEST_ONLY = "request_only"


class HandoffEventOutcome(StrEnum):
    """`handoff.completed|returned` attrs and `handoff_outcome` labels."""

    COMPLETED = "completed"
    RETURNED = "returned"
    ABANDONED = "abandoned"


class HandoffState(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    COMPLETED = "completed"
    RETURNED = "returned"
    EXPIRED = "expired"


class HandoffOutcome(StrEnum):
    """`handoff_task.outcome` (queue row, not the event)."""

    RESOLVED = "resolved"
    ESCALATED = "escalated"
    ABANDONED = "abandoned"
    RETURNED_TO_AGENT = "returned_to_agent"
    EXPIRED_UNCLAIMED = "expired_unclaimed"


class FeedbackTargetKind(StrEnum):
    TRACE = "trace"
    TASK = "task"
    CALL = "call"
    PACKET = "packet"


class FeedbackRater(StrEnum):
    END_USER = "end_user"
    OPERATOR = "operator"
    JUDGE = "judge"


class TaskOutcome(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"
    ABANDONED = "abandoned"
    HANDED_OFF = "handed_off"


class OutcomeDeclaredBy(StrEnum):
    SDK = "sdk"
    OPERATOR = "operator"
    JUDGE = "judge"


class DiscoveredVia(StrEnum):
    GATEWAY_HEADER = "gateway_header"
    API_KEY_DEFAULT = "api_key_default"
    SPAN_ATTR = "span_attr"
    A2A_CARD = "a2a_card"
    MCP_LIST_TOOLS = "mcp_list_tools"
    EGRESS_LOG = "egress_log"
    RUN_TREE = "run_tree"


class PolicyDecisionAction(StrEnum):
    FORWARD_STALE = "forward_stale"
    INLINE_FALLBACK = "inline_fallback"
    REJECT_CLOSED = "reject_closed"
    REJECT_KILLED = "reject_killed"
    REJECT_QUARANTINED = "reject_quarantined"
    THROTTLE = "throttle"
    BREAKER_OPEN = "breaker_open"
    UNKNOWN_AGENT_DEFAULT = "unknown_agent_default"
    LOCAL_BREAKER_PREFER_FALLBACK = "local_breaker_prefer_fallback"
    TOOL_BLOCKED = "tool_blocked"
    TOOL_ESCALATED = "tool_escalated"
    """D48 Action Gate: a proposed tool call was held for a human."""


class GapCause(StrEnum):
    CONTROL_PLANE_UNREACHABLE = "control_plane_unreachable"
    EMITTER_SILENT = "emitter_silent"
    BUFFER_DROPPED = "buffer_dropped"
    INGEST_BACKPRESSURE = "ingest_backpressure"
    CLOCK_SKEW = "clock_skew"


class GapStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    CLOSED_WITH_LOSS = "closed_with_loss"


class ProviderStatus(StrEnum):
    """Wire set; R4 ordinal in `PROVIDER_STATUS_ORDINAL`."""

    OPERATIONAL = "operational"
    DEGRADED_PERFORMANCE = "degraded_performance"
    PARTIAL_OUTAGE = "partial_outage"
    MAJOR_OUTAGE = "major_outage"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


PROVIDER_STATUS_ORDINAL: Final = MappingProxyType(
    {
        ProviderStatus.OPERATIONAL: 0,
        ProviderStatus.MAINTENANCE: 1,
        ProviderStatus.DEGRADED_PERFORMANCE: 2,
        ProviderStatus.PARTIAL_OUTAGE: 3,
        ProviderStatus.MAJOR_OUTAGE: 4,
    }
)
"""ML §2.3 `provider_status_code`; `unknown` has no ordinal (feature is null)."""


class ProviderStatusFeed(StrEnum):
    """`provider.status.attrs.feed` (event wire spelling)."""

    STATUSPAGE_JSON = "statuspage_json"
    PROBE = "probe"
    MANUAL = "manual"


class SideEffectKind(StrEnum):
    EXTERNAL_WRITE = "external_write"
    MESSAGE_SENT = "message_sent"
    PAYMENT = "payment"
    FILE_WRITTEN = "file_written"
    DB_WRITE = "db_write"
    TICKET_CREATED = "ticket_created"
    API_CALL = "api_call"
    UNKNOWN = "unknown"


class DeadlineSource(StrEnum):
    TASK_DEADLINE = "task_deadline"
    TIER_RTO = "tier_rto"
    OPERATOR = "operator"


class RejectReason(StrEnum):
    """`events_rejected.reason` / `sibyl-ingest-response/1` `rejected[].reason`."""

    SCHEMA_INVALID = "schema_invalid"
    MISSING_REQUIRED = "missing_required"
    UNKNOWN_TYPE = "unknown_type"
    LATE_CONTRIBUTION = "late_contribution"
    OUTSIDE_RETENTION = "outside_retention"
    NO_PARTITION = "no_partition"
    CAPTURE_POLICY_MISSING = "capture_policy_missing"
    TENANT_ERASING = "tenant_erasing"
    ENV_MISMATCH = "env_mismatch"
    AGENT_NOT_PERMITTED = "agent_not_permitted"


# ------------------------------------------------------------------ actors, routing


class ActorType(StrEnum):
    """`audit_events.actor_type`: who an audit row is attributed to."""

    HUMAN = "human"
    RULE = "rule"
    POLICY = "policy"
    SYSTEM = "system"
    AGENT = "agent"
    """An agent-bound API key (SDK); `actor_key_id` names the key."""
    API_KEY = "api_key"
    """A tenant-level API key acting in its own name: the break-glass `killswitch:pull` key."""


class ActorKind(StrEnum):
    """`routing_transition.actor_kind` / `failover.actor_kind`."""

    HUMAN = "human"
    RULE = "rule"
    POLICY = "policy"
    SYSTEM = "system"
    API_KEY = "api_key"
    """Break-glass kill: `actor_key_id` carries the key (never attributed to `system`)."""


class Tier(IntEnum):
    T1 = 1
    T2 = 2
    T3 = 3


TIER_RTO_S: Final = MappingProxyType({Tier.T1: 900, Tier.T2: 3600, Tier.T3: 14400})
"""D23 defaults when a continuity plan is silent: 15 min / 1 h / 4 h."""

TIER_SLO: Final = MappingProxyType({Tier.T1: 0.995, Tier.T2: 0.99, Tier.T3: 0.98})
"""D40 agent-minute SLO defaults over 30 days."""


class RoutingState(StrEnum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    AWAITING_APPROVAL = "awaiting_approval"
    FAILED_OVER = "failed_over"
    FAILING_BACK = "failing_back"
    QUARANTINED = "quarantined"
    KILLED = "killed"


class TargetKind(StrEnum):
    PRIMARY = "primary"
    MODEL = "model"
    AGENT = "agent"
    HUMAN_QUEUE = "human_queue"


class TransitionTrigger(StrEnum):
    REGISTER = "register"
    RULE = "rule"
    APPROVAL = "approval"
    APPROVAL_TIMEOUT = "approval_timeout"
    OPERATOR = "operator"
    POLICY = "policy"
    FAILBACK_PROBE = "failback_probe"
    CANARY = "canary"
    UNDO = "undo"
    SYSTEM = "system"


class SagaKind(StrEnum):
    """`failover.kind`: one saga row = one incident (R24)."""

    FAILOVER = "failover"
    PREEMPTIVE = "preemptive"
    FAILBACK = "failback"
    UNDO = "undo"
    QUARANTINE = "quarantine"
    RELEASE = "release"
    KILL = "kill"
    DEGRADE = "degrade"
    RECOVER = "recover"
    DRILL = "drill"
    """lane S: a rehearsed failover (sibyl-sim drills); never applied to live traffic"""


class SagaState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    DONE = "done"
    CANCELLED = "cancelled"
    FAILED = "failed"


class SagaStep(StrEnum):
    VALIDATE = "validate"
    CHECK_VIABILITY = "check_viability"
    WRITE_ROUTING = "write_routing"
    CREATE_HANDOFF_TASKS = "create_handoff_tasks"
    MARK_ALERT_ACTIONED = "mark_alert_actioned"
    DONE = "done"


class FallbackKind(StrEnum):
    """Ranked 0..5 by position; chains are non-decreasing in rank."""

    RETRY = "retry"
    ALT_MODEL_SAME_PROVIDER = "alt_model_same_provider"
    ALT_PROVIDER = "alt_provider"
    BACKUP_AGENT = "backup_agent"
    DEGRADED_SAFE_MODE = "degraded_safe_mode"
    HUMAN_QUEUE = "human_queue"

    @property
    def rank(self) -> int:
        return list(FallbackKind).index(self)


class StepRisk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DegradedMode(StrEnum):
    CONTINUE = "continue"
    SAFE_NO_TOOLS = "safe_no_tools"
    QUEUE_ONLY = "queue_only"


class IdentityEnforcement(StrEnum):
    OBSERVE = "observe"
    BLOCK = "block"


class IncidentAction(StrEnum):
    """R25: canonical action vocabulary and audit verb."""

    FAILOVER = "failover"
    DEGRADE = "degrade"
    RECOVER = "recover"
    HANDOFF = "handoff"
    QUARANTINE = "quarantine"
    KILL = "kill"
    APPROVE = "approve"
    DENY = "deny"
    UNDO = "undo"
    CLEAR_HOLD = "clear_hold"
    RELEASE = "release"
    FAIL_BACK = "fail_back"
    CANCEL = "cancel"


INCIDENT_CREATE_ACTIONS: Final = frozenset(
    {
        IncidentAction.FAILOVER,
        IncidentAction.DEGRADE,
        IncidentAction.RECOVER,
        IncidentAction.HANDOFF,
        IncidentAction.QUARANTINE,
        IncidentAction.KILL,
    }
)
"""`POST /api/v1/incidents` `action` values."""

INCIDENT_TRANSITION_ACTIONS: Final = frozenset(set(IncidentAction) - INCIDENT_CREATE_ACTIONS)
"""`POST /api/v1/incidents/{id}/actions` `action` values."""


class ApprovalAction(StrEnum):
    ALT_PROVIDER_FAILOVER = "alt_provider_failover"
    BACKUP_AGENT_FAILOVER = "backup_agent_failover"
    PREEMPTIVE_FAILOVER = "preemptive_failover"
    QUARANTINE = "quarantine"
    INLINE_FALLBACK_ENABLE = "inline_fallback_enable"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalRequesterKind(StrEnum):
    RULE = "rule"
    HUMAN = "human"


class ApprovalTimeoutPolicy(StrEnum):
    HOLD = "hold"
    FAIL_SAFE = "fail_safe"


class PreemptiveMode(StrEnum):
    AUTO = "auto"
    DEGRADE_THEN_AUTO = "degrade_then_auto"
    APPROVAL = "approval"


class KillSwitchState(StrEnum):
    PULLED = "pulled"
    RELEASED = "released"


class KillSwitchScope(StrEnum):
    TENANT = "tenant"
    AGENT = "agent"
    PROVIDER = "provider"


class SnapshotRejectCause(StrEnum):
    """Gateway verification order (API §3.5); the first failing check names the cause.

    `malformed` (since 1.1.0): the received bytes fail `parse_json_strict` (duplicate or
    extra members, size or depth caps) or the schema, before any signature work.
    """

    MALFORMED = "malformed"
    UNKNOWN_KID = "unknown_kid"
    BAD_SIGNATURE = "bad_signature"
    NON_MONOTONIC = "non_monotonic"
    FUTURE_ISSUED = "future_issued"
    BAD_TTL = "bad_ttl"


class KeySetRejectCause(StrEnum):
    """Signed key-set verification order (security M6); the first failing check names the
    cause. A verifier pins the first key and follows the rotation chain from there.

    `sequence_gap` (CR-G1): a `?since=<sequence>` delivery whose next set is not exactly the
    held sequence + 1 (every set in between could have changed the trusted keys); a set
    delivered on its own may skip sequences."""

    MALFORMED = "malformed"
    UNKNOWN_SIGNER = "unknown_signer"
    SIGNER_EXPIRED = "signer_expired"
    BAD_SIGNATURE = "bad_signature"
    NON_MONOTONIC = "non_monotonic"
    SEQUENCE_GAP = "sequence_gap"
    CHAIN_BROKEN = "chain_broken"


class SigningKeyStatus(StrEnum):
    """`/.well-known/sibyl-keys.json` key status."""

    ACTIVE = "active"
    RETIRING = "retiring"


class SignatureAlgorithm(StrEnum):
    ED25519 = "Ed25519"


SNAPSHOT_DEFAULT_TTL_S: Final = 60
SNAPSHOT_DEFAULT_GRACE_S: Final = 300
SNAPSHOT_TTL_BOUNDS_S: Final = (60, 600)
SNAPSHOT_GRACE_BOUNDS_S: Final = (0, 900)
SNAPSHOT_MAX_FUTURE_SKEW_S: Final = 30
SNAPSHOT_MAX_BYTES: Final = 2 * 1024 * 1024
