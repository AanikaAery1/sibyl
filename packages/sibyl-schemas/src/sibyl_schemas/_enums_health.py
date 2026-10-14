"""Failure modes, alerts, verdicts, health bands, rule ids, labels (frozen)."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final


class FailureMode(StrEnum):
    PROVIDER_OUTAGE = "provider_outage"
    LATENCY_DEGRADATION = "latency_degradation"
    QUALITY_COLLAPSE = "quality_collapse"
    PROMPT_INJECTION = "prompt_injection"
    POLICY_VIOLATION = "policy_violation"
    TOOL_FAILURE = "tool_failure"
    DATA_SOURCE_FAILURE = "data_source_failure"
    INFINITE_LOOP = "infinite_loop"
    COST_RUNAWAY = "cost_runaway"
    PERMISSION_ERROR = "permission_error"
    MODEL_DEPRECATION = "model_deprecation"
    SILENT_DRIFT = "silent_drift"


class AlertState(StrEnum):
    OPEN = "open"
    ACKED = "acked"
    RESOLVED = "resolved"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditSeverity(StrEnum):
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    CRITICAL = "critical"


class ChainBreakKind(StrEnum):
    """First break an audit-chain verification reports (``sibyl.audit_verify`` kinds, plus
    ``anchor_signature`` checked outside Postgres where the Ed25519 public keys live, plus the
    offline verifier's export-only verdicts in ``OFFLINE_CHAIN_BREAK_KINDS``)."""

    GAP = "gap"
    PREV_MISMATCH = "prev_mismatch"
    CONTENT_MISMATCH = "content_mismatch"
    HASH_MISMATCH = "hash_mismatch"
    TRUNCATED = "truncated"
    HEAD_MISMATCH = "head_mismatch"
    ANCHOR_MISMATCH = "anchor_mismatch"
    ANCHOR_SIGNATURE = "anchor_signature"
    ANCHOR_TENANT = "anchor_tenant"
    NO_ANCHOR = "no_anchor"
    UNANCHORED_TAIL = "unanchored_tail"


OFFLINE_CHAIN_BREAK_KINDS: Final = frozenset(
    {ChainBreakKind.ANCHOR_TENANT, ChainBreakKind.NO_ANCHOR, ChainBreakKind.UNANCHORED_TAIL}
)
"""Verdicts only ``sibyl audit verify`` reports on an export (an anchor of another tenant, no
usable anchor, rows past the last anchor); ``sibyl.audit_verify`` has no counterpart."""


class AnchorKind(StrEnum):
    """`audit_anchors.kind`: why a signed checkpoint of the audit chain was written."""

    HOURLY = "hourly"
    PARTITION_BOUNDARY = "partition_boundary"
    ERASURE = "erasure"
    EXPORT = "export"
    REKEY = "rekey"
    BREAK_GLASS = "break_glass"


class Verdict(StrEnum):
    """D24/D33: mandatory on human close; hysteresis may resolve with `null`."""

    TP = "tp"
    FP = "fp"
    UNSURE = "unsure"


class HealthBand(StrEnum):
    HEALTHY = "healthy"
    WATCH = "watch"
    DEGRADED = "degraded"
    FAILED = "failed"


class PriorHealthBand(StrEnum):
    """`health.transition.attrs.from_status`: a band, or `unknown` before the first score."""

    HEALTHY = "healthy"
    WATCH = "watch"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ProbabilityBand(StrEnum):
    P05 = "0.05"
    P25 = "0.25"
    P60 = "0.60"
    P90 = "0.90"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Horizon(StrEnum):
    M15 = "15m"
    H1 = "1h"
    H24 = "24h"


HORIZON_SECONDS: Final = MappingProxyType({Horizon.M15: 900, Horizon.H1: 3600, Horizon.H24: 86400})


class FeatureGrain(StrEnum):
    M1 = "1m"
    M5 = "5m"
    M15 = "15m"
    H1 = "1h"


class WindowGrainS(IntEnum):
    S60 = 60
    S300 = 300
    S900 = 900
    S3600 = 3600


class RecommendedAction(StrEnum):
    NONE = "none"
    WATCH = "watch"
    REROUTE_TO_FALLBACK = "reroute_to_fallback"
    REROUTE_TO_BACKUP_AGENT = "reroute_to_backup_agent"
    THROTTLE = "throttle"
    TRIM_CONTEXT = "trim_context"
    QUARANTINE = "quarantine"
    HANDOFF = "handoff"
    AWAIT_APPROVAL = "await_approval"


class FactorDirection(StrEnum):
    ABOVE = "above"
    BELOW = "below"
    EQUALS = "equals"
    RISING = "rising"
    FALLING = "falling"


class RuleKind(StrEnum):
    DETECTED = "detected"
    LEADING = "leading"


class SliFamily(StrEnum):
    AVAILABILITY = "availability"
    LATENCY = "latency"
    TASK_COMPLETION = "task_completion"
    OUTPUT_QUALITY = "output_quality"
    RATE_LIMIT_HEADROOM = "rate_limit_headroom"
    BUDGET_DEPENDENCY = "budget_dependency"


RULE_ID_PATTERN: Final = r"^[a-z][a-z0-9_]{2,40}$"
"""Rule ids are an additive registry; the wire pattern stays open (Step 3 §8)."""


class RuleId(StrEnum):
    ERROR_RATE = "error_rate"
    P95_LATENCY = "p95_latency"
    CONSECUTIVE_FAILURES = "consecutive_failures"
    PROVIDER_STATUS = "provider_status"
    BUDGET_BREACH = "budget_breach"
    REFUSAL_SHARE = "refusal_share"
    TRUNCATION_SHARE = "truncation_share"
    SCHEMA_FAIL_SHARE = "schema_fail_share"
    HEARTBEAT_MISSING = "heartbeat_missing"
    TOOL_LOOP = "tool_loop"
    QUALITY_PROXY = "quality_proxy"
    ERROR_TREND = "error_trend"
    LATENCY_TREND = "latency_trend"
    RATELIMIT_PROXIMITY = "ratelimit_proximity"
    BUDGET_PROXIMITY = "budget_proximity"
    FALLBACK_PRESSURE = "fallback_pressure"
    REFUSAL_TREND = "refusal_trend"
    CONTINUITY_UNVERIFIED = "continuity_unverified"
    CONTEXT_SATURATION = "context_saturation"
    CREDENTIAL_EXPIRY = "credential_expiry"
    MODEL_DEPRECATION = "model_deprecation"
    DRIFT_CUSUM = "drift_cusum"
    ANOMALY_SCORE = "anomaly_score"


RULE_SHORT_CODES: Final = MappingProxyType(
    {
        "R1": RuleId.ERROR_RATE,
        "R2": RuleId.P95_LATENCY,
        "R3": RuleId.CONSECUTIVE_FAILURES,
        "R4": RuleId.PROVIDER_STATUS,
        "R5": RuleId.BUDGET_BREACH,
        "R6": RuleId.REFUSAL_SHARE,
        "R7": RuleId.TRUNCATION_SHARE,
        "R8": RuleId.SCHEMA_FAIL_SHARE,
        "R9": RuleId.HEARTBEAT_MISSING,
        "L1": RuleId.ERROR_TREND,
        "L2": RuleId.LATENCY_TREND,
        "L3": RuleId.RATELIMIT_PROXIMITY,
        "L4": RuleId.BUDGET_PROXIMITY,
        "L5": RuleId.FALLBACK_PRESSURE,
        "L6": RuleId.REFUSAL_TREND,
        "L7": RuleId.CONTINUITY_UNVERIFIED,
    }
)

_DETECTED = RuleKind.DETECTED
_LEADING = RuleKind.LEADING
RULE_KIND: Final = MappingProxyType(
    {
        RuleId.ERROR_RATE: _DETECTED,
        RuleId.P95_LATENCY: _DETECTED,
        RuleId.CONSECUTIVE_FAILURES: _DETECTED,
        RuleId.PROVIDER_STATUS: _DETECTED,
        RuleId.BUDGET_BREACH: _DETECTED,
        RuleId.REFUSAL_SHARE: _DETECTED,
        RuleId.TRUNCATION_SHARE: _DETECTED,
        RuleId.SCHEMA_FAIL_SHARE: _DETECTED,
        RuleId.HEARTBEAT_MISSING: _DETECTED,
        RuleId.TOOL_LOOP: _DETECTED,
        RuleId.QUALITY_PROXY: _DETECTED,
        RuleId.ERROR_TREND: _LEADING,
        RuleId.LATENCY_TREND: _LEADING,
        RuleId.RATELIMIT_PROXIMITY: _LEADING,
        RuleId.BUDGET_PROXIMITY: _LEADING,
        RuleId.FALLBACK_PRESSURE: _LEADING,
        RuleId.REFUSAL_TREND: _LEADING,
        RuleId.CONTINUITY_UNVERIFIED: _LEADING,
        RuleId.CONTEXT_SATURATION: _LEADING,
        RuleId.CREDENTIAL_EXPIRY: _LEADING,
        RuleId.MODEL_DEPRECATION: _LEADING,
        RuleId.DRIFT_CUSUM: _LEADING,
        RuleId.ANOMALY_SCORE: _LEADING,
    }
)
"""ML §3.3 kind per rule. `anomaly_score` is the Phase 2 unknown-unknowns factor."""


class LabelKind(StrEnum):
    ALERT_VERDICT = "alert_verdict"
    TASK_OUTCOME = "task_outcome"
    FEEDBACK = "feedback"
    FAILOVER_OUTCOME = "failover_outcome"
    HANDOFF_OUTCOME = "handoff_outcome"
    PROVIDER_INCIDENT = "provider_incident"


class JudgesKind(StrEnum):
    HEALTH_SNAPSHOT = "health_snapshot"
    EVENT = "event"
    ALERT = "alert"
    PACKET = "packet"
    TRANSITION = "transition"
    WINDOW = "window"


class LabellerKind(StrEnum):
    OPERATOR = "operator"
    END_USER = "end_user"
    SDK = "sdk"
    JUDGE = "judge"
    WORKER = "worker"
