"""Public literal types and the small value objects of the SDK surface (API §8.2)."""

from __future__ import annotations

from dataclasses import KW_ONLY, dataclass
from typing import Any, Literal

CaptureMode = Literal["full", "redacted", "metadata"]
FailMode = Literal["open", "closed"]
SideEffectClass = Literal["none", "read", "write", "external", "unknown"]
ToolType = Literal["function", "mcp", "a2a", "http", "retrieval", "code", "extension", "datastore"]
Outcome = Literal["success", "partial", "failure", "abandoned", "handed_off"]
FailureMode = Literal[
    "provider_outage",
    "latency_degradation",
    "quality_collapse",
    "prompt_injection",
    "policy_violation",
    "tool_failure",
    "data_source_failure",
    "infinite_loop",
    "cost_runaway",
    "permission_error",
    "model_deprecation",
    "silent_drift",
]
RoutingState = Literal[
    "active",
    "degraded",
    "awaiting_approval",
    "failed_over",
    "failing_back",
    "quarantined",
    "killed",
]
"""B5: the SDK's `PolicySnapshot.state` uses the seven routing states."""
Freshness = Literal["fresh", "stale", "expired", "unavailable"]
SideEffectKind = Literal[
    "external_write",
    "message_sent",
    "payment",
    "file_written",
    "db_write",
    "ticket_created",
    "api_call",
    "unknown",
]

CAPTURE_MODES: tuple[CaptureMode, ...] = ("full", "redacted", "metadata")
_OPENNESS: dict[str, int] = {"metadata": 0, "redacted": 1, "full": 2}


def most_restrictive(*modes: CaptureMode) -> CaptureMode:
    """D12: `metadata < redacted < full`; the tighter mode always wins."""
    return min(modes, key=lambda mode: _OPENNESS[mode])


@dataclass(frozen=True)
class Step:
    """A completed or pending task step for checkpoints and handoff packets."""

    step: str
    _: KW_ONLY
    index: int | None = None
    description: str | None = None
    output: Any | None = None
    inputs_needed: tuple[str, ...] = ()
    blocked_on: str | None = None
    tool_name: str | None = None


@dataclass(frozen=True)
class SideEffect:
    """An externally visible effect the task already caused (needed for safe resumption)."""

    kind: SideEffectKind
    _: KW_ONLY
    target: str | None = None
    idempotency_key: str | None = None
    reversible: bool | None = None
