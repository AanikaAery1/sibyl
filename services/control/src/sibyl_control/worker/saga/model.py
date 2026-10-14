"""Shared vocabulary of the failover saga (API.md §6.2, B1: one ``failover`` row = one incident).

The saga is driven by two callers with different database roles: the worker (``sibyl_worker``,
SKIP LOCKED claims, one transaction per step) and the api (``sibyl_app``, operator actions run
inline in the request transaction). Both use ``engine.advance``; ``Env`` says what the caller
may do (only the worker can insert ``handoff_task`` rows).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal
from uuid import UUID

from ...core.audit import AuditActor, AuditWriter, PgAuditWriter
from ...core.outbox import OutboxWriter, PgOutboxWriter

STEPS: tuple[str, ...] = (
    "validate",
    "check_viability",
    "write_routing",
    "create_handoff_tasks",
    "mark_alert_actioned",
    "done",
)
LIVE_STATES: tuple[str, ...] = ("pending", "running", "waiting_approval")
TERMINAL_STATES: tuple[str, ...] = ("done", "failed", "cancelled")
SAGA_KINDS: tuple[str, ...] = ("failover", "preemptive")  # the kinds the saga runner drives
AUTOMATED_ACTORS: frozenset[str] = frozenset({"rule", "policy"})

CLAIM_LOCK = timedelta(seconds=30)
RETRY_BASE_S = 2.0
RETRY_MAX_S = 60.0
DEFAULT_APPROVAL_TIMEOUT_S = 600
OPERATOR_HOLD = timedelta(minutes=30)  # D21
PROVIDER_LOOKBACK = timedelta(minutes=5)  # ML §4.6 guard rail 3
LONE_AGENT_EXTRA = timedelta(seconds=10)  # ML §4.6 guard rail 2: one extra scoring cycle
DEGRADE_THEN_AUTO = timedelta(seconds=20)  # D39
IN_FLIGHT_WINDOW = timedelta(minutes=15)
MAX_TASKS_PER_SAGA = 50
TIER_RTO_S: Mapping[int, int] = {1: 900, 2: 3600, 3: 14400}  # D23
TIER_RPO_S: Mapping[int, int] = {1: 60, 2: 300, 3: 900}  # R38

# Failure modes a different model or provider cannot fix: the saga skips model/provider steps
# and moves to a backup agent, safe mode or the human queue (S-11: tool loop -> handoff).
AGENT_INTERNAL_MODES: frozenset[str] = frozenset(
    {
        "infinite_loop",
        "tool_failure",
        "data_source_failure",
        "permission_error",
        "policy_violation",
        "prompt_injection",
        "cost_runaway",
    }
)
RULE_FAILURE_MODE: Mapping[str, str] = {
    "error_rate": "provider_outage",
    "p95_latency": "latency_degradation",
    "consecutive_failures": "provider_outage",
    "provider_status": "provider_outage",
    "budget_breach": "cost_runaway",
    "refusal_share": "quality_collapse",
    "truncation_share": "quality_collapse",
    "schema_fail_share": "quality_collapse",
    "heartbeat_missing": "provider_outage",
    "tool_loop": "infinite_loop",
    "quality_proxy": "quality_collapse",
}


@dataclass(frozen=True)
class Actor:
    """Who a saga acts for. ``kind`` is the routing/audit actor kind."""

    kind: str  # human | rule | policy | system | api_key
    user_id: UUID | None = None
    rule_id: UUID | None = None
    key_id: UUID | None = None
    session_id: UUID | None = None

    @property
    def automated(self) -> bool:
        return self.kind in AUTOMATED_ACTORS

    @classmethod
    def of(cls, actor: AuditActor) -> Actor:
        """The saga actor for a principal's audit actor (``core.audit.audit_actor``)."""
        return cls(
            actor.actor_type,
            user_id=actor.actor_id,
            key_id=actor.actor_key_id,
            session_id=actor.actor_session_id,
        )

    def audit_fields(self) -> dict[str, Any]:
        """The ``AuditRecord`` actor columns: a rule acts under its rule id, a human under its
        user and session, an api key under its key id (G0-6)."""
        human = self.kind == "human"
        return {
            "actor_type": self.kind,
            "actor_id": self.user_id if human else self.rule_id,
            "actor_key_id": self.key_id,
            "actor_session_id": self.session_id if human else None,
        }


SYSTEM = Actor("system")
AutomationBand = Literal["0.60", "0.90"]


@dataclass(frozen=True)
class Target:
    """An operator-chosen failover target: a chain step, or ad hoc model / agent."""

    step_id: UUID | None = None
    kind: str | None = None  # model | agent (ad hoc)
    provider_id: UUID | None = None
    model_id: UUID | None = None
    agent_id: UUID | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "step_id": _s(self.step_id),
            "kind": self.kind,
            "provider_id": _s(self.provider_id),
            "model_id": _s(self.model_id),
            "agent_id": _s(self.agent_id),
        }

    @classmethod
    def from_json(cls, doc: Mapping[str, Any] | None) -> Target | None:
        if not doc:
            return None
        return cls(
            step_id=_u(doc.get("step_id")),
            kind=doc.get("kind"),
            provider_id=_u(doc.get("provider_id")),
            model_id=_u(doc.get("model_id")),
            agent_id=_u(doc.get("agent_id")),
        )


@dataclass(frozen=True)
class SagaOpen:
    """Everything needed to open one saga (one incident)."""

    agent_id: UUID
    actor: Actor
    trigger: str  # detected | predicted | operator
    idempotency_key: str
    kind: str = "failover"
    request_idempotency_key: str | None = None
    trigger_alert_id: UUID | None = None
    alert_ids: tuple[UUID, ...] = ()
    rule_codes: tuple[str, ...] = ()
    health_snapshot_id: UUID | None = None
    target: Target | None = None
    failure_mode: str | None = None
    priority: str = "normal"
    reason: str | None = None
    batch: Mapping[str, Any] | None = None
    excluded_provider_ids: tuple[UUID, ...] = ()
    prediction: Mapping[str, Any] | None = None
    degrade_then_auto: bool = False
    delay: timedelta = timedelta(0)
    max_attempts: int = 5


@dataclass
class Env:
    """What the driving caller may do, and its writers."""

    worker_id: str
    can_build_handoff: bool
    completion_audit: bool
    audit: AuditWriter = field(default_factory=PgAuditWriter)
    outbox: OutboxWriter = field(default_factory=PgOutboxWriter)
    request_id: UUID | None = None
    demo_mode: bool = False
    # ``core.settings.Settings``: the D36/R41 predicted-failover gate for tiers 2-3
    # (``predicted_automation_band``) and the Phase 1.5 canary ramp (``failback_ramp``, A4).
    automation_band: AutomationBand = "0.90"
    failback_ramp: bool = False


class SagaError(Exception):
    """A step refused. ``code`` is a registered problem code; ``retryable`` asks for a retry."""

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        retryable: bool = False,
        extensions: Mapping[str, Any] | None = None,
    ) -> None:
        self.code = code
        self.detail = detail
        self.retryable = retryable
        self.extensions = dict(extensions or {})
        super().__init__(f"{code}: {detail or ''}")


def _s(value: Any) -> str | None:
    return None if value is None else str(value)


def _u(value: Any) -> UUID | None:
    if value is None or value == "":
        return None
    return value if isinstance(value, UUID) else UUID(str(value))
