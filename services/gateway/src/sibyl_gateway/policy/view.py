"""``PolicyView``: the frozen in-process seam between G-hot and G-policy (R62, W0-6).

G-policy owns the snapshot (fetch, Ed25519 verify, hold, refresh, kill acks, sealed credentials)
and implements this protocol. G-hot (proxy, streaming, limits, telemetry) consumes it and never
reads the snapshot document itself. Every method is synchronous and in-memory: no control-plane
call and no I/O on the hot path (ADR-9). Decisions are immutable values; G-hot executes them.

The fail-mode matrix and the error map below are API.md §3.5 as data. CHANGE REQUEST (G0): if
``sibyl_schemas`` registry ``gateway_decisions`` (W0-4) carries the same tables, import them from
there and keep this module as the typed facade.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, NoReturn, Protocol, runtime_checkable
from uuid import UUID

FailMode = Literal["open", "closed"]
Operation = Literal[
    "chat.completions",
    "embeddings",
    "models",
    "anthropic.messages",
    "anthropic.count_tokens",
    "gemini.generate_content",
]
RouteKind = Literal["primary", "failover", "inline_fallback", "canary", "stale_primary"]
Dialect = Literal["openai_compatible", "anthropic", "gemini"]
DegradedMode = Literal["continue", "safe_no_tools", "queue_only"]
CaptureMode = Literal["full", "redacted", "metadata"]
FallbackHeader = Literal["inherit", "none", "inline"]
RoutingState = Literal[
    "active",
    "degraded",
    "awaiting_approval",
    "failed_over",
    "failing_back",
    "quarantined",
    "killed",
]
KeyRejectCode = Literal["sibyl_key_invalid", "sibyl_key_revoked", "sibyl_key_expired"]


class PolicyState(StrEnum):
    FRESH = "fresh"  # age <= ttl (60 s)
    STALE = "stale"  # ttl < age <= ttl + grace (300 s)
    EXPIRED = "expired"  # past grace
    UNAVAILABLE = "unavailable"  # no verified snapshot ever loaded


# OpenAI error envelope mapping: code -> (HTTP status, error.type). API.md §3.5.
ERROR_MAP: Mapping[str, tuple[int, str]] = MappingProxyType(
    {
        "sibyl_header_not_allowed": (400, "invalid_request_error"),
        "sibyl_bad_request": (400, "invalid_request_error"),
        "sibyl_key_invalid": (401, "authentication_error"),
        "sibyl_key_revoked": (401, "authentication_error"),
        "sibyl_key_expired": (401, "authentication_error"),
        "sibyl_agent_mismatch": (403, "permission_error"),
        "sibyl_scope_missing": (403, "permission_error"),
        "sibyl_agent_killed": (403, "permission_error"),
        "sibyl_agent_quarantined": (403, "permission_error"),
        "sibyl_policy_blocked": (403, "permission_error"),
        "sibyl_model_not_allowed": (403, "permission_error"),
        "sibyl_agent_unknown": (404, "not_found_error"),
        "sibyl_rate_limited": (429, "rate_limit_error"),
        "sibyl_inflight_limit": (429, "rate_limit_error"),
        "sibyl_budget_exhausted": (429, "rate_limit_error"),
        "upstream_rate_limited": (429, "rate_limit_error"),
        "upstream_error": (502, "api_error"),
        "sibyl_policy_expired": (503, "api_error"),
        "sibyl_no_snapshot": (503, "api_error"),
        "sibyl_agent_handed_off": (503, "api_error"),
        "sibyl_agent_queued": (503, "api_error"),
        "sibyl_breaker_open": (503, "api_error"),
        "upstream_timeout": (504, "api_error"),
    }
)
RETRY_AFTER_S: Mapping[str, int] = MappingProxyType({"sibyl_agent_handed_off": 300})


@dataclass(frozen=True)
class PolicyStatus:
    state: PolicyState
    version: int | None = None
    kid: str | None = None
    age_s: int | None = None


@dataclass(frozen=True)
class KeyPrincipal:
    """A ``sbl_`` key verified against the snapshot's ``prefix -> secret_hash`` map."""

    tenant_id: UUID
    api_key_id: UUID
    prefix: str
    env: Literal["live", "test"]
    scopes: frozenset[str]
    bound_agent_id: UUID | None = None


@dataclass(frozen=True)
class KeyRejected:
    """Unknown prefix, bad secret, revoked and expired all render the identical 401 body."""

    code: KeyRejectCode


@dataclass(frozen=True)
class DecisionRequest:
    principal: KeyPrincipal
    operation: Operation
    request_id: str
    has_provider_credential: bool
    agent_header: str | None = None  # X-Sibyl-Agent: narrows a tenant key, never widens
    task_id: str | None = None
    requested_model: str | None = None
    fallback_header: FallbackHeader = "inherit"
    capture_header: CaptureMode | None = None  # tightening only
    has_tools: bool = False
    # The wire protocol the caller speaks: only targets of the same dialect are eligible
    # (no cross-protocol translation; fallback stays inside the protocol).
    dialect: Dialect = "openai_compatible"


@dataclass(frozen=True)
class CredentialRef:
    credential_id: UUID
    key_version: int


@dataclass(frozen=True)
class UpstreamTarget:
    """One upstream attempt. ``credential='passthrough'`` forwards the caller's credential."""

    route: RouteKind
    provider_id: UUID
    provider_slug: str
    dialect: Dialect
    base_url: str
    model: str
    credential: Literal["passthrough"] | CredentialRef
    step_id: UUID | None = None
    max_attempts: int = 1


@dataclass(frozen=True)
class AgentLimits:
    rps_limit: int | None = None
    burst: int | None = None
    max_inflight: int | None = None
    budget_exhausted: bool = False


@dataclass(frozen=True)
class ActionContext:
    """Action Gate inputs for one served call (D48): the agent's signed action policies in
    precedence order. ``missing`` = a referenced policy is absent or invalid (fail closed)."""

    policies: tuple[Any, ...] = ()  # sibyl_schemas.action_gate.ActionPolicy
    missing: bool = False


@dataclass(frozen=True)
class Serve:
    """Proxy the request. ``targets[0]`` first; the rest only before the first byte (§3.5)."""

    tenant_id: UUID
    agent_id: UUID | str  # str for provisional ``unclaimed/<hash8>``
    routing_state: RoutingState
    policy: PolicyStatus
    targets: tuple[UpstreamTarget, ...]
    fail_mode: FailMode
    capture_mode: CaptureMode
    redaction_profile_hash: str
    limits: AgentLimits = AgentLimits()
    degraded_mode: DegradedMode | None = None
    strip_tools: bool = False
    policy_violation: bool = False  # identity enforcement=observe: serve and stamp
    audit_events: tuple[str, ...] = ()  # e.g. policy.stale_bypass, windowed by G-hot telemetry
    actions: ActionContext | None = None  # set only when the agent has action policies

    def __post_init__(self) -> None:
        if not self.targets:
            raise ValueError("Serve needs at least one upstream target")

    def response_headers(self) -> dict[str, str]:
        """``X-Sibyl-*`` headers sent before the first streamed chunk (API.md §3.4)."""
        headers = {
            "X-Sibyl-Agent-Id": str(self.agent_id),
            "X-Sibyl-Policy-Version": str(self.policy.version or 0),
            "X-Sibyl-Policy-State": self.policy.state.value,
            "X-Sibyl-Route": self.targets[0].route,
            "X-Sibyl-Provider": self.targets[0].provider_slug,
            "X-Sibyl-Model": self.targets[0].model,
            "X-Sibyl-Routing-State": self.routing_state,
            "X-Sibyl-Capture-Mode": self.capture_mode,
        }
        if self.degraded_mode is not None:
            headers["X-Sibyl-Degraded-Mode"] = self.degraded_mode
        return headers


@dataclass(frozen=True)
class Refuse:
    http_status: int
    error_type: str
    error_code: str
    agent_id: UUID | str | None = None
    policy: PolicyStatus | None = None
    retry_after_s: int | None = None
    audit_event: str | None = None

    @classmethod
    def of(
        cls,
        code: str,
        *,
        agent_id: UUID | str | None = None,
        policy: PolicyStatus | None = None,
        audit_event: str | None = None,
    ) -> Refuse:
        status, error_type = ERROR_MAP[code]
        return cls(status, error_type, code, agent_id, policy, RETRY_AFTER_S.get(code), audit_event)


Decision = Serve | Refuse


@dataclass(frozen=True)
class ModelList:
    """``GET /v1/models``: snapshot models ∩ ``agent_identity.allowed_models``; never upstream."""

    models: tuple[str, ...]


class SecretHandle:
    """A vaulted provider secret held in memory only (≤ 300 s); never repr'd, never spilled.

    It cannot be pickled or copied, and ``reveal()`` after ``zeroise()`` raises. Zeroisation is
    best effort: it clears this handle's buffer, but ``reveal()`` returns an immutable ``bytes``
    copy and the caller's original bytes are not touched (CPython cannot wipe them).
    """

    __slots__ = ("_value", "_zeroised")

    def __init__(self, value: bytes) -> None:
        self._value = bytearray(value)
        self._zeroised = False

    def __repr__(self) -> str:
        return "SecretHandle(***)"

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretHandle cannot be pickled or copied")

    def __copy__(self) -> NoReturn:
        raise TypeError("SecretHandle cannot be copied")

    def __deepcopy__(self, memo: object) -> NoReturn:
        raise TypeError("SecretHandle cannot be copied")

    def reveal(self) -> bytes:
        if self._zeroised:
            raise RuntimeError("secret handle was zeroised")
        return bytes(self._value)

    def zeroise(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0
        self._value = bytearray()
        self._zeroised = True


@dataclass(frozen=True)
class FailModeRule:
    refuse_code: str | None  # None = serve
    audit: str | None = None
    note: str = field(default="", compare=False)


# (snapshot state, agent fail_mode) -> outcome; ``killed`` is checked first and always refuses.
FAIL_MODE_MATRIX: Mapping[tuple[PolicyState, FailMode], FailModeRule] = MappingProxyType(
    {
        (PolicyState.FRESH, "open"): FailModeRule(None),
        (PolicyState.FRESH, "closed"): FailModeRule(None),
        (PolicyState.STALE, "open"): FailModeRule(None, note="X-Sibyl-Policy-State: stale"),
        (PolicyState.STALE, "closed"): FailModeRule(None, note="X-Sibyl-Policy-State: stale"),
        (PolicyState.EXPIRED, "open"): FailModeRule(None, "policy.stale_bypass", "windowed audit"),
        (PolicyState.EXPIRED, "closed"): FailModeRule(
            "sibyl_policy_expired", "policy.fail_closed_block"
        ),
        (PolicyState.UNAVAILABLE, "open"): FailModeRule(
            "sibyl_no_snapshot", "policy.no_snapshot_refusal"
        ),
        (PolicyState.UNAVAILABLE, "closed"): FailModeRule(
            "sibyl_no_snapshot", "policy.no_snapshot_refusal"
        ),
    }
)


def apply_fail_mode(
    state: PolicyState,
    fail_mode: FailMode,
    *,
    killed: bool,
    ever_loaded: bool,
    agent_id: UUID | str | None,
    policy: PolicyStatus,
) -> Refuse | None:
    """Kill beats fail-open; no snapshot ever loaded refuses everything. ``None`` = serve."""
    if killed and ever_loaded:
        return Refuse.of("sibyl_agent_killed", agent_id=agent_id, policy=policy)
    if not ever_loaded:
        state = PolicyState.UNAVAILABLE
    rule = FAIL_MODE_MATRIX[(state, fail_mode)]
    if rule.refuse_code is None:
        return None
    return Refuse.of(rule.refuse_code, agent_id=agent_id, policy=policy, audit_event=rule.audit)


@runtime_checkable
class PolicyView(Protocol):
    """Implemented by G-policy; consumed by G-hot. Frozen at contracts-v1.1.0."""

    def status(self) -> PolicyStatus:
        """Freshness of the held snapshot (drives ``/readyz`` and ``X-Sibyl-Policy-State``)."""
        ...

    def authenticate(self, presented_key: str) -> KeyPrincipal | KeyRejected:
        """Constant-time HMAC check against the snapshot's key map (both hashes in grace)."""
        ...

    def decide(self, request: DecisionRequest) -> Serve | Refuse:
        """The full routing decision (§3.5 steps 1-4) including fail mode and inline fallback."""
        ...

    def models(self, principal: KeyPrincipal, agent_header: str | None) -> ModelList | Refuse:
        """Model listing for ``GET /v1/models``."""
        ...

    def credential(self, ref: CredentialRef) -> SecretHandle | None:
        """Unsealed vaulted secret for one fallback attempt; ``None`` when absent or expired."""
        ...
