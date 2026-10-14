"""Scope catalogue (API §2.2; R21 `<resource>:<verb>`; D20, D30) and role mapping.

This module is the human-readable projection that `role_permission` seeds and
`core/authz` evaluate; at G0 it becomes their single source.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from sibyl_schemas._enums import ApiKeyEnv, IncidentAction, RoutingState

SCOPE_PATTERN: Final = r"^[a-z][a-z_]*:[a-z_]+$"
"""`<resource>:<verb>`; a resource may hold `_` (D48 `action_policies:write`)."""


class Scope(StrEnum):
    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    USERS_MANAGE = "users:manage"
    OIDC_MANAGE = "oidc:manage"
    APIKEYS_MANAGE = "apikeys:manage"
    APIKEYS_MANAGE_AGENT = "apikeys:manage_agent"
    AGENTS_READ = "agents:read"
    AGENTS_WRITE = "agents:write"
    AGENTS_APPROVE = "agents:approve"
    IDENTITY_WRITE = "identity:write"
    CAPTURE_WRITE = "capture:write"
    CREDENTIALS_MANAGE = "credentials:manage"
    CREDENTIALS_READ = "credentials:read"
    KEYS_READ = "keys:read"
    KEYS_ROTATE = "keys:rotate"
    ROUTING_READ = "routing:read"
    ROUTING_WRITE = "routing:write"
    INCIDENTS_ACT = "incidents:act"
    ROUTING_OVERRIDE = "routing:override"
    APPROVALS_DECIDE = "approvals:decide"
    QUARANTINE_ACT = "quarantine:act"
    KILLSWITCH_PULL = "killswitch:pull"
    KILLSWITCH_RELEASE = "killswitch:release"
    QUEUE_ACT = "queue:act"
    PACKETS_READ = "packets:read"
    PAYLOADS_READ = "payloads:read"
    PAYLOADS_REVEAL = "payloads:reveal"
    ALERTS_ACT = "alerts:act"
    AUDIT_READ = "audit:read"
    AUDIT_VERIFY = "audit:verify"
    AUDIT_EXPORT = "audit:export"
    DATA_EXPORT = "data:export"
    ERASURE_REQUEST = "erasure:request"
    ERASURE_APPROVE = "erasure:approve"
    HOLDS_MANAGE = "holds:manage"
    GATEWAY_PROXY = "gateway:proxy"
    INGEST_WRITE = "ingest:write"
    HANDOFF_WRITE = "handoff:write"
    # Action Gate (D48, ACTION-GATE.md §3)
    ACTIONS_READ = "actions:read"
    ACTIONS_DECIDE = "actions:decide"
    ACTION_POLICIES_WRITE = "action_policies:write"
    ACTIONS_HOLD = "actions:hold"
    # Model drift (D51, wave 3 lane DRIFT)
    DRIFT_READ = "drift:read"
    DRIFT_WRITE = "drift:write"
    # Sibyl Sentinel (D52): advisory monitoring agent on the tenant's own LLM key
    SENTINEL_READ = "sentinel:read"
    SENTINEL_ADMIN = "sentinel:admin"
    # External monitor agents (D53): monitor-bound keys read (metadata) and report findings;
    # tenant admins register and manage monitors.
    MONITOR_READ = "monitor:read"
    FINDINGS_WRITE = "findings:write"
    MONITORS_ADMIN = "monitors:admin"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_ADMIN = "security_admin"
    ENGINEER = "engineer"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class GrantMode(StrEnum):
    TENANT = "tenant"
    """✓ tenant-wide."""
    GROUP = "group"
    """G: object rule, resource's agent group must be one of the caller's (out-of-group = 404)."""


class MachineGrant(StrEnum):
    NONE = "none"
    ALLOWED = "allowed"
    """M: grantable to an API key."""
    BOUND_ONLY = "bound_only"
    """M (bound): grantable only to an agent-bound key."""
    ONLY = "only"
    """M only: never held by a human role."""
    EXCLUSIVE = "exclusive"
    """M (exclusive): the key holds this scope and nothing else (break-glass, D20)."""
    MONITOR_BOUND = "monitor_bound"
    """M (monitor): grantable only to a key bound to an external monitor (D53), never to a
    human role; such a key holds monitor scopes only."""


@dataclass(frozen=True, slots=True)
class Grant:
    mode: GrantMode = GrantMode.TENANT
    step_up: bool = False
    """↑: fresh IdP authentication within 5 minutes."""
    audited: bool = False
    """A: use of the scope emits its own audit row."""
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ScopeSpec:
    scope: Scope
    covers: str
    machine: MachineGrant = MachineGrant.NONE
    grants: Mapping[Role, Grant] = field(default_factory=lambda: MappingProxyType({}))


_T = Grant()
_G = Grant(mode=GrantMode.GROUP)
_UP = Grant(step_up=True)
_AUD = Grant(audited=True)


def _spec(
    scope: Scope,
    covers: str,
    grants: Mapping[Role, Grant],
    machine: MachineGrant = MachineGrant.NONE,
) -> ScopeSpec:
    return ScopeSpec(scope, covers, machine, MappingProxyType(dict(grants)))


_O, _AD, _SA, _EN, _OP, _AU, _VI = (
    Role.OWNER,
    Role.ADMIN,
    Role.SECURITY_ADMIN,
    Role.ENGINEER,
    Role.OPERATOR,
    Role.AUDITOR,
    Role.VIEWER,
)
_ALL_ROLES: Final = {role: _T for role in Role}

_SPECS: Final = (
    _spec(Scope.TENANT_READ, "tenant.settings.read", _ALL_ROLES),
    _spec(Scope.TENANT_WRITE, "tenant.settings.write", {_O: _UP}),
    _spec(Scope.USERS_MANAGE, "users.manage, membership.manage", {_O: _T, _AD: _T}),
    _spec(Scope.OIDC_MANAGE, "oidc_issuer.manage", {_O: _UP, _AD: _UP}),
    _spec(Scope.APIKEYS_MANAGE, "api_key.manage (tenant-level)", {_O: _T, _AD: _T}),
    _spec(
        Scope.APIKEYS_MANAGE_AGENT,
        "api_key.manage (agent-bound)",
        {_O: _T, _AD: _T, _EN: _G},
    ),
    _spec(
        Scope.AGENTS_READ,
        "agent.read (registry, health, risk, graph)",
        _ALL_ROLES,
        MachineGrant.ALLOWED,
    ),
    _spec(
        Scope.AGENTS_WRITE,
        "agent.register, agent.edit, versions, BOM",
        {_O: _T, _AD: _T, _EN: _G},
        MachineGrant.BOUND_ONLY,
    ),
    _spec(Scope.AGENTS_APPROVE, "agent.approve_lifecycle", {_O: _T, _AD: _T, _SA: _T}),
    _spec(
        Scope.IDENTITY_WRITE,
        "agent_identity.edit",
        {_O: _T, _AD: _T, _SA: _T, _EN: Grant(mode=GrantMode.GROUP, note="narrow only")},
    ),
    _spec(
        Scope.CAPTURE_WRITE,
        "capture_policy.set, redaction.manage",
        {_O: _T, _AD: _T, _SA: _T},
    ),
    _spec(Scope.CREDENTIALS_MANAGE, "credential.manage", {_O: _UP, _AD: _UP, _SA: _UP}),
    _spec(
        Scope.CREDENTIALS_READ,
        "credential.read_metadata",
        {_O: _T, _AD: _T, _SA: _T, _EN: _G, _AU: _T},
    ),
    _spec(Scope.KEYS_READ, "tenant_key.read_metadata", {_O: _T, _SA: _T}),
    _spec(Scope.KEYS_ROTATE, "tenant_key.rotate", {_O: _UP, _SA: _UP}),
    _spec(
        Scope.ROUTING_READ,
        "routing state, continuity plan, chains, snapshot",
        _ALL_ROLES,
        MachineGrant.ALLOWED,
    ),
    _spec(
        Scope.ROUTING_WRITE,
        "continuity_plan, fallback_chain draft/approve, alert rules",
        {_O: _T, _AD: _T, _SA: _T, _EN: _G},
    ),
    _spec(
        Scope.INCIDENTS_ACT,
        "base scope for POST …/actions (never sufficient alone)",
        {
            _O: _T,
            _SA: _T,
            _EN: _G,
            _OP: Grant(note="alert and queue actions only"),
        },
    ),
    _spec(
        Scope.ROUTING_OVERRIDE,
        "incident create failover/degrade/recover/handoff/fail_back; undo, clear_hold, cancel",
        {_O: _T, _SA: _T, _EN: _G},
    ),
    _spec(Scope.APPROVALS_DECIDE, "actions approve, deny; four-eyes", {_O: _T, _SA: _T}),
    _spec(
        Scope.QUARANTINE_ACT,
        "incident create quarantine; release from quarantined",
        {_O: _T, _SA: _T},
    ),
    _spec(
        Scope.KILLSWITCH_PULL,
        "POST /kill-switches; break-glass",
        {_O: _UP, _SA: _UP},
        MachineGrant.EXCLUSIVE,
    ),
    _spec(
        Scope.KILLSWITCH_RELEASE,
        "POST /kill-switches/{id}/release; release from killed",
        {_O: _UP, _SA: _UP},
    ),
    _spec(Scope.QUEUE_ACT, "handoff-task claim/complete/return", {_O: _T, _OP: _T}),
    _spec(
        Scope.PACKETS_READ,
        "handoff packet body",
        {_O: _T, _SA: _T, _EN: _G, _OP: _T, _AU: _AUD},
    ),
    _spec(
        Scope.PAYLOADS_READ,
        "payload.read (own agents)",
        {_O: _T, _SA: _T, _EN: _G, _AU: _AUD},
    ),
    _spec(
        Scope.PAYLOADS_REVEAL,
        "payload.reveal (any payload, reason required)",
        {_O: _AUD, _SA: _AUD, _AU: _AUD},
    ),
    _spec(
        Scope.ALERTS_ACT,
        "ack, silence, close+verdict",
        {_O: _T, _SA: _T, _EN: _G, _OP: _T},
    ),
    _spec(
        Scope.AUDIT_READ,
        "audit.read",
        {_O: _T, _AD: _T, _SA: _T, _EN: _G, _AU: _T},
    ),
    _spec(Scope.AUDIT_VERIFY, "audit.verify", {_O: _T, _AD: _T, _SA: _T, _AU: _T}),
    _spec(Scope.AUDIT_EXPORT, "audit.export", {_O: _AUD, _SA: _AUD, _AU: _AUD}),
    _spec(Scope.DATA_EXPORT, "data.export", {_O: _AUD, _SA: _AUD, _AU: _AUD}),
    _spec(Scope.ERASURE_REQUEST, "erasure.request", {_O: _T, _AD: _T, _SA: _T}),
    _spec(
        Scope.ERASURE_APPROVE,
        "erasure.approve (approver differs from requester)",
        {_O: _UP, _SA: _UP},
    ),
    _spec(Scope.HOLDS_MANAGE, "hold.place, hold.release", {_O: _UP, _SA: _UP}),
    _spec(
        Scope.GATEWAY_PROXY,
        "data-plane calls, snapshot, credential bundle, kill acks",
        {},
        MachineGrant.ONLY,
    ),
    _spec(Scope.INGEST_WRITE, "OTLP, /v1/events, checkpoints", {}, MachineGrant.ONLY),
    _spec(Scope.HANDOFF_WRITE, "SDK handoff.requested events", {}, MachineGrant.ONLY),
    # Action Gate (D48): Admin and Security admin write policies, Operator and Security admin
    # decide held actions, every role reads them (the Auditor included).
    _spec(Scope.ACTIONS_READ, "action policies, held actions, decisions (read)", _ALL_ROLES),
    _spec(
        Scope.ACTIONS_DECIDE,
        "held action approve, deny (four-eyes per policy; step-up for sensitive tools)",
        {_O: _T, _SA: _T, _OP: _T},
    ),
    _spec(
        Scope.ACTION_POLICIES_WRITE,
        "action policy create, approve (tier-1 four-eyes), retire",
        {_O: _T, _AD: _T, _SA: _T},
    ),
    _spec(
        Scope.ACTIONS_HOLD,
        "gateway/SDK: create and poll held actions, cumulative check-and-increment",
        {},
        MachineGrant.ONLY,
    ),
    # Model drift (D51): every role reads drift reports (watch-only health information, like
    # agents:read); Admin and Security admin reset or re-freeze a baseline.
    _spec(Scope.DRIFT_READ, "drift baselines and reports (read)", _ALL_ROLES),
    _spec(
        Scope.DRIFT_WRITE,
        "drift baseline reset / re-freeze (audited drift.baseline_reset)",
        {_O: _T, _AD: _T, _SA: _T},
    ),
    # Sibyl Sentinel (D52, advisory): readers see findings and rate them; tenant-wide admins
    # configure it (provider, vaulted key, budget). Engineers and viewers are left out because
    # findings span every agent group. The config write route itself demands step-up.
    _spec(
        Scope.SENTINEL_READ,
        "sentinel findings (read, feedback), sentinel config metadata",
        {_O: _T, _AD: _T, _SA: _T, _OP: _T, _AU: _T},
    ),
    _spec(
        Scope.SENTINEL_ADMIN,
        "sentinel config (provider, vaulted key, budget), connectivity test, on-demand explain",
        {_O: _T, _AD: _T, _SA: _T},
    ),
    # External monitor agents (D53, advisory like Sentinel): a monitor-bound key reads fleet
    # metadata within its watched agent groups and submits findings; tenant-wide admins
    # register monitors, issue their keys and webhooks, pause and revoke them.
    _spec(
        Scope.MONITOR_READ,
        "monitor key: fleet, health, runs, drift, alerts, incidents, held actions (metadata,"
        " watched groups only)",
        {},
        MachineGrant.MONITOR_BOUND,
    ),
    _spec(
        Scope.FINDINGS_WRITE,
        "monitor key: submit advisory findings and held-action recommendations",
        {},
        MachineGrant.MONITOR_BOUND,
    ),
    _spec(
        Scope.MONITORS_ADMIN,
        "monitor register, update, pause, revoke; monitor keys and webhooks",
        {_O: _T, _AD: _T, _SA: _T},
    ),
)

SCOPE_CATALOGUE: Final = MappingProxyType({spec.scope: spec for spec in _SPECS})

ROLE_SCOPES: Final = MappingProxyType(
    {role: frozenset(spec.scope for spec in _SPECS if role in spec.grants) for role in Role}
)

MACHINE_SCOPES: Final = frozenset(
    spec.scope for spec in _SPECS if spec.machine is not MachineGrant.NONE
)
"""The only scopes `POST /api/v1/api-keys` accepts (400 `invalid_scope` otherwise)."""

MACHINE_ONLY_SCOPES: Final = frozenset(
    spec.scope for spec in _SPECS if spec.machine in (MachineGrant.ONLY, MachineGrant.MONITOR_BOUND)
)
"""M only: held by API keys alone, never by a human role (monitor-bound scopes included)."""

STEP_UP_SCOPES: Final = frozenset(
    spec.scope for spec in _SPECS if any(grant.step_up for grant in spec.grants.values())
)
"""↑: a human principal needs fresh IdP authentication (≤ 5 min) to use these."""

BREAK_GLASS_SCOPE: Final = Scope.KILLSWITCH_PULL
"""M (exclusive): the only scope a break-glass key holds (D20)."""

DEFAULT_SDK_KEY_SCOPES: Final = (
    Scope.INGEST_WRITE,
    Scope.ROUTING_READ,
    Scope.HANDOFF_WRITE,
    Scope.ACTIONS_HOLD,
)
"""Agent-bound SDK key issued by the quickstart (R57)."""

GATEWAY_KEY_SCOPES: Final = (Scope.GATEWAY_PROXY, Scope.ROUTING_READ, Scope.ACTIONS_HOLD)
"""Tenant-level key a Sibyl-hosted gateway holds per fronted tenant (R26, D31)."""

SDK_FORBIDDEN_SCOPES: Final = frozenset({Scope.GATEWAY_PROXY, Scope.KILLSWITCH_PULL})
"""`sibyl.init()` refuses keys carrying any of these."""

MAX_BREAK_GLASS_KEYS_PER_TENANT: Final = 2

MONITOR_KEY_SCOPES: Final = frozenset(
    spec.scope for spec in _SPECS if spec.machine is MachineGrant.MONITOR_BOUND
)
"""The scopes only a monitor-bound key may hold (D53); such a key holds nothing else."""


def api_key_scope_errors(
    scopes: Iterable[Scope],
    *,
    agent_bound: bool,
    env: str,
    monitor_bound: bool = False,
) -> list[str]:
    """Static shape rules for an API key's scope set (API §2.2 contract rules 2-3).

    Returns human-readable violations; an empty list means the shape is valid. Counting
    rules (≤ 2 active break-glass keys) need the database and are not checked here.
    """
    requested = list(scopes)
    errors: list[str] = []
    if env not in {e.value for e in ApiKeyEnv}:
        errors.append(f"env must be one of live, test (got {env!r})")
    if not requested:
        errors.append("an API key needs at least one scope")
    if len(set(requested)) != len(requested):
        errors.append("duplicate scope in request")
    for scope in dict.fromkeys(requested):
        spec = SCOPE_CATALOGUE[scope]
        if spec.machine is MachineGrant.NONE:
            errors.append(f"{scope.value} is not grantable to an API key")
        if spec.machine is MachineGrant.BOUND_ONLY and not agent_bound:
            errors.append(f"{scope.value} needs an agent-bound key")
        if spec.machine is MachineGrant.MONITOR_BOUND and not monitor_bound:
            errors.append(f"{scope.value} needs a monitor-bound key (POST /monitors/{{id}}/keys)")
    if monitor_bound:
        if not set(requested) <= MONITOR_KEY_SCOPES:
            errors.append("a monitor-bound key holds monitor scopes only")
        if agent_bound:
            errors.append("a monitor-bound key is never agent-bound")
    if Scope.KILLSWITCH_PULL in requested:
        if set(requested) != {Scope.KILLSWITCH_PULL}:
            errors.append("killswitch:pull is exclusive: the key may hold no other scope")
        if agent_bound:
            errors.append("killswitch:pull keys are tenant-level, never agent-bound")
        if env != ApiKeyEnv.LIVE.value:
            errors.append("killswitch:pull keys must be env=live")
    return errors


_ACTION_SCOPE: Final = MappingProxyType(
    {
        IncidentAction.FAILOVER: Scope.ROUTING_OVERRIDE,
        IncidentAction.DEGRADE: Scope.ROUTING_OVERRIDE,
        IncidentAction.RECOVER: Scope.ROUTING_OVERRIDE,
        IncidentAction.HANDOFF: Scope.ROUTING_OVERRIDE,
        IncidentAction.QUARANTINE: Scope.QUARANTINE_ACT,
        IncidentAction.KILL: Scope.KILLSWITCH_PULL,
        IncidentAction.APPROVE: Scope.APPROVALS_DECIDE,
        IncidentAction.DENY: Scope.APPROVALS_DECIDE,
        IncidentAction.UNDO: Scope.ROUTING_OVERRIDE,
        IncidentAction.CLEAR_HOLD: Scope.ROUTING_OVERRIDE,
        IncidentAction.FAIL_BACK: Scope.ROUTING_OVERRIDE,
        IncidentAction.CANCEL: Scope.ROUTING_OVERRIDE,
    }
)


def incident_action_scope(
    action: IncidentAction,
    *,
    from_state: RoutingState | None = None,
) -> Scope:
    """Second scope required next to `incidents:act` for an incident action (API §6.3).

    `release` depends on the state it leaves: `quarantine:act` from `quarantined`,
    `killswitch:release` (with step-up) from `killed`.
    """
    if action is not IncidentAction.RELEASE:
        return _ACTION_SCOPE[action]
    if from_state is None:
        raise ValueError("release needs from_state (quarantined or killed)")
    if from_state is RoutingState.KILLED:
        return Scope.KILLSWITCH_RELEASE
    if from_state is RoutingState.QUARANTINED:
        return Scope.QUARANTINE_ACT
    raise ValueError(f"release is only legal from quarantined or killed, not {from_state}")


@dataclass(frozen=True, slots=True)
class RouteContract:
    """Authorization/audit contract of one control-plane route (x-sibyl-scope/-audit).

    The full route table is the OpenAPI document (W0-KER); only routes the chair froze
    directly into this package are listed here.
    """

    method: str
    path: str
    scope: Scope
    step_up: bool
    idempotent: bool
    audit: str | None
    rate_policy: str | None = None


TENANT_KEY_ROTATE_RATE_PER_HOUR: Final = 6

TENANT_KEY_ROUTES: Final = (
    RouteContract(
        method="GET",
        path="/api/v1/tenant-keys",
        scope=Scope.KEYS_READ,
        step_up=False,
        idempotent=True,
        audit=None,
    ),
    RouteContract(
        method="POST",
        path="/api/v1/tenant-keys/{purpose}/rotate",
        scope=Scope.KEYS_ROTATE,
        step_up=True,
        idempotent=True,
        audit="tenant_key.rotated",
        rate_policy="tenant_key_rotate",
    ),
)
"""security-auditor §3.4 tenant-key routes; `{purpose}` is a `TenantKeyPurpose` value."""


@dataclass(frozen=True, slots=True)
class RatePolicySpec:
    """`quota` requests per `window_s`; bucket capacity `burst` (default `quota`)."""

    name: str
    quota: int
    window_s: int
    burst: int | None = None


_MIN, _HOUR, _DAY = 60, 3600, 86400

_RATE_SPECS: Final = (
    RatePolicySpec("read", 600, _MIN),
    RatePolicySpec("mutation", 60, _MIN),
    RatePolicySpec("apikeys_create", 10, _HOUR),
    RatePolicySpec("tenant_key_rotate", TENANT_KEY_ROTATE_RATE_PER_HOUR, _HOUR),
    RatePolicySpec("credentials_create", 10, _HOUR),
    RatePolicySpec("erasure_create", 5, _DAY),
    RatePolicySpec("payload_reveal", 10, _MIN),
    RatePolicySpec("killswitch", 30, _MIN),
    RatePolicySpec("break_glass_key", 3, 600),
    RatePolicySpec("break_glass_tenant", 6, _HOUR),
    RatePolicySpec("audit_jobs", 10, _HOUR),
    RatePolicySpec("auth", 30, _MIN),
    RatePolicySpec("auth_tenant", 300, _MIN),
    RatePolicySpec("snapshot", 2, 1),
    RatePolicySpec("sse", 600, _MIN),
    RatePolicySpec("ingest", 500, 1, burst=5000),
    RatePolicySpec("ingest_key_batches", 20, 1),
    RatePolicySpec("gateway_401_ip", 60, _MIN),
)

RATE_POLICY_SPECS: Final = MappingProxyType({spec.name: spec for spec in _RATE_SPECS})
"""API §2.8 rate policies by name; OpenAPI `x-sibyl-rate-limit` names one of these."""

RATE_POLICIES: Final = MappingProxyType(
    {spec.name: (spec.quota, spec.window_s) for spec in _RATE_SPECS}
)
"""Named rate policies: name → (requests, window seconds)."""
