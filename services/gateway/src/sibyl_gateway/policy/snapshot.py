"""Immutable in-memory index of one verified ``sibyl.policy_snapshot/1`` delivery.

Built once per accepted snapshot, off the hot path; afterwards every lookup is a dict access
(ADR-9: no I/O and no parsing per request). A body that verifies but does not have the
documented shape is rejected as ``malformed`` and the held snapshot stays in place.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

from sibyl_schemas.action_gate import ActionPolicy

from .verify import MALFORMED, SnapshotRejected, VerifiedSnapshot, parse_ts


@dataclass(frozen=True)
class KeyEntry:
    prefix: str
    key_id: UUID
    secret_hash: bytes = field(repr=False)
    env: str
    scopes: frozenset[str]
    agent_id: UUID | None
    status: str
    expires_at: datetime
    rotation_grace_until: datetime | None = None


@dataclass(frozen=True)
class ProviderEntry:
    id: UUID
    slug: str
    kind: str
    dialect: str
    base_url: str
    enabled: bool


@dataclass(frozen=True)
class StepEntry:
    position: int
    kind: str
    viable: bool
    provider_id: UUID | None = None
    model: str | None = None
    agent_id: UUID | None = None
    credential_id: UUID | None = None
    max_attempts: int = 1
    risk: str = "low"


@dataclass(frozen=True)
class Identity:
    version: int = 0
    enforcement: str = "observe"
    allowed_models: frozenset[str] | None = None
    allowed_tools: frozenset[str] | None = None
    allowed_providers: frozenset[UUID] | None = None


@dataclass(frozen=True)
class Limits:
    max_inflight: int | None = None
    rps: float | None = None
    budget_usd_month: Decimal | None = None
    spent_usd_month: Decimal = Decimal(0)

    @property
    def budget_exhausted(self) -> bool:
        return self.budget_usd_month is not None and self.spent_usd_month >= self.budget_usd_month


@dataclass(frozen=True)
class Route:
    state: str
    target_kind: str
    canary_pct: int = 100
    provider_id: UUID | None = None
    model: str | None = None
    agent_id: UUID | None = None
    step_position: int | None = None
    transition_id: UUID | None = None


@dataclass(frozen=True)
class AgentEntry:
    id: UUID
    slug: str
    tier: int
    fail_mode: str
    capture_mode: str
    capture_profile: str
    degraded_mode: str
    inline_fallback: bool
    primary_provider_id: UUID
    primary_model: str
    route: Route
    chain_id: UUID | None
    steps: tuple[StepEntry, ...]
    limits: Limits
    identity: Identity
    action_policies: tuple[ActionPolicy, ...] = ()
    action_policy_missing: bool = False  # a dangling/invalid reference: tool calls fail closed

    def step(self, position: int | None) -> StepEntry | None:
        for step in self.steps:
            if step.position == position:
                return step
        return None


@dataclass(frozen=True)
class TenantBlock:
    tenant_id: UUID
    routing_version: int
    unknown_agent_fail_mode: str
    demo_mode: bool
    profiles: Mapping[str, str]
    keys: Mapping[str, KeyEntry]
    providers: Mapping[UUID, ProviderEntry]
    agents: Mapping[UUID, AgentEntry]
    agents_by_slug: Mapping[str, AgentEntry]
    tenant_killed: bool
    killed_agents: frozenset[UUID]
    killed_providers: frozenset[UUID]
    kill_switch_ids: frozenset[UUID]

    def agent(self, ref: str) -> AgentEntry | None:
        found = self.agents_by_slug.get(ref)
        if found is not None:
            return found
        try:
            return self.agents.get(UUID(ref))
        except ValueError:
            return None

    def credential_ids(self) -> frozenset[UUID]:
        return frozenset(
            step.credential_id
            for agent in self.agents.values()
            for step in agent.steps
            if step.credential_id is not None and step.viable
        )


@dataclass(frozen=True)
class PolicyDocument:
    snapshot: VerifiedSnapshot
    tenants: Mapping[UUID, TenantBlock]

    @property
    def version(self) -> int:
        return self.snapshot.version


def index_snapshot(snapshot: VerifiedSnapshot) -> PolicyDocument:
    try:
        tenants = {UUID(tid): _tenant(UUID(tid), raw) for tid, raw in snapshot.tenants.items()}
    except (KeyError, TypeError, ValueError, AttributeError, InvalidOperation) as exc:
        raise SnapshotRejected(MALFORMED, f"tenant block: {type(exc).__name__}") from None
    return PolicyDocument(snapshot, tenants)


def _uuid(value: Any) -> UUID | None:
    return None if value is None else UUID(str(value))


def _set(values: Any) -> frozenset[Any] | None:
    return None if values is None else frozenset(values)


def _policies(raw: Mapping[str, Any]) -> dict[str, ActionPolicy | None]:
    """policy_id -> parsed policy, or None for a document that is invalid or keyed wrongly."""
    out: dict[str, ActionPolicy | None] = {}
    for key, doc in (raw.get("action_policies") or {}).items():
        try:
            policy = ActionPolicy.model_validate(doc)
        except ValueError:
            out[key] = None
            continue
        out[key] = policy if policy.policy_id == key else None
    return out


def _tenant(tenant_id: UUID, raw: Mapping[str, Any]) -> TenantBlock:
    policies = _policies(raw)
    agents = {UUID(aid): _agent(UUID(aid), a, policies) for aid, a in raw["agents"].items()}
    kills = list(raw["kill_switches"])
    return TenantBlock(
        tenant_id=tenant_id,
        routing_version=int(raw["routing_version"]),
        unknown_agent_fail_mode=str(raw["unknown_agent_fail_mode"]),
        demo_mode=bool(raw["demo_mode"]),
        profiles={name: str(p["profile_hash"]) for name, p in raw["capture_profiles"].items()},
        keys={prefix: _key(prefix, k) for prefix, k in raw["api_keys"].items()},
        providers={UUID(pid): _provider(UUID(pid), p) for pid, p in raw["providers"].items()},
        agents=agents,
        agents_by_slug={agent.slug: agent for agent in agents.values()},
        tenant_killed=any(k["scope_kind"] == "tenant" for k in kills),
        killed_agents=frozenset(UUID(k["scope_id"]) for k in kills if k["scope_kind"] == "agent"),
        killed_providers=frozenset(
            UUID(k["scope_id"]) for k in kills if k["scope_kind"] == "provider"
        ),
        kill_switch_ids=frozenset(UUID(k["kill_switch_id"]) for k in kills),
    )


def _key(prefix: str, raw: Mapping[str, Any]) -> KeyEntry:
    grace = raw.get("rotation_grace_until")
    return KeyEntry(
        prefix=prefix,
        key_id=UUID(raw["key_id"]),
        secret_hash=bytes.fromhex(raw["secret_hash"]),
        env=str(raw["env"]),
        scopes=frozenset(raw["scopes"]),
        agent_id=_uuid(raw["agent_id"]),
        status=str(raw["status"]),
        expires_at=parse_ts(raw["expires_at"]),
        rotation_grace_until=parse_ts(grace) if grace else None,
    )


def _provider(provider_id: UUID, raw: Mapping[str, Any]) -> ProviderEntry:
    return ProviderEntry(
        provider_id,
        str(raw["slug"]),
        str(raw["provider_kind"]),
        str(raw["dialect"]),
        str(raw["base_url"]),
        bool(raw["is_enabled"]),
    )


def _step(raw: Mapping[str, Any]) -> StepEntry:
    return StepEntry(
        position=int(raw["position"]),
        kind=str(raw["kind"]),
        viable=bool(raw["viable"]),
        provider_id=_uuid(raw.get("provider_id")),
        model=raw.get("model"),
        agent_id=_uuid(raw.get("agent_id")),
        credential_id=_uuid(raw.get("credential_id")),
        max_attempts=int(raw.get("max_attempts", 1)),
        risk=str(raw.get("risk", "low")),
    )


def _agent(
    agent_id: UUID, raw: Mapping[str, Any], policies: Mapping[str, ActionPolicy | None]
) -> AgentEntry:
    refs = list(raw.get("action_policies") or [])
    resolved = [policies.get(ref) for ref in refs]
    route = raw["route"]
    chain = raw["fallback_chain"]
    limits = raw["limits"]
    identity = raw["identity"]
    budget = limits["budget_usd_month"]
    return AgentEntry(
        id=agent_id,
        slug=str(raw["slug"]),
        tier=int(raw["tier"]),
        fail_mode=str(raw["fail_mode"]),
        capture_mode=str(raw["capture"]["mode"]),
        capture_profile=str(raw["capture"]["profile"]),
        degraded_mode=str(raw["degraded_mode"]),
        inline_fallback=bool(raw["inline_fallback"]),
        primary_provider_id=UUID(raw["primary"]["provider_id"]),
        primary_model=str(raw["primary"]["model"]),
        route=Route(
            state=str(route["state"]),
            target_kind=str(route["target_kind"]),
            canary_pct=int(route["canary_pct"]),
            provider_id=_uuid(route.get("provider_id")),
            model=route.get("model"),
            agent_id=_uuid(route.get("agent_id")),
            step_position=route.get("step_position"),
            transition_id=_uuid(route.get("transition_id")),
        ),
        chain_id=_uuid(chain["chain_id"]) if chain else None,
        steps=tuple(sorted((_step(s) for s in chain["steps"]), key=lambda s: s.position))
        if chain
        else (),
        limits=Limits(
            max_inflight=limits["max_inflight"],
            rps=None if limits["rps"] is None else float(limits["rps"]),
            budget_usd_month=None if budget is None else Decimal(budget),
            spent_usd_month=Decimal(limits["spent_usd_month"]),
        ),
        identity=Identity(
            version=int(identity["identity_version"]),
            enforcement=str(identity["enforcement"]),
            allowed_models=_set(identity["allowed_models"]),
            allowed_tools=_set(identity["allowed_tools"]),
            allowed_providers=None
            if identity["allowed_providers"] is None
            else frozenset(UUID(p) for p in identity["allowed_providers"]),
        ),
        action_policies=tuple(p for p in resolved if p is not None),
        action_policy_missing=any(p is None for p in resolved),
    )
