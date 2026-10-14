"""The routing decision (API.md §3.5 steps 1-4) as a pure function of one tenant block.

Order: agent resolution (bound keys narrow, never widen) -> kill (route ``killed``, tenant,
agent or provider kill switch; beats every fail mode) -> fail-mode matrix -> quarantine /
hand-off -> identity -> degraded mode -> target list (route, canary split, inline fallback).
Credentials (D11): the caller's provider credential is only ever sent to the agent's primary
provider; any other provider needs a vaulted ``credential_id``, otherwise the step is skipped.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from dataclasses import dataclass, replace
from uuid import UUID

from ..policy.snapshot import AgentEntry, ProviderEntry, StepEntry, TenantBlock
from ..policy.view import (
    ActionContext,
    AgentLimits,
    CredentialRef,
    DecisionRequest,
    KeyPrincipal,
    PolicyState,
    PolicyStatus,
    Refuse,
    RouteKind,
    Serve,
    UpstreamTarget,
    apply_fail_mode,
)

CAPTURE_RANK = {"metadata": 0, "redacted": 1, "full": 2}
PROXY_SCOPE = "gateway:proxy"
_STOP_KINDS = frozenset({"backup_agent", "degraded_safe_mode", "human_queue"})
KeyVersionOf = Callable[[UUID], int | None]


@dataclass(frozen=True)
class Provisional:
    """An agent the snapshot does not know yet (tenant key, R13): ``unclaimed/<hash8>``."""

    slug: str
    candidate: str
    candidate_hash: str
    discovered_via: str


def candidate_hash(tenant_id: UUID, candidate: str) -> str:
    return hashlib.sha256(f"{tenant_id}:{candidate}".encode()).hexdigest()[:16]


def provisional_agent_id(tenant_id: UUID, slug: str) -> UUID:
    """Deterministic id ingest registers the discovered agent under (stable across replicas)."""
    raw = bytearray(hashlib.sha256(f"sibyl-agent:{tenant_id}:{slug}".encode()).digest()[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80  # version 8 (custom)
    raw[8] = (raw[8] & 0x3F) | 0x80  # RFC 9562 variant
    return UUID(bytes=bytes(raw))


def resolve_agent(
    block: TenantBlock, principal: KeyPrincipal, agent_header: str | None
) -> AgentEntry | Provisional | Refuse:
    if principal.bound_agent_id is not None:
        bound = block.agents.get(principal.bound_agent_id)
        if agent_header:
            named = block.agent(agent_header)
            if named is None or named.id != principal.bound_agent_id:
                return Refuse.of("sibyl_agent_mismatch", audit_event="access.denied")
        if bound is None:
            return Refuse.of("sibyl_agent_unknown")
        return bound
    if agent_header:
        found = block.agent(agent_header)
        if found is not None:
            return found
        candidate, via = agent_header, "gateway_header"
    else:
        candidate, via = f"key:{principal.prefix}", "api_key_default"
    digest = candidate_hash(block.tenant_id, candidate)
    slug = f"unclaimed/{digest[:8]}"
    known = block.agents_by_slug.get(slug)
    if known is not None:
        return known
    return Provisional(slug, candidate[:256], digest, via)


def _killed(block: TenantBlock, agent: AgentEntry) -> bool:
    return agent.route.state == "killed" or block.tenant_killed or agent.id in block.killed_agents


def _usable(block: TenantBlock, provider_id: UUID | None) -> ProviderEntry | None:
    provider = block.providers.get(provider_id) if provider_id is not None else None
    if provider is None or not provider.enabled or provider_id in block.killed_providers:
        return None
    return provider


@dataclass
class _Builder:
    block: TenantBlock
    agent: AgentEntry
    request: DecisionRequest
    key_version: KeyVersionOf
    allowed_providers: frozenset[UUID] | None
    other_protocol: bool = False  # a usable target was dropped for speaking another protocol

    def target(
        self,
        route: RouteKind,
        provider_id: UUID | None,
        model: str | None,
        *,
        step: StepEntry | None = None,
        attempts: int = 1,
    ) -> UpstreamTarget | None:
        provider = _usable(self.block, provider_id)
        if provider is None or not model:
            return None
        if self.allowed_providers is not None and provider.id not in self.allowed_providers:
            return None
        credential: object
        if step is not None and step.credential_id is not None:
            credential = CredentialRef(
                step.credential_id, self.key_version(step.credential_id) or 0
            )
        elif provider.id == self.agent.primary_provider_id and self.request.has_provider_credential:
            credential = "passthrough"
        else:
            return None  # never send the caller's credential to another provider
        if provider.dialect != self.request.dialect:
            self.other_protocol = True  # no cross-protocol translation (D50)
            return None
        return UpstreamTarget(
            route=route,
            provider_id=provider.id,
            provider_slug=provider.slug,
            dialect=provider.dialect,
            base_url=provider.base_url,
            model=model,
            credential=credential,  # type: ignore[arg-type]
            step_id=None,
            max_attempts=max(1, attempts),
        )


def _canary_primary(request: DecisionRequest, pct: int) -> bool:
    seed = f"{request.task_id or ''}|{request.request_id}".encode()
    return int.from_bytes(hashlib.sha256(seed).digest()[:4], "big") % 100 < pct


def _base_target(b: _Builder, expired: bool) -> UpstreamTarget | None:
    agent, request = b.agent, b.request
    primary_model = request.requested_model or agent.primary_model
    route = agent.route
    if route.state in ("failed_over", "failing_back"):
        if route.state == "failing_back" and _canary_primary(request, route.canary_pct):
            return b.target("canary", agent.primary_provider_id, primary_model)
        step = agent.step(route.step_position)
        if route.target_kind == "agent":
            backup_id = route.agent_id or (step.agent_id if step else None)
            backup = b.block.agents.get(backup_id) if backup_id is not None else None
            if backup is None:
                return None
            return b.target("failover", backup.primary_provider_id, backup.primary_model)
        if step is not None:
            provider_id = step.provider_id or agent.primary_provider_id
            return b.target("failover", provider_id, step.model or primary_model, step=step)
        return b.target(
            "failover", route.provider_id or agent.primary_provider_id, route.model or primary_model
        )
    kind: RouteKind = "stale_primary" if expired else "primary"
    return b.target(kind, agent.primary_provider_id, primary_model)


def _inline(b: _Builder, base: UpstreamTarget | None) -> tuple[UpstreamTarget, ...]:
    agent, request = b.agent, b.request
    targets = [base] if base is not None else []
    if not agent.inline_fallback or request.fallback_header == "none":
        return tuple(targets)
    for step in agent.steps:
        if step.kind in _STOP_KINDS:
            break
        if not step.viable:
            continue
        if step.kind == "retry":
            if targets:
                targets[0] = replace(
                    targets[0], max_attempts=targets[0].max_attempts + step.max_attempts
                )
            continue
        if request.operation == "embeddings":
            continue  # embedding spaces differ: inline retry only (§3.1)
        provider_id = step.provider_id or agent.primary_provider_id
        nxt = b.target("inline_fallback", provider_id, step.model, step=step)
        if nxt is not None and (nxt.provider_id, nxt.model) not in {
            (t.provider_id, t.model) for t in targets
        }:
            targets.append(nxt)
    return tuple(targets)


def effective_capture(mode: str, header: str | None) -> str:
    if header is not None and CAPTURE_RANK.get(header, 9) < CAPTURE_RANK[mode]:
        return header
    return mode


def _limits(agent: AgentEntry) -> AgentLimits:
    rps = agent.limits.rps
    rate = math.ceil(rps) if rps else None
    return AgentLimits(
        rps_limit=rate,
        burst=rate * 2 if rate else None,
        max_inflight=agent.limits.max_inflight,
        budget_exhausted=agent.limits.budget_exhausted,
    )


def decide(
    block: TenantBlock,
    status: PolicyStatus,
    request: DecisionRequest,
    *,
    key_version: KeyVersionOf,
) -> Serve | Refuse:
    principal = request.principal
    if PROXY_SCOPE not in principal.scopes:
        return Refuse.of("sibyl_scope_missing", policy=status, audit_event="access.denied")
    resolved = resolve_agent(block, principal, request.agent_header)
    if isinstance(resolved, Refuse):
        return replace(resolved, policy=status)
    if isinstance(resolved, Provisional):
        return _decide_provisional(block, status, request, resolved)
    return _decide_known(block, status, request, resolved, key_version)


def _decide_known(
    block: TenantBlock,
    status: PolicyStatus,
    request: DecisionRequest,
    agent: AgentEntry,
    key_version: KeyVersionOf,
) -> Serve | Refuse:
    refusal = apply_fail_mode(
        status.state,
        agent.fail_mode,  # type: ignore[arg-type]
        killed=_killed(block, agent),
        ever_loaded=True,
        agent_id=agent.id,
        policy=status,
    )
    if refusal is not None:
        return refusal
    state = agent.route.state
    if state == "quarantined":
        return Refuse.of("sibyl_agent_quarantined", agent_id=agent.id, policy=status)
    if state == "failed_over" and agent.route.target_kind == "human_queue":
        return Refuse.of("sibyl_agent_handed_off", agent_id=agent.id, policy=status)
    audit: list[str] = []
    if status.state is PolicyState.EXPIRED:
        audit.append("policy.stale_bypass")
    identity = agent.identity
    violation = False
    model = request.requested_model
    if identity.allowed_models is not None and model and model not in identity.allowed_models:
        if identity.enforcement == "block":
            return Refuse.of(
                "sibyl_model_not_allowed",
                agent_id=agent.id,
                policy=status,
                audit_event="policy.blocked",
            )
        violation = True
    if identity.allowed_tools is not None and not identity.allowed_tools and request.has_tools:
        if identity.enforcement == "block":
            return Refuse.of(
                "sibyl_policy_blocked",
                agent_id=agent.id,
                policy=status,
                audit_event="policy.blocked",
            )
        violation = True
    if violation:
        audit.append("policy.violated")
    degraded = agent.degraded_mode if state == "degraded" else None
    if degraded == "queue_only":
        return Refuse.of("sibyl_agent_queued", agent_id=agent.id, policy=status)
    allowed = identity.allowed_providers if identity.enforcement == "block" else None
    builder = _Builder(block, agent, request, key_version, allowed)
    targets = _inline(builder, _base_target(builder, status.state is PolicyState.EXPIRED))
    if not targets:
        if not request.has_provider_credential:
            return Refuse.of("sibyl_bad_request", agent_id=agent.id, policy=status)
        if block.killed_providers:
            return Refuse.of("sibyl_agent_killed", agent_id=agent.id, policy=status)
        if builder.other_protocol:
            return Refuse.of("sibyl_bad_request", agent_id=agent.id, policy=status)
        return Refuse.of("upstream_error", agent_id=agent.id, policy=status)
    return Serve(
        tenant_id=block.tenant_id,
        agent_id=agent.id,
        routing_state=state,  # type: ignore[arg-type]
        policy=status,
        targets=targets,
        fail_mode=agent.fail_mode,  # type: ignore[arg-type]
        capture_mode=effective_capture(agent.capture_mode, request.capture_header),  # type: ignore[arg-type]
        redaction_profile_hash=block.profiles.get(agent.capture_profile, ""),
        limits=_limits(agent),
        degraded_mode=degraded,  # type: ignore[arg-type]
        strip_tools=degraded == "safe_no_tools",
        policy_violation=violation,
        audit_events=tuple(audit),
        actions=ActionContext(agent.action_policies, agent.action_policy_missing)
        if agent.action_policies or agent.action_policy_missing
        else None,
    )


def _decide_provisional(
    block: TenantBlock, status: PolicyStatus, request: DecisionRequest, agent: Provisional
) -> Serve | Refuse:
    fail_mode = block.unknown_agent_fail_mode
    refusal = apply_fail_mode(
        status.state,
        fail_mode,  # type: ignore[arg-type]
        killed=block.tenant_killed,
        ever_loaded=True,
        agent_id=agent.slug,
        policy=status,
    )
    if refusal is not None:
        return refusal
    providers = sorted(
        (
            p
            for p in block.providers.values()
            if _usable(block, p.id) is not None and p.dialect == request.dialect
        ),
        key=lambda p: p.slug,
    )
    if not providers or not request.requested_model or not request.has_provider_credential:
        return Refuse.of("sibyl_agent_unknown", agent_id=agent.slug, policy=status)
    provider = providers[0]
    target = UpstreamTarget(
        route="stale_primary" if status.state is PolicyState.EXPIRED else "primary",
        provider_id=provider.id,
        provider_slug=provider.slug,
        dialect=provider.dialect,  # type: ignore[arg-type]
        base_url=provider.base_url,
        model=request.requested_model,
        credential="passthrough",
    )
    audit = ["agent.discovered"]
    if status.state is PolicyState.EXPIRED:
        audit.append("policy.stale_bypass")
    return Serve(
        tenant_id=block.tenant_id,
        agent_id=agent.slug,
        routing_state="active",
        policy=status,
        targets=(target,),
        fail_mode=fail_mode,  # type: ignore[arg-type]
        capture_mode=effective_capture("metadata", request.capture_header),  # type: ignore[arg-type]
        redaction_profile_hash=block.profiles.get(
            "default", next(iter(block.profiles.values()), "")
        ),
        audit_events=tuple(audit),
    )
