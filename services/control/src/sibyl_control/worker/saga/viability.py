"""Step ``check_viability``: pick the first viable fallback step (ML §4.6 guard rail 3).

A step is viable when its target can serve right now: the model is allowed, the provider is
enabled and has had no non-operational status or open provider incident in the last 5 minutes
(and is not the provider of a batched provider incident), a vaulted credential exists and is
active when the plan or the step needs one (never in demo mode), a backup agent is itself
serving, the agent's identity (``enforcement=block``) allows the target, and the failure mode is
one a different model or provider can fix. ``retry`` is gateway-local and never a routing target.
Each candidate is recorded with its reason so the incident shows why a step was skipped.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from .model import AGENT_INTERNAL_MODES, PROVIDER_LOOKBACK, Target

VIABLE_CREDENTIAL = ("active", "rotating")
SERVING_STATES = ("active", "degraded")

_CHAIN_SQL = """
SELECT c.id FROM sibyl.fallback_chain c
  LEFT JOIN sibyl.continuity_plan p ON p.tenant_id = c.tenant_id AND p.agent_id = c.agent_id
 WHERE c.tenant_id = $1 AND c.agent_id = $2 AND c.status = 'approved'
 ORDER BY (c.id = p.fallback_chain_id) DESC NULLS LAST LIMIT 1
"""
_STEPS_SQL = (
    "SELECT * FROM sibyl.fallback_step WHERE tenant_id = $1 AND chain_id = $2 ORDER BY position"
)
_UNHEALTHY_PROVIDERS_SQL = """
SELECT DISTINCT provider_id FROM (
  SELECT provider_id FROM sibyl.provider_status
   WHERE tenant_id = $1 AND status NOT IN ('operational', 'unknown') AND observed_at > now() -
     $2::interval
  UNION ALL
  SELECT provider_id FROM sibyl.provider_incident WHERE tenant_id = $1 AND state = 'open'
) s
"""


@dataclass(frozen=True)
class Candidate:
    step_id: UUID | None
    kind: str
    viable: bool
    reason: str
    risk: str = "low"
    provider_id: UUID | None = None
    model_id: UUID | None = None
    backup_agent_id: UUID | None = None
    credential_id: UUID | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "step_id": None if self.step_id is None else str(self.step_id),
            "kind": self.kind,
            "viable": self.viable,
            "reason": self.reason,
            "risk": self.risk,
        }

    @property
    def routing_kind(self) -> str:
        """``routing_state.target_kind`` this step moves the agent to."""
        if self.kind == "human_queue":
            return "human_queue"
        if self.kind == "backup_agent":
            return "agent"
        return "model"


@dataclass
class Context:
    tenant: UUID
    agent_id: UUID
    tier: int
    plan: Mapping[str, Any] | None
    identity: Mapping[str, Any] | None
    routing_state: str
    failure_mode: str | None
    unhealthy: frozenset[UUID]
    excluded: frozenset[UUID]
    demo_mode: bool
    models: dict[UUID, Mapping[str, Any]] = field(default_factory=dict)
    providers: dict[UUID, Mapping[str, Any]] = field(default_factory=dict)
    credentials: dict[UUID, str] = field(default_factory=dict)
    agents: dict[UUID, Mapping[str, Any]] = field(default_factory=dict)


async def load_context(
    conn: Any,
    tenant: UUID,
    agent: Mapping[str, Any],
    *,
    routing_state: str,
    failure_mode: str | None,
    excluded: Sequence[UUID],
    demo_mode: bool,
) -> Context:
    plan = await conn.fetchrow(
        "SELECT * FROM sibyl.continuity_plan WHERE tenant_id = $1 AND agent_id = $2",
        tenant,
        agent["id"],
    )
    identity = await conn.fetchrow(
        "SELECT allowed_models, allowed_providers, enforcement FROM sibyl.agent_identity"
        " WHERE tenant_id = $1 AND agent_id = $2",
        tenant,
        agent["id"],
    )
    unhealthy = await conn.fetch(_UNHEALTHY_PROVIDERS_SQL, tenant, PROVIDER_LOOKBACK)
    return Context(
        tenant=tenant,
        agent_id=agent["id"],
        tier=int(agent["tier"]),
        plan=dict(plan) if plan is not None else None,
        identity=dict(identity) if identity is not None else None,
        routing_state=routing_state,
        failure_mode=failure_mode,
        unhealthy=frozenset(r["provider_id"] for r in unhealthy),
        excluded=frozenset(excluded),
        demo_mode=demo_mode,
    )


async def chain_steps(conn: Any, tenant: UUID, agent_id: UUID) -> list[dict[str, Any]]:
    chain_id = await conn.fetchval(_CHAIN_SQL, tenant, agent_id)
    if chain_id is None:
        return []
    return [dict(r) for r in await conn.fetch(_STEPS_SQL, tenant, chain_id)]


async def _prefetch(conn: Any, ctx: Context, steps: Sequence[Mapping[str, Any]]) -> None:
    model_ids = {s["model_id"] for s in steps if s.get("model_id")}
    if model_ids:
        for r in await conn.fetch(
            "SELECT id, provider_id, model_name, is_allowed FROM sibyl.model"
            " WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
            ctx.tenant,
            list(model_ids),
        ):
            ctx.models[r["id"]] = dict(r)
    provider_ids = {s["provider_id"] for s in steps if s.get("provider_id")}
    provider_ids |= {m["provider_id"] for m in ctx.models.values()}
    if provider_ids:
        for r in await conn.fetch(
            "SELECT id, is_enabled FROM sibyl.provider WHERE tenant_id = $1 AND id ="
            " ANY($2::uuid[])",
            ctx.tenant,
            list(provider_ids),
        ):
            ctx.providers[r["id"]] = dict(r)
    cred_ids = {s["credential_id"] for s in steps if s.get("credential_id")}
    if cred_ids:
        for r in await conn.fetch(
            "SELECT id, status FROM sibyl.provider_credential_meta"
            " WHERE tenant_id = $1 AND id = ANY($2::uuid[])",
            ctx.tenant,
            list(cred_ids),
        ):
            ctx.credentials[r["id"]] = r["status"]
    agent_ids = {s["backup_agent_id"] for s in steps if s.get("backup_agent_id")}
    if agent_ids:
        for r in await conn.fetch(
            "SELECT a.id, a.lifecycle, coalesce(rs.state, 'unregistered') AS state"
            " FROM sibyl.agent a LEFT JOIN sibyl.routing_state rs"
            "   ON rs.tenant_id = a.tenant_id AND rs.agent_id = a.id"
            " WHERE a.tenant_id = $1 AND a.id = ANY($2::uuid[])",
            ctx.tenant,
            list(agent_ids),
        ):
            ctx.agents[r["id"]] = dict(r)


def _provider_problem(ctx: Context, provider_id: UUID | None) -> str | None:
    if provider_id is None:
        return "provider_unknown"
    provider = ctx.providers.get(provider_id)
    if provider is None:
        return "provider_unknown"
    if not provider["is_enabled"]:
        return "provider_disabled"
    if provider_id in ctx.excluded:
        return "provider_incident_batch"
    if provider_id in ctx.unhealthy:
        return "provider_unhealthy"
    return None


def _identity_problem(ctx: Context, provider_id: UUID | None, model_name: str | None) -> str | None:
    identity = ctx.identity
    if identity is None or identity.get("enforcement") != "block":
        return None
    providers = list(identity.get("allowed_providers") or [])
    if providers and provider_id not in providers:
        return "identity_provider"
    models = list(identity.get("allowed_models") or [])
    if models and model_name is not None and model_name not in models:
        return "identity_model"
    return None


def _model_step(ctx: Context, step: Mapping[str, Any]) -> Candidate:
    kind = step["kind"]
    model = ctx.models.get(step["model_id"]) if step.get("model_id") else None
    provider_id = step.get("provider_id") or (model["provider_id"] if model else None)
    base = {
        "step_id": step.get("id"),
        "kind": kind,
        "risk": step.get("risk", "low"),
        "provider_id": provider_id,
        "model_id": step.get("model_id"),
        "credential_id": step.get("credential_id"),
    }
    if ctx.failure_mode in AGENT_INTERNAL_MODES:
        return Candidate(viable=False, reason="failure_mode_not_provider", **base)
    if step.get("model_id") and model is None:
        return Candidate(viable=False, reason="model_unknown", **base)
    if model is not None and not model["is_allowed"]:
        return Candidate(viable=False, reason="model_not_allowed", **base)
    problem = _provider_problem(ctx, provider_id)
    if problem:
        return Candidate(viable=False, reason=problem, **base)
    if kind == "alt_provider":
        vaulted = bool(ctx.plan and ctx.plan.get("credential_mode") == "vaulted_fallback")
        cred = step.get("credential_id")
        if cred is not None and ctx.credentials.get(cred) not in VIABLE_CREDENTIAL:
            return Candidate(viable=False, reason="credential_not_active", **base)
        if vaulted and cred is None:
            return Candidate(viable=False, reason="credential_missing", **base)
        if cred is not None and ctx.demo_mode:
            return Candidate(viable=False, reason="demo_mode", **base)
    problem = _identity_problem(ctx, provider_id, model["model_name"] if model else None)
    if problem:
        return Candidate(viable=False, reason=problem, **base)
    return Candidate(viable=True, reason="ok", **base)


def _agent_step(ctx: Context, step: Mapping[str, Any]) -> Candidate:
    backup = step.get("backup_agent_id")
    base = {
        "step_id": step.get("id"),
        "kind": "backup_agent",
        "risk": step.get("risk", "low"),
        "backup_agent_id": backup,
    }
    if backup is None:
        return Candidate(viable=False, reason="backup_agent_erased", **base)
    info = ctx.agents.get(backup)
    if info is None:
        return Candidate(viable=False, reason="backup_agent_unknown", **base)
    if info["lifecycle"] == "retired" or info["state"] not in SERVING_STATES:
        return Candidate(viable=False, reason="backup_agent_not_serving", **base)
    return Candidate(viable=True, reason="ok", **base)


def evaluate_step(ctx: Context, step: Mapping[str, Any]) -> Candidate:
    kind = step["kind"]
    if kind == "retry":
        return Candidate(step.get("id"), kind, False, "retry_is_gateway_local")
    if kind in ("alt_model_same_provider", "alt_provider"):
        return _model_step(ctx, step)
    if kind == "backup_agent":
        return _agent_step(ctx, step)
    if kind == "degraded_safe_mode":
        ok = ctx.routing_state == "active"
        return Candidate(step.get("id"), kind, ok, "ok" if ok else "already_degraded")
    return Candidate(step.get("id"), "human_queue", True, "ok", risk=step.get("risk", "low"))


def _ad_hoc_step(target: Target) -> dict[str, Any]:
    if target.kind == "agent":
        return {"id": None, "kind": "backup_agent", "backup_agent_id": target.agent_id}
    if target.kind == "human_queue":
        return {"id": None, "kind": "human_queue"}
    return {
        "id": None,
        "kind": "alt_provider",
        "provider_id": target.provider_id,
        "model_id": target.model_id,
        "risk": "medium",
    }


async def choose(
    conn: Any, ctx: Context, *, target: Target | None
) -> tuple[Candidate | None, list[Candidate]]:
    """The first viable step (or the operator's chosen one) plus every candidate's verdict."""
    steps = await chain_steps(conn, ctx.tenant, ctx.agent_id)
    if target is not None and target.step_id is not None:
        steps = [s for s in steps if s["id"] == target.step_id]
        if not steps:
            return None, [Candidate(target.step_id, "unknown", False, "step_not_in_approved_chain")]
    elif target is not None:
        steps = [_ad_hoc_step(target)]
    await _prefetch(conn, ctx, steps)
    candidates = [evaluate_step(ctx, s) for s in steps]
    chosen = next((c for c in candidates if c.viable), None)
    return chosen, candidates
