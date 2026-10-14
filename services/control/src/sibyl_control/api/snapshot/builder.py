"""Projection of one tenant into a ``sibyl.policy_snapshot/1`` tenant block (R26, D31).

Runs inside the caller's ``tenant_tx`` (RLS scoped to the key's tenant), so it can never read
another tenant's rows. Pure SQL reads of: tenant, api_key, provider, agent (+ current version's
primary model), continuity_plan, routing_state, fallback_chain/step, agent_identity,
capture_policy/redaction_profile and kill_switch. Credentials are never part of the block;
fallback steps carry ``credential_id`` only.

Shaping rules (recorded in the lane hand-back): agents need a primary model and are not
``retired``; providers must be ``https`` (schemas 1.1), a step whose provider is filtered out
is ``viable=false``; empty identity arrays mean "unrestricted" (``null``); positions are
1-based ordinals; a tenant in ``erasing`` forces ``capture.mode = metadata`` (API §10.4.5).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sibyl_schemas.scrub import REGISTRY_VERSION

GATEWAY_SCOPE = "gateway:proxy"
SYSTEM_PROFILE = "secrets_only"
_DEAD_CREDENTIAL = frozenset({"revoked", "shredded", "expired"})


@dataclass(frozen=True)
class SnapshotScope:
    """What the caller may see: its tenant, optionally one agent, keys only for gateways."""

    tenant_id: UUID
    agent_id: UUID | None
    include_keys: bool
    require_agent: bool = False  # an explicit ?agent_id= that is not visible is a 404


def iso(ts: datetime) -> str:
    ts = ts.astimezone(UTC)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def money(value: Decimal | None) -> str | None:
    return None if value is None else str(Decimal(value).quantize(Decimal("0.0001")))


def _ids(values: Sequence[Any] | None) -> list[str] | None:
    return [str(v) for v in values] if values else None


def _texts(values: Sequence[str] | None) -> list[str] | None:
    return sorted(values) if values else None


_KEYS_SQL = """
SELECT prefix, id, secret_hash, env, scopes, agent_id, status, expires_at, rotation_grace_until
  FROM sibyl.api_key
 WHERE status IN ('active', 'rotating') AND expires_at > now()
   AND (status = 'active' OR rotation_grace_until > now())
   AND monitor_id IS NULL
"""
_AGENTS_SQL = """
SELECT a.id, a.slug, a.tier, a.fail_mode, a.risk_class, a.created_at, m.provider_id, m.model_name
  FROM sibyl.agent a
  JOIN sibyl.agent_version v ON v.tenant_id = a.tenant_id AND v.id = a.current_version_id
  JOIN sibyl.model m ON m.tenant_id = v.tenant_id AND m.id = v.primary_model_id
 WHERE a.lifecycle <> 'retired' AND ($1::uuid IS NULL OR a.id = $1)
"""
_ROUTES_SQL = """
SELECT r.agent_id, r.state, r.target_kind, r.target_provider_id, m.model_name AS target_model,
       r.target_agent_id, r.current_step_id, r.canary_pct, r.last_transition_id,
       r.operator_hold_until, r.state_since
  FROM sibyl.routing_state r
  LEFT JOIN sibyl.model m ON m.tenant_id = r.tenant_id AND m.id = r.target_model_id
"""
_STEPS_SQL = """
SELECT c.id AS chain_id, c.agent_id, c.version_no, s.id AS step_id, s.position, s.kind,
       coalesce(s.provider_id, m.provider_id) AS provider_id, m.model_name, m.is_allowed,
       s.backup_agent_id, s.credential_id, s.risk, s.max_attempts, pc.status AS credential_status
  FROM sibyl.fallback_chain c
  JOIN sibyl.fallback_step s ON s.tenant_id = c.tenant_id AND s.chain_id = c.id
  LEFT JOIN sibyl.model m ON m.tenant_id = s.tenant_id AND m.id = s.model_id
  LEFT JOIN sibyl.provider_credential_meta pc
         ON pc.tenant_id = s.tenant_id AND pc.id = s.credential_id
 WHERE c.status = 'approved'
 ORDER BY c.id, s.position
"""
_CAPTURE_SQL = """
SELECT cp.scope_kind, cp.agent_id, cp.capture_mode, rp.name, rp.content_hash
  FROM sibyl.capture_policy cp
  JOIN sibyl.redaction_profile rp ON rp.tenant_id = cp.tenant_id AND rp.id = cp.redaction_profile_id
 WHERE cp.superseded_by IS NULL
"""


async def build_tenant_block(conn: Any, scope: SnapshotScope, *, demo_mode: bool) -> dict[str, Any]:
    tenant = await conn.fetchrow(
        "SELECT routing_version, unknown_agent_fail_mode, status FROM sibyl.tenant WHERE id = $1",
        scope.tenant_id,
    )
    if tenant is None:
        raise LookupError("tenant not visible")
    providers = await _providers(conn)
    agents_raw = await conn.fetch(_AGENTS_SQL, scope.agent_id)
    agent_ids = {row["id"] for row in agents_raw}
    plans = {
        r["agent_id"]: r
        for r in await conn.fetch(
            "SELECT agent_id, degraded_mode, inline_fallback, fallback_chain_id, budget_usd_month,"
            " max_inflight, rps_limit FROM sibyl.continuity_plan"
        )
    }
    routes = {r["agent_id"]: r for r in await conn.fetch(_ROUTES_SQL)}
    identities = {
        r["agent_id"]: r
        for r in await conn.fetch(
            "SELECT agent_id, identity_version, enforcement, allowed_models, allowed_tools,"
            " allowed_providers FROM sibyl.agent_identity"
        )
    }
    chains = _chains(await conn.fetch(_STEPS_SQL), providers)
    profiles, capture = await _capture(conn, erasing=tenant["status"] == "erasing")
    agents: dict[str, Any] = {}
    for row in agents_raw:
        if str(row["provider_id"]) not in providers:
            continue  # primary provider filtered (disabled scheme): the agent cannot be routed
        agents[str(row["id"])] = _agent(
            row,
            plans.get(row["id"]),
            routes.get(row["id"]),
            identities.get(row["id"]),
            chains,
            capture,
        )
    block: dict[str, Any] = {
        "routing_version": int(tenant["routing_version"]),
        "unknown_agent_fail_mode": tenant["unknown_agent_fail_mode"],
        "demo_mode": demo_mode,
        "capture_profiles": profiles,
        "api_keys": await _keys(conn, scope) if scope.include_keys else {},
        "providers": providers,
        "agents": agents,
        "kill_switches": await _kills(conn, scope, agent_ids),
    }
    documents = await _action_policies(conn, scope, agents, identities)
    if documents:
        block["action_policies"] = documents
    return block


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


_ACTION_POLICIES_SQL = """
SELECT id, scope_kind, agent_id, agent_group_id, document
  FROM sibyl.action_policy WHERE state = 'approved'
"""
MAX_AGENT_ACTION_POLICIES = 16


def _with_allowlist(document: dict[str, Any], identity: Any) -> dict[str, Any]:
    if document.get("tool_allowlist_enforced") and document.get("tool_allowlist") is None:
        tools = identity["allowed_tools"] if identity is not None else None
        if tools:
            return {**document, "tool_allowlist": sorted(tools)}
    return document


async def _action_policies(
    conn: Any,
    scope: SnapshotScope,
    agents: dict[str, dict[str, Any]],
    identities: Mapping[UUID, Any],
) -> dict[str, Any]:
    """D48, chair ruling B22: each approved policy the agents in scope enforce is signed once in
    the tenant block (``policy_id -> sibyl-action-policy/1``); each agent lists the ids that
    apply to it, agent-specific first, then its group's, then the tenant's (never embedded per
    agent: B4). An agent policy with allowlist enforcement carries the agent identity's
    ``allowed_tools``. The approval route keeps approved documents within 1 MiB (B4)."""
    rows = await conn.fetch(_ACTION_POLICIES_SQL)
    if not rows:
        return {}
    by_agent = {r["agent_id"]: r for r in rows if r["scope_kind"] == "agent"}
    by_group = {r["agent_group_id"]: r for r in rows if r["scope_kind"] == "agent_group"}
    tenant_rows = [r for r in rows if r["scope_kind"] == "tenant"]
    groups = {
        str(r["id"]): r["agent_group_id"]
        for r in await conn.fetch(
            "SELECT id, agent_group_id FROM sibyl.agent WHERE ($1::uuid IS NULL OR id = $1)",
            scope.agent_id,
        )
    }
    documents: dict[str, Any] = {}
    for agent_key, agent in agents.items():
        agent_id = UUID(agent_key)
        chain = [by_agent.get(agent_id), by_group.get(groups.get(agent_key)), *tenant_rows]
        refs: list[str] = []
        for row in chain:
            if row is None or len(refs) >= MAX_AGENT_ACTION_POLICIES:
                continue
            pid = str(row["id"])
            document = _json(row["document"])
            if row["scope_kind"] == "agent":
                document = _with_allowlist(document, identities.get(agent_id))
            documents[pid] = document
            refs.append(pid)
        if refs:
            agent["action_policies"] = refs
    return dict(sorted(documents.items()))


async def _providers(conn: Any) -> dict[str, Any]:
    rows = await conn.fetch(
        "SELECT id, slug, provider_kind, dialect, base_url, is_enabled FROM sibyl.provider"
    )
    return {
        str(r["id"]): {
            "slug": r["slug"],
            "provider_kind": r["provider_kind"],
            "dialect": r["dialect"],
            "base_url": r["base_url"],
            "is_enabled": bool(r["is_enabled"]),
        }
        for r in rows
        if str(r["base_url"]).startswith("https://")
    }


async def _keys(conn: Any, scope: SnapshotScope) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in await conn.fetch(_KEYS_SQL):
        if scope.agent_id is not None and r["agent_id"] != scope.agent_id:
            continue
        entry: dict[str, Any] = {
            "key_id": str(r["id"]),
            "secret_hash": bytes(r["secret_hash"]).hex(),
            "env": r["env"],
            "scopes": sorted(r["scopes"]),
            "agent_id": str(r["agent_id"]) if r["agent_id"] else None,
            "status": r["status"],
            "expires_at": iso(r["expires_at"]),
        }
        if r["status"] == "rotating":
            entry["rotation_grace_until"] = iso(r["rotation_grace_until"])
        out[str(r["prefix"]).strip()] = entry
    return out


async def _kills(conn: Any, scope: SnapshotScope, agent_ids: set[UUID]) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT id, scope_kind, scope_id, pulled_at FROM sibyl.kill_switch WHERE state = 'pulled'"
        " ORDER BY pulled_at, id"
    )
    out = []
    for r in rows:
        if (
            scope.agent_id is not None
            and r["scope_kind"] == "agent"
            and r["scope_id"] != scope.agent_id
        ):
            continue
        out.append(
            {
                "kill_switch_id": str(r["id"]),
                "scope_kind": r["scope_kind"],
                "scope_id": str(r["scope_id"]) if r["scope_id"] else None,
                "pulled_at": iso(r["pulled_at"]),
            }
        )
    return out


@dataclass(frozen=True)
class _Chain:
    chain_id: UUID
    agent_id: UUID
    version: int
    steps: tuple[dict[str, Any], ...]
    ordinal: Mapping[UUID, int]


def _chains(rows: Sequence[Any], providers: Mapping[str, Any]) -> dict[UUID, _Chain]:
    grouped: dict[UUID, list[Any]] = {}
    for r in rows:
        grouped.setdefault(r["chain_id"], []).append(r)
    out: dict[UUID, _Chain] = {}
    for chain_id, steps in grouped.items():
        built, ordinal = [], {}
        for index, r in enumerate(steps, start=1):
            ordinal[r["step_id"]] = index
            step: dict[str, Any] = {"position": index, "kind": r["kind"]}
            provider = providers.get(str(r["provider_id"])) if r["provider_id"] else None
            if r["provider_id"]:
                step["provider_id"] = str(r["provider_id"])
            if r["model_name"]:
                step["model"] = r["model_name"]
            if r["backup_agent_id"]:
                step["agent_id"] = str(r["backup_agent_id"])
            if r["credential_id"]:
                step["credential_id"] = str(r["credential_id"])
            step["max_attempts"] = int(r["max_attempts"])
            step["risk"] = r["risk"]
            step["viable"] = not (
                (r["provider_id"] and (provider is None or not provider["is_enabled"]))
                or r["is_allowed"] is False
                or (r["credential_id"] and r["credential_status"] in _DEAD_CREDENTIAL)
            )
            built.append(step)
        out[chain_id] = _Chain(
            chain_id, steps[0]["agent_id"], int(steps[0]["version_no"]), tuple(built), ordinal
        )
    return out


async def _capture(conn: Any, *, erasing: bool) -> tuple[dict[str, Any], dict[UUID | None, Any]]:
    """(capture_profiles, agent_id-or-None -> (mode, profile name))."""
    profiles: dict[str, Any] = {}
    policies: dict[UUID | None, Any] = {}
    for r in await conn.fetch(_CAPTURE_SQL):
        name = r["name"]
        profiles[name] = {
            "profile_hash": bytes(r["content_hash"]).hex(),
            "detectors_ref": REGISTRY_VERSION,
        }
        key = r["agent_id"] if r["scope_kind"] == "agent" else None
        policies[key] = ("metadata" if erasing else r["capture_mode"], name)
    if None not in policies:
        policies[None] = ("metadata", SYSTEM_PROFILE)
    if policies[None][1] not in profiles:
        row = await conn.fetchrow(
            "SELECT content_hash FROM sibyl.redaction_profile WHERE name = $1"
            " ORDER BY version_no DESC LIMIT 1",
            SYSTEM_PROFILE,
        )
        digest = bytes(row["content_hash"]).hex() if row else "0" * 64
        profiles[SYSTEM_PROFILE] = {"profile_hash": digest, "detectors_ref": REGISTRY_VERSION}
    return profiles, policies


def _agent(
    row: Any,
    plan: Any,
    route: Any,
    identity: Any,
    chains: Mapping[UUID, _Chain],
    capture: Mapping[UUID | None, Any],
) -> dict[str, Any]:
    agent_id = row["id"]
    chain = None
    if plan is not None and plan["fallback_chain_id"] in chains:
        chain = chains[plan["fallback_chain_id"]]
    else:
        chain = next((c for c in chains.values() if c.agent_id == agent_id), None)
    mode, profile = capture.get(agent_id, capture[None])
    return {
        "slug": row["slug"],
        "tier": int(row["tier"]),
        "fail_mode": row["fail_mode"],
        "risk_class": row["risk_class"],
        "capture": {"mode": mode, "profile": profile},
        "degraded_mode": plan["degraded_mode"] if plan else "safe_no_tools",
        "inline_fallback": bool(plan["inline_fallback"]) if plan else int(row["tier"]) != 1,
        "primary": {"provider_id": str(row["provider_id"]), "model": row["model_name"]},
        "route": _route(row, route, chain),
        "fallback_chain": None
        if chain is None
        else {
            "chain_id": str(chain.chain_id),
            "version": chain.version,
            "steps": list(chain.steps),
        },
        "limits": {
            "max_inflight": plan["max_inflight"] if plan else None,
            "rps": float(plan["rps_limit"]) if plan and plan["rps_limit"] else None,
            "budget_usd_month": money(plan["budget_usd_month"]) if plan else None,
            "spent_usd_month": "0",
        },
        "identity": _identity(identity),
    }


def _route(row: Any, route: Any, chain: _Chain | None) -> dict[str, Any]:
    if route is None:
        return {
            "state": "active",
            "target_kind": "primary",
            "canary_pct": 100,
            "since": iso(row["created_at"]),
        }
    out: dict[str, Any] = {
        "state": route["state"],
        "target_kind": route["target_kind"],
        "canary_pct": int(route["canary_pct"]),
        "since": iso(route["state_since"]),
    }
    step = route["current_step_id"]
    if step is not None and chain is not None and step in chain.ordinal:
        out["step_position"] = chain.ordinal[step]
    else:
        if route["target_provider_id"]:
            out["provider_id"] = str(route["target_provider_id"])
        if route["target_model"]:
            out["model"] = route["target_model"]
        if route["target_agent_id"]:
            out["agent_id"] = str(route["target_agent_id"])
    if route["last_transition_id"]:
        out["transition_id"] = str(route["last_transition_id"])
    if route["operator_hold_until"]:
        out["operator_hold_until"] = iso(route["operator_hold_until"])
    return out


def _identity(row: Any) -> dict[str, Any]:
    if row is None:
        return {
            "identity_version": 0,
            "enforcement": "observe",
            "allowed_models": None,
            "allowed_tools": None,
            "allowed_providers": None,
        }
    return {
        "identity_version": int(row["identity_version"]),
        "enforcement": row["enforcement"],
        "allowed_models": _texts(row["allowed_models"]),
        "allowed_tools": _texts(row["allowed_tools"]),
        "allowed_providers": _ids(row["allowed_providers"]),
    }
