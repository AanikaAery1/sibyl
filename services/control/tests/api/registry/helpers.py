"""Setup helpers for the registry tests (direct SQL as the superuser, like a fixture loader)."""

from __future__ import annotations

import secrets
from typing import Any
from uuid import UUID, uuid4

from sibyl_lane_r_harness import Tenant, World


def unique(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def provider(world: World, tenant: Tenant, *, kind: str = "openai") -> UUID:
    pid = uuid4()
    world.admin.execute(
        "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, base_url,"
        " is_known_provider) VALUES ($1, $2, $3, $3, $4, 'openai_compatible',"
        " 'https://api.openai.com/v1', true)",
        tenant.id,
        pid,
        unique("prov"),
        kind,
    )
    return pid


def model(world: World, tenant: Tenant, provider_id: UUID | None = None) -> UUID:
    mid = uuid4()
    world.admin.in_tenant(
        tenant.id,
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, $4)",
        tenant.id,
        mid,
        provider_id or provider(world, tenant),
        unique("model"),
    )
    return mid


def bound_key_row(world: World, tenant: Tenant, agent_id: UUID) -> UUID:
    key_id = uuid4()
    world.admin.execute(
        "INSERT INTO sibyl.api_key (tenant_id, id, agent_id, name, env, prefix, secret_hash,"
        " scopes, expires_at) VALUES ($1, $2, $3, 'bound', 'test', $4, $5,"
        " ARRAY['ingest:write','routing:read'], now() + interval '30 days')",
        tenant.id,
        key_id,
        agent_id,
        secrets.token_hex(6),
        secrets.token_bytes(32),
    )
    return key_id


def register(
    world: World, who: str = "owner", **fields: Any
) -> tuple[int, dict[str, Any], dict[str, str]]:
    body: dict[str, Any] = {
        "slug": unique("agent"),
        "name": "Billing agent",
        "kind": "autonomous_agent",
        "fail_mode": "closed",
    }
    body.update(fields)
    resp = world.client.post("/api/v1/agents", json=body, headers=world.idem(who))
    return resp.status_code, resp.json(), dict(resp.headers)


def agent(world: World, who: str = "owner", **fields: Any) -> dict[str, Any]:
    status, body, _ = register(world, who, **fields)
    assert status == 201, body
    return body


def outbox_events(world: World, tenant: Tenant, aggregate_id: UUID | str) -> list[str]:
    rows = world.admin.fetch(
        "SELECT event_type FROM sibyl.outbox WHERE tenant_id = $1 AND aggregate_id = $2"
        " ORDER BY created_at",
        tenant.id,
        UUID(str(aggregate_id)),
    )
    return [r["event_type"] for r in rows]
