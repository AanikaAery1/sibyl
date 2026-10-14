"""Direct-SQL setup for the policy tests (the registry routes are built in another lane).

Inserts that fire SECURITY DEFINER triggers writing the outbox (model → served_by edge,
dependency edges) run through ``SyncConn.in_tenant`` so RLS sees the tenant.
"""

from __future__ import annotations

import secrets
from typing import Any
from uuid import UUID, uuid4

from sibyl_lane_r_harness import Tenant, World

SECRETS_ONLY = (
    "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'secrets_only'"
)


def slug(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def add_agent(
    world: World,
    tenant: Tenant,
    *,
    tier: int = 2,
    group: UUID | None = None,
    tags: tuple[str, ...] = (),
) -> UUID:
    agent = uuid4()
    world.admin.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle,"
        " agent_group_id, tags)"
        " VALUES ($1, $2, $3, $3, 'chatbot', $4, 'closed', 'proposed', $5, $6)",
        tenant.id,
        agent,
        slug("agent"),
        tier,
        group,
        list(tags),
    )
    return agent


def add_provider(world: World, tenant: Tenant) -> UUID:
    provider = uuid4()
    name = slug("prov")
    world.admin.execute(
        "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect, base_url,"
        " is_known_provider) VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible', $4, true)",
        tenant.id,
        provider,
        name,
        f"https://api.{name}.example.com/v1",
    )
    return provider


def add_model(world: World, tenant: Tenant, provider: UUID) -> UUID:
    model = uuid4()
    world.admin.in_tenant(
        tenant.id,
        "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1, $2, $3, $4)",
        tenant.id,
        model,
        provider,
        slug("model"),
    )
    return model


def add_credential(world: World, tenant: Tenant, provider: UUID, *, status: str = "active") -> UUID:
    cred = uuid4()
    key_id = world.admin.fetchval(
        "SELECT id FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'credential'"
        " AND state = 'active'",
        tenant.id,
    )
    sealed = status not in ("revoked", "shredded")
    world.admin.execute(
        "INSERT INTO sibyl.provider_credential (tenant_id, id, provider_id, name, base_url,"
        " allowlist_basis, auth_scheme, ciphertext, nonce, tenant_key_id, key_version,"
        " secret_sha256, status, created_by)"
        " SELECT $1, $2, $3, $4, base_url, 'known_provider', 'bearer', $5, $6, $7, 1, $8, $9, $10"
        " FROM sibyl.provider WHERE tenant_id = $1 AND id = $3",
        tenant.id,
        cred,
        provider,
        slug("cred"),
        b"x" * 16 if sealed else None,
        b"n" * 12 if sealed else None,
        key_id,
        b"h" * 32,
        status,
        tenant.users["owner"],
    )
    return cred


def add_pii_source(world: World, tenant: Tenant, agent: UUID) -> UUID:
    source = uuid4()
    world.admin.execute(
        "INSERT INTO sibyl.data_source (tenant_id, id, slug, name, kind, classification)"
        " VALUES ($1, $2, $3, $3, 'database', 'pii')",
        tenant.id,
        source,
        slug("ds"),
    )
    world.admin.in_tenant(
        tenant.id,
        "INSERT INTO sibyl.dependency_edge (tenant_id, src_kind, src_id, dst_kind, dst_id,"
        " edge_type, origin) VALUES ($1, 'agent', $2, 'data_source', $3, 'reads_data', 'declared')",
        tenant.id,
        agent,
        source,
    )
    return source


def secrets_only(world: World, tenant: Tenant) -> UUID:
    value: UUID = world.admin.fetchval(SECRETS_ONLY, tenant.id)
    return value


def outbox_count(world: World, tenant: Tenant, event_type: str, aggregate: UUID) -> int:
    value: Any = world.admin.fetchval(
        "SELECT count(*) FROM sibyl.outbox WHERE tenant_id = $1 AND event_type = $2"
        " AND aggregate_id = $3",
        tenant.id,
        event_type,
        aggregate,
    )
    return int(value)


def receipt_ok(resp: Any, tenant: Tenant) -> bool:
    return str(resp.headers.get("x-sibyl-audit-receipt", "")).startswith(f"{tenant.id}:")
