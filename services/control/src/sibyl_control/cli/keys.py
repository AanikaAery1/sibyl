"""``keys`` commands: create (secret printed once), list, revoke.

Operator path for bootstrap keys (the first gateway key, the D20 break-glass key while the IdP is
not yet wired). Same rules as ``POST /api/v1/api-keys``: scopes ⊆ M, break-glass exclusive,
tenant-level and live (≤ 2 active, DB trigger), the deployment's env only, a tenant
``capture_policy`` first for anything but break-glass (D12), expiry ≤ 400 days. Audited as
``system`` with the reason ``operator CLI: …``; ``policy_changed`` is emitted in the same
transaction.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from ..core.apikeys import generate_api_key, validate_expiry, validate_key_scopes
from ..core.audit import AuditRecord, PgAuditWriter
from ..core.authz import BREAK_GLASS_SCOPE, KEY_SCOPES
from ..core.outbox import OutboxMessage, PgOutboxWriter
from . import CliContext, CliError, tenant_id_for


def register(groups: Any) -> None:
    parser = groups.add_parser("keys", help="tenant API keys")
    cmds = parser.add_subparsers(dest="command", required=True)

    create = cmds.add_parser("create", help="issue a key; the secret is printed exactly once")
    create.add_argument("tenant")
    create.add_argument("--name", required=True)
    create.add_argument("--env", choices=("live", "test"), required=True)
    create.add_argument(
        "--scope", action="append", required=True, dest="scopes", choices=sorted(KEY_SCOPES)
    )
    create.add_argument("--agent", help="bind to an agent (slug or id)")
    create.add_argument("--expires-days", type=int, default=None)
    create.add_argument("--reason", default=None)
    create.set_defaults(handler=create_key)

    listing = cmds.add_parser("list", help="list keys (never secrets or hashes)")
    listing.add_argument("tenant")
    listing.add_argument("--all", action="store_true", help="include revoked and expired keys")
    listing.set_defaults(handler=list_keys)

    revoke = cmds.add_parser("revoke", help="revoke a key")
    revoke.add_argument("tenant")
    revoke.add_argument("key", help="key id or prefix")
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(handler=revoke_key)


def _detail(row: Any, **extra: Any) -> dict[str, Any]:
    return {
        "key_id": str(row["id"]),
        "prefix": row["prefix"],
        "scopes": sorted(row["scopes"]),
        "agent_id": str(row["agent_id"]) if row["agent_id"] else None,
        "grace_until": None,
        "env": row["env"],
        "break_glass": list(row["scopes"]) == [BREAK_GLASS_SCOPE],
        **extra,
    }


async def _policy_changed(conn: Any, tenant: UUID, agent: UUID | None) -> None:
    version = await conn.fetchval("SELECT routing_version FROM sibyl.tenant WHERE id = $1", tenant)
    await PgOutboxWriter().emit(
        conn,
        tenant,
        OutboxMessage.for_event(
            "policy_changed",
            "agent" if agent else "tenant",
            agent or tenant,
            {
                "tenant_id": str(tenant),
                "routing_version": int(version or 0),
                "agent_id": str(agent) if agent else None,
            },
        ),
    )


async def _agent(conn: Any, tenant: UUID, ref: str) -> UUID:
    try:
        value = await conn.fetchval(
            "SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND id = $2", tenant, UUID(ref)
        )
    except ValueError:
        value = await conn.fetchval(
            "SELECT id FROM sibyl.agent WHERE tenant_id = $1 AND slug = $2", tenant, ref
        )
    if value is None:
        raise CliError(f"no agent {ref!r} in this tenant")
    agent: UUID = value
    return agent


async def create_key(args: argparse.Namespace, ctx: CliContext) -> int:
    if args.env != ctx.settings.env:
        raise CliError(f"this deployment accepts only {ctx.settings.env} keys (env_mismatch)")
    tenant = await tenant_id_for(ctx.db, args.tenant)
    now = datetime.now(UTC)
    expires = validate_expiry(
        now + timedelta(days=args.expires_days) if args.expires_days is not None else None, now=now
    )
    pepper = ctx.settings.pepper()
    reason = f"operator CLI: keys create{(' — ' + args.reason) if args.reason else ''}"
    async with ctx.db.tenant_tx(tenant) as conn:
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        agent = await _agent(conn, tenant, args.agent) if args.agent else None
        scopes = validate_key_scopes(args.scopes, agent_id=agent, env=args.env)
        if scopes != {BREAK_GLASS_SCOPE} and not await conn.fetchval(
            "SELECT EXISTS (SELECT 1 FROM sibyl.capture_policy WHERE tenant_id = $1"
            " AND scope_kind = 'tenant' AND superseded_by IS NULL)",
            tenant,
        ):
            raise CliError(
                "the tenant has no capture policy yet (D12): set one before issuing keys"
            )
        generated = generate_api_key(args.env, pepper)
        row = await conn.fetchrow(
            "INSERT INTO sibyl.api_key (tenant_id, agent_id, name, env, prefix, secret_hash,"
            " scopes, expires_at)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
            tenant,
            agent,
            args.name,
            args.env,
            generated.prefix,
            generated.secret_hash,
            sorted(scopes),
            expires,
        )
        await PgAuditWriter().append(
            conn,
            tenant,
            AuditRecord(
                action="api_key.created",
                actor_type="system",
                resource_type="api_key",
                resource_id=row["id"],
                resource_ref=row["prefix"],
                reason=reason,
                detail=_detail(row, expires_at=expires.isoformat(), via="operator_cli"),
            ),
        )
        await _policy_changed(conn, tenant, agent)
    doc = {
        "id": str(row["id"]),
        "prefix": row["prefix"],
        "scopes": sorted(scopes),
        "expires_at": expires.isoformat(),
        "secret": generated.plaintext,
    }
    ctx.emit(
        doc,
        f"key {row['id']} prefix {row['prefix']} scopes {','.join(sorted(scopes))}\n"
        f"secret (shown once, store it now): {generated.plaintext}",
    )
    return 0


async def list_keys(args: argparse.Namespace, ctx: CliContext) -> int:
    tenant = await tenant_id_for(ctx.db, args.tenant)
    async with ctx.db.tenant_tx(tenant, readonly=True) as conn:
        rows = await conn.fetch(
            "SELECT id, name, env, prefix, scopes, agent_id, status, expires_at, last_used_at"
            " FROM sibyl.api_key WHERE tenant_id = $1 AND ($2 OR status IN ('active', 'rotating'))"
            " ORDER BY created_at, id",
            tenant,
            args.all,
        )
    data = [
        {
            "id": str(r["id"]),
            "name": r["name"],
            "env": r["env"],
            "prefix": r["prefix"],
            "scopes": list(r["scopes"]),
            "agent_id": str(r["agent_id"]) if r["agent_id"] else None,
            "status": r["status"],
            "expires_at": r["expires_at"].isoformat(),
        }
        for r in rows
    ]
    ctx.emit(
        data,
        "\n".join(
            f"{d['prefix']} {d['status']:<9} {d['env']} {','.join(d['scopes'])} {d['name']}"
            for d in data
        ),
    )
    return 0


async def revoke_key(args: argparse.Namespace, ctx: CliContext) -> int:
    if len(args.reason.strip()) < 10:
        raise CliError("--reason must be at least 10 characters")
    tenant = await tenant_id_for(ctx.db, args.tenant)
    async with ctx.db.tenant_tx(tenant) as conn:
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        try:
            row = await conn.fetchrow(
                "SELECT * FROM sibyl.api_key WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
                tenant,
                UUID(args.key),
            )
        except ValueError:
            row = await conn.fetchrow(
                "SELECT * FROM sibyl.api_key WHERE tenant_id = $1 AND prefix = $2 FOR UPDATE",
                tenant,
                args.key,
            )
        if row is None:
            raise CliError(f"no key {args.key!r} in this tenant")
        if row["status"] == "revoked":
            raise CliError("the key is already revoked")
        row = await conn.fetchrow(
            "UPDATE sibyl.api_key SET status = 'revoked', revoked_at = now(), revoke_reason = $3"
            " WHERE tenant_id = $1 AND id = $2 RETURNING *",
            tenant,
            row["id"],
            args.reason,
        )
        await PgAuditWriter().append(
            conn,
            tenant,
            AuditRecord(
                action="api_key.revoked",
                actor_type="system",
                resource_type="api_key",
                resource_id=row["id"],
                resource_ref=row["prefix"],
                reason=f"operator CLI: {args.reason}",
                detail=_detail(row, via="operator_cli"),
            ),
        )
        await _policy_changed(conn, tenant, row["agent_id"])
    ctx.emit({"id": str(row["id"]), "status": "revoked"}, f"revoked {row['prefix']}")
    return 0
