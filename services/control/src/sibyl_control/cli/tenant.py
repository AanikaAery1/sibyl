"""``tenant`` commands: create, list, show, add-issuer, add-user, seed-demo.

``create`` generates the three v1 DEKs, wraps them under the KEK outside Postgres (AAD =
tenant ‖ purpose ‖ version) and calls ``sibyl.tenant_create``. ``seed-demo`` applies the D29/R56
seed contract (``deploy/compose/dex/personas.yaml``): the demo tenants, one dex issuer each and
the persona role bindings (B3: the On-call Operator in meridian and northstar only). Every
command is idempotent where re-running makes sense (existing rows are reported, not duplicated).
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml

from ..core.audit import AuditRecord, PgAuditWriter
from ..core.crypto.deks import kek_from_settings, new_wrapped_dek
from . import CliContext, CliError, tenant_id_for

PURPOSES = ("payload", "credential", "config")
ROLES = ("owner", "admin", "security_admin", "engineer", "operator", "auditor", "viewer")
DEFAULT_CLIENT_ID = "sibyl-console"


def register(groups: Any) -> None:
    parser = groups.add_parser("tenant", help="tenants, issuers and bootstrap users")
    cmds = parser.add_subparsers(dest="command", required=True)

    create = cmds.add_parser("create", help="create a tenant (tenant_create + KEK-wrapped DEKs)")
    create.add_argument("slug")
    create.add_argument("--name", required=True)
    create.add_argument("--fail-mode", choices=("open", "closed"), default="closed")
    create.add_argument("--region", default=None)
    create.set_defaults(handler=create_tenant)

    cmds.add_parser("list", help="list tenants").set_defaults(handler=list_tenants)

    show = cmds.add_parser("show", help="one tenant with its issuers and key versions")
    show.add_argument("tenant")
    show.set_defaults(handler=show_tenant)

    issuer = cmds.add_parser("add-issuer", help="register an OIDC issuer for a tenant")
    issuer.add_argument("tenant")
    issuer.add_argument("--issuer-url", required=True)
    issuer.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    issuer.add_argument("--domain", action="append", default=[], dest="domains")
    issuer.add_argument("--jit-role", choices=("engineer", "operator", "auditor", "viewer"))
    issuer.set_defaults(handler=add_issuer)

    user = cmds.add_parser(
        "add-user", help="bootstrap a user bound to roles (e.g. the first owner)"
    )
    user.add_argument("tenant")
    user.add_argument("--issuer-url", required=True)
    user.add_argument("--subject", required=True)
    user.add_argument("--email", required=True)
    user.add_argument("--role", action="append", choices=ROLES, required=True, dest="roles")
    user.set_defaults(handler=add_user)

    seed = cmds.add_parser("seed-demo", help="demo tenants + persona bindings from personas.yaml")
    seed.add_argument("--personas", type=Path, default=Path("deploy/compose/dex/personas.yaml"))
    seed.add_argument(
        "--issuer-url", required=True, help="the dex issuer, e.g. https://localhost:8443/dex"
    )
    seed.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    seed.set_defaults(handler=seed_demo)


async def _create(
    ctx: CliContext, slug: str, name: str, fail_mode: str, region: str | None
) -> tuple[UUID, bool]:
    async with ctx.db.pre_tenant() as conn:
        existing = await conn.fetchval("SELECT id FROM sibyl.tenant WHERE slug = $1", slug)
        tenant: UUID = existing or await conn.fetchval("SELECT sibyl.uuidv7()")
    if existing is not None:
        return tenant, False
    kek = kek_from_settings(ctx.settings)
    wrapped = [new_wrapped_dek(kek, tenant, purpose, 1).wrapped for purpose in PURPOSES]
    async with ctx.db.tenant_tx(tenant) as conn:
        await conn.fetchval(
            "SELECT sibyl.tenant_create($1, $2, $3, $4, $5, $6, $7, $8, NULL, $9)",
            slug,
            name,
            fail_mode,
            region,
            kek.kek_id,
            *wrapped,
            tenant,
        )
    return tenant, True


async def create_tenant(args: argparse.Namespace, ctx: CliContext) -> int:
    tenant, created = await _create(ctx, args.slug, args.name, args.fail_mode, args.region)
    if not created:
        raise CliError(f"tenant {args.slug!r} already exists ({tenant})")
    ctx.emit(
        {"id": str(tenant), "slug": args.slug, "created": True},
        f"created tenant {args.slug} {tenant}",
    )
    return 0


async def list_tenants(args: argparse.Namespace, ctx: CliContext) -> int:
    async with ctx.db.pre_tenant() as conn:
        rows = await conn.fetch(
            "SELECT id, slug, name, status, created_at FROM sibyl.tenant ORDER BY slug"
        )
    data = [
        {"id": str(r["id"]), "slug": r["slug"], "name": r["name"], "status": r["status"]}
        for r in rows
    ]
    ctx.emit(
        data, "\n".join(f"{d['slug']:<24} {d['status']:<10} {d['id']}  {d['name']}" for d in data)
    )
    return 0


async def show_tenant(args: argparse.Namespace, ctx: CliContext) -> int:
    tenant = await tenant_id_for(ctx.db, args.tenant)
    async with ctx.db.tenant_tx(tenant, readonly=True) as conn:
        row = await conn.fetchrow("SELECT * FROM sibyl.tenant WHERE id = $1", tenant)
        issuers = await conn.fetch(
            "SELECT id, issuer_url, client_id, status FROM sibyl.oidc_issuer WHERE tenant_id = $1"
            " ORDER BY created_at",
            tenant,
        )
        keys = await conn.fetch(
            "SELECT purpose, version, state, kek_id FROM sibyl.tenant_key WHERE tenant_id = $1"
            " ORDER BY purpose, version",
            tenant,
        )
        users = await conn.fetchval(
            "SELECT count(*) FROM sibyl.app_user WHERE tenant_id = $1", tenant
        )
    doc = {
        "id": str(tenant),
        "slug": row["slug"],
        "name": row["name"],
        "status": row["status"],
        "issuers": [dict(i) | {"id": str(i["id"])} for i in issuers],
        "tenant_keys": [dict(k) for k in keys],
        "users": users,
    }
    lines = [f"{row['slug']} ({tenant}) {row['status']} — {users} users"]
    lines += [f"  issuer {i['issuer_url']} client={i['client_id']} {i['status']}" for i in issuers]
    lines += [f"  key {k['purpose']} v{k['version']} {k['state']} ({k['kek_id']})" for k in keys]
    ctx.emit(doc, "\n".join(lines))
    return 0


async def _issuer(
    conn: Any, tenant: UUID, url: str, client_id: str, domains: list[str], jit: str | None
) -> tuple[UUID, bool]:
    existing = await conn.fetchval(
        "SELECT id FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND issuer_url = $2", tenant, url
    )
    if existing is not None:
        return existing, False
    if not url.startswith("https://"):
        raise CliError("issuer_url must be https")
    if jit is not None and not domains:
        raise CliError("--jit-role needs at least one --domain")
    issuer: UUID = await conn.fetchval(
        "INSERT INTO sibyl.oidc_issuer (tenant_id, issuer_url, client_id, allowed_email_domains,"
        " jit_default_role) VALUES ($1, $2, $3, $4, $5) RETURNING id",
        tenant,
        url.rstrip("/"),
        client_id,
        sorted({d.lower() for d in domains}),
        jit,
    )
    return issuer, True


async def add_issuer(args: argparse.Namespace, ctx: CliContext) -> int:
    tenant = await tenant_id_for(ctx.db, args.tenant)
    async with ctx.db.tenant_tx(tenant) as conn:
        issuer, created = await _issuer(
            conn, tenant, args.issuer_url, args.client_id, args.domains, args.jit_role
        )
    ctx.emit(
        {"id": str(issuer), "created": created},
        f"{'created' if created else 'exists'} issuer {issuer}",
    )
    return 0


async def _user(
    conn: Any, tenant: UUID, issuer: UUID, subject: str, email: str, roles: list[str], command: str
) -> tuple[UUID, list[str]]:
    """Upsert the user by (issuer, subject); grant missing roles. Audited ``user.provisioned``."""
    user = await conn.fetchval(
        "SELECT id FROM sibyl.app_user WHERE tenant_id = $1 AND oidc_issuer_id = $2 AND subject ="
        " $3",
        tenant,
        issuer,
        subject,
    )
    if user is None:
        await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
        user = await conn.fetchval(
            "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email,"
            " email_verified, status)"
            " VALUES ($1, $2, $3, $4, true, 'active') RETURNING id",
            tenant,
            issuer,
            subject,
            email,
        )
        await PgAuditWriter().append(
            conn,
            tenant,
            AuditRecord(
                action="user.provisioned",
                actor_type="system",
                resource_type="app_user",
                resource_id=user,
                reason=f"operator CLI: {command}",
                detail={
                    "user_id": str(user),
                    "issuer_id": str(issuer),
                    "via": "operator_cli",
                    "roles": sorted(roles),
                },
            ),
        )
    granted = []
    for role in roles:
        added = await conn.fetchval(
            "INSERT INTO sibyl.membership (tenant_id, user_id, role_name, scope_kind) VALUES ($1,"
            " $2, $3, 'tenant')"
            " ON CONFLICT DO NOTHING RETURNING id",
            tenant,
            user,
            role,
        )
        if added is not None:
            granted.append(role)
    return user, granted


async def add_user(args: argparse.Namespace, ctx: CliContext) -> int:
    tenant = await tenant_id_for(ctx.db, args.tenant)
    async with ctx.db.tenant_tx(tenant) as conn:
        issuer = await conn.fetchval(
            "SELECT id FROM sibyl.oidc_issuer WHERE tenant_id = $1 AND issuer_url = $2",
            tenant,
            args.issuer_url.rstrip("/"),
        )
        if issuer is None:
            raise CliError(
                f"no issuer {args.issuer_url!r} on this tenant; run tenant add-issuer first"
            )
        user, granted = await _user(
            conn, tenant, issuer, args.subject, args.email, args.roles, "tenant add-user"
        )
    ctx.emit(
        {"id": str(user), "granted": granted}, f"user {user} granted {granted or 'nothing new'}"
    )
    return 0


async def seed_demo(args: argparse.Namespace, ctx: CliContext) -> int:
    contract = yaml.safe_load(args.personas.read_text(encoding="utf-8"))
    personas = {p["username"]: p for p in contract["personas"]}
    report: dict[str, Any] = {}
    for slug, meta in contract["tenants"].items():
        tenant, created = await _create(ctx, slug, meta["display_name"], "closed", None)
        entry: dict[str, Any] = {"id": str(tenant), "created": created, "bindings": {}}
        async with ctx.db.tenant_tx(tenant) as conn:
            issuer, _ = await _issuer(conn, tenant, args.issuer_url, args.client_id, [], None)
            for binding in (b for b in contract["bindings"] if b["tenant"] == slug):
                persona = personas[binding["persona"]]
                user, granted = await _user(
                    conn,
                    tenant,
                    issuer,
                    persona["subject"],
                    persona["email"],
                    list(binding["roles"]),
                    "tenant seed-demo",
                )
                entry["bindings"][binding["persona"]] = {"user_id": str(user), "granted": granted}
        report[slug] = entry
    lines = [
        f"{slug}: {'created' if e['created'] else 'exists'}; "
        + ", ".join(f"{p}+{b['granted']}" for p, b in e["bindings"].items())
        for slug, e in report.items()
    ]
    ctx.emit(report, "\n".join(lines))
    return 0
