"""Build (or reuse) the seeded template database and its `World`.

1. migrate an empty database through the real runner;
2. allow the doubles' host (`base_url_dev_host`, as `sibyl_migrate`) and publish the snapshot
   signing key (the deployment step `SIBYL_SNAPSHOT_SIGNING_KEY` stands for);
3. `sibyl seed` with the provider base URLs pointing at the in-process doubles;
4. through the real api, as the Admin: one agent-bound SDK key per agent, a gateway key and an
   ingest key per tenant, tier-1 agents moved to `deployed` (R35 needs the bound key first),
   and every provider's status feed pointed at the status-feed double.

The world (ids and key plaintexts) is cached beside the template (mode 0600); losing either
rebuilds both.
"""

from __future__ import annotations

import logging
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import asyncpg
import httpx
from sibyl_control.cli import seed as seed_cli
from sibyl_control.core.crypto.signing import Ed25519Signer, signing_key
from sibyl_control.core.db import Database

from ..world import AgentInfo, PersonaInfo, TenantInfo, World
from . import database as pg
from .control import build_api_app, control_settings, persona_resolver
from .secrets import DEV_SECRETS, StackSecrets

log = logging.getLogger("sibyl_sim.harness")
SIM_HOST = "127.0.0.1"
DEFAULT_DOUBLES_PORT = 18390
API = "/api/v1"
SDK_SCOPES = ["ingest:write", "routing:read", "actions:hold"]  # A-5: holds + cap counters
GATEWAY_SCOPES = ["gateway:proxy", "routing:read", "actions:hold"]
INGEST_SCOPES = ["ingest:write"]
FEED_PROVIDER = {"openai-stub": "openai", "anthropic-stub": "anthropic", "ollama-stub": "ollama"}


@dataclass(frozen=True)
class SimOptions(seed_cli.Options):
    """`sibyl seed` options addressing one doubles port with a per-double path prefix."""

    doubles_port: int = DEFAULT_DOUBLES_PORT

    def base_url(self, provider: str) -> str:
        return f"https://{self.sim_host}:{self.doubles_port}/{provider}/v1"


def cache_dir() -> Path:
    root = os.environ.get("SIBYL_SIM_CACHE") or os.environ.get("XDG_CACHE_HOME")
    return Path(root) / "sibyl-sim" if root else Path.home() / ".cache" / "sibyl-sim"


def world_path(template: str) -> Path:
    return cache_dir() / f"{template}.world.json"


def pinned_key_json(secrets_: StackSecrets = DEV_SECRETS) -> str:
    import json

    signer = Ed25519Signer.from_seed(secrets_.snapshot_kid, secrets_.snapshot_seed)
    return json.dumps(signing_key(signer.kid, signer.public_key_raw, status="active"))


def sdk_pin(secrets_: StackSecrets = DEV_SECRETS) -> str:
    """`PolicyConfig.public_key` for the SDK: `kid:public_key_b64url` (R33 key pinning)."""
    from sibyl_control.core.crypto.signing import b64url

    signer = Ed25519Signer.from_seed(secrets_.snapshot_kid, secrets_.snapshot_seed)
    return f"{signer.kid}:{b64url(signer.public_key_raw)}"


async def ensure_template(
    *, doubles_port: int = DEFAULT_DOUBLES_PORT, secrets_: StackSecrets = DEV_SECRETS
) -> World:
    """The ready template and its world, building both if either is missing."""
    name = f"{pg.TEMPLATE_PREFIX}{pg.fingerprint(str(doubles_port))}"
    path = world_path(name)
    async with pg.build_lock(name):
        if await pg.is_ready_template(name) and path.is_file():
            return World.load(path)
        await pg.drop(name)
        log.warning("sibyl-sim: building template %s (one-off, ~30 s)", name)
        world = await _build(name, doubles_port, secrets_)
        world.save(path)
        await pg.mark_ready(name)
        return world


async def _build(name: str, doubles_port: int, secrets_: StackSecrets) -> World:
    await pg.create_empty(name)
    await pg.migrate(name)
    await pg.ensure_partitions(name)
    dsns = pg.RoleDsns.for_database(name)
    await _publish_signing_key(dsns.admin, secrets_)
    blob = Path(tempfile.mkdtemp(prefix="sibyl-sim-seed-"))
    settings = control_settings(dsns.app, secrets_, blob)
    opts = SimOptions(sim_host=SIM_HOST, doubles_port=doubles_port)
    await seed_cli.seed(settings, opts=opts, migrate_dsn=dsns.migrate)
    world = await _identities(dsns.admin, doubles_port, name)
    await _status_feeds(dsns.admin, world, doubles_port)
    # B11 (one DEK wrapping convention) and the alert-silence columns (0009) are on main, so the
    # template needs no bridges; `World.bridges` stays for any future pending change request.
    world = World(world.tenants, world.doubles_port, world.template, ())
    db = await Database.connect(dsns.app, min_size=1, max_size=4, application_name="sibyl-sim")
    try:
        app = build_api_app(
            db,
            settings,
            secrets_,
            persona_resolver(world, stepped_up=True),
            rate_limiter=seed_cli._Unlimited(),  # the operator bootstrap, as in `sibyl seed`
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
            world = await _provision(_Api(client), world, doubles_port)
    finally:
        await db.close()
    return world


async def _publish_signing_key(admin_dsn: str, secrets_: StackSecrets) -> None:
    """Snapshot and audit-anchor keys (the deployment step behind the signing-key secrets)."""
    snapshot = Ed25519Signer.from_seed(secrets_.snapshot_kid, secrets_.snapshot_seed)
    anchor = Ed25519Signer.from_seed(secrets_.anchor_kid, secrets_.anchor_seed)
    conn = await asyncpg.connect(admin_dsn)
    try:
        for signer, purpose, ref in (
            (snapshot, "snapshot", f"env:{secrets_.snapshot_ref_env}"),
            (anchor, "audit_anchor", "env:SIBYL_ANCHOR_SIGNING_KEY"),
        ):
            await conn.execute(
                "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref)"
                " VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                signer.kid,
                purpose,
                signer.public_key_raw,
                ref,
            )
    finally:
        await conn.close()


async def _identities(admin_dsn: str, doubles_port: int, template: str) -> World:
    """Tenants, persona users and memberships as `sibyl seed` wrote them (operator read)."""
    conn = await asyncpg.connect(admin_dsn)
    tenants: dict[str, TenantInfo] = {}
    try:
        for spec in seed_cli.WORLD:
            tenant_id: UUID = await conn.fetchval(
                "SELECT id FROM sibyl.tenant WHERE slug = $1", spec.slug
            )
            personas: dict[str, PersonaInfo] = {}
            for username, roles in seed_cli.BINDINGS[spec.slug].items():
                user_id = await conn.fetchval(  # the admin bypasses RLS: scope explicitly
                    "SELECT id FROM sibyl.app_user WHERE tenant_id = $1 AND subject = $2",
                    tenant_id,
                    seed_cli.PERSONAS[username].subject,
                )
                token = f"sim-{spec.slug}-{username}-{secrets.token_hex(12)}"
                personas[username] = PersonaInfo(username, user_id, tuple(roles), token)
            tenants[spec.slug] = TenantInfo(
                spec.slug, tenant_id, personas=personas, provider_secret=f"sk-sim-{spec.slug}"
            )
    finally:
        await conn.close()
    return World(tenants, doubles_port, template)


async def _status_feeds(admin_dsn: str, world: World, doubles_port: int) -> None:
    """Point each stub provider at its status-feed double.

    Operator SQL, not the api: `updateProvider` needs `If-Match`, but no operation returns a
    provider's ETag (no `getProvider`, list items carry none, the 412 omits it), so a provider
    created by `sibyl seed` cannot be patched through the api at all (hand-back bug B-01;
    change request: `sibyl seed` should send `status_feed_url` on `createProvider`).
    """
    conn = await asyncpg.connect(admin_dsn)
    try:
        for tenant in world.tenants.values():
            for double, feed in FEED_PROVIDER.items():
                url = f"https://{SIM_HOST}:{doubles_port}/status/{feed}/api/v2/summary.json"
                await conn.execute(
                    "UPDATE sibyl.provider SET status_feed_url = $2 WHERE tenant_id = $1"
                    " AND slug = $3",
                    tenant.id,
                    url,
                    double,
                )
    finally:
        await conn.close()


class _Api:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client

    async def call(self, token: str, method: str, path: str, body: Any = None) -> Any:
        headers = {"Authorization": f"Bearer {token}", "Idempotency-Key": str(uuid4())}
        resp = await self.client.request(method, API + path, json=body, headers=headers)
        if resp.status_code >= 300:
            raise RuntimeError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp.json() if resp.content else None

    async def pages(self, token: str, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            sep = "&" if "?" in path else "?"
            url = path + (f"{sep}cursor={cursor}" if cursor else f"{sep}limit=100")
            page = await self.call(token, "GET", url)
            items.extend(page.get("data") or page.get("items") or [])
            cursor = (page.get("page") or {}).get("next_cursor") or page.get("next_cursor")
            if not cursor:
                return items


async def _provision(api: _Api, world: World, doubles_port: int) -> World:
    specs = {spec.slug: spec for spec in seed_cli.WORLD}
    tenants: dict[str, TenantInfo] = {}
    for slug, tenant in world.tenants.items():
        spec = specs[slug]
        if not spec.agents:
            tenants[slug] = tenant
            continue
        admin = tenant.token("admin")
        listed = {a["slug"]: a for a in await api.pages(admin, "/agents")}
        agents: dict[str, AgentInfo] = {}
        for agent_spec in spec.agents:
            row = listed[agent_spec.slug]
            provider = next(p for p in spec.providers if p.slug == agent_spec.provider)
            key = await api.call(
                admin,
                "POST",
                "/api-keys",
                {
                    "name": f"sim sdk {agent_spec.slug}",
                    "env": "live",
                    "scopes": SDK_SCOPES,
                    "agent_id": row["id"],
                },
            )
            agents[agent_spec.slug] = AgentInfo(
                agent_spec.slug,
                UUID(row["id"]),
                agent_spec.tier,
                agent_spec.provider,
                provider.models[0],
                key["secret"],
            )
            if row.get("lifecycle") == "proposed":
                for stage in ("approved", "deployed"):
                    await api.call(
                        admin,
                        "POST",
                        f"/agents/{row['id']}/lifecycle",
                        {"to_stage": stage, "reason": "sibyl-sim: bound key minted (R35)"},
                    )
        gateway = await api.call(
            admin,
            "POST",
            "/api-keys",
            {"name": f"sim gateway {slug}", "env": "live", "scopes": GATEWAY_SCOPES},
        )
        ingest = await api.call(
            admin,
            "POST",
            "/api-keys",
            {"name": f"sim gateway ingest {slug}", "env": "live", "scopes": INGEST_SCOPES},
        )
        providers = {p["slug"]: UUID(p["id"]) for p in await api.pages(admin, "/providers")}
        tenants[slug] = TenantInfo(
            slug,
            tenant.id,
            agents,
            providers,
            tenant.personas,
            gateway["secret"],
            ingest["secret"],
            tenant.provider_secret,
        )
    return World(tenants, world.doubles_port, world.template)
