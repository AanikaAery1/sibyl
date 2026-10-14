"""Lane G database: ``sibyl_g_<hex>`` on the local PG17, migrated by the real runner, seeded with
two tenants through ``tenant_create``/``routing_apply`` and real crypto (wrapped DEKs, an
encrypted fallback credential, a snapshot signing key), dropped at the end of the session."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx
import pytest
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import ApiKeyResolver, ChainResolver, Services, pg_key_lookup
from sibyl_control.api.snapshot import SnapshotService, router
from sibyl_control.api.snapshot.keys import SignerResolver
from sibyl_control.core.apikeys import generate_api_key
from sibyl_control.core.crypto.deks import dek_wrap_aad as dek_aad
from sibyl_control.core.crypto.envelope import LocalKek, generate_dek, seal
from sibyl_control.core.crypto.sealed import credential_context
from sibyl_control.core.crypto.signing import Ed25519Signer
from sibyl_control.core.db import Database
from sibyl_control.core.ratelimit import RateDecision, RatePolicy
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
PEPPER = secrets.token_bytes(32)
KEK = LocalKek("kek-g-test", secrets.token_bytes(32))
SNAP_SEED = secrets.token_bytes(32)
SNAP_KID = "snap-g-1"
VAULTED_SECRET = b"sk-vaulted-fallback-0123456789abcdef"


def h32(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@dataclass
class World:
    db_name: str
    tenant: uuid.UUID
    other: uuid.UUID
    agent_a: uuid.UUID  # tier 1, approved chain with a vaulted alt-provider step
    agent_b: uuid.UUID  # tier 2, killed by an agent kill switch
    agent_retired: uuid.UUID
    other_agent: uuid.UUID
    credential: uuid.UUID
    keys: dict[str, str] = field(default_factory=dict)  # name -> plaintext sbl_ key
    signer: Ed25519Signer = field(
        default_factory=lambda: Ed25519Signer.from_seed(SNAP_KID, SNAP_SEED)
    )


def _dsn(db: str, user: str | None) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    netloc = f"{user}@{host}" if user else parts.netloc
    return urlunsplit((parts.scheme, netloc, f"/{db}", "", ""))


async def _admin(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


async def _tenant(c: Any, slug: str) -> uuid.UUID:
    tenant = uuid.uuid4()
    wrapped = [
        KEK.wrap(generate_dek(), dek_aad(tenant, p, 1)) for p in ("payload", "credential", "config")
    ]
    await c.execute(
        "SELECT sibyl.tenant_create($1, $2, 'open', 'eu-west', $3, $4, $5, $6, NULL, $7)",
        slug,
        slug.title(),
        KEK.kek_id,
        *wrapped,
        tenant,
    )
    return tenant


async def _key(
    c: Any, w: World, name: str, tenant: uuid.UUID, scopes: list[str], **kw: Any
) -> uuid.UUID:
    generated = generate_api_key("live", PEPPER)
    key_id = uuid.uuid4()
    await c.execute(
        "INSERT INTO sibyl.api_key (tenant_id, id, agent_id, name, env, prefix, secret_hash,"
        " scopes, status, expires_at, rotation_grace_until, revoked_at)"
        " VALUES ($1,$2,$3,$4,'live',$5,$6,$7,"
        " $8, $9, $10, $11)",
        tenant,
        key_id,
        kw.get("agent"),
        name,
        generated.prefix,
        generated.secret_hash,
        scopes,
        kw.get("status", "active"),
        kw.get("expires", datetime.now(UTC) + timedelta(days=30)),
        kw.get("grace"),
        datetime.now(UTC) if kw.get("status") == "revoked" else None,
    )
    w.keys[name] = generated.plaintext
    return key_id


async def _agent(
    c: Any, t: uuid.UUID, slug: str, tier: int, mode: str, model: uuid.UUID, **kw: Any
) -> uuid.UUID:
    agent, version = uuid.uuid4(), uuid.uuid4()
    await c.execute(
        "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, tier, fail_mode, lifecycle)"
        " VALUES ($1,$2,$3,$3,'chatbot',$4,$5,'discovered')",
        t,
        agent,
        slug,
        tier,
        mode,
    )
    await c.execute(
        "INSERT INTO sibyl.agent_version (tenant_id, id, agent_id, version_no, primary_model_id,"
        " source)"
        " VALUES ($1,$2,$3,1,$4,'api')",
        t,
        version,
        agent,
        model,
    )
    await c.execute(
        "UPDATE sibyl.agent SET current_version_id = $3 WHERE tenant_id = $1 AND id = $2",
        t,
        agent,
        version,
    )
    await c.execute(
        "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
        " 'system',"
        " NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3, 'route.changed', NULL,"
        " NULL, NULL, NULL)",
        t,
        agent,
        f"register:{agent}",
    )
    return agent


async def _seed(db_name: str) -> World:
    conn = await asyncpg.connect(_dsn(db_name, None))
    try:
        tenant = await _tenant(conn, "gtenant")
        other = await _tenant(conn, "gother")
        w = World(db_name, tenant, other, *(uuid.uuid4() for _ in range(5)))
        await conn.execute(
            "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref)"
            " VALUES ($1, 'snapshot', $2, 'env:SIBYL_TEST_SNAPSHOT_SEED')",
            SNAP_KID,
            w.signer.public_key_raw,
        )
        async with conn.transaction():
            await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
            await _seed_tenant(conn, w)
        async with conn.transaction():
            await conn.execute("SELECT sibyl.set_tenant($1)", other)
            p = uuid.uuid4()
            m = uuid.uuid4()
            await conn.execute(
                "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind,"
                " dialect, base_url) VALUES ($1,$2,'o','o','openai','openai_compatible',"
                " 'https://api.other.example/v1')",
                other,
                p,
            )
            await conn.execute(
                "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name)"
                " VALUES ($1,$2,$3,'other-1')",
                other,
                m,
                p,
            )
            w.other_agent = await _agent(conn, other, "other-agent", 2, "open", m)
            await _key(conn, w, "other_gw", other, ["gateway:proxy", "routing:read"])
        return w
    finally:
        await conn.close()


async def _seed_tenant(c: Any, w: World) -> None:
    t = w.tenant
    owner, approver, issuer = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await c.execute(
        "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id)"
        " VALUES ($1,$2,'https://dex.example/g','sibyl')",
        t,
        issuer,
    )
    for user, label in ((owner, "owner"), (approver, "approver")):
        await c.execute(
            "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
            " display_name, status) VALUES ($1,$2,$3,$4,$5,$4,'active')",
            t,
            user,
            issuer,
            label,
            f"{label}@g.example",
        )
    p1, p2, m1, m2 = (uuid.uuid4() for _ in range(4))
    for pid, slug, url in (
        (p1, "openai", "https://api.openai.com/v1"),
        (p2, "alt", "https://api.alt.example/v1"),
    ):
        await c.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect,"
            " base_url, is_known_provider) VALUES ($1,$2,$3,$3,'openai','openai_compatible',"
            " $4, true)",
            t,
            pid,
            slug,
            url,
        )
    for mid, pid, name in ((m1, p1, "large-1"), (m2, p2, "alt-1")):
        await c.execute(
            "INSERT INTO sibyl.model (tenant_id, id, provider_id, model_name) VALUES ($1,$2,$3,$4)",
            t,
            mid,
            pid,
            name,
        )
    w.agent_a = await _agent(c, t, "billing-agent", 1, "closed", m1)
    w.agent_b = await _agent(c, t, "triage-bot", 2, "open", m1)
    w.agent_retired = await _agent(c, t, "old-bot", 3, "open", m1)
    await c.execute(
        "UPDATE sibyl.agent SET lifecycle = 'retired' WHERE tenant_id = $1 AND id = $2",
        t,
        w.agent_retired,
    )
    await c.execute(
        "INSERT INTO sibyl.agent_identity (tenant_id, agent_id, allowed_models,"
        " enforcement, tools_hash) VALUES ($1,$2,'{large-1,alt-1}','block',$3)",
        t,
        w.agent_a,
        h32("tools"),
    )
    profile = await c.fetchval(
        "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'secrets_only'", t
    )
    await c.execute(
        "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, capture_mode,"
        " redaction_profile_id, consequences_version, chosen_by, version_no)"
        " VALUES ($1,'tenant','full',$2,'c1',$3,1)",
        t,
        profile,
        owner,
    )
    key = await c.fetchrow(
        "SELECT id, version FROM sibyl.tenant_key WHERE tenant_id = $1 AND"
        " purpose = 'credential' AND state = 'active'",
        t,
    )
    wrapped = await c.fetchval("SELECT wrapped_dek FROM sibyl.tenant_key WHERE id = $1", key["id"])
    dek = KEK.unwrap(bytes(wrapped), dek_aad(t, "credential", key["version"]))
    sealed = seal(
        dek,
        VAULTED_SECRET,
        dek_aad(t, "credential", key["version"]) + credential_context(w.credential),
    )
    await c.execute(
        "INSERT INTO sibyl.provider_credential (tenant_id, id, provider_id, name, base_url,"
        " allowlist_basis, auth_scheme, ciphertext, nonce, tenant_key_id, key_version,"
        " secret_sha256,"
        " created_by) VALUES ($1,$2,$3,'fb','https://api.alt.example/v1','known_provider','bearer',"
        " $4,$5,$6,$7,$8,$9)",
        t,
        w.credential,
        p2,
        sealed.ciphertext,
        sealed.nonce,
        key["id"],
        key["version"],
        hashlib.sha256(VAULTED_SECRET).digest(),
        owner,
    )
    chain = uuid.uuid4()
    await c.execute(
        "INSERT INTO sibyl.fallback_chain (tenant_id, id, agent_id, version_no,"
        " requested_by_user_id) VALUES ($1,$2,$3,1,$4)",
        t,
        chain,
        w.agent_a,
        owner,
    )
    for pos, kind, provider, model, cred in (
        (0, "retry", None, None, None),
        (1, "alt_provider", p2, m2, w.credential),
        (2, "human_queue", None, None, None),
    ):
        await c.execute(
            "INSERT INTO sibyl.fallback_step (tenant_id, chain_id, position, kind,"
            " provider_id, model_id, credential_id) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            t,
            chain,
            pos,
            kind,
            provider,
            model,
            cred,
        )
    await c.execute(
        "UPDATE sibyl.fallback_chain SET status = 'approved', approved_by_user_id = $3,"
        " approved_at = now() WHERE tenant_id = $1 AND id = $2",
        t,
        chain,
        approver,
    )
    await c.execute(
        "INSERT INTO sibyl.continuity_plan (tenant_id, agent_id, fallback_chain_id,"
        " max_inflight, rps_limit, budget_usd_month) VALUES ($1,$2,$3,10,5.5,1500)",
        t,
        w.agent_a,
        chain,
    )
    gw = await _key(c, w, "gateway", t, ["gateway:proxy", "routing:read"])
    await _key(c, w, "sdk", t, ["ingest:write", "routing:read"], agent=w.agent_a)
    await _key(c, w, "bound_gw", t, ["gateway:proxy"], agent=w.agent_a)
    await _key(c, w, "revoked", t, ["gateway:proxy"], status="revoked")
    await _key(
        c,
        w,
        "rotating_old",
        t,
        ["gateway:proxy"],
        status="rotating",
        grace=datetime.now(UTC) - timedelta(minutes=1),
    )
    version = await c.fetchval("SELECT routing_version FROM sibyl.tenant WHERE id = $1", t)
    await c.execute(
        "INSERT INTO sibyl.kill_switch (tenant_id, scope_kind, scope_id, reason,"
        " pulled_by_key_id, routing_version_at_pull) VALUES ($1,'agent',$2,'test',$3,$4)",
        t,
        w.agent_b,
        gw,
        version,
    )


@pytest.fixture(scope="session")
def world() -> Iterator[World]:
    async def probe() -> bool:
        try:
            await (await asyncpg.connect(ADMIN_DSN, timeout=3)).close()
        except (OSError, asyncpg.PostgresError):
            return False
        return True

    if not asyncio.run(probe()):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_g_{secrets.token_hex(6)}"
    asyncio.run(_admin(f'CREATE DATABASE "{name}"'))
    try:
        spec = ConnSpec(dsn=ADMIN_DSN, database=name)
        asyncio.run(
            apply(
                MigrateConfig(
                    migrate=ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name), admin=spec
                )
            )
        )
        yield asyncio.run(_seed(name))
    finally:
        asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@dataclass
class Api:
    client: httpx.AsyncClient
    service: SnapshotService
    db: Database
    world: World
    services: Services

    def auth(self, name: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.world.keys[name]}", **extra}


class Unlimited:
    """Tests call faster than the contract's 2/s per key; one test re-enables the real one."""

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)


@pytest.fixture
async def api(world: World) -> AsyncIterator[Api]:
    db = await Database.connect(_dsn(world.db_name, "sibyl_app"), min_size=1, max_size=4)
    services = Services(
        principals=ChainResolver(ApiKeyResolver(pg_key_lookup(db), PEPPER)),
        db=db,
        rate_limiter=Unlimited(),
    )
    app = create_app(services, include=lambda a: a.include_router(router))
    service = SnapshotService(
        db, resolver=SignerResolver({"SIBYL_TEST_SNAPSHOT_SEED": SNAP_SEED.hex()}), kek=KEK
    )
    app.state.snapshot_service = service
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
        yield Api(client, service, db, world, services)
    await db.close()


def load(raw: bytes) -> Any:
    return json.loads(raw)
