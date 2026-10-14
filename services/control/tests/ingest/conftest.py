"""Ingest integration harness.

One migrated PG17 database per session (``sibyl_ingest_<hex>`` on ``SIBYL_PG_ADMIN_DSN``,
dropped at the end; no cluster roles created). Each test gets a fresh tenant created through
``sibyl.tenant_create`` with DEKs wrapped by a test KEK exactly as ingest unwraps them, a
tenant capture policy, a registered agent (the golden fixtures' agent id), a priced model and
API keys of several shapes. The ingest app runs in-process over ``httpx.ASGITransport`` with a
pool logged in as ``sibyl_ingest``, so grants and RLS are the real ones.
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from pydantic import SecretStr
from sibyl_control.core.apikeys import generate_api_key
from sibyl_control.core.blob.fs import FsBlobStore
from sibyl_control.core.crypto.deks import wrap_dek
from sibyl_control.core.crypto.envelope import LocalKek, generate_dek
from sibyl_control.core.db import Database
from sibyl_control.core.settings import Settings
from sibyl_control.ingest.app import IngestServices, assemble, create_app
from sibyl_control.ingest.config import IngestConfig
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
FIXTURE_AGENT = UUID("0192767f-0000-7000-8000-00000000c010")
PEPPER = secrets.token_bytes(32)
KEK = LocalKek("kek-ingest-test", generate_dek())
SCRUB_SALT = secrets.token_bytes(32)
PARTITIONED = ("events", "events_rejected", "payload_refs", "checkpoint", "ingest_batch_seen")


async def _admin_exec(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def _dsn(name: str, role: str | None) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    user = role or (parts.username or "postgres")
    return urlunsplit((parts.scheme, f"{user}@{host}", f"/{name}", "", ""))


async def _available() -> bool:
    try:
        conn = await asyncpg.connect(ADMIN_DSN, timeout=3)
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


@pytest.fixture(scope="session")
def ingest_dbname() -> Iterator[str]:
    if not asyncio.run(_available()):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_ingest_{secrets.token_hex(6)}"
    asyncio.run(_admin_exec(f'CREATE DATABASE "{name}"'))

    async def setup() -> None:
        await apply(
            MigrateConfig(
                migrate=ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name),
                admin=ConnSpec(dsn=ADMIN_DSN, user=None, database=name),
            )
        )
        conn = await asyncpg.connect(_dsn(name, None))
        try:
            lo = datetime(2026, 10, 1, tzinfo=UTC)
            hi = datetime.now(UTC) + timedelta(days=8)
            for table in PARTITIONED:
                await conn.execute("SELECT sibyl.partition_ensure($1, $2, $3)", table, lo, hi)
        finally:
            await conn.close()

    try:
        asyncio.run(setup())
        yield name
    finally:
        asyncio.run(_admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@dataclass
class Key:
    plaintext: str = field(repr=False)
    id: UUID
    scopes: tuple[str, ...]
    agent_id: UUID | None
    env: str


@dataclass
class World:
    tenant_id: UUID
    slug: str
    admin: asyncpg.Connection
    db: Database
    services: IngestServices
    client: httpx.AsyncClient
    blob: FsBlobStore
    keys: dict[str, Key]
    owner: UUID
    tmp: Path

    async def post(
        self,
        path: str,
        content: bytes,
        *,
        key: str = "tenant",
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        all_headers = {
            "authorization": f"Bearer {self.keys[key].plaintext}",
            "content-type": content_type,
        }
        all_headers.update(headers or {})
        return await self.client.post(path, content=content, headers=all_headers)

    async def rows(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        return await self.admin.fetch(sql, *args)

    async def val(self, sql: str, *args: Any) -> Any:
        return await self.admin.fetchval(sql, *args)

    async def set_capture(
        self, mode: str, *, profile: str = "secrets_only", agent: UUID | None = None
    ) -> None:
        async with self.admin.transaction():
            await self.admin.execute("SELECT sibyl.set_tenant($1)", self.tenant_id)
            scope = "agent" if agent else "tenant"
            current = await self.admin.fetchrow(
                "SELECT id, version_no FROM sibyl.capture_policy WHERE tenant_id = $3 AND"
                " scope_kind = $1"
                " AND agent_id IS NOT DISTINCT FROM $2 AND superseded_by IS NULL",
                scope,
                agent,
                self.tenant_id,
            )
            new_id = uuid4()
            version = (current["version_no"] + 1) if current else 1
            await self.admin.execute("SET CONSTRAINTS ALL DEFERRED")
            if current:
                await self.admin.execute(
                    "UPDATE sibyl.capture_policy SET superseded_by = $1 WHERE tenant_id = $3 AND"
                    " id = $2",
                    new_id,
                    current["id"],
                    self.tenant_id,
                )
            await self.admin.execute(
                "INSERT INTO sibyl.capture_policy (tenant_id, id, scope_kind, agent_id,"
                " capture_mode,"
                " redaction_profile_id, consequences_version, chosen_by, version_no)"
                " SELECT $1, $2, $3, $4, $5, rp.id, 'consequences/v1', $6, $7 FROM"
                " sibyl.redaction_profile rp"
                " WHERE rp.name = $8 AND rp.tenant_id = $1",
                self.tenant_id,
                new_id,
                scope,
                agent,
                mode,
                self.owner,
                version,
                profile,
            )


def _settings(tmp: Path) -> Settings:
    return Settings(
        key_pepper=SecretStr(PEPPER.hex()),
        kek=SecretStr(base64.urlsafe_b64encode(KEK._material).decode()),
        kek_id=KEK.kek_id,
        scrub_salt=SecretStr(SCRUB_SALT.hex()),
        subject_salt=SecretStr(secrets.token_hex(32)),
        env="live",
        blob_root=str(tmp / "blob"),
    )


async def create_tenant(admin: asyncpg.Connection, slug: str) -> UUID:
    tenant_id = uuid4()
    wrapped = [
        wrap_dek(KEK, tenant_id, p, 1, generate_dek()) for p in ("payload", "credential", "config")
    ]
    await admin.execute(
        "SELECT sibyl.tenant_create($1, $2, 'open', 'eu-west', $3, $4, $5, $6, NULL, $7)",
        slug,
        slug.title(),
        KEK.kek_id,
        *wrapped,
        tenant_id,
    )
    return tenant_id


async def _populate(
    admin: asyncpg.Connection, tenant_id: UUID, slug: str, mode: str
) -> tuple[UUID, dict[str, Key]]:
    owner, issuer, provider = uuid4(), uuid4(), uuid4()
    keys: dict[str, Key] = {}
    async with admin.transaction():
        await admin.execute("SELECT sibyl.set_tenant($1)", tenant_id)
        await admin.execute(
            "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id) VALUES ($1,"
            " $2, $3, 'sibyl')",
            tenant_id,
            issuer,
            f"https://dex.example/{slug}",
        )
        await admin.execute(
            "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
            " display_name, status)"
            " VALUES ($1, $2, $3, $4, $5, 'Owner', 'active')",
            tenant_id,
            owner,
            issuer,
            f"{slug}-owner",
            f"owner@{slug}.example",
        )
        await admin.execute(
            "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, capture_mode,"
            " redaction_profile_id,"
            " consequences_version, chosen_by, version_no)"
            " SELECT $1, 'tenant', $2, rp.id, 'consequences/v1', $3, 1 FROM"
            " sibyl.redaction_profile rp"
            " WHERE rp.name = 'secrets_only' AND rp.tenant_id = $1",
            tenant_id,
            mode,
            owner,
        )
        await admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, fail_mode, lifecycle)"
            " VALUES ($1, $2, 'quote-worker', 'Quote worker', 'autonomous_agent', 'open',"
            " 'deployed')",
            tenant_id,
            FIXTURE_AGENT,
        )
        await admin.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect,"
            " base_url, is_known_provider)"
            " VALUES ($1, $2, 'openai', 'OpenAI', 'openai', 'openai_compatible',"
            " 'https://api.openai.com/v1', true)",
            tenant_id,
            provider,
        )
        await admin.execute(
            "INSERT INTO sibyl.model (tenant_id, provider_id, model_name, input_usd_per_1m,"
            " output_usd_per_1m)"
            " VALUES ($1, $2, 'gpt-5-mini', 0.25, 2.00)",
            tenant_id,
            provider,
        )
        for name, scopes, agent, env in (
            ("tenant", ("ingest:write", "handoff:write"), None, "live"),
            ("bound", ("ingest:write",), FIXTURE_AGENT, "live"),
            ("nohandoff", ("ingest:write",), None, "live"),
            ("reader", ("routing:read",), None, "live"),
            ("testenv", ("ingest:write",), None, "test"),
        ):
            gen = generate_api_key(env, PEPPER)
            key_id = uuid4()
            await admin.execute(
                "INSERT INTO sibyl.api_key (tenant_id, id, agent_id, name, env, prefix,"
                " secret_hash, scopes, expires_at)"
                " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + interval '30 days')",
                tenant_id,
                key_id,
                agent,
                name,
                env,
                gen.prefix,
                gen.secret_hash,
                list(scopes),
            )
            keys[name] = Key(gen.plaintext, key_id, scopes, agent, env)
    return owner, keys


@pytest.fixture
async def world_factory(ingest_dbname: str, tmp_path: Path) -> AsyncIterator[Any]:
    admin = await asyncpg.connect(_dsn(ingest_dbname, None))
    db = await Database.connect(
        _dsn(ingest_dbname, "sibyl_ingest"), min_size=1, max_size=8, application_name="ingest-test"
    )
    clients: list[httpx.AsyncClient] = []

    async def make(
        *, mode: str = "full", cfg: IngestConfig | None = None, limiter: Any = None
    ) -> World:
        slug = f"t{secrets.token_hex(5)}"
        tenant_id = await create_tenant(admin, slug)
        owner, keys = await _populate(admin, tenant_id, slug, mode)
        tmp = tmp_path / slug
        blob = FsBlobStore(tmp / "blob")
        services = assemble(db, _settings(tmp), store=blob, cfg=cfg, limiter=limiter)
        client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(services)), base_url="http://ingest.test"
        )
        clients.append(client)
        return World(tenant_id, slug, admin, db, services, client, blob, keys, owner, tmp)

    try:
        yield make
    finally:
        for client in clients:
            await client.aclose()
        await db.close()
        await admin.close()


@pytest.fixture
async def world(world_factory: Any) -> World:
    result: World = await world_factory()
    return result
