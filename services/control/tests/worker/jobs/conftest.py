"""Jobs harness (B14): a migrated PG17 database with two tenants, a vaulted credential each, the
worker pool (``sibyl_worker``), the api pool (``sibyl_app``) and the api app.

The database is created once per module (``sibyl_jobs_<hex>``, dropped after). Credentials are
sealed with the kernel convention (B11) under a test KEK; the probe's HTTP goes to an
``httpx.MockTransport`` unless a test wires the real ``GuardedTransport``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import secrets
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.core.authz import (
    MembershipGrant,
    Principal,
    PrincipalKind,
    grants_from_memberships,
)
from sibyl_control.core.crypto.deks import ConnDekProvider, new_wrapped_dek
from sibyl_control.core.crypto.envelope import PURPOSES, LocalKek
from sibyl_control.core.crypto.sealed import seal_credential
from sibyl_control.core.db import Database
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.ratelimit import RateDecision, RatePolicy
from sibyl_control.core.settings import Settings
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply
from sibyl_control.worker.jobs.runner import JobEnv, JobRunner

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
KEK_ID = "kek-jobs-test"
KEK_MATERIAL = bytes(range(32, 64))
KEK = LocalKek(KEK_ID, KEK_MATERIAL)
SETTINGS = Settings(
    kek=SecretStr(base64.urlsafe_b64encode(KEK_MATERIAL).decode().rstrip("=")), kek_id=KEK_ID
)
SECRET = "sk-probe-secret-0123456789"  # noqa: S105 (synthetic test secret)
BASE_URL = "https://api.openai.com/v1"


def _dsn(db: str, role: str | None) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    user = role or (parts.username or "postgres")
    return urlunsplit((parts.scheme, f"{user}@{host}", f"/{db}", "", ""))


async def _admin(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@dataclass
class Tenant:
    id: UUID
    owner: UUID
    other_user: UUID
    provider: UUID
    credential: UUID


@dataclass
class Rig:
    db_name: str
    a: Tenant
    b: Tenant

    @asynccontextmanager
    async def admin(self, tenant: UUID | None = None) -> AsyncIterator[asyncpg.Connection]:
        conn = await asyncpg.connect(_dsn(self.db_name, None))
        for name in ("json", "jsonb"):
            await conn.set_type_codec(
                name, encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
        try:
            if tenant is None:
                yield conn
            else:
                async with conn.transaction():
                    await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
                    yield conn
        finally:
            await conn.close()


async def add_credential(
    conn: asyncpg.Connection,
    tenant: UUID,
    provider: UUID,
    created_by: UUID,
    *,
    base_url: str = BASE_URL,
    basis: str = "known_provider",
    scheme: str = "bearer",
    secret: str = SECRET,
) -> UUID:
    """Insert a vaulted credential on ``conn`` (already in ``tenant``'s transaction)."""
    credential = uuid4()
    sealed = await seal_credential(ConnDekProvider(conn, KEK), tenant, credential, secret.encode())
    await conn.execute(
        "INSERT INTO sibyl.provider_credential (tenant_id, id, provider_id, name, base_url,"
        " allowlist_basis, auth_scheme, ciphertext, nonce, tenant_key_id, key_version,"
        " secret_sha256, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,"
        " $13)",
        tenant,
        credential,
        provider,
        f"cred-{credential.hex[:8]}",
        base_url,
        basis,
        scheme,
        sealed.blob.ciphertext,
        sealed.blob.nonce,
        sealed.key_id,
        sealed.blob.key_version,
        secrets.token_bytes(32),
        created_by,
    )
    return credential


async def _tenant(conn: asyncpg.Connection, slug: str) -> Tenant:
    tenant = uuid4()
    deks = [new_wrapped_dek(KEK, tenant, p, 1).wrapped for p in PURPOSES]
    await conn.fetchval(
        "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', $3, $4, $5, $6, NULL, $7)",
        slug,
        slug.title(),
        KEK_ID,
        *deks,
        tenant,
    )
    issuer, owner, other, provider = uuid4(), uuid4(), uuid4(), uuid4()
    async with conn.transaction():
        await conn.execute("SELECT sibyl.set_tenant($1)", tenant)
        await conn.execute(
            "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id)"
            " VALUES ($1, $2, $3, 'sibyl')",
            tenant,
            issuer,
            f"https://dex.example.com/{slug}",
        )
        for uid, who in ((owner, "owner"), (other, "other")):
            await conn.execute(
                "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
                " display_name, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')",
                tenant,
                uid,
                issuer,
                f"{slug}-{who}",
                f"{who}@{slug}.example.com",
                who.title(),
            )
        await conn.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect,"
            " base_url, is_known_provider) VALUES ($1, $2, 'openai', 'OpenAI', 'openai',"
            " 'openai_compatible', $3, true)",
            tenant,
            provider,
            BASE_URL,
        )
        credential = await add_credential(conn, tenant, provider, owner)
    return Tenant(tenant, owner, other, provider, credential)


@pytest.fixture(scope="module")
def rig() -> Iterator[Rig]:
    name = f"sibyl_jobs_{secrets.token_hex(5)}"
    try:
        asyncio.run(_admin(f'CREATE DATABASE "{name}"'))
    except (OSError, asyncpg.PostgresError):
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    try:
        spec = ConnSpec(dsn=ADMIN_DSN, database=name)
        migrate = ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name)
        asyncio.run(apply(MigrateConfig(migrate=migrate, admin=spec)))

        async def seed() -> Rig:
            conn = await asyncpg.connect(_dsn(name, None))
            try:
                return Rig(name, await _tenant(conn, "jobsa"), await _tenant(conn, "jobsb"))
            finally:
                await conn.close()

        yield asyncio.run(seed())
    finally:
        asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


@dataclass
class Upstream:
    """A fake provider: records requests, answers with ``status`` (or raises ``error``)."""

    status: int = 200
    error: Exception | None = None
    requests: list[httpx.Request] = field(default_factory=list)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return httpx.Response(self.status, json={"data": []})

    def factory(self) -> Callable[[Any], httpx.AsyncBaseTransport]:
        return lambda _dev_hosts: httpx.MockTransport(self.handler)


@dataclass
class Worker:
    rig: Rig
    db: Database
    app_db: Database
    upstream: Upstream
    env: JobEnv

    def runner(self, **kw: Any) -> JobRunner:
        return JobRunner(self.env, **kw)


@pytest.fixture
async def worker(rig: Rig) -> AsyncIterator[Worker]:
    db = await Database.connect(_dsn(rig.db_name, "sibyl_worker"), min_size=1, max_size=4)
    app_db = await Database.connect(_dsn(rig.db_name, "sibyl_app"), min_size=1, max_size=2)
    upstream = Upstream()
    env = JobEnv(db, SETTINGS, extras={"probe_transport": upstream.factory()})
    try:
        yield Worker(rig, db, app_db, upstream, env)
    finally:
        await db.close()
        await app_db.close()


class Unlimited:
    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)


def _human(tenant: UUID, user: UUID, roles: tuple[str, ...] = ("owner",)) -> Principal:
    return Principal(
        kind=PrincipalKind.SESSION,
        tenant_id=tenant,
        id=user,
        grants=grants_from_memberships(MembershipGrant(r, None) for r in roles),
        session_id=uuid4(),
        step_up_at=datetime.now(UTC) + timedelta(days=1),
        roles=frozenset(roles),
    )


@pytest.fixture(scope="module")
def api(rig: Rig) -> Iterator[TestClient]:
    resolver = StaticTokenResolver(
        {
            "owner-a": _human(rig.a.id, rig.a.owner),
            "other-a": _human(rig.a.id, rig.a.other_user),
            "owner-b": _human(rig.b.id, rig.b.owner),
        }
    )
    services = Services(principals=resolver, rate_limiter=Unlimited(), settings=SETTINGS)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = await Database.connect(_dsn(rig.db_name, "sibyl_app"), min_size=1, max_size=4)
        services.db = db
        services.idempotency = PgIdempotencyStore(db)
        try:
            yield
        finally:
            await db.close()

    with TestClient(create_app(services, lifespan=lifespan), raise_server_exceptions=False) as c:
        yield c
