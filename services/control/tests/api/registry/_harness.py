"""Lane R test harness: a migrated PG17 database, two tenants, real users and the api.

Shared by ``tests/api/{registry,policy,credentials}`` (each conftest loads this file). One
throw-away database ``sibyl_r_<hex>`` per test module on the dev cluster
(``SIBYL_PG_ADMIN_DSN``), dropped afterwards; skipped when the cluster is down. The app runs
with the real ``Database`` (as ``sibyl_app``, opened in the app lifespan so the pool lives on
the TestClient loop), ``PgIdempotencyStore``, ``PgOutboxWriter`` and ``PgAuditWriter`` wrapped
by a recorder; principals come from ``StaticTokenResolver`` and are the tenant's real users.
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.core.audit import AuditReceipt, AuditRecord, PgAuditWriter
from sibyl_control.core.authz import (
    KEY_SCOPES,
    MONITOR_SCOPES,
    MembershipGrant,
    Principal,
    PrincipalKind,
    grants_for_api_key,
    grants_from_memberships,
)
from sibyl_control.core.crypto.deks import new_wrapped_dek
from sibyl_control.core.crypto.envelope import PURPOSES, LocalKek
from sibyl_control.core.db import Database
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.ratelimit import RateDecision, RatePolicy
from sibyl_control.core.settings import Settings
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
KEK_ID = "kek-lane-r-test"
KEK_MATERIAL = bytes(range(32))
KEK_ENV = base64.urlsafe_b64encode(KEK_MATERIAL).decode().rstrip("=")
DEV_HOSTS = ("sibyl-sim",)
ROLES = ("owner", "admin", "security_admin", "engineer", "operator", "auditor", "viewer")
FRESH = datetime.now(UTC) + timedelta(days=1)  # step-up "fresh" for the whole module


def kek() -> LocalKek:
    return LocalKek(KEK_ID, KEK_MATERIAL)


class SyncConn:
    """A synchronous facade over one asyncpg connection (setup and assertions)."""

    def __init__(self, loop: asyncio.AbstractEventLoop, conn: asyncpg.Connection) -> None:
        self._loop = loop
        self.raw = conn

    def run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def execute(self, sql: str, *args: Any) -> Any:
        return self.run(self.raw.execute(sql, *args))

    def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        return self.run(self.raw.fetch(sql, *args))

    def fetchrow(self, sql: str, *args: Any) -> asyncpg.Record | None:
        return self.run(self.raw.fetchrow(sql, *args))

    def fetchval(self, sql: str, *args: Any) -> Any:
        return self.run(self.raw.fetchval(sql, *args))

    def in_tenant(self, tenant_id: UUID, sql: str, *args: Any) -> Any:
        """Run one statement in a transaction scoped to ``tenant_id`` (SECURITY DEFINER
        triggers, e.g. the graph-version outbox row, run under RLS and need the tenant)."""

        async def run() -> Any:
            async with self.raw.transaction():
                await self.raw.execute("SELECT sibyl.set_tenant($1)", tenant_id)
                return await self.raw.fetch(sql, *args)

        return self.run(run())

    def close(self) -> None:
        self.run(self.raw.close())


class Unlimited:
    """Rate limiter that never refuses (handler tests are not rate-limit tests)."""

    def _ok(self, policy: RatePolicy) -> RateDecision:
        return RateDecision(True, policy, policy.quota, 0, 0)

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return self._ok(policy)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return self._ok(policy)


class RecordingAuditWriter:
    """``PgAuditWriter`` plus a per-tenant list of the actions it appended."""

    def __init__(self) -> None:
        self._inner = PgAuditWriter()
        self.rows: dict[UUID, list[AuditRecord]] = {}

    async def append(self, conn: Any, tenant_id: UUID, record: AuditRecord) -> AuditReceipt:
        receipt = await self._inner.append(conn, tenant_id, record)
        self.rows.setdefault(tenant_id, []).append(record)
        return receipt

    def actions(self, tenant_id: UUID) -> list[str]:
        return [r.action for r in self.rows.get(tenant_id, [])]

    def clear(self) -> None:
        self.rows.clear()


@dataclass
class Tenant:
    id: UUID
    slug: str
    issuer_id: UUID
    group_id: UUID
    other_group_id: UUID
    users: dict[str, UUID] = field(default_factory=dict)


@dataclass
class World:
    db_name: str
    loop: asyncio.AbstractEventLoop
    admin: SyncConn
    client: TestClient
    audit: RecordingAuditWriter
    resolver: StaticTokenResolver
    a: Tenant
    b: Tenant
    settings: Settings

    def headers(self, token: str, **extra: str) -> dict[str, str]:
        out = {"Authorization": f"Bearer {token}"}
        out.update(extra)
        return out

    def idem(self, who: str = "owner", **extra: str) -> dict[str, str]:
        return self.headers(who, **{"Idempotency-Key": str(uuid4()), **extra})

    def add_key(
        self,
        token: str,
        tenant: Tenant,
        *,
        scopes: frozenset[str] = KEY_SCOPES - {"killswitch:pull"} - MONITOR_SCOPES,
        agent_id: UUID | None = None,
    ) -> UUID:
        key_id = uuid4()
        self.resolver.add(
            token,
            Principal(
                PrincipalKind.API_KEY,
                tenant.id,
                key_id,
                grants_for_api_key(scopes),
                bound_agent_id=agent_id,
            ),
        )
        return key_id

    def as_tenant(self, tenant: Tenant, sql: str, *args: Any) -> list[asyncpg.Record]:
        """Admin read (superuser, RLS bypassed) narrowed to ``tenant`` by the caller's SQL."""
        return self.admin.fetch(sql, *args)


def _app_dsn(name: str) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"sibyl_app@{host}", f"/{name}", "", ""))


def _spec(name: str, role: str | None) -> ConnSpec:
    return ConnSpec(dsn=ADMIN_DSN, user=role, database=name)


def _available(loop: asyncio.AbstractEventLoop) -> bool:
    async def probe() -> bool:
        try:
            conn = await asyncpg.connect(ADMIN_DSN, timeout=3)
        except (OSError, asyncpg.PostgresError):
            return False
        await conn.close()
        return True

    return loop.run_until_complete(probe())


async def _admin_exec(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def add_dev_hosts(loop: asyncio.AbstractEventLoop, name: str, hosts: tuple[str, ...]) -> None:
    """``base_url_dev_host`` is writable only by ``sibyl_migrate`` (G0)."""

    async def run() -> None:
        conn = await asyncpg.connect(**_spec(name, "sibyl_migrate").kwargs())
        try:
            for host in hosts:
                await conn.execute(
                    "INSERT INTO sibyl.base_url_dev_host (host, note) VALUES ($1, 'lane R tests')"
                    " ON CONFLICT DO NOTHING",
                    host,
                )
        finally:
            await conn.close()

    loop.run_until_complete(run())


def create_tenant(admin: SyncConn, slug: str) -> Tenant:
    tenant_id = uuid4()
    deks = [new_wrapped_dek(kek(), tenant_id, purpose, 1).wrapped for purpose in PURPOSES]
    admin.fetchval(
        "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', $3, $4, $5, $6, NULL, $7)",
        slug,
        slug.title(),
        KEK_ID,
        *deks,
        tenant_id,
    )
    issuer, group, other = uuid4(), uuid4(), uuid4()
    admin.execute(
        "INSERT INTO sibyl.oidc_issuer (tenant_id, id, issuer_url, client_id)"
        " VALUES ($1, $2, $3, 'sibyl')",
        tenant_id,
        issuer,
        f"https://dex.example.com/{slug}",
    )
    for gid, gslug in ((group, "ops"), (other, "finance")):
        admin.execute(
            "INSERT INTO sibyl.agent_group (tenant_id, id, slug, name) VALUES ($1, $2, $3, $3)",
            tenant_id,
            gid,
            gslug,
        )
    tenant = Tenant(tenant_id, slug, issuer, group, other)
    for role in (*ROLES, "approver"):
        uid = uuid4()
        admin.execute(
            "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
            " display_name, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')",
            tenant_id,
            uid,
            issuer,
            f"{slug}-{role}",
            f"{role}@{slug}.example.com",
            role.title(),
        )
        tenant.users[role] = uid
    return tenant


def _human(
    tenant: Tenant, user: str, roles: tuple[str, ...], group: UUID | None = None
) -> Principal:
    return Principal(
        kind=PrincipalKind.SESSION,
        tenant_id=tenant.id,
        id=tenant.users[user],
        grants=grants_from_memberships(MembershipGrant(r, group) for r in roles),
        session_id=uuid4(),
        step_up_at=FRESH,
        roles=frozenset(roles),
    )


def tokens_for(a: Tenant, b: Tenant) -> dict[str, Principal]:
    out = {role: _human(a, role, (role,)) for role in ROLES if role != "engineer"}
    out["engineer"] = _human(a, "engineer", ("engineer",), a.group_id)
    out["approver"] = _human(a, "approver", ("security_admin",))
    stale = _human(a, "owner", ("owner",))
    out["owner-stale"] = Principal(
        stale.kind,
        stale.tenant_id,
        stale.id,
        stale.grants,
        stale.session_id,
        step_up_at=datetime.now(UTC) - timedelta(hours=1),
        roles=stale.roles,
    )
    out["nobody"] = _human(a, "viewer", ())
    out["owner-b"] = _human(b, "owner", ("owner",))
    return out


@pytest.fixture(scope="module")
def world() -> Iterator[World]:
    loop = asyncio.new_event_loop()
    if not _available(loop):
        loop.close()
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_r_{secrets.token_hex(6)}"
    loop.run_until_complete(_admin_exec(f'CREATE DATABASE "{name}"'))
    admin: SyncConn | None = None
    try:
        loop.run_until_complete(
            apply(MigrateConfig(migrate=_spec(name, "sibyl_migrate"), admin=_spec(name, None)))
        )
        add_dev_hosts(loop, name, DEV_HOSTS)
        admin = SyncConn(
            loop, loop.run_until_complete(asyncpg.connect(**_spec(name, None).kwargs()))
        )
        a = create_tenant(admin, "acme")
        b = create_tenant(admin, "globex")
        resolver = StaticTokenResolver(tokens_for(a, b))
        audit = RecordingAuditWriter()
        settings = Settings(kek=SecretStr(KEK_ENV), kek_id=KEK_ID)
        services = Services(
            principals=resolver, audit=audit, rate_limiter=Unlimited(), settings=settings
        )

        @asynccontextmanager
        async def lifespan(app: FastAPI) -> AsyncIterator[None]:
            db = await Database.connect(_app_dsn(name), min_size=1, max_size=4)
            services.db = db
            services.idempotency = PgIdempotencyStore(db)
            try:
                yield
            finally:
                await db.close()

        app = create_app(services, lifespan=lifespan)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield World(name, loop, admin, client, audit, resolver, a, b, settings)
    finally:
        if admin is not None:
            admin.close()
        loop.run_until_complete(_admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        loop.close()
