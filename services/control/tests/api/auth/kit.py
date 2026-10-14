"""Lane A/V test kit: one migrated PG17 database per test session, seed helpers, app factory.

Loaded by path from every lane conftest as the module ``sibyl_lane_a_kit`` (the sibling test
directories are not one package), so all five suites share one database. The database is
``sibyl_lanea_<hex>`` on ``SIBYL_PG_ADMIN_DSN`` (default the dev PG17 on :5433), migrated by the
real runner (bootstrap as admin, the rest as ``sibyl_migrate``) and dropped when the last suite
releases it. The api runs as ``sibyl_app`` with the real resolver chain, the Pg idempotency
store, the Pg audit/outbox writers and a local fake OIDC issuer.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import os
import secrets
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import httpx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sibyl_control.api.app import create_app
from sibyl_control.api.auth.common import LANE_STATE
from sibyl_control.api.auth.config import AuthSettings
from sibyl_control.api.auth.oidc import OidcClient
from sibyl_control.api.auth.principals import build_principal_resolver, session_token_hash
from sibyl_control.api.deps import Services
from sibyl_control.core.crypto.deks import dek_wrap_aad as wrap_aad
from sibyl_control.core.crypto.envelope import LocalKek
from sibyl_control.core.db import Database, _init_connection
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.settings import Settings
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
KEK_ID = "test-kek"
KEK_MATERIAL = hashlib.sha256(b"sibyl lane a test kek").digest()
KEK_B64 = base64.urlsafe_b64encode(KEK_MATERIAL).rstrip(b"=").decode()
TEST_KEK = LocalKek(KEK_ID, KEK_MATERIAL)
PEPPER_HEX = hashlib.sha256(b"sibyl lane a pepper").hexdigest()
SESSION_SECRET = "lane-a-session-secret-0123456789abcdef"  # noqa: S105  (test fixture)
PUBLIC_URL = "https://sibyl.test"
RAISE = os.environ.get("SIBYL_LANE_RAISE") == "1"  # debug: surface server exceptions


def _load(name: str, filename: str) -> Any:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


FakeIssuer = _load("sibyl_lane_a_fake_issuer", "fake_issuer.py").FakeIssuer

if RAISE:  # debug aid: show which database error a 500 problem came from
    from sibyl_control.api.auth import common as _common

    _orig = _common.problem_from_db_error

    def _loud(exc: BaseException) -> Any:
        print("DB ERROR:", getattr(exc, "sqlstate", None), exc)
        return _orig(exc)

    _common.problem_from_db_error = _loud


# ---- database ----------------------------------------------------------------------------------


class Conn:
    """Synchronous facade over one asyncpg connection (admin or a login role)."""

    def __init__(self, loop: asyncio.AbstractEventLoop, conn: asyncpg.Connection) -> None:
        self._loop = loop
        self.raw = conn

    def run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def execute(self, sql: str, *args: Any) -> str:
        return self.run(self.raw.execute(sql, *args))

    def fetch(self, sql: str, *args: Any) -> list[Any]:
        return self.run(self.raw.fetch(sql, *args))

    def fetchrow(self, sql: str, *args: Any) -> Any:
        return self.run(self.raw.fetchrow(sql, *args))

    def fetchval(self, sql: str, *args: Any) -> Any:
        return self.run(self.raw.fetchval(sql, *args))

    @contextmanager
    def tx(self, tenant: UUID | None = None) -> Iterator[Conn]:
        transaction = self.raw.transaction()
        self.run(transaction.start())
        try:
            if tenant is not None:
                self.execute("SELECT sibyl.set_tenant($1)", tenant)
            yield self
        except BaseException:
            self.run(transaction.rollback())
            raise
        self.run(transaction.commit())

    def close(self) -> None:
        self.run(self.raw.close())


@dataclass
class LaneDb:
    name: str
    loop: asyncio.AbstractEventLoop
    admin: Conn

    def dsn(self, role: str = "sibyl_app") -> str:
        parts = urlsplit(ADMIN_DSN)
        host = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, f"{role}@{host}", f"/{self.name}", "", ""))


_STATE: dict[str, Any] = {"refs": 0, "db": None}


async def _admin_exec(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN, timeout=5)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


def available() -> bool:
    loop = asyncio.new_event_loop()
    try:
        conn = loop.run_until_complete(asyncpg.connect(ADMIN_DSN, timeout=3))
        loop.run_until_complete(conn.close())
        return True
    except (OSError, asyncpg.PostgresError):
        return False
    finally:
        loop.close()


def acquire() -> LaneDb:
    """The shared, fully migrated lane database (created on first use)."""
    _STATE["refs"] += 1
    if _STATE["db"] is None:
        loop = asyncio.new_event_loop()
        name = f"sibyl_lanea_{secrets.token_hex(6)}"
        loop.run_until_complete(_admin_exec(f'CREATE DATABASE "{name}"'))
        spec = ConnSpec(dsn=ADMIN_DSN, user=None, database=name)
        migrate = ConnSpec(dsn=ADMIN_DSN, user="sibyl_migrate", database=name)
        loop.run_until_complete(apply(MigrateConfig(migrate=migrate, admin=spec)))
        raw = loop.run_until_complete(asyncpg.connect(**spec.kwargs()))
        loop.run_until_complete(_init_connection(raw))
        admin = Conn(loop, raw)
        _STATE["db"] = LaneDb(name, loop, admin)
    db: LaneDb = _STATE["db"]
    return db


def release() -> None:
    _STATE["refs"] -= 1
    db: LaneDb | None = _STATE["db"]
    if _STATE["refs"] > 0 or db is None:
        return
    db.admin.close()
    db.loop.run_until_complete(_admin_exec(f'DROP DATABASE IF EXISTS "{db.name}" WITH (FORCE)'))
    db.loop.close()
    _STATE["db"] = None


# ---- seed helpers (admin connection, always inside the tenant's transaction context) -----------


@dataclass
class World:
    """One seeded tenant: issuer, users by role, groups, agents."""

    tenant: UUID
    slug: str
    issuer_id: UUID
    issuer_url: str
    users: dict[str, UUID] = field(default_factory=dict)
    subjects: dict[str, str] = field(default_factory=dict)
    groups: dict[str, UUID] = field(default_factory=dict)
    agents: dict[str, UUID] = field(default_factory=dict)


def make_tenant(db: LaneDb, slug: str | None = None) -> tuple[UUID, str]:
    slug = slug or f"t{secrets.token_hex(5)}"
    tenant = uuid4()
    wrapped = [
        TEST_KEK.wrap(os.urandom(32), wrap_aad(tenant, p, 1))
        for p in ("payload", "credential", "config")
    ]
    with db.admin.tx():
        db.admin.fetchval(
            "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', $3, $4, $5, $6, NULL, $7)",
            slug,
            slug.title(),
            KEK_ID,
            *wrapped,
            tenant,
        )
    return tenant, slug


def add_issuer(
    db: LaneDb, tenant: UUID, url: str, *, client_id: str = "sibyl-console", **cols: Any
) -> UUID:
    issuer = uuid4()
    names = ["tenant_id", "id", "issuer_url", "client_id", *cols]
    values = [tenant, issuer, url, client_id, *cols.values()]
    marks = ", ".join(f"${i + 1}" for i in range(len(values)))
    with db.admin.tx(tenant):
        db.admin.execute(
            f"INSERT INTO sibyl.oidc_issuer ({', '.join(names)}) VALUES ({marks})",  # noqa: S608 (constant SQL fragments, no input)
            *values,
        )
    return issuer


def add_group(db: LaneDb, tenant: UUID, slug: str, parent: UUID | None = None) -> UUID:
    with db.admin.tx(tenant):
        return db.admin.fetchval(
            "INSERT INTO sibyl.agent_group (tenant_id, slug, name, parent_group_id)"
            " VALUES ($1, $2, $2, $3) RETURNING id",
            tenant,
            slug,
            parent,
        )


def add_user(
    db: LaneDb,
    tenant: UUID,
    issuer: UUID,
    *,
    roles: tuple[str, ...] = (),
    group: UUID | None = None,
    subject: str | None = None,
    email: str | None = None,
    status: str = "active",
) -> UUID:
    subject = subject or f"sub-{secrets.token_hex(6)}"
    email = email or f"{subject}@example.test"
    with db.admin.tx(tenant):
        user = db.admin.fetchval(
            "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email, email_verified,"
            " status) VALUES ($1, $2, $3, $4, true, $5) RETURNING id",
            tenant,
            issuer,
            subject,
            email,
            status,
        )
        for role in roles:
            scoped = group is not None and role not in (
                "owner",
                "admin",
                "security_admin",
                "auditor",
            )
            db.admin.execute(
                "INSERT INTO sibyl.membership (tenant_id, user_id, role_name, scope_kind, scope_id)"
                " VALUES ($1, $2, $3, $4, $5)",
                tenant,
                user,
                role,
                "agent_group" if scoped else "tenant",
                group if scoped else None,
            )
    return user


def add_agent(
    db: LaneDb, tenant: UUID, slug: str, *, group: UUID | None = None, tier: int = 3
) -> UUID:
    agent = uuid4()
    with db.admin.tx(tenant):
        db.admin.execute(
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, fail_mode, agent_group_id,"
            " tier, lifecycle) VALUES ($1, $2, $3, $3, 'autonomous_agent', 'open', $4, $5,"
            " 'deployed')",
            tenant,
            agent,
            slug,
            group,
            tier,
        )
        db.admin.fetchrow(
            "SELECT * FROM sibyl.routing_apply($1, $2, NULL, NULL, 'active', NULL, 'register',"
            " 'system', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, $3,"
            " 'route.changed', NULL, NULL, NULL, NULL)",
            tenant,
            agent,
            f"register:{agent}",
        )
    return agent


def add_capture_policy(db: LaneDb, tenant: UUID, chosen_by: UUID) -> None:
    with db.admin.tx(tenant):
        profile = db.admin.fetchval(
            "SELECT id FROM sibyl.redaction_profile WHERE tenant_id = $1 AND name = 'secrets_only'",
            tenant,
        )
        db.admin.execute(
            "INSERT INTO sibyl.capture_policy (tenant_id, scope_kind, capture_mode,"
            " redaction_profile_id, consequences_version, chosen_by, version_no)"
            " VALUES ($1, 'tenant', 'metadata', $2, 'c1', $3, 1)",
            tenant,
            profile,
            chosen_by,
        )


def add_session(
    db: LaneDb,
    tenant: UUID,
    user: UUID,
    *,
    step_up: bool = True,
    step_up_at: datetime | None = None,
) -> str:
    """A live console session for ``user``; returns the BFF bearer token."""
    value = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    with db.admin.tx(tenant):
        db.admin.execute(
            "INSERT INTO sibyl.session (tenant_id, user_id, token_hash, step_up_at)"
            " VALUES ($1, $2, $3, $4)",
            tenant,
            user,
            session_token_hash(value),
            step_up_at if step_up_at is not None else (now if step_up else None),
        )
    return f"sibyl_sess_{value}"


def world(db: LaneDb, issuer_url: str = "https://idp.test/dex") -> World:
    """A tenant with an issuer, the seven roles, two groups (g2 under g1) and three agents."""
    tenant, slug = make_tenant(db)
    issuer = add_issuer(db, tenant, issuer_url)
    w = World(tenant, slug, issuer, issuer_url)
    w.groups["g1"] = add_group(db, tenant, "group-one")
    w.groups["g2"] = add_group(db, tenant, "group-two", parent=w.groups["g1"])
    w.groups["other"] = add_group(db, tenant, "group-other")
    for role in ("owner", "admin", "security_admin", "operator", "auditor", "viewer"):
        subject = f"{role}-{secrets.token_hex(4)}"
        w.subjects[role] = subject
        w.users[role] = add_user(db, tenant, issuer, roles=(role,), subject=subject)
    w.subjects["engineer"] = f"engineer-{secrets.token_hex(4)}"
    w.users["engineer"] = add_user(
        db,
        tenant,
        issuer,
        roles=("engineer",),
        group=w.groups["g1"],
        subject=w.subjects["engineer"],
    )
    w.users["nobody"] = add_user(db, tenant, issuer)
    w.agents["in_g1"] = add_agent(db, tenant, "agent-in-g1", group=w.groups["g1"])
    w.agents["in_g2"] = add_agent(db, tenant, "agent-in-g2", group=w.groups["g2"], tier=1)
    w.agents["other"] = add_agent(db, tenant, "agent-other", group=w.groups["other"])
    return w


def audit_actions(db: LaneDb, tenant: UUID, since_seq: int = 0) -> list[str]:
    with db.admin.tx(tenant):
        rows = db.admin.fetch(
            "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2 ORDER BY seq",
            tenant,
            since_seq,
        )
    return [r["action"] for r in rows]


def audit_rows(db: LaneDb, tenant: UUID, action: str) -> list[Any]:
    with db.admin.tx(tenant):
        return db.admin.fetch(
            "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = $2 ORDER BY seq",
            tenant,
            action,
        )


def audit_head(db: LaneDb, tenant: UUID) -> int:
    with db.admin.tx(tenant):
        return int(
            db.admin.fetchval(
                "SELECT coalesce(max(seq), 0) FROM sibyl.audit_events WHERE tenant_id = $1", tenant
            )
        )


def outbox_events(db: LaneDb, tenant: UUID) -> list[Any]:
    with db.admin.tx(tenant):
        return db.admin.fetch(
            "SELECT * FROM sibyl.outbox WHERE tenant_id = $1 ORDER BY xid, id", tenant
        )


# ---- the app -----------------------------------------------------------------------------------


@dataclass
class Lane:
    client: TestClient
    app: FastAPI
    issuer: Any
    db: LaneDb
    settings: Settings
    services: Services

    def bearer(self, token: str, **headers: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", **headers}


def lane_settings(db: LaneDb, *, env: str = "test") -> Settings:
    return Settings(
        pg_dsn=db.dsn(),
        key_pepper=PEPPER_HEX,
        kek=KEK_B64,
        kek_id=KEK_ID,
        env=env,
        public_url=PUBLIC_URL,
    )


@contextmanager
def lane_app(
    db: LaneDb,
    issuer: Any | None = None,
    *,
    env: str = "test",
    clock: Any = None,
    extra_state: dict[str, Any] | None = None,
) -> Iterator[Lane]:
    issuer = issuer or FakeIssuer()
    settings = lane_settings(db, env=env)
    auth = AuthSettings(session_secret=SESSION_SECRET, oidc_client_secret=issuer.client_secret)
    services = Services(settings=settings)
    if clock is not None:
        services.clock = clock
    oidc = OidcClient(httpx.AsyncClient(transport=issuer.transport()))

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        database = await Database.connect(settings.dsn(), min_size=1, max_size=6)
        services.db = database
        services.idempotency = PgIdempotencyStore(database)
        services.principals = build_principal_resolver(
            services, settings, oidc=lambda: oidc, auth=auth
        )
        try:
            yield
        finally:
            await database.close()

    app = create_app(services, settings=settings, lifespan=lifespan)
    setattr(app.state, LANE_STATE, {"oidc": oidc, "auth_settings": auth, **(extra_state or {})})
    with TestClient(app, base_url=PUBLIC_URL, raise_server_exceptions=RAISE) as client:
        yield Lane(client, app, issuer, db, settings, services)


def idem() -> dict[str, str]:
    return {"Idempotency-Key": str(uuid4())}


def utcnow() -> datetime:
    return datetime.now(UTC)


def stale(minutes: int = 6) -> datetime:
    return utcnow() - timedelta(minutes=minutes)
