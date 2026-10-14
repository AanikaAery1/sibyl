"""Lane U test harness: migrated PG17, two tenants with real users and memberships, the api,
and a worker pool, so one test can drive api routes and housekeeping ticks against one database.

Reuses the lane R harness helpers (``tests/api/registry/_harness.py``, loaded by path) for the
database, tenants, users and principals; adds a second owner, owner memberships, an
``audit_anchor`` signing key, a filesystem BlobStore under a temp dir, the erasure-ledger key
file and a ``sibyl_worker`` ``Database`` on the harness loop for the housekeeping loops.
Shared by ``tests/api/governance`` and ``tests/worker/housekeeping`` (loaded by path).
"""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import logging
import os
import secrets
import sys
import tempfile
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sibyl_control.api.app import create_app
from sibyl_control.api.deps import Services, StaticTokenResolver
from sibyl_control.core.authz import Principal, PrincipalKind
from sibyl_control.core.blob.fs import FsBlobStore
from sibyl_control.core.crypto.deks import wrap_dek
from sibyl_control.core.db import Database, _init_connection
from sibyl_control.core.idempotency import PgIdempotencyStore
from sibyl_control.core.settings import Settings
from sibyl_control.migrate import ledger as ledger_mod
from sibyl_control.migrate.config import MigrateConfig
from sibyl_control.migrate.runner import apply
from sibyl_control.worker.housekeeping import common as hk_common
from sibyl_control.worker.jobs.runner import JobEnv, JobRunner
from sibyl_control.worker.loops import LoopContext


def _load_lane_r() -> Any:
    name = "sibyl_lane_r_harness"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "registry" / "_harness.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


R = _load_lane_r()
ADMIN_DSN = R.ADMIN_DSN
ANCHOR_KID = "anchor-test-1"
SUBJECT_SALT = "lane-u-subject-salt-0123456789"


def _role_dsn(name: str, role: str) -> str:
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"{role}@{host}", f"/{name}", "", ""))


@dataclass
class World:
    db_name: str
    loop: asyncio.AbstractEventLoop
    admin: Any  # lane R SyncConn (superuser)
    client: TestClient
    audit: Any
    resolver: StaticTokenResolver
    a: Any
    b: Any
    settings: Settings
    worker_db: Database
    blob: FsBlobStore
    anchor_key: Ed25519PrivateKey
    ledger_key: Ed25519PrivateKey
    ledger_public_path: Path
    tmp: Path
    log: logging.Logger = field(default_factory=lambda: logging.getLogger("sibyl.test.u"))

    # --- requests -------------------------------------------------------------------------

    def headers(self, token: str, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", **extra}

    def idem(self, who: str = "owner", **extra: str) -> dict[str, str]:
        return self.headers(who, **{"Idempotency-Key": str(uuid4()), **extra})

    def get(self, token: str, path: str, **kw: Any) -> Any:
        return self.client.get("/api/v1" + path, headers=self.headers(token), **kw)

    def post(self, token: str, path: str, body: Any, **extra: str) -> Any:
        return self.client.post("/api/v1" + path, json=body, headers=self.idem(token, **extra))

    # --- worker ---------------------------------------------------------------------------

    def run(self, coro: Any) -> Any:
        return self.loop.run_until_complete(coro)

    def ctx(self, name: str) -> LoopContext:
        return LoopContext(name, self.worker_db, self.settings, self.log)

    def tick(self, module: Any, name: str | None = None) -> None:
        self.run(module.tick(self.ctx(name or module.__name__.rsplit(".", 1)[-1])))

    def run_jobs(self, *kinds: str) -> int:
        """One ``JobRunner`` tick over ``kinds`` (default: every kind with a live handler) on
        the worker pool; → jobs finished."""
        runner = JobRunner(JobEnv(self.worker_db, self.settings), kinds=kinds or None)
        missing = set(kinds) - set(runner.handlers)
        assert not missing, f"no live job handler for {sorted(missing)}"
        finished: int = self.run(runner.run_once())
        return finished

    def settle_outbox(self, timeout_s: float = 20.0) -> None:
        """Wait until every committed outbox row is below the commit horizon (R60 readers skip
        rows above it). The dev cluster is shared with other suites, whose open transactions
        hold the cluster-wide horizon back for a moment; this waits them out deterministically.
        """
        newest = self.fetchval("SELECT max(xid) FROM sibyl.outbox")
        if newest is None:
            return
        deadline = time.monotonic() + timeout_s
        while not self.fetchval("SELECT sibyl.commit_horizon() > $1::xid8", newest):
            if time.monotonic() > deadline:
                raise AssertionError("commit horizon did not pass the outbox within the timeout")
            self.run(asyncio.sleep(0.05))

    # --- database -------------------------------------------------------------------------

    def fetch(self, sql: str, *args: Any) -> list[Any]:
        return self.admin.fetch(sql, *args)

    def fetchrow(self, sql: str, *args: Any) -> Any:
        return self.admin.fetchrow(sql, *args)

    def fetchval(self, sql: str, *args: Any) -> Any:
        return self.admin.fetchval(sql, *args)

    def in_tenant(self, tenant: UUID, sql: str, *args: Any) -> Any:
        return self.admin.in_tenant(tenant, sql, *args)

    def head(self, tenant: UUID) -> int:
        return int(
            self.fetchval("SELECT seq FROM sibyl.audit_chain_head WHERE tenant_id = $1", tenant)
        )

    def actions(self, tenant: UUID, since: int = -1) -> list[str]:
        rows = self.fetch(
            "SELECT action FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2 ORDER BY seq",
            tenant,
            since,
        )
        return [r["action"] for r in rows]

    def add_agent(self, tenant: Any, slug: str, *, group: UUID | None = None) -> UUID:
        agent_id = uuid4()
        self.in_tenant(
            tenant.id,
            "INSERT INTO sibyl.agent (tenant_id, id, slug, name, kind, agent_group_id, tier,"
            " fail_mode) VALUES ($1, $2, $3, $3, 'chatbot', $4, 3, 'open')",
            tenant.id,
            agent_id,
            slug,
            group or tenant.group_id,
        )
        return agent_id

    def anchor_public_raw(self) -> bytes:
        return self.anchor_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _seed_hex(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def _memberships(admin: Any, tenant: Any) -> None:
    for user, role in (
        ("owner", "owner"),
        ("owner2", "owner"),
        ("admin", "admin"),
        ("security_admin", "security_admin"),
        ("approver", "security_admin"),
        ("auditor", "auditor"),
        ("viewer", "viewer"),
        ("operator", "operator"),
    ):
        admin.execute(
            "INSERT INTO sibyl.membership (tenant_id, user_id, role_name) VALUES ($1, $2, $3)",
            tenant.id,
            tenant.users[user],
            role,
        )


def _add_user(admin: Any, tenant: Any, name: str) -> None:
    uid = uuid4()
    admin.execute(
        "INSERT INTO sibyl.app_user (tenant_id, id, oidc_issuer_id, subject, email,"
        " display_name, status) VALUES ($1, $2, $3, $4, $5, $6, 'active')",
        tenant.id,
        uid,
        tenant.issuer_id,
        f"{tenant.slug}-{name}",
        f"{name}@{tenant.slug}.example.com",
        name.title(),
    )
    tenant.users[name] = uid


def _create_tenant(admin: Any, slug: str) -> Any:
    """Lane R's ``create_tenant`` with the DEKs wrapped the way ingest and the payload route
    unwrap them (``build_aad(tenant, purpose, version)``). Lane R's vault wraps with a
    ``sibyl.tenant_key`` prefix; reconciling the two is INT-1's B11 work."""
    tenant_id = uuid4()
    kek = R.kek()
    deks = [
        wrap_dek(kek, tenant_id, purpose, 1, os.urandom(32))
        for purpose in ("payload", "credential", "config")
    ]
    admin.fetchval(
        "SELECT sibyl.tenant_create($1, $2, 'closed', 'eu-west', $3, $4, $5, $6, NULL, $7)",
        slug,
        slug.title(),
        R.KEK_ID,
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
    tenant = R.Tenant(tenant_id, slug, issuer, group, other)
    for role in (*R.ROLES, "approver"):
        _add_user(admin, tenant, role)
    return tenant


def _tokens(a: Any, b: Any) -> dict[str, Principal]:
    out = R.tokens_for(a, b)
    out["owner2"] = R._human(a, "owner2", ("owner",))
    out["owner-b"] = R._human(b, "owner", ("owner",))
    out["owner2-b"] = R._human(b, "owner2", ("owner",))
    stale = R._human(a, "security_admin", ("security_admin",))
    out["secadmin-stale"] = Principal(
        stale.kind,
        stale.tenant_id,
        stale.id,
        stale.grants,
        stale.session_id,
        step_up_at=datetime.now(UTC) - timedelta(hours=1),
        roles=stale.roles,
    )
    return out


@pytest.fixture(scope="module")
def world() -> Iterator[World]:
    loop = asyncio.new_event_loop()
    if not R._available(loop):
        loop.close()
        pytest.skip(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    name = f"sibyl_u_{secrets.token_hex(6)}"
    loop.run_until_complete(R._admin_exec(f'CREATE DATABASE "{name}"'))
    admin = None
    worker_db = None
    tmp = Path(tempfile.mkdtemp(prefix="sibyl-u-"))
    try:
        loop.run_until_complete(
            apply(MigrateConfig(migrate=R._spec(name, "sibyl_migrate"), admin=R._spec(name, None)))
        )
        raw_admin = loop.run_until_complete(asyncpg.connect(**R._spec(name, None).kwargs()))
        loop.run_until_complete(_init_connection(raw_admin))  # jsonb as Python objects
        admin = R.SyncConn(loop, raw_admin)
        a = _create_tenant(admin, "acme")
        b = _create_tenant(admin, "globex")
        for tenant in (a, b):
            _add_user(admin, tenant, "owner2")
            _memberships(admin, tenant)
        anchor_key = Ed25519PrivateKey.generate()
        admin.execute(
            "INSERT INTO sibyl.signing_key (kid, purpose, public_key, private_key_ref)"
            " VALUES ($1, 'audit_anchor', $2, 'env:SIBYL_ANCHOR_SIGNING_KEY')",
            ANCHOR_KID,
            _raw(anchor_key),
        )
        ledger_key = Ed25519PrivateKey.generate()
        ledger_file = tmp / "ledger.key"
        ledger_file.write_bytes(ledger_mod.private_key_pem(ledger_key))
        ledger_public = tmp / "ledger.pub"
        ledger_public.write_bytes(ledger_mod.public_key_pem(ledger_key.public_key()))
        blob_root = tmp / "blob"
        settings = Settings(
            kek=SecretStr(R.KEK_ENV),
            kek_id=R.KEK_ID,
            subject_salt=SecretStr(SUBJECT_SALT),
            blob_root=str(blob_root),
            anchor_signing_key=SecretStr(_seed_hex(anchor_key)),
            ledger_signing_key_file=str(ledger_file),
        )
        blob = FsBlobStore(blob_root)
        hk_common.install(settings, "blob", blob)
        resolver = StaticTokenResolver(_tokens(a, b))
        audit = R.RecordingAuditWriter()
        services = Services(
            principals=resolver, audit=audit, rate_limiter=R.Unlimited(), settings=settings
        )

        @asynccontextmanager
        async def lifespan(app: FastAPI) -> AsyncIterator[None]:
            db = await Database.connect(R._app_dsn(name), min_size=1, max_size=4)
            services.db = db
            services.idempotency = PgIdempotencyStore(db)
            try:
                yield
            finally:
                await db.close()

        worker_db = loop.run_until_complete(
            Database.connect(_role_dsn(name, "sibyl_worker"), min_size=1, max_size=3)
        )
        app = create_app(services, lifespan=lifespan)
        with TestClient(app, raise_server_exceptions=False) as client:
            yield World(
                name,
                loop,
                admin,
                client,
                audit,
                resolver,
                a,
                b,
                settings,
                worker_db,
                blob,
                anchor_key,
                ledger_key,
                ledger_public,
                tmp,
            )
    finally:
        if worker_db is not None:
            loop.run_until_complete(worker_db.close())
        if admin is not None:
            admin.close()
        loop.run_until_complete(R._admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        loop.close()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


__all__ = ["ANCHOR_KID", "SUBJECT_SALT", "World", "b64url", "world"]
_ = PrincipalKind  # re-exported for test modules that build principals
