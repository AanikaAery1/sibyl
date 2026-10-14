"""Session database for the W0-DB suites.

Creates ``sibyl_w0db_<random>`` on the local PG17 (``SIBYL_PG_ADMIN_DSN``, default
``postgresql://postgres@localhost:5433/postgres``), applies every migration through the real
runner (bootstrap as the admin, the rest as ``sibyl_migrate``) and drops it at the end.
Tests are synchronous; a private event loop drives asyncpg.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from sibyl_control.core.db import Database as KernelDatabase
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import apply

ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
LOGIN_ROLES = ("sibyl_app", "sibyl_ingest", "sibyl_worker")


class Conn:
    """A synchronous facade over one asyncpg connection."""

    def __init__(self, loop: asyncio.AbstractEventLoop, conn: asyncpg.Connection) -> None:
        self._loop = loop
        self.raw = conn

    def run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def execute(self, sql: str, *args: Any) -> str:
        return self.run(self.raw.execute(sql, *args))

    def fetch(self, sql: str, *args: Any) -> list[asyncpg.Record]:
        return self.run(self.raw.fetch(sql, *args))

    def fetchrow(self, sql: str, *args: Any) -> asyncpg.Record | None:
        return self.run(self.raw.fetchrow(sql, *args))

    def fetchval(self, sql: str, *args: Any) -> Any:
        return self.run(self.raw.fetchval(sql, *args))

    @contextmanager
    def tx(self, tenant: Any = None, *, rollback: bool = False) -> Iterator[Conn]:
        """A transaction, scoped to ``tenant`` when given; rolled back on error or on request."""
        transaction = self.raw.transaction()
        self.run(transaction.start())
        try:
            if tenant is not None:
                self.execute("SELECT sibyl.set_tenant($1)", tenant)
            yield self
        except BaseException:
            self.run(transaction.rollback())
            raise
        if rollback:
            self.run(transaction.rollback())
        else:
            self.run(transaction.commit())

    def close(self) -> None:
        self.run(self.raw.close())


@dataclass
class Database:
    name: str
    loop: asyncio.AbstractEventLoop

    def spec(self, role: str | None = None) -> ConnSpec:
        return ConnSpec(dsn=ADMIN_DSN, user=role, database=self.name)

    def connect(self, role: str | None = None) -> Conn:
        """Connect as ``role`` (a Sibyl login role) or, with None, as the admin superuser."""
        conn = self.loop.run_until_complete(asyncpg.connect(**self.spec(role).kwargs()))
        return Conn(self.loop, conn)

    def migrate_config(self) -> MigrateConfig:
        return MigrateConfig(migrate=self.spec("sibyl_migrate"), admin=self.spec(None))


def pg_required(env: dict[str, str] | None = None) -> bool:
    """CI (``CI=1``) or an explicit ``SIBYL_REQUIRE_PG=1`` turns a missing database into a
    failure: a skipped DB suite must never let the pipeline go green (G0-tests F1)."""
    source = os.environ if env is None else env
    return any(
        source.get(name, "").lower() in ("1", "true", "yes") for name in ("CI", "SIBYL_REQUIRE_PG")
    )


def unavailable(reason: str) -> None:
    """Fail under CI, skip on a developer machine."""
    if pg_required():
        pytest.fail(f"{reason} (required: CI / SIBYL_REQUIRE_PG is set)", pytrace=False)
    pytest.skip(reason)


def _admin_available(loop: asyncio.AbstractEventLoop) -> bool:
    async def probe() -> bool:
        try:
            conn = await asyncpg.connect(ADMIN_DSN, timeout=3)
        except (OSError, asyncpg.PostgresError):
            return False
        await conn.close()
        return True

    return loop.run_until_complete(probe())


@pytest.fixture(scope="session")
def loop() -> Iterator[asyncio.AbstractEventLoop]:
    event_loop = asyncio.new_event_loop()
    yield event_loop
    event_loop.close()


@pytest.fixture(scope="session")
def database_factory(loop: asyncio.AbstractEventLoop) -> Iterator[Any]:
    if not _admin_available(loop):
        unavailable(f"PostgreSQL 17 not reachable at {ADMIN_DSN} (make db-up)")
    created: list[str] = []

    def create(migrate: bool = True) -> Database:
        name = f"sibyl_w0db_{secrets.token_hex(6)}"
        loop.run_until_complete(_admin_exec(f'CREATE DATABASE "{name}"'))
        created.append(name)
        db = Database(name=name, loop=loop)
        if migrate:
            loop.run_until_complete(apply(db.migrate_config()))
        return db

    yield create
    for name in created:
        loop.run_until_complete(_admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))


async def _admin_exec(sql: str) -> None:
    conn = await asyncpg.connect(ADMIN_DSN)
    try:
        await conn.execute(sql)
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def db(database_factory: Any) -> Database:
    """The shared, fully migrated session database."""
    return database_factory()


@pytest.fixture(scope="session")
def admin(db: Database) -> Iterator[Conn]:
    conn = db.connect(None)
    yield conn
    conn.close()


@pytest.fixture(scope="session")
def roles(db: Database) -> Iterator[dict[str, Conn]]:
    conns = {role: db.connect(role) for role in LOGIN_ROLES}
    yield conns
    for conn in conns.values():
        conn.close()


def app_dsn(db: Database) -> str:
    """DSN for the ``sibyl_app`` login role on ``db`` (trust auth on the dev cluster)."""
    parts = urlsplit(ADMIN_DSN)
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, f"sibyl_app@{host}", f"/{db.name}", "", ""))


@pytest.fixture(scope="session")
def kernel_db(db: Database, loop: asyncio.AbstractEventLoop) -> Iterator[KernelDatabase]:
    """The kernel's own pooled ``Database`` as ``sibyl_app`` on the migrated session database."""
    database = loop.run_until_complete(KernelDatabase.connect(app_dsn(db), min_size=1, max_size=2))
    yield database
    loop.run_until_complete(database.close())
