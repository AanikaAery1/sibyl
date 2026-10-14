"""Fresh PG17 databases for harness runs (localhost:5433 by default).

A run never shares a database with another run. Building the seeded world (migrations, `sibyl
seed`, keys) takes tens of seconds, so it happens once per *template*: a database named after a
fingerprint of the migrations and the harness world version. Each run then clones the template
(`CREATE DATABASE … TEMPLATE …`, about a second) and drops its clone at the end. The template is
built under an advisory lock so two harness processes never race to build it.

Setup-time writes made here as the cluster admin are fixture work on a database no product
process has touched yet (partitions ahead, the dev-host allowlist, the snapshot signing key);
nothing here writes a derived table (ML §8.1 rule 1).
"""

from __future__ import annotations

import hashlib
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import asyncpg

ADMIN_DSN_ENV = "SIBYL_PG_ADMIN_DSN"
DEFAULT_ADMIN_DSN = "postgresql://postgres@localhost:5433/postgres"
TEMPLATE_PREFIX = "sibyl_simtpl_"
RUN_PREFIX = "sibyl_sim_"
READY_COMMENT = "sibyl-sim template ready"
WORLD_VERSION = "world/8"  # bump when the world builder changes what a template contains


def admin_dsn() -> str:
    return os.environ.get(ADMIN_DSN_ENV, DEFAULT_ADMIN_DSN)


def dsn_for(database: str, role: str | None = None, *, base: str | None = None) -> str:
    """DSN for `database` as `role` (trust auth on the dev cluster), or as the admin."""
    parts = urlsplit(base or admin_dsn())
    host = parts.netloc.rsplit("@", 1)[-1]
    netloc = f"{role}@{host}" if role else parts.netloc
    return urlunsplit((parts.scheme, netloc, f"/{database}", "", ""))


def fingerprint(extra: str = "") -> str:
    """Stable id of everything a template depends on: migration files, seed, world version."""
    from sibyl_control.cli import seed as seed_module
    from sibyl_control.migrate.runner import discover

    digest = hashlib.sha256(WORLD_VERSION.encode())
    for migration in discover():
        digest.update(f"{migration.version}:{migration.checksum}".encode())
    seed_file = seed_module.__file__
    assert seed_file is not None  # a regular module, never a namespace package
    digest.update(Path(seed_file).read_bytes())
    digest.update(extra.encode())
    return digest.hexdigest()[:16]


async def available(timeout_s: float = 3.0) -> bool:
    try:
        conn = await asyncpg.connect(admin_dsn(), timeout=timeout_s)
    except asyncpg.TooManyConnectionsError:
        return True  # up but full (shared dev cluster): the stack start waits for a slot
    except (OSError, asyncpg.PostgresError):
        return False
    await conn.close()
    return True


async def admin_exec(sql: str, *args: Any, database: str | None = None) -> Any:
    conn = await asyncpg.connect(dsn_for(database) if database else admin_dsn())
    try:
        return await conn.execute(sql, *args)
    finally:
        await conn.close()


async def admin_fetchval(sql: str, *args: Any, database: str | None = None) -> Any:
    conn = await asyncpg.connect(dsn_for(database) if database else admin_dsn())
    try:
        return await conn.fetchval(sql, *args)
    finally:
        await conn.close()


async def exists(name: str) -> bool:
    return bool(await admin_fetchval("SELECT 1 FROM pg_database WHERE datname = $1", name))


async def is_ready_template(name: str) -> bool:
    comment = await admin_fetchval(
        "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1", name
    )
    return bool(comment == READY_COMMENT)


async def drop(name: str) -> None:
    await admin_exec(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


async def create_empty(name: str) -> None:
    await admin_exec(f'CREATE DATABASE "{name}"')


async def migrate(name: str) -> None:
    from sibyl_control.migrate.config import ConnSpec, MigrateConfig
    from sibyl_control.migrate.runner import apply

    base = admin_dsn()
    await apply(
        MigrateConfig(
            migrate=ConnSpec(dsn=base, user="sibyl_migrate", database=name),
            admin=ConnSpec(dsn=base, user=None, database=name),
        )
    )


async def ensure_partitions(name: str) -> None:
    """What the (lane U) partitions loop does, once, before any product process starts."""
    await admin_exec("SELECT sibyl.partition_ensure_ahead(now())", database=name)


async def mark_ready(name: str) -> None:
    await admin_exec(f"COMMENT ON DATABASE \"{name}\" IS '{READY_COMMENT}'")


@asynccontextmanager
async def build_lock(key: str) -> AsyncIterator[None]:
    conn = await asyncpg.connect(admin_dsn())
    try:
        await conn.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", key)
        try:
            yield
        finally:
            await conn.execute("SELECT pg_advisory_unlock(hashtextextended($1, 0))", key)
    finally:
        await conn.close()


async def clone(template: str) -> str:
    name = f"{RUN_PREFIX}{secrets.token_hex(5)}"
    await admin_exec(f'CREATE DATABASE "{name}" TEMPLATE "{template}"')
    await ensure_partitions(name)
    return name


@dataclass(frozen=True)
class RoleDsns:
    app: str
    ingest: str
    worker: str
    migrate: str
    admin: str

    @classmethod
    def for_database(cls, name: str) -> RoleDsns:
        return cls(
            app=dsn_for(name, "sibyl_app"),
            ingest=dsn_for(name, "sibyl_ingest"),
            worker=dsn_for(name, "sibyl_worker"),
            migrate=dsn_for(name, "sibyl_migrate"),
            admin=dsn_for(name),
        )
