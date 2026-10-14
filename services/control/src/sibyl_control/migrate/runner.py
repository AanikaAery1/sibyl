"""Plain-SQL migration runner (asyncpg).

* Migrations are ``NNNN_<name>.sql`` files, contiguous from 0000.
* ``0000`` carries ``-- sibyl:run-as=admin`` and is the only step run by the admin role; it
  creates the roles, schema, extensions and the ledger table ``sibyl.schema_migrations``.
* Every other migration runs as the non-superuser ``sibyl_migrate`` in one transaction with
  ``lock_timeout`` and ``statement_timeout`` set; the runner refuses to apply as a superuser.
* Each applied version is recorded with the sha256 of its file. A file edited after it was
  applied, or a version in the database that is missing on disk, stops the run.
* A session advisory lock serialises concurrent runners.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import random
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import asyncpg

from sibyl_control.migrate.config import LOGIN_ROLES, MIGRATE_ROLE, ConnSpec, MigrateConfig

FILENAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")
LOCK_KEY = "sibyl.migrate"
LOCK_TIMEOUT = "5s"
STATEMENT_TIMEOUT = "300s"


class MigrationError(RuntimeError):
    """Base class for runner failures."""


class ChecksumMismatchError(MigrationError):
    """An applied migration file changed on disk."""


class UnknownAppliedMigrationError(MigrationError):
    """The database has a version that is not on disk."""


class SuperuserRefusedError(MigrationError):
    """Migrations must apply as a non-superuser."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str
    run_as_admin: bool


@dataclass(frozen=True)
class MigrationStatus:
    version: int
    name: str
    state: str  # applied | pending | modified | missing (applied, no longer on disk)


CONTAINER_MIGRATIONS_DIR = Path("/app/migrations")


def default_migrations_dir() -> Path:
    """Resolve the migrations directory: env override, then source tree, then container path."""
    override = os.environ.get("SIBYL_MIGRATIONS_DIR")
    if override:
        return Path(override)
    source_tree = Path(__file__).resolve().parents[3] / "migrations"
    if source_tree.is_dir():
        return source_tree
    return CONTAINER_MIGRATIONS_DIR


def discover(directory: Path | None = None) -> tuple[Migration, ...]:
    """Load and validate the migration files in version order."""
    root = directory or default_migrations_dir()
    if not root.is_dir():
        raise MigrationError(f"migrations directory not found: {root}")
    found: list[Migration] = []
    for path in sorted(root.glob("*.sql")):
        match = FILENAME.match(path.name)
        if not match:
            raise MigrationError(f"unexpected file name {path.name}")
        raw = path.read_bytes()
        sql = raw.decode("utf-8")
        if not sql.strip():
            raise MigrationError(f"{path.name} is empty")
        found.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                path=path,
                sql=sql,
                checksum=hashlib.sha256(raw).hexdigest(),
                run_as_admin="-- sibyl:run-as=admin" in sql.splitlines()[0],
            )
        )
    if not found:
        raise MigrationError(f"no migrations found in {root}")
    for expected, migration in enumerate(found):
        if migration.version != expected:
            raise MigrationError(
                f"migration versions must be contiguous from 0; found {migration.path.name}"
            )
        if migration.run_as_admin != (migration.version == 0):
            raise MigrationError("only 0000 may (and must) run as the admin role")
    return tuple(found)


async def _connect(spec: ConnSpec) -> asyncpg.Connection:
    return await asyncpg.connect(**spec.kwargs())


async def _applied(conn: asyncpg.Connection) -> dict[int, str]:
    exists = await conn.fetchval("SELECT to_regclass('sibyl.schema_migrations') IS NOT NULL")
    if not exists:
        return {}
    rows = await conn.fetch("SELECT version, checksum FROM sibyl.schema_migrations")
    return {r["version"]: r["checksum"] for r in rows}


def _check_applied(migrations: Sequence[Migration], applied: dict[int, str]) -> None:
    by_version = {m.version: m for m in migrations}
    for version, checksum in sorted(applied.items()):
        migration = by_version.get(version)
        if migration is None:
            raise UnknownAppliedMigrationError(f"version {version:04d} is applied but not on disk")
        if migration.checksum != checksum:
            raise ChecksumMismatchError(
                f"{migration.path.name} was edited after it was applied; add a new migration "
                f"instead"
            )


SCRAM_ITERATIONS = 4096


def scram_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = SCRAM_ITERATIONS
) -> str:
    """A PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677), computed client-side like psql's
    \\password, so the plaintext never reaches the server or its statement log (G0 L6).
    Non-ASCII passwords are NFKC-normalised as the SASLprep mapping step does."""
    normalised = password if password.isascii() else unicodedata.normalize("NFKC", password)
    salt = os.urandom(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac("sha256", normalised.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    def b64(raw: bytes) -> str:
        return base64.b64encode(raw).decode("ascii")

    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


async def _set_passwords(conn: asyncpg.Connection, passwords: dict[str, str]) -> None:
    for role in (*LOGIN_ROLES, MIGRATE_ROLE):
        password = passwords.get(role)
        if password:
            statement = await conn.fetchval(
                "SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text)",
                role,
                scram_verifier(password),
            )
            await conn.execute(statement)


BOOTSTRAP_ATTEMPTS = 8


def _is_cluster_race(exc: BaseException) -> bool:
    """0000 updates cluster-wide catalogue rows (pg_authid, default ACLs, database ACLs).
    Advisory locks are per database, so two databases bootstrapping at once can collide with
    'tuple concurrently updated' (XX000) or a deadlock; both are safe to retry because 0000
    is idempotent and runs in one transaction."""
    if not isinstance(exc, asyncpg.PostgresError):
        return False
    return exc.sqlstate in ("40001", "40P01") or (
        exc.sqlstate == "XX000" and "concurrently" in str(exc)
    )


async def _bootstrap(config: MigrateConfig, bootstrap: Migration) -> bool:
    """Apply 0000 as the admin when needed; always (re)apply role passwords. Retries the
    cross-database catalogue race with jittered backoff."""
    for attempt in range(BOOTSTRAP_ATTEMPTS):
        try:
            return await _bootstrap_once(config, bootstrap)
        except asyncpg.PostgresError as exc:
            if not _is_cluster_race(exc) or attempt == BOOTSTRAP_ATTEMPTS - 1:
                raise
            await asyncio.sleep(0.05 * (attempt + 1) + random.random() * 0.05)  # noqa: S311
    raise AssertionError("unreachable")  # pragma: no cover


async def _bootstrap_once(config: MigrateConfig, bootstrap: Migration) -> bool:
    if config.admin is None:
        return False
    conn = await _connect(config.admin)
    try:
        await conn.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", LOCK_KEY)
        applied = await _applied(conn)
        ran = False
        if 0 in applied:
            _check_applied([bootstrap], {0: applied[0]})
        else:
            async with conn.transaction():
                await conn.execute(bootstrap.sql)
                await conn.execute(
                    "INSERT INTO sibyl.schema_migrations (version, name, checksum) VALUES (0, $1, "
                    "$2)",
                    bootstrap.name,
                    bootstrap.checksum,
                )
            ran = True
        await _set_passwords(conn, dict(config.role_passwords))
        return ran
    finally:
        await conn.close()


async def _apply_one(conn: asyncpg.Connection, migration: Migration) -> None:
    try:
        await _apply_one_tx(conn, migration)
    except asyncpg.PostgresError as exc:
        raise MigrationError(f"{migration.path.name}: {type(exc).__name__}: {exc}") from exc


async def _apply_one_tx(conn: asyncpg.Connection, migration: Migration) -> None:
    async with conn.transaction():
        await conn.execute(
            f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'; SET LOCAL statement_timeout = "
            f"'{STATEMENT_TIMEOUT}'; "
            "SET LOCAL search_path = sibyl, pg_temp"
        )
        await conn.execute(migration.sql)
        await conn.execute("RESET ROLE")
        await conn.execute(
            "INSERT INTO sibyl.schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
            migration.version,
            migration.name,
            migration.checksum,
        )


async def apply(
    config: MigrateConfig,
    directory: Path | None = None,
    *,
    target: int | None = None,
    allow_superuser: bool = False,
) -> list[int]:
    """Bring the database up to ``target`` (default: latest). Returns the versions applied."""
    migrations = discover(directory)
    applied_now: list[int] = []
    if await _bootstrap(config, migrations[0]):
        applied_now.append(0)
    conn = await _connect(config.migrate)
    try:
        if not allow_superuser and await conn.fetchval(
            "SELECT rolsuper FROM pg_roles WHERE rolname = current_user"
        ):
            raise SuperuserRefusedError(
                "refusing to migrate as a superuser; connect as sibyl_migrate"
            )
        await conn.execute("SELECT pg_advisory_lock(hashtextextended($1, 0))", LOCK_KEY)
        applied = await _applied(conn)
        if 0 not in applied:
            raise MigrationError("bootstrap (0000) has not run; provide admin credentials")
        _check_applied(migrations, applied)
        for migration in migrations[1:]:
            if target is not None and migration.version > target:
                break
            if migration.version not in applied:
                await _apply_one(conn, migration)
                applied_now.append(migration.version)
        return applied_now
    finally:
        await conn.close()


async def status(config: MigrateConfig, directory: Path | None = None) -> list[MigrationStatus]:
    """Report each migration as applied, pending or modified."""
    migrations = discover(directory)
    conn = await _connect(config.migrate)
    try:
        applied = await _applied(conn)
        names = (
            {
                r["version"]: r["name"]
                for r in await conn.fetch("SELECT version, name FROM sibyl.schema_migrations")
            }
            if applied
            else {}
        )
    finally:
        await conn.close()
    out: list[MigrationStatus] = []
    on_disk = {m.version for m in migrations}
    for m in migrations:
        if m.version not in applied:
            state = "pending"
        elif applied[m.version] != m.checksum:
            state = "modified"
        else:
            state = "applied"
        out.append(MigrationStatus(m.version, m.name, state))
    for version, name in sorted(names.items()):
        if version not in on_disk:
            out.append(MigrationStatus(version, name, "missing"))
    return out
