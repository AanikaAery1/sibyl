"""(e) Migrations apply cleanly as the non-superuser sibyl_migrate and are guarded."""

from __future__ import annotations

import asyncio
import base64
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
from sibyl_control.migrate import runner
from sibyl_control.migrate.config import ConnSpec, MigrateConfig
from sibyl_control.migrate.runner import (
    ChecksumMismatchError,
    MigrationError,
    MigrationStatus,
    SuperuserRefusedError,
    UnknownAppliedMigrationError,
    apply,
    default_migrations_dir,
    discover,
    status,
)

from .conftest import Conn, Database


def test_every_migration_applied_by_sibyl_migrate(admin: Conn) -> None:
    rows = admin.fetch("SELECT version, applied_by FROM sibyl.schema_migrations ORDER BY version")
    migrations = discover()
    assert [r["version"] for r in rows] == [m.version for m in migrations]
    assert rows[0]["applied_by"] == "postgres"
    assert {r["applied_by"] for r in rows[1:]} == {"sibyl_migrate"}


def test_sibyl_migrate_is_not_privileged(admin: Conn) -> None:
    row = admin.fetchrow(
        "SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles "
        "WHERE rolname = 'sibyl_migrate'"
    )
    assert not any(row.values())


def test_reapply_is_a_no_op(db: Database) -> None:
    assert db.loop.run_until_complete(apply(db.migrate_config())) == []
    states = db.loop.run_until_complete(status(db.migrate_config()))
    assert {s.state for s in states} == {"applied"}


def test_edited_migration_is_refused(db: Database, tmp_path: Path) -> None:
    edited = tmp_path / "migrations"
    shutil.copytree(default_migrations_dir(), edited)
    target = edited / "0005_policy_security.sql"
    target.write_text(target.read_text() + "\n-- edited after apply\n")
    with pytest.raises(ChecksumMismatchError):
        db.loop.run_until_complete(apply(db.migrate_config(), edited))
    states = {
        s.version: s.state for s in db.loop.run_until_complete(status(db.migrate_config(), edited))
    }
    assert states[5] == "modified"


def test_missing_applied_migration_is_refused(db: Database, tmp_path: Path) -> None:
    truncated = tmp_path / "migrations"
    shutil.copytree(default_migrations_dir(), truncated)
    sorted(truncated.glob("*.sql"))[-1].unlink()
    with pytest.raises(UnknownAppliedMigrationError):
        db.loop.run_until_complete(apply(db.migrate_config(), truncated))


def test_superuser_is_refused(db: Database) -> None:
    config = MigrateConfig(migrate=db.spec(None), admin=None)
    with pytest.raises(SuperuserRefusedError):
        db.loop.run_until_complete(apply(config))


def test_fresh_database_applies_in_steps(database_factory: Any) -> None:
    fresh: Database = database_factory(migrate=False)
    assert fresh.loop.run_until_complete(apply(fresh.migrate_config(), target=4)) == [0, 1, 2, 3, 4]
    rest = fresh.loop.run_until_complete(apply(fresh.migrate_config()))
    assert rest == [m.version for m in discover()][5:]


def test_without_admin_bootstrap_is_required(database_factory: Any) -> None:
    fresh: Database = database_factory(migrate=False)
    config = MigrateConfig(migrate=fresh.spec("sibyl_migrate"), admin=None)
    with pytest.raises(MigrationError, match="bootstrap"):
        fresh.loop.run_until_complete(apply(config))


def test_discover_rejects_gaps_and_admin_misuse(tmp_path: Path) -> None:
    (tmp_path / "0000_bootstrap.sql").write_text("-- sibyl:run-as=admin\nSELECT 1;\n")
    (tmp_path / "0002_skip.sql").write_text("SELECT 1;\n")
    with pytest.raises(MigrationError, match="contiguous"):
        discover(tmp_path)
    (tmp_path / "0002_skip.sql").unlink()
    (tmp_path / "0001_sneaky.sql").write_text("-- sibyl:run-as=admin\nSELECT 1;\n")
    with pytest.raises(MigrationError, match="admin"):
        discover(tmp_path)


def test_migrations_are_sibyl_named_and_lock_safe() -> None:
    for migration in discover():
        text = migration.sql.lower()
        assert "vigil" not in text, migration.path.name
        assert "alembic" not in text, migration.path.name
        assert "concurrently" not in text, (
            f"{migration.path.name}: CONCURRENTLY needs a no-transaction step"
        )
        assert not re.search(r"create extension[^;]*\bvector\b", text), "pgvector is Phase 3 (R58)"


def test_role_passwords_are_applied_by_bootstrap(database_factory: Any, admin: Conn) -> None:
    fresh: Database = database_factory(migrate=False)
    config = MigrateConfig(
        migrate=fresh.spec("sibyl_migrate"),
        admin=fresh.spec(None),
        role_passwords={"sibyl_app": "app-test-password"},
    )
    try:
        fresh.loop.run_until_complete(apply(config))
        stored = admin.fetchval("SELECT rolpassword FROM pg_authid WHERE rolname = 'sibyl_app'")
        assert stored is not None and stored.startswith("SCRAM-SHA-256$4096:")
        iterations_salt, _keys = stored.removeprefix("SCRAM-SHA-256$").split("$")
        iterations, salt = iterations_salt.split(":")
        assert (
            runner.scram_verifier(
                "app-test-password", salt=base64.b64decode(salt), iterations=int(iterations)
            )
            == stored
        )
    finally:
        admin.execute("ALTER ROLE sibyl_app PASSWORD NULL")  # cluster-wide: always reset (F18)


class _Recorder:
    def __init__(self) -> None:
        self.statements: list[str] = []

    async def execute(self, sql: str, *args: Any) -> None:
        self.statements.append(sql + " " + " ".join(map(str, args)))

    async def fetchval(self, sql: str, *args: Any) -> str:
        self.statements.append(sql + " " + " ".join(map(str, args)))
        return f"ALTER ROLE {args[0]} PASSWORD '{args[1]}'"


def test_plaintext_passwords_never_reach_the_server() -> None:
    """Only a client-computed SCRAM verifier is sent, so statement logging cannot leak it (L6)."""
    recorder = _Recorder()
    asyncio.run(runner._set_passwords(recorder, {"sibyl_app": "hunter2-plaintext"}))  # type: ignore[arg-type]
    assert recorder.statements
    assert not any("hunter2-plaintext" in s for s in recorder.statements)
    assert any("SCRAM-SHA-256$" in s for s in recorder.statements)


def test_scram_verifier_matches_rfc7677_shape() -> None:
    verifier = runner.scram_verifier("pencil", salt=b"\x00" * 16, iterations=4096)
    head, keys = verifier.split("$")[1:]
    stored_key, server_key = keys.split(":")
    assert head == "4096:" + base64.b64encode(b"\x00" * 16).decode()
    assert len(base64.b64decode(stored_key)) == 32 and len(base64.b64decode(server_key)) == 32
    assert runner.scram_verifier("pencil", salt=b"\x00" * 16, iterations=4096) == verifier
    assert runner.scram_verifier("pencil") != runner.scram_verifier("pencil")  # random salt


def test_discover_refuses_an_empty_migration(tmp_path: Path) -> None:
    (tmp_path / "0000_bootstrap.sql").write_text("")
    with pytest.raises(MigrationError, match="empty"):
        discover(tmp_path)


def test_status_reports_applied_versions_missing_on_disk(db: Database, tmp_path: Path) -> None:
    migrations = discover()
    for migration in migrations[:-1]:
        (tmp_path / migration.path.name).write_bytes(migration.path.read_bytes())
    report = db.loop.run_until_complete(status(db.migrate_config(), tmp_path))
    last = migrations[-1]
    assert MigrationStatus(last.version, last.name, "missing") in report
    assert {r.state for r in report} == {"applied", "missing"}


def test_connspec_kwargs_override_dsn() -> None:
    spec = ConnSpec(
        dsn="postgresql://postgres@localhost:5433/postgres", user="sibyl_migrate", database="x"
    )
    assert spec.kwargs() == {
        "dsn": "postgresql://postgres@localhost:5433/postgres",
        "user": "sibyl_migrate",
        "database": "x",
    }


def test_concurrent_bootstraps_of_different_databases_both_succeed(database_factory: Any) -> None:
    """0000 touches cluster-wide role rows; advisory locks are per database, so two fresh
    databases bootstrapping at once used to fail with 'tuple concurrently updated'."""
    fresh = [database_factory(migrate=False) for _ in range(4)]

    async def both() -> list[Any]:
        return await asyncio.gather(
            *(apply(d.migrate_config()) for d in fresh), return_exceptions=True
        )

    results = fresh[0].loop.run_until_complete(both())
    assert [r for r in results if isinstance(r, BaseException)] == []
