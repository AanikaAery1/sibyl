"""Backup/restore against FIX-DB's real signed-ledger pieces (H1).

Uses the real migrations, the real ``python -m sibyl_control.migrate ledger-verify`` and the real
``sibyl.erasure_reapply_from_ledger(ledger_jsonl, expected_count, expected_head_hash)`` (skips
only if they disappear, and that skip reason is not allow-listed, so CI goes red). The script
mechanics are covered by test_backup_restore.py with stubs.

The happy path uses an empty ledger (count 0, genesis head), so the re-apply has nothing to
shred; the H1 exploits (a truncated or a forged signed ledger) are refused offline.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP = REPO_ROOT / "ops" / "backup" / "backup.sh"
RESTORE = REPO_ROOT / "ops" / "backup" / "restore.sh"
MIGRATIONS = REPO_ROOT / "services" / "control" / "migrations"
PGBIN = Path(os.environ.get("PGBIN", "/opt/homebrew/opt/postgresql@17/bin"))
ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
PREFIX = f"sibyl_infl_{secrets.token_hex(4)}"
SOURCE_DB, TARGET_DB = f"{PREFIX}_src", f"{PREFIX}_dst"
GENESIS = "0" * 64
NOT_LANDED = "FIX-DB signed-ledger pieces not landed"
THREE_ARG = re.compile(
    r"FUNCTION\s+sibyl\.erasure_reapply_from_ledger\s*\(\s*\w+\s+text\s*,\s*\w+\s+(big)?int",
    re.I,
)


def _dsn(db: str, user: str | None = None) -> str:
    parts = urlsplit(ADMIN_DSN)
    netloc = parts.netloc if user is None else f"{user}@{parts.netloc.rsplit('@', 1)[-1]}"
    return urlunsplit(parts._replace(path=f"/{db}", netloc=netloc))


def _landed() -> bool:
    sql = "\n".join(p.read_text() for p in sorted(MIGRATIONS.glob("*.sql")))
    if not THREE_ARG.search(sql):
        return False
    proc = subprocess.run(
        ["uv", "run", "--frozen", "--quiet", "python", "-m", "sibyl_control.migrate",  # noqa: S607
         "ledger-verify", "--help"],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO_ROOT,
    )  # fmt: skip
    return proc.returncode == 0


pytestmark = pytest.mark.skipif(not _landed(), reason=NOT_LANDED)


def _psql(dsn: str, sql: str) -> str:
    return subprocess.run(  # noqa: S603
        [str(PGBIN / "psql"), "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", dsn, "-c", sql],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _run(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PGBIN": str(PGBIN)}
    return subprocess.run(  # noqa: S603
        ["bash", str(script), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


@pytest.fixture
def migrated(tmp_path: Path) -> Iterator[Path]:
    isready = subprocess.run([str(PGBIN / "pg_isready"), "-q", "-d", ADMIN_DSN], check=False)  # noqa: S603
    if isready.returncode != 0:
        if os.environ.get("SIBYL_REQUIRE_PG") == "1":
            pytest.fail("PostgreSQL is down and SIBYL_REQUIRE_PG=1")
        pytest.skip("PostgreSQL is not accepting connections")
    if shutil.which("age") is None:
        pytest.skip("age not installed")
    _psql(ADMIN_DSN, f"CREATE DATABASE {SOURCE_DB}")
    try:
        env = {
            **os.environ,
            "SIBYL_PG_ADMIN_DSN": ADMIN_DSN,
            "SIBYL_PG_MIGRATE_DSN": _dsn("postgres", "sibyl_migrate"),
            "SIBYL_DB_NAME": SOURCE_DB,
        }
        up = subprocess.run(
            ["uv", "run", "--frozen", "--quiet", "python", "-m", "sibyl_control.migrate", "up"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            env=env,
            cwd=REPO_ROOT,
        )
        assert up.returncode == 0, up.stderr[-2000:]
        yield tmp_path
    finally:
        query = f"SELECT datname FROM pg_database WHERE datname LIKE '{PREFIX}%'"  # noqa: S608
        rows = _psql(ADMIN_DSN, query)
        for db in rows.splitlines():
            _psql(ADMIN_DSN, f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


def _ledger_module():  # type: ignore[no-untyped-def]
    from sibyl_control.migrate import ledger

    return ledger


def _signed_ledger(n: int, key: object) -> str:
    led = _ledger_module()
    entries: tuple[object, ...] = ()
    for i in range(n):
        entries = led.append(
            entries,
            signing_key=key,
            tenant_id=str(uuid.uuid4()),
            erasure_request_id=str(uuid.uuid4()),
            scope_kind="agent",
            scope_ref=str(uuid.uuid4()),
            key_ids=[],
            completed_at=f"2026-10-0{i + 1}T00:00:00Z",
        )
    text: str = led.to_jsonl(entries)
    return text


def _keys(tmp: Path) -> tuple[str, Path, Path, object]:
    led = _ledger_module()
    identity = tmp / "id.age"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True)  # noqa: S603, S607
    recipient = subprocess.run(  # noqa: S603
        ["age-keygen", "-y", str(identity)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    key = led.generate_signing_key()
    pem = tmp / "ledger_signing.pem"
    pem.write_bytes(led.public_key_pem(led.public_key_of(key)))
    return recipient, identity, pem, key


def _backup_and_restore(
    tmp: Path,
    *restore_extra: str,
    entries: int = 0,
    live_entries: int | None = None,
    forge: bool = False,
) -> subprocess.CompletedProcess[str]:
    recipient, identity, pem, key = _keys(tmp)
    ledger = tmp / "ledger.jsonl"
    full = _signed_ledger(entries, key)
    ledger.write_text(full)
    out = tmp / "backups"
    proc = _run(
        BACKUP, "--dsn", _dsn(SOURCE_DB), "--out", str(out), "--ledger", str(ledger),
        "--ledger-public-key", str(pem), "--recipient", recipient, "--no-sign",
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    if live_entries is not None:
        ledger.write_text("".join(full.splitlines(keepends=True)[:live_entries]))
    if forge:
        other = _ledger_module().generate_signing_key()
        ledger.write_text(_signed_ledger(entries, other))
    return _run(
        RESTORE, "--dump", proc.stdout.strip(), "--target-db", TARGET_DB, "--admin-dsn", ADMIN_DSN,
        "--ledger", str(ledger), "--ledger-public-key", str(pem), "--identity", str(identity),
        "--allow-unsigned", *restore_extra,
    )  # fmt: skip


def _created() -> list[str]:
    query = f"SELECT datname FROM pg_database WHERE datname LIKE '{PREFIX}%'"  # noqa: S608
    return sorted(_psql(ADMIN_DSN, query).splitlines())


def test_real_verifier_and_reapply_accept_the_recorded_head(migrated: Path) -> None:
    proc = _backup_and_restore(migrated)
    assert proc.returncode == 0, proc.stderr
    assert "erasure ledger ok" in proc.stderr and "restore ok" in proc.stderr
    count = _psql(_dsn(TARGET_DB), "SELECT count(*) FROM sibyl.schema_migrations")
    assert int(count) > 1


def test_real_verifier_rejects_a_head_the_ledger_does_not_have(migrated: Path) -> None:
    proc = _backup_and_restore(migrated, "--expected-head", "a" * 64, "--expected-count", "1")
    assert proc.returncode != 0
    assert "ledger verification failed" in proc.stderr
    assert _created() == [SOURCE_DB], "nothing created before the ledger verified"


def test_truncated_live_ledger_is_refused_offline(migrated: Path) -> None:
    """H1 exploit 1: a ledger cut after the backup must not let the restore open."""
    proc = _backup_and_restore(migrated, entries=2, live_entries=1)
    assert proc.returncode != 0
    assert "ledger verification failed" in proc.stderr
    assert _created() == [SOURCE_DB]


def test_forged_ledger_is_refused_offline(migrated: Path) -> None:
    """H1 exploit 2: entries signed by any other key are rejected."""
    proc = _backup_and_restore(migrated, entries=2, forge=True)
    assert proc.returncode != 0
    assert "ledger verification failed" in proc.stderr
    assert _created() == [SOURCE_DB]


# --- the ledger in the BlobStore (lane U: ledger/erasure/{ledger.jsonl,head.json}) ------------


def _blob_root(tmp: Path, text: str, key: object, *, head_key: object | None = None) -> Path:
    """A BlobStore fs root as the worker's erasure_ledger loop leaves it (ledger_store.py)."""
    led = _ledger_module()
    root = tmp / "blob"
    erasure = root / "ledger" / "erasure"
    erasure.mkdir(parents=True)
    (erasure / "ledger.jsonl").write_text(text)
    entries = led.verify(text, led.public_key_of(key))
    head = led.sign_head(entries, head_key or key, at="2026-10-11T00:00:00.000Z")
    (erasure / "head.json").write_text(json.dumps(head, sort_keys=True))
    return root


def _blob_backup(
    tmp: Path, root: Path, pem: Path, recipient: str
) -> subprocess.CompletedProcess[str]:
    return _run(
        BACKUP, "--dsn", _dsn(SOURCE_DB), "--out", str(tmp / "backups"), "--blob-root", str(root),
        "--ledger-public-key", str(pem), "--recipient", recipient, "--no-sign",
    )  # fmt: skip


def _blob_restore(
    dump: str, root: Path, pem: Path, identity: Path
) -> subprocess.CompletedProcess[str]:
    return _run(
        RESTORE, "--dump", dump, "--target-db", TARGET_DB, "--admin-dsn", ADMIN_DSN,
        "--blob-root", str(root), "--ledger-public-key", str(pem), "--identity", str(identity),
        "--allow-unsigned",
    )  # fmt: skip


def test_blob_root_empty_ledger_round_trips_to_a_restored_database(migrated: Path) -> None:
    recipient, identity, pem, key = _keys(migrated)
    root = _blob_root(migrated, _signed_ledger(0, key), key)
    backup = _blob_backup(migrated, root, pem, recipient)
    assert backup.returncode == 0, backup.stderr
    assert "signed head ok" in backup.stderr
    restore = _blob_restore(backup.stdout.strip(), root, pem, identity)
    assert restore.returncode == 0, restore.stderr
    assert "restore ok" in restore.stderr


def test_blob_root_ledger_and_signed_head_verify_offline(migrated: Path) -> None:
    recipient, identity, pem, key = _keys(migrated)
    root = _blob_root(migrated, _signed_ledger(2, key), key)
    backup = _blob_backup(migrated, root, pem, recipient)
    assert backup.returncode == 0, backup.stderr
    restore = _blob_restore(backup.stdout.strip(), root, pem, identity)
    assert restore.returncode == 0, restore.stderr
    assert "erasure ledger signed head ok" in restore.stderr
    assert "restore ok" in restore.stderr


def test_blob_root_head_ahead_of_a_truncated_ledger_is_refused(migrated: Path) -> None:
    """The signed head.json pins the ledger end: cutting entries off is caught offline."""
    recipient, identity, pem, key = _keys(migrated)
    full = _signed_ledger(2, key)
    root = _blob_root(migrated, full, key)
    backup = _blob_backup(migrated, root, pem, recipient)
    assert backup.returncode == 0, backup.stderr
    jsonl = root / "ledger" / "erasure" / "ledger.jsonl"
    jsonl.write_text(full.splitlines(keepends=True)[0])
    restore = _blob_restore(backup.stdout.strip(), root, pem, identity)
    assert restore.returncode != 0
    assert "ledger verification failed" in restore.stderr
    assert _created() == [SOURCE_DB]


def test_blob_root_head_signed_by_another_key_fails_the_backup(migrated: Path) -> None:
    recipient, _, pem, key = _keys(migrated)
    other = _ledger_module().generate_signing_key()
    root = _blob_root(migrated, _signed_ledger(1, key), key, head_key=other)
    backup = _blob_backup(migrated, root, pem, recipient)
    assert backup.returncode != 0
    assert "signed head" in backup.stderr


def test_blob_root_without_a_ledger_is_refused_with_a_hint(migrated: Path) -> None:
    recipient, _, pem, _ = _keys(migrated)
    (migrated / "blob").mkdir()
    backup = _blob_backup(migrated, migrated / "blob", pem, recipient)
    assert backup.returncode != 0
    assert "ledger/erasure/ledger.jsonl" in backup.stderr and "--no-ledger" in backup.stderr


@pytest.mark.parametrize("script", [BACKUP, RESTORE])
def test_blob_root_and_ledger_are_exclusive(script: Path, tmp_path: Path) -> None:
    proc = _run(script, "--blob-root", str(tmp_path), "--ledger", str(tmp_path / "l.jsonl"))
    assert proc.returncode != 0
    assert "--blob-root" in proc.stderr
