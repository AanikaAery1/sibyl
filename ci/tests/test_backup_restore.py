"""ops/backup: encrypted, signed backups and the verify-first, swap-last restore (H1, M10, M11).

Argument and dry-run tests always run. Round trips use the PG17 cluster named by
``SIBYL_PG_ADMIN_DSN`` (default the dev cluster on :5433, the same knob as the rest of the
suite) with per-run database names ``sibyl_inf_<token>*``, so concurrent runs never collide.
When the cluster is down they skip, or fail when ``SIBYL_REQUIRE_PG=1`` (ci/run.sh sets it).

The ledger verifier is stubbed here through ``SIBYL_MIGRATE_CMD`` and the reapply function
is a stub with FIX-DB's three-argument signature; ``test_backup_restore_ledger.py`` runs the
real ``sibyl_control.migrate ledger-verify`` and SQL function once FIX-DB has landed them.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP = REPO_ROOT / "ops" / "backup" / "backup.sh"
RESTORE = REPO_ROOT / "ops" / "backup" / "restore.sh"
PGBIN = Path(os.environ.get("PGBIN", "/opt/homebrew/opt/postgresql@17/bin"))
ADMIN_DSN = os.environ.get("SIBYL_PG_ADMIN_DSN", "postgresql://postgres@localhost:5433/postgres")
PREFIX = f"sibyl_inf_{secrets.token_hex(4)}"
SOURCE_DB = f"{PREFIX}_src"
TARGET_DB = f"{PREFIX}_dst"
GENESIS = "0" * 64

# Stand-in for `python -m sibyl_control.migrate` (SIBYL_MIGRATE_CMD): `ledger-head` reports the
# toy ledger's head (last entry's "hash"); `ledger-verify` records its arguments in $STUB_ARGS
# and exits $STUB_VERIFY_RC. The real CLI is exercised in test_backup_restore_ledger.py.
STUB = Path(tempfile.mkdtemp(prefix="sibyl-migrate-stub-")) / "migrate_stub.sh"
STUB.write_text(
    """#!/usr/bin/env bash
if [[ "$1" == ledger-head ]]; then
  while [[ $# -gt 0 ]]; do [[ "$1" == --ledger ]] && ledger="$2"; shift; done
  exec python3 -I -c '
import json, sys
e = [json.loads(ln) for ln in open(sys.argv[1]) if ln.strip()]
print(json.dumps({"count": len(e), "head_hash": e[-1]["hash"] if e else "0" * 64}))' "$ledger"
fi
printf "%s\\n" "$@" > "${STUB_ARGS:-/dev/null}"
exit "${STUB_VERIFY_RC:-0}"
""",
    encoding="utf-8",
)
STUB_CMD = f"bash {STUB}"


def _dsn(db: str) -> str:
    parts = urlsplit(ADMIN_DSN)
    return urlunsplit(parts._replace(path=f"/{db}"))


def _run(script: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, "PGBIN": str(PGBIN), "SIBYL_MIGRATE_CMD": STUB_CMD, **env}
    for key in (
        "SIBYL_PG_DSN",
        "SIBYL_ERASURE_LEDGER",
        "SIBYL_BACKUP_AGE_RECIPIENT",
        "SIBYL_LEDGER_PUBLIC_KEY_FILE",
    ):
        full_env.setdefault(key, "")
    return subprocess.run(  # noqa: S603
        ["bash", str(script), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        env=full_env,
    )


def _pg_available() -> bool:
    isready = PGBIN / "pg_isready"
    if not isready.exists():
        return False
    proc = subprocess.run([str(isready), "-q", "-d", ADMIN_DSN], check=False)  # noqa: S603
    return proc.returncode == 0


def _psql(dsn: str, sql: str) -> str:
    proc = subprocess.run(  # noqa: S603
        [
            str(PGBIN / "psql"),
            "-X",
            "-q",
            "-t",
            "-A",
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            dsn,
            "-c",
            sql,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _databases() -> dict[str, int]:
    rows = _psql(
        ADMIN_DSN,
        f"SELECT datname || '|' || datconnlimit FROM pg_database WHERE datname LIKE '{PREFIX}%'",  # noqa: S608
    )
    return {r.split("|")[0]: int(r.split("|")[1]) for r in rows.splitlines() if r}


def make_ledger(n: int) -> str:
    """A structurally valid hash-chained ledger (the stub verifier does not check signatures)."""
    prev, lines = GENESIS, []
    for seq in range(n):
        body = {"seq": seq, "prev_hash": prev, "scope_kind": "agent", "tenant_id": f"t{seq}"}
        digest = hashlib.sha256(
            bytes.fromhex(prev) + json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
        lines.append(json.dumps({**body, "hash": digest}, sort_keys=True))
        prev = digest
    return "".join(line + "\n" for line in lines)


def ledger_head(text: str) -> tuple[int, str]:
    entries = [json.loads(ln) for ln in text.splitlines() if ln.strip()]
    return len(entries), (entries[-1]["hash"] if entries else GENESIS)


# --- keys ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Keys:
    recipient: str
    identity: Path
    signing_key: Path
    allowed_signers: Path
    ledger_pub: Path


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Keys:
    if shutil.which("age") is None or shutil.which("age-keygen") is None:
        pytest.skip("age not installed (brew install age / apt install age)")
    root = tmp_path_factory.mktemp("keys")
    identity = root / "backup.agekey"
    subprocess.run(["age-keygen", "-o", str(identity)], capture_output=True, check=True)  # noqa: S603, S607
    recipient = subprocess.run(  # noqa: S603
        ["age-keygen", "-y", str(identity)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    signing = root / "backup_signing"
    subprocess.run(  # noqa: S603
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sibyl-backup", "-f", str(signing)],  # noqa: S607
        check=True,
    )
    pub = (root / "backup_signing.pub").read_text(encoding="utf-8").split()
    signers = root / "allowed_signers"
    signers.write_text(f"sibyl-backup {pub[0]} {pub[1]}\n", encoding="utf-8")
    ledger_pub = root / "ledger_signing.pem"
    ledger_pub.write_text("-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n")
    return Keys(recipient, identity, signing, signers, ledger_pub)


@pytest.fixture
def stub_verify(tmp_path: Path) -> tuple[str, Path]:
    """The migrate stand-in plus a per-test file for the ledger-verify arguments."""
    return STUB_CMD, tmp_path / "verify-args.txt"


def restore_args(keys: Keys, dump: Path, ledger: Path, target: str = TARGET_DB) -> list[str]:
    return [
        "--dump", str(dump), "--target-db", target, "--admin-dsn", ADMIN_DSN,
        "--ledger", str(ledger), "--ledger-public-key", str(keys.ledger_pub),
        "--identity", str(keys.identity), "--allowed-signers", str(keys.allowed_signers),
    ]  # fmt: skip


def backup_args(keys: Keys, dsn: str, out: Path, ledger: Path | None) -> list[str]:
    led = (
        ["--ledger", str(ledger), "--ledger-public-key", str(keys.ledger_pub)]
        if ledger
        else ["--no-ledger"]
    )
    return [
        "--dsn", dsn, "--out", str(out), *led, "--recipient", keys.recipient,
        "--signing-key", str(keys.signing_key),
    ]  # fmt: skip


# --- argument checks and dry runs (no database) ----------------------------------------------


def test_backup_dry_run_masks_password_and_encrypts(keys: Keys, tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(make_ledger(3), encoding="utf-8")
    dsn = "postgresql://sibyl:hunter2@db.example:5432/sibyl"
    proc = _run(BACKUP, "--dry-run", *backup_args(keys, dsn, tmp_path, ledger))
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout + proc.stderr
    assert "hunter2" not in out
    assert "--format=custom" in out and f"age -r {keys.recipient}" in out
    count, head = ledger_head(ledger.read_text())
    assert f"ledger_count={count}, ledger_head_hash={head}" in out
    assert "expires after 7d" in out
    assert "off-host" in out.lower(), "C0: warn when no off-host copy is configured"


def test_backup_requires_a_dsn(keys: Keys, tmp_path: Path) -> None:
    args = backup_args(keys, "", tmp_path, None)[2:]
    assert _run(BACKUP, "--dry-run", *args).returncode != 0


@pytest.mark.parametrize(
    ("drop", "message"),
    [
        ("ledger", "erasure ledger"),
        ("recipient", "age recipient"),
        ("signing", "signing key"),
        ("public_key", "ledger public key"),
    ],
)
def test_backup_refuses_without_ledger_encryption_or_signature(
    keys: Keys, tmp_path: Path, drop: str, message: str
) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("", encoding="utf-8")
    args = ["--dry-run", "--dsn", "postgresql://u@h/db", "--out", str(tmp_path)]
    if drop != "ledger":
        args += ["--ledger", str(ledger)]
    if drop not in ("ledger", "public_key"):
        args += ["--ledger-public-key", str(keys.ledger_pub)]
    if drop != "recipient":
        args += ["--recipient", keys.recipient]
    if drop != "signing":
        args += ["--signing-key", str(keys.signing_key)]
    proc = _run(BACKUP, *args)
    assert proc.returncode != 0
    assert message in proc.stderr.lower()


def test_backup_rejects_malformed_ledger(keys: Keys, tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text('{"seq": 1, "hash": "x"}\n', encoding="utf-8")
    proc = _run(BACKUP, "--dry-run", *backup_args(keys, "postgresql://u@h/db", tmp_path, ledger))
    assert proc.returncode != 0
    assert "ledger" in proc.stderr.lower()


@pytest.mark.parametrize("script", [BACKUP, RESTORE], ids=["backup", "restore"])
@pytest.mark.parametrize("param", ["dbname", "service"])
def test_dsn_query_cannot_redirect_the_database(
    keys: Keys, tmp_path: Path, script: Path, param: str
) -> None:
    dsn = f"postgresql://postgres@localhost:5433/postgres?sslmode=disable&{param}=other"
    dump = tmp_path / "x.dump.age"
    dump.write_bytes(b"x")
    if script == BACKUP:
        args = backup_args(keys, dsn, tmp_path, None)
    else:
        args = [*restore_args(keys, dump, tmp_path, "sibyl_x"), "--admin-dsn", dsn]
        (tmp_path / "ledger").write_text("")
        args[args.index("--ledger") + 1] = str(tmp_path / "ledger")
    proc = _run(script, "--dry-run", *args)
    assert proc.returncode != 0
    assert f"{param}=" in proc.stderr


def test_restore_refuses_without_ledger_decision(tmp_path: Path) -> None:
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    proc = _run(
        RESTORE, "--dry-run", "--dump", str(dump), "--admin-dsn", ADMIN_DSN, "--target-db", "t"
    )
    assert proc.returncode != 0
    assert "ledger" in proc.stderr.lower()


def test_restore_requires_the_ledger_public_key(tmp_path: Path) -> None:
    dump, ledger = tmp_path / "x.dump", tmp_path / "l.jsonl"
    dump.write_bytes(b"x")
    ledger.write_text("")
    proc = _run(
        RESTORE, "--dry-run", "--dump", str(dump), "--admin-dsn", ADMIN_DSN,
        "--target-db", "t", "--ledger", str(ledger), SIBYL_LEDGER_PUBLIC_KEY="",
    )  # fmt: skip
    assert proc.returncode != 0
    assert "public key" in proc.stderr.lower()


@pytest.mark.parametrize("name", ['x"; drop database postgres; --', "a" * 41, "Upper"])
def test_restore_rejects_bad_target_db_name(tmp_path: Path, name: str) -> None:
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    proc = _run(
        RESTORE, "--dry-run", "--dump", str(dump), "--no-ledger", "--admin-dsn", ADMIN_DSN,
        "--target-db", name,
    )  # fmt: skip
    assert proc.returncode != 0


def _plain_args(dump: Path, *extra: str) -> list[str]:
    return [
        "--dry-run", "--dump", str(dump), "--no-ledger", "--admin-dsn", ADMIN_DSN,
        "--target-db", "sibyl_x", *extra,
    ]  # fmt: skip


def test_restore_rejects_checksum_mismatch(tmp_path: Path) -> None:
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    (tmp_path / "x.dump.sha256").write_text("0" * 64 + "  x.dump\n", encoding="utf-8")
    proc = _run(RESTORE, *_plain_args(dump, "--allow-unsigned", "--allow-unencrypted"))
    assert proc.returncode != 0
    assert "checksum" in proc.stderr.lower()


def test_restore_refuses_a_dump_without_checksum(tmp_path: Path) -> None:
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    proc = _run(RESTORE, *_plain_args(dump, "--allow-unsigned", "--allow-unencrypted"))
    assert proc.returncode != 0
    assert "no checksum" in proc.stderr.lower()
    ok = _run(
        RESTORE,
        *_plain_args(dump, "--allow-unsigned", "--allow-unencrypted", "--allow-missing-checksum"),
    )
    assert ok.returncode == 0, ok.stderr


def test_restore_refuses_unsigned_or_plaintext_without_override(tmp_path: Path) -> None:
    dump = tmp_path / "x.dump"
    dump.write_bytes(b"x")
    (tmp_path / "x.dump.sha256").write_text(hashlib.sha256(b"x").hexdigest() + "  x.dump\n")
    unsigned = _run(RESTORE, *_plain_args(dump, "--allow-unencrypted"))
    assert unsigned.returncode != 0 and "manifest not found" in unsigned.stderr
    plaintext = _run(RESTORE, *_plain_args(dump, "--allow-unsigned"))
    assert plaintext.returncode != 0 and "not encrypted" in plaintext.stderr


def test_restore_dry_run_plans_staging_reshred_and_swap(keys: Keys, tmp_path: Path) -> None:
    dump = tmp_path / "x.dump.age"
    dump.write_bytes(b"x")
    (tmp_path / "x.dump.age.sha256").write_text(hashlib.sha256(b"x").hexdigest() + "  x\n")
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(make_ledger(2))
    count, head = ledger_head(ledger.read_text())
    args = restore_args(keys, dump, ledger, "sibyl_x")
    proc = _run(
        RESTORE, "--dry-run", *args, "--allow-unsigned", "--expected-head", head,
        "--expected-count", str(count), "--replace",
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    plan = proc.stdout
    assert f"--expected-head {head} --expected-count {count}" in plan
    assert "sibyl_x_restore_" in plan and "CONNECTION LIMIT 0" in plan
    assert f"sibyl.erasure_reapply_from_ledger(<ledger>, {count}, '{head}')" in plan
    assert 'RENAME TO "sibyl_x"' in plan and "CONNECTION LIMIT -1" in plan
    lines = plan.splitlines()
    first_create = next(i for i, ln in enumerate(lines) if "CREATE DATABASE" in ln)
    verify = next(i for i, ln in enumerate(lines) if "ledger-verify" in ln)
    assert verify < first_create, "the ledger is verified before anything is created"


def test_restore_needs_expected_head_and_count_together(keys: Keys, tmp_path: Path) -> None:
    dump = tmp_path / "x.dump.age"
    dump.write_bytes(b"x")
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text("")
    proc = _run(RESTORE, "--dry-run", *restore_args(keys, dump, ledger), "--expected-count", "1")
    assert proc.returncode != 0
    assert "together" in proc.stderr


# --- retention (D26) ---------------------------------------------------------------------------


def _fake_set(directory: Path, name: str, age_days: float | None) -> None:
    (directory / name).write_bytes(b"x")
    (directory / f"{name}.sha256").write_text("x")
    lines = [f"file={name}"]
    if age_days is not None:
        lines.append(f"created_epoch={int(time.time() - age_days * 86400)}")
    (directory / f"{name}.manifest").write_text("\n".join(lines) + "\n")


def test_prune_removes_sets_past_retention_by_manifest_date(tmp_path: Path) -> None:
    out, offhost = tmp_path / "out", tmp_path / "offhost"
    for d in (out, offhost):
        d.mkdir()
        _fake_set(d, "sibyl_20260101T000000Z.dump.age", age_days=10)
        _fake_set(d, "sibyl_20260108T000000Z.dump.age", age_days=6)
        _fake_set(d, "sibyl_20250101T000000Z.dump", age_days=None)  # pre-v2 manifest
    old = out / "sibyl_20260101T000000Z.dump.age"
    os.utime(old, (time.time(), time.time()))  # file mtime is fresh; only the manifest counts
    proc = _run(
        BACKUP, "--prune-only", "--out", str(out), "--offhost", str(offhost),
        "--retention-days", "7",
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    for d in (out, offhost):
        names = sorted(p.name for p in d.iterdir())
        assert not any(n.startswith("sibyl_20260101") for n in names), names
        assert "sibyl_20260108T000000Z.dump.age.manifest" in names
        assert "sibyl_20250101T000000Z.dump" in names, "unknown age: never pruned silently"
    assert "not pruned" in proc.stderr


def test_retention_must_be_positive(tmp_path: Path) -> None:
    proc = _run(BACKUP, "--prune-only", "--out", str(tmp_path), "--retention-days", "0")
    assert proc.returncode != 0


# --- round trips against PG17 -------------------------------------------------------------------

STUB_SCHEMA = """
CREATE SCHEMA sibyl;
CREATE TABLE sibyl.reshred_calls (ledger text NOT NULL, expected_count bigint,
  expected_head text, at timestamptz DEFAULT now());
CREATE TABLE sibyl.payload (id int PRIMARY KEY, body text);
INSERT INTO sibyl.payload VALUES (1, 'erased-after-backup'), (2, 'kept');
CREATE FUNCTION sibyl.erasure_reapply_from_ledger(ledger_jsonl text, expected_count bigint,
  expected_head_hash text) RETURNS integer
LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO sibyl.reshred_calls(ledger, expected_count, expected_head)
    VALUES (ledger_jsonl, expected_count, expected_head_hash);
  DELETE FROM sibyl.payload WHERE body = 'erased-after-backup';
  RETURN 1;
END $$;
"""


@pytest.fixture
def pg() -> Iterator[None]:
    if not _pg_available():
        message = f"PostgreSQL at {ADMIN_DSN.rsplit('@', 1)[-1]} is not accepting connections"
        if os.environ.get("SIBYL_REQUIRE_PG") == "1":
            pytest.fail(f"{message} and SIBYL_REQUIRE_PG=1")
        pytest.skip(message)
    yield
    for db in _databases():
        _psql(ADMIN_DSN, f'DROP DATABASE IF EXISTS "{db}" WITH (FORCE)')


@dataclass(frozen=True)
class BackupSet:
    dump: Path
    out: Path
    ledger: Path
    count: int
    head: str


@pytest.fixture
def backed_up(pg: None, keys: Keys, tmp_path: Path) -> BackupSet:
    _psql(ADMIN_DSN, f"CREATE DATABASE {SOURCE_DB}")
    _psql(_dsn(SOURCE_DB), STUB_SCHEMA)
    ledger = tmp_path / "erasure-ledger.jsonl"
    ledger.write_text(make_ledger(2), encoding="utf-8")
    out, offhost = tmp_path / "backups", tmp_path / "offhost"
    args = backup_args(keys, _dsn(SOURCE_DB), out, ledger)
    proc = _run(BACKUP, *args, "--offhost", str(offhost))
    assert proc.returncode == 0, proc.stderr
    dump = Path(proc.stdout.strip())
    assert (offhost / dump.name).is_file()
    # The live ledger grows after the backup: the restore must re-apply the newer erasure.
    ledger.write_text(make_ledger(3), encoding="utf-8")
    count, head = ledger_head(ledger.read_text())
    return BackupSet(dump, out, ledger, count, head)


def _restore(
    keys: Keys, bset: BackupSet, stub: tuple[str, Path], *extra: str, rc: int = 0
) -> subprocess.CompletedProcess[str]:
    cmd, args_file = stub
    return _run(
        RESTORE, *restore_args(keys, bset.dump, bset.ledger), "--expected-head", bset.head,
        "--expected-count", str(bset.count), *extra,
        SIBYL_MIGRATE_CMD=cmd, STUB_ARGS=str(args_file), STUB_VERIFY_RC=str(rc),
    )  # fmt: skip


def test_backup_is_encrypted_signed_and_records_the_ledger_head(
    backed_up: BackupSet, keys: Keys
) -> None:
    dump = backed_up.dump
    assert dump.name.endswith(".dump.age")
    raw = dump.read_bytes()
    assert raw.startswith(b"age-encryption.org/v1")
    assert b"erased-after-backup" not in raw and b"PGDMP" not in raw
    manifest = dump.with_name(dump.name + ".manifest").read_text()
    count, head = ledger_head(make_ledger(2))
    assert f"ledger_count={count}\n" in manifest and f"ledger_head_hash={head}\n" in manifest
    assert "encryption=age\n" in manifest and "server_version=17" in manifest
    assert "retention_days=7\n" in manifest
    sig = dump.with_name(dump.name + ".manifest.sig")
    verify = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "ssh-keygen", "-Y", "verify", "-f", str(keys.allowed_signers), "-I", "sibyl-backup",
            "-n", "sibyl-backup", "-s", str(sig),
        ],
        input=manifest,
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    assert verify.returncode == 0, verify.stderr
    copy = dump.with_name(dump.name + ".erasure-ledger.jsonl.age")
    assert copy.read_bytes().startswith(b"age-encryption.org/v1")


def test_round_trip_verifies_ledger_then_reshreds_with_expected_head(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    proc = _restore(keys, backed_up, stub_verify)
    assert proc.returncode == 0, proc.stderr
    called = stub_verify[1].read_text().split("\n")
    assert called[0] == "ledger-verify"
    assert called[called.index("--ledger") + 1] == str(backed_up.ledger)
    assert called[called.index("--public-key") + 1] == str(keys.ledger_pub)
    assert called[called.index("--expected-head") + 1] == backed_up.head
    assert called[called.index("--expected-count") + 1] == str(backed_up.count)
    target = _dsn(TARGET_DB)
    row = _psql(target, "SELECT expected_count || '|' || expected_head FROM sibyl.reshred_calls")
    assert row == f"{backed_up.count}|{backed_up.head}"
    assert (
        _psql(target, "SELECT ledger FROM sibyl.reshred_calls")
        == backed_up.ledger.read_text().strip()
    )
    assert _psql(target, "SELECT string_agg(body, ',') FROM sibyl.payload") == "kept", (
        "resurrected rows"
    )
    assert _databases() == {SOURCE_DB: -1, TARGET_DB: -1}, "staging renamed, nothing left behind"


def test_expected_head_defaults_to_the_newest_signed_manifest(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    cmd, args_file = stub_verify
    proc = _run(
        RESTORE, *restore_args(keys, backed_up.dump, backed_up.ledger),
        SIBYL_MIGRATE_CMD=cmd, STUB_ARGS=str(args_file),
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    called = args_file.read_text().split("\n")
    count, head = ledger_head(make_ledger(2))  # the head the backup recorded
    assert called[called.index("--expected-head") + 1] == head
    assert called[called.index("--expected-count") + 1] == str(count)
    assert "newest manifest" in proc.stderr


def test_failed_ledger_verification_touches_nothing(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    proc = _restore(keys, backed_up, stub_verify, rc=1)
    assert proc.returncode != 0
    assert "ledger verification failed" in proc.stderr
    assert _databases() == {SOURCE_DB: -1}, "no database created before the ledger verified"


def test_stale_expected_head_behind_the_backup_is_refused(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    cmd, args_file = stub_verify
    count, head = ledger_head(make_ledger(1))
    proc = _run(
        RESTORE, *restore_args(keys, backed_up.dump, backed_up.ledger), "--expected-head", head,
        "--expected-count", str(count), SIBYL_MIGRATE_CMD=cmd, STUB_ARGS=str(args_file),
    )  # fmt: skip
    assert proc.returncode != 0
    assert "truncated" in proc.stderr
    assert not args_file.exists() and _databases() == {SOURCE_DB: -1}


def test_rewritten_live_ledger_fails_the_prefix_check(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    forged = make_ledger(3).replace('"t0"', '"tX"')
    backed_up.ledger.write_text(forged)
    proc = _restore(keys, backed_up, stub_verify)
    assert proc.returncode != 0
    assert "not a prefix" in proc.stderr
    assert _databases() == {SOURCE_DB: -1}


def test_tampered_manifest_is_rejected_before_anything_runs(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    manifest = backed_up.dump.with_name(backed_up.dump.name + ".manifest")
    manifest.write_text(manifest.read_text().replace("ledger_count=2", "ledger_count=0"))
    proc = _restore(keys, backed_up, stub_verify)
    assert proc.returncode != 0
    assert "signature" in proc.stderr
    assert not stub_verify[1].exists() and _databases() == {SOURCE_DB: -1}


def test_replace_swaps_only_after_reshred_and_keeps_old_closed(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    _psql(ADMIN_DSN, f"CREATE DATABASE {TARGET_DB}")
    _psql(_dsn(TARGET_DB), "CREATE TABLE live_marker (id int)")
    refused = _restore(keys, backed_up, stub_verify)
    assert refused.returncode != 0 and "--replace" in refused.stderr
    proc = _restore(keys, backed_up, stub_verify, "--replace")
    assert proc.returncode == 0, proc.stderr
    dbs = _databases()
    old = [d for d in dbs if d.startswith(f"{TARGET_DB}_old_")]
    assert len(old) == 1 and dbs[old[0]] == 0, "previous database kept, closed"
    assert dbs[TARGET_DB] == -1
    assert _psql(_dsn(old[0]), "SELECT to_regclass('live_marker') IS NOT NULL") == "t"
    assert _psql(_dsn(TARGET_DB), "SELECT count(*) FROM sibyl.payload") == "1"


def test_drop_old_removes_the_previous_database(
    backed_up: BackupSet, keys: Keys, stub_verify: tuple[str, Path]
) -> None:
    _psql(ADMIN_DSN, f"CREATE DATABASE {TARGET_DB}")
    proc = _restore(keys, backed_up, stub_verify, "--replace", "--drop-old")
    assert proc.returncode == 0, proc.stderr
    assert _databases() == {SOURCE_DB: -1, TARGET_DB: -1}


def test_failed_reshred_leaves_staging_closed_and_target_untouched(
    pg: None, keys: Keys, tmp_path: Path, stub_verify: tuple[str, Path]
) -> None:
    _psql(ADMIN_DSN, f"CREATE DATABASE {SOURCE_DB}")
    _psql(_dsn(SOURCE_DB), "CREATE TABLE t (id int)")  # no reapply function in this dump
    ledger = tmp_path / "ledger.jsonl"
    ledger.write_text(make_ledger(1))
    out = tmp_path / "backups"
    proc = _run(BACKUP, *backup_args(keys, _dsn(SOURCE_DB), out, ledger))
    assert proc.returncode == 0, proc.stderr
    _psql(ADMIN_DSN, f"CREATE DATABASE {TARGET_DB}")
    _psql(_dsn(TARGET_DB), "CREATE TABLE live_marker (id int)")
    count, head = ledger_head(ledger.read_text())
    bset = BackupSet(Path(proc.stdout.strip()), out, ledger, count, head)
    proc = _restore(keys, bset, stub_verify, "--replace")
    assert proc.returncode != 0
    assert "not safe to serve" in proc.stderr.lower()
    dbs = _databases()
    staging = [d for d in dbs if d.startswith(f"{TARGET_DB}_restore_")]
    assert len(staging) == 1 and dbs[staging[0]] == 0, "staging stays closed for forensics"
    assert dbs[TARGET_DB] == -1, "the live target is never touched"
    assert _psql(_dsn(TARGET_DB), "SELECT to_regclass('live_marker') IS NOT NULL") == "t"


def test_truncated_dump_is_rejected_before_the_target_is_touched(
    pg: None, tmp_path: Path, keys: Keys
) -> None:
    """M10: a truncated dump with a matching checksum never costs the live database."""
    _psql(ADMIN_DSN, f"CREATE DATABASE {SOURCE_DB}")
    _psql(_dsn(SOURCE_DB), "CREATE TABLE t AS SELECT g FROM generate_series(1, 5000) g")
    out = tmp_path / "backups"
    proc = _run(
        BACKUP, "--dsn", _dsn(SOURCE_DB), "--out", str(out), "--no-ledger", "--no-encrypt",
        "--no-sign",
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    dump = Path(proc.stdout.strip())
    dump.write_bytes(dump.read_bytes()[: dump.stat().st_size // 2])
    digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    dump.with_name(dump.name + ".sha256").write_text(f"{digest}  {dump.name}\n")
    manifest = dump.with_name(dump.name + ".manifest")
    lines = [
        f"sha256={digest}" if ln.startswith("sha256=") else ln
        for ln in manifest.read_text().splitlines()
    ]
    manifest.write_text("\n".join(lines) + "\n")
    _psql(ADMIN_DSN, f"CREATE DATABASE {TARGET_DB}")
    _psql(_dsn(TARGET_DB), "CREATE TABLE live_marker (id int)")
    proc = _run(
        RESTORE, "--dump", str(dump), "--no-ledger", "--admin-dsn", ADMIN_DSN,
        "--target-db", TARGET_DB, "--replace", "--allow-unsigned", "--allow-unencrypted",
    )  # fmt: skip
    assert proc.returncode != 0
    assert "archive is incomplete" in proc.stderr or "rejects" in proc.stderr
    assert _databases() == {SOURCE_DB: -1, TARGET_DB: -1}, "nothing created"
    assert _psql(_dsn(TARGET_DB), "SELECT to_regclass('live_marker') IS NOT NULL") == "t"
