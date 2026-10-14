"""Secrets: per-service file secrets (M8), nothing secret inline or in env files.

The matrix below is the contract: each service receives exactly these compose secrets, mounted
at /run/secrets/<target> and exported by the image entrypoint as the env var <target>.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest


def _load_matrix() -> dict[str, dict[str, str]]:
    # --import-mode=importlib puts nothing on sys.path; load the shared module by path.
    import importlib.util

    path = Path(__file__).with_name("sibyl_ci_secret_matrix.py")
    spec = importlib.util.spec_from_file_location("sibyl_ci_secret_matrix", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix: dict[str, dict[str, str]] = module.SECRET_MATRIX
    return matrix


SECRET_MATRIX = _load_matrix()

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"
ENTRYPOINT = REPO_ROOT / "deploy" / "docker" / "sibyl-entrypoint.sh"
SECRET_KEY = re.compile(r"(PASSWORD|SECRET|TOKEN|PEPPER|SALT|KEK|PRIVATE|_KEYS?$|_HASH)", re.I)
SECRET_FILE_REF = re.compile(r"^/run/secrets/[a-z0-9_]+$")
REFERENCE = re.compile(r"^\$\{[A-Z0-9_]+(:?[-?][^}]*)?\}$")
CREDENTIAL_IN_URL = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s/]+@", re.I)
BCRYPT = re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# Names that look secret but are identifiers.
NON_SECRET_KEYS = frozenset({"SIBYL_KEK_ID"})

# Invariants stated in the brief, checked independently of the matrix literal above.
ONLY = {
    "kek": {"api", "ingest", "worker"},  # B7
    "snapshot_signing_key": {"api"},
    "ledger_signing_key": {"worker"},
    "anchor_signing_key": {"worker"},
    "postgres_password": {"postgres", "bootstrap"},
    "db_password_app": {"api", "bootstrap"},
    "db_password_ingest": {"ingest", "bootstrap"},
    "db_password_worker": {"worker", "bootstrap"},
    "db_password_migrate": {"migrate", "bootstrap"},
    "key_pepper": {"api", "ingest", "gateway"},  # B12
    "scrub_salt": {"ingest", "gateway"},
    "subject_salt": {"api", "ingest"},
    "session_secret": {"api"},
    "oidc_client_secret": {"api", "dex"},
    "gateway_ingest_key": {"gateway"},  # B12
    "gateway_tenant_keys": {"gateway"},
}


def _granted(svc: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in svc.get("secrets", []):
        if isinstance(entry, str):
            out[entry] = entry
        else:
            out[entry.get("target", entry["source"])] = entry["source"]
    return out


def _env_items(env: Any) -> list[tuple[str, str]]:
    if isinstance(env, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    items = []
    for entry in env or []:
        key, _, value = str(entry).partition("=")
        items.append((key, value))
    return items


# --- matrix ------------------------------------------------------------------------------------


def test_every_service_is_in_the_matrix(services: dict[str, Any]) -> None:
    assert set(services) == set(SECRET_MATRIX)


@pytest.mark.parametrize("name", sorted(SECRET_MATRIX))
def test_service_receives_exactly_its_secrets(services: dict[str, Any], name: str) -> None:
    assert _granted(services[name]) == SECRET_MATRIX[name]


@pytest.mark.parametrize(("source", "allowed"), sorted(ONLY.items()))
def test_key_material_reaches_only_its_owners(
    services: dict[str, Any], source: str, allowed: set[str]
) -> None:
    holders = {n for n, s in services.items() if source in _granted(s).values()}
    assert holders == allowed


def test_declared_secrets_are_files_under_the_env_secrets_dir(compose: dict[str, Any]) -> None:
    declared = compose["secrets"]
    used = {src for svc in compose["services"].values() for src in _granted(svc).values()}
    runtime = {k for k in declared if k != "extra_ca"}
    assert used == runtime, "every runtime secret is granted somewhere, and only declared ones"
    for name in runtime:
        assert declared[name]["file"] == "${SIBYL_ENV_DIR:-./env}/secrets/" + name


def test_ledger_key_is_file_only_for_the_writer(services: dict[str, Any]) -> None:
    worker = services["worker"]
    assert (
        worker["environment"]["SIBYL_LEDGER_SIGNING_KEY_FILE"] == "/run/secrets/ledger_signing_key"
    )
    assert _granted(worker)["ledger_signing_key"] == "ledger_signing_key"


def test_admin_credentials_only_in_bootstrap(services: dict[str, Any]) -> None:
    for name, svc in services.items():
        keys = {k for k, _ in _env_items(svc.get("environment"))}
        if name != "bootstrap":
            assert "SIBYL_PG_ADMIN_USER" not in keys, name
    assert services["bootstrap"].get("profiles") == ["bootstrap"], "explicit, not every `up`"


# --- nothing secret inline or in env files -----------------------------------------------------


def test_compose_environment_has_no_literal_secrets(services: dict[str, Any]) -> None:
    for name, svc in services.items():
        for key, value in _env_items(svc.get("environment")):
            if SECRET_KEY.search(key) and value:
                ok = REFERENCE.match(value) or SECRET_FILE_REF.match(value)
                assert ok, f"{name}.{key} is a literal; use a compose file secret"
            assert not CREDENTIAL_IN_URL.search(value), f"{name}.{key} embeds a credential"


@pytest.mark.parametrize(
    "path",
    sorted(
        p
        for p in COMPOSE_DIR.rglob("*")
        if p.is_file()
        and p.suffix not in (".md", ".env")
        and p.name != ".env"
        and not {"secrets", "public"} & set(p.relative_to(COMPOSE_DIR).parts)
    ),
    ids=lambda p: str(p.relative_to(COMPOSE_DIR)),
)
def test_committed_compose_files_hold_no_secret_material(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert not BCRYPT.search(text), f"{path.name} holds a bcrypt hash"
    assert not PEM.search(text), f"{path.name} holds a private key"
    assert not CREDENTIAL_IN_URL.search(text), f"{path.name} embeds a credential in a URL"


@pytest.mark.parametrize(
    "path", sorted(COMPOSE_DIR.glob("env/*.env.example")), ids=lambda p: p.name
)
def test_env_examples_hold_no_secret_keys_at_all(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, _ = line.partition("=")
        assert sep, f"{path.name}: malformed line {raw!r}"
        if key in NON_SECRET_KEYS:
            continue
        assert not SECRET_KEY.search(key), f"{path.name}: {key} belongs in a file secret"


def test_real_env_and_secret_files_are_gitignored() -> None:
    ignore = (COMPOSE_DIR / ".gitignore").read_text(encoding="utf-8").split()
    assert {"env/*.env", ".env", "env/secrets/"} <= set(ignore)


# --- init-env.sh -------------------------------------------------------------------------------


def _b64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("initenv")
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "bash", str(COMPOSE_DIR / "init-env.sh"), "--env-dir", str(root / "env"),
            "--compose-env", str(root / "compose.env"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    return root / "env"


def test_init_env_writes_every_declared_secret(generated: Path, compose: dict[str, Any]) -> None:
    secrets_dir = generated / "secrets"
    assert stat.S_IMODE(secrets_dir.stat().st_mode) == 0o700
    runtime = {k for k in compose["secrets"] if k != "extra_ca"}
    assert {p.name for p in secrets_dir.iterdir()} == runtime
    for path in secrets_dir.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o444, path.name


def test_init_env_secret_formats(generated: Path) -> None:
    s = {p.name: p.read_text() for p in (generated / "secrets").iterdir()}
    assert len(_b64url(s["kek"])) == 32, "LocalKek: base64url of 32 bytes"
    for name in ("snapshot_signing_key", "ledger_signing_key", "anchor_signing_key"):
        assert len(_b64url(s[name])) == 32, f"{name}: Ed25519 seed"
        pub = generated / "public" / f"{name.removesuffix('_key')}.pem"
        assert pub.read_text().startswith("-----BEGIN PUBLIC KEY-----")
    for name in ("postgres_password", "db_password_app", "key_pepper", "scrub_salt"):
        assert re.fullmatch(r"[0-9a-f]{64}", s[name]), name
    assert len({s[n] for n in ("db_password_app", "db_password_ingest", "db_password_worker")}) == 3
    assert s["gateway_tenant_keys"] == "" and s["sim_gateway_key"] == ""
    assert s["gateway_ingest_key"] == "", "minted after first boot (ingest:write)"
    assert BCRYPT.search(base64.b64decode(s["dex_persona_hash"]).decode())


def test_init_env_writes_the_gateway_snapshot_pin(generated: Path) -> None:
    """B12: the gateway pins the public half of secrets/snapshot_signing_key ($defs/signing_key)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pin_path = generated / "public" / "snapshot_pin.json"
    assert stat.S_IMODE(pin_path.stat().st_mode) == 0o644, "public, readable by uid 10001"
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    assert set(pin) == {"kid", "alg", "public_key"}
    assert pin["alg"] == "Ed25519"
    assert re.fullmatch(r"snapshot-[0-9a-f]{16}", pin["kid"])
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", pin["public_key"])
    seed = _b64url((generated / "secrets" / "snapshot_signing_key").read_text())
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    assert _b64url(pin["public_key"]) == public
    assert pin["kid"] == "snapshot-" + hashlib.sha256(public).hexdigest()[:16]


def test_init_env_publishes_the_audit_anchor_key(generated: Path) -> None:
    """Lane U: the anchor key's public half is registered (signing_key, purpose audit_anchor)
    and published so `sibyl audit verify --public-key` works offline."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    seed = _b64url((generated / "secrets" / "anchor_signing_key").read_text())
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    key = json.loads((generated / "public" / "anchor_key.json").read_text(encoding="utf-8"))
    assert set(key) == {"kid", "alg", "public_key"}
    assert key["alg"] == "Ed25519"
    assert key["kid"] == "audit-anchor-" + hashlib.sha256(public).hexdigest()[:16]
    assert _b64url(key["public_key"]) == public
    pem = load_pem_public_key((generated / "public" / "anchor_signing.pem").read_bytes())
    assert pem.public_bytes_raw() == public  # type: ignore[union-attr]


def test_init_env_rederives_missing_public_material_from_kept_seeds(generated: Path) -> None:
    public = generated / "public"
    before = {p.name: p.read_text() for p in public.iterdir()}
    for name in ("anchor_key.json", "anchor_signing.pem", "ledger_signing.pem"):
        (public / name).unlink()
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "bash", str(COMPOSE_DIR / "init-env.sh"), "--env-dir", str(generated),
            "--compose-env", str(generated.parent / "compose.env"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert {p.name: p.read_text() for p in public.iterdir()} == before


def test_init_env_rederives_a_missing_pin_from_the_kept_seed(generated: Path) -> None:
    pin_path = generated / "public" / "snapshot_pin.json"
    before = pin_path.read_text(encoding="utf-8")
    pin_path.unlink()
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "bash", str(COMPOSE_DIR / "init-env.sh"), "--env-dir", str(generated),
            "--compose-env", str(generated.parent / "compose.env"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert pin_path.read_text(encoding="utf-8") == before


def test_init_env_never_overwrites_and_flags_legacy_env_files(generated: Path) -> None:
    before = (generated / "secrets" / "kek").read_text()
    control = generated / "control.env"
    control.write_text(control.read_text() + "SIBYL_MASTER_KEK=old-secret\n")
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "bash", str(COMPOSE_DIR / "init-env.sh"), "--env-dir", str(generated),
            "--compose-env", str(generated.parent / "compose.env"),
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # fmt: skip
    assert proc.returncode != 0, "a pre-split env file with secrets must not pass silently"
    assert "control.env still holds secret values" in proc.stderr
    assert (generated / "secrets" / "kek").read_text() == before


# --- the image entrypoint shim -----------------------------------------------------------------


def _shim(tmp_path: Path, files: dict[str, str], env: dict[str, str] | None = None) -> str:
    d = tmp_path / "run-secrets"
    d.mkdir()
    for name, value in files.items():
        (d / name).write_text(value)
    proc = subprocess.run(  # noqa: S603
        ["sh", str(ENTRYPOINT), "env"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": os.environ["PATH"], "SIBYL_SECRETS_DIR": str(d), **(env or {})},
    )
    return proc.stdout


def test_entrypoint_exports_granted_secrets(tmp_path: Path) -> None:
    out = _shim(
        tmp_path,
        {
            "SIBYL_KEK": "k3k\n",
            "DEX_API_CLIENT_SECRET": "d",
            "postgres_password": "not-exported",
            "SIBYL_bad-name": "x",
        },
        env={"SIBYL_KEK": "stale"},
    )
    lines = out.splitlines()
    assert "SIBYL_KEK=k3k" in lines, "file wins over env, trailing newline stripped"
    assert "DEX_API_CLIENT_SECRET=d" in lines
    assert not any(ln.startswith(("postgres_password=", "SIBYL_bad-name=")) for ln in lines)


def test_entrypoint_without_secrets_dir_just_execs(tmp_path: Path) -> None:
    proc = subprocess.run(  # noqa: S603
        ["sh", str(ENTRYPOINT), "echo", "ok"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
        env={"PATH": os.environ["PATH"], "SIBYL_SECRETS_DIR": str(tmp_path / "missing")},
    )
    assert proc.stdout.strip() == "ok"
