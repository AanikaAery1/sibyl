"""``python -m sibyl_control.cli tenant …`` against the lane's migrated PG17 database."""

from __future__ import annotations

import importlib.util
import io
import json
import secrets
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sibyl_control.cli import main

REPO = Path(__file__).resolve().parents[4]


def _kit() -> Any:
    name = "sibyl_lane_a_kit"
    if name not in sys.modules:
        path = Path(__file__).resolve().parents[1] / "api" / "auth" / "kit.py"
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


kit = _kit()


@pytest.fixture(scope="module")
def lane_db() -> Iterator[Any]:
    if not kit.available():
        pytest.skip("PostgreSQL 17 not reachable (make db-up)")
    db = kit.acquire()
    yield db
    kit.release()


@pytest.fixture
def cli_env(lane_db: Any, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    env = {
        "SIBYL_PG_DSN": lane_db.dsn(),
        "SIBYL_KEK": kit.KEK_B64,
        "SIBYL_KEK_ID": kit.KEK_ID,
        "SIBYL_KEY_PEPPER": kit.PEPPER_HEX,
        "SIBYL_ENV": "live",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_create_list_show(cli_env: dict[str, str], lane_db: Any) -> None:
    slug = f"cli{secrets.token_hex(4)}"
    code, out, err = run(
        "--json", "tenant", "create", slug, "--name", "CLI Tenant", "--region", "eu-west"
    )
    assert code == 0, err
    tenant = json.loads(out)["id"]
    again = run("tenant", "create", slug, "--name", "x")
    assert again[0] == 2 and "already exists" in again[2]
    code, out, _ = run("--json", "tenant", "list")
    assert slug in {t["slug"] for t in json.loads(out)}
    code, out, _ = run("--json", "tenant", "show", slug)
    doc = json.loads(out)
    assert doc["id"] == tenant and {k["purpose"] for k in doc["tenant_keys"]} == {
        "payload",
        "credential",
        "config",
    }
    with lane_db.admin.tx(doc["id"]):
        wrapped = lane_db.admin.fetchval(
            "SELECT wrapped_dek FROM sibyl.tenant_key WHERE tenant_id = $1 AND purpose = 'config'",
            doc["id"],
        )
    assert (
        len(kit.TEST_KEK.unwrap(bytes(wrapped), kit.wrap_aad(kit.UUID(tenant), "config", 1))) == 32
    )
    assert run("tenant", "show", "no-such-tenant")[0] == 2


def test_issuer_and_bootstrap_owner(cli_env: dict[str, str], lane_db: Any) -> None:
    slug = f"cli{secrets.token_hex(4)}"
    run("tenant", "create", slug, "--name", "Boot")
    assert run("tenant", "add-issuer", slug, "--issuer-url", "http://insecure.test")[0] == 2
    code, out, err = run(
        "--json", "tenant", "add-issuer", slug, "--issuer-url", "https://idp.test/dex"
    )
    assert code == 0 and json.loads(out)["created"], err
    assert (
        json.loads(
            run("--json", "tenant", "add-issuer", slug, "--issuer-url", "https://idp.test/dex")[1]
        )["created"]
        is False
    )
    code, out, err = run(
        "--json",
        "tenant",
        "add-user",
        slug,
        "--issuer-url",
        "https://idp.test/dex",
        "--subject",
        "first-owner",
        "--email",
        "o@x.test",
        "--role",
        "owner",
    )
    assert code == 0, err
    assert json.loads(out)["granted"] == ["owner"]
    code, out, _ = run(
        "--json",
        "tenant",
        "add-user",
        slug,
        "--issuer-url",
        "https://idp.test/dex",
        "--subject",
        "first-owner",
        "--email",
        "o@x.test",
        "--role",
        "owner",
    )
    assert json.loads(out)["granted"] == []
    tenant = json.loads(run("--json", "tenant", "show", slug)[1])["id"]
    assert kit.audit_actions(lane_db, kit.UUID(tenant))[-1] == "user.provisioned"


def test_seed_demo_applies_the_persona_contract(
    cli_env: dict[str, str], lane_db: Any, tmp_path: Path
) -> None:
    source = (REPO / "deploy/compose/dex/personas.yaml").read_text()
    suffix = secrets.token_hex(3)
    personas = tmp_path / "personas.yaml"
    personas.write_text(
        source.replace("meridian", f"meridian{suffix}")
        .replace("northstar", f"northstar{suffix}")
        .replace("sandbox", f"sandbox{suffix}")
    )
    code, out, err = run(
        "--json",
        "tenant",
        "seed-demo",
        "--personas",
        str(personas),
        "--issuer-url",
        "https://localhost:8443/dex",
    )
    assert code == 0, err
    report = json.loads(out)
    meridian = report[f"meridian{suffix}"]
    assert meridian["created"] and set(meridian["bindings"]) == {"admin", "operator", "auditor"}
    assert meridian["bindings"]["operator"]["granted"] == ["operator", "security_admin"]
    assert set(report[f"sandbox{suffix}"]["bindings"]) == {"admin"}  # B3: sandbox is the admin only
    rerun = json.loads(
        run(
            "--json",
            "tenant",
            "seed-demo",
            "--personas",
            str(personas),
            "--issuer-url",
            "https://localhost:8443/dex",
        )[1]
    )
    assert not rerun[f"meridian{suffix}"]["created"]
    assert all(b["granted"] == [] for b in rerun[f"meridian{suffix}"]["bindings"].values())


def test_module_entrypoint_runs() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "sibyl_control.cli", "tenant", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0 and "seed-demo" in proc.stdout
