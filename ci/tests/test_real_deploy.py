"""The real deployment (D55): compose override, Caddy/dex variants, real.sh and the demo console
launcher. Static checks only; the live bring-up is `make up` (docs/setup/SETUP.md)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_DIR = REPO_ROOT / "deploy" / "compose"


class _Loader(yaml.SafeLoader):
    """Accepts compose's !override / !reset tags."""


def _tagged(loader: yaml.SafeLoader, _suffix: str, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)  # type: ignore[arg-type]


_Loader.add_multi_constructor("!", _tagged)


def _load(name: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.load((COMPOSE_DIR / name).read_text(encoding="utf-8"), _Loader)  # noqa: S506
    return data


def _bash(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607


def test_real_override_turns_demo_mode_off_for_every_control_process() -> None:
    services = _load("docker-compose.real.yml")["services"]
    for name in ("api", "ingest", "worker"):
        assert services[name]["environment"]["SIBYL_DEMO"] == "false"
        assert "SIBYL_OIDC_ISSUER" in services[name]["environment"]


def test_real_override_never_trusts_the_simulator() -> None:
    gateway = _load("docker-compose.real.yml")["services"]["gateway"]["environment"]
    assert gateway["SIBYL_DEV_HOSTS"] == "" and gateway["SIBYL_SIM_CA_URL"] == ""
    assert "sibyl-sim" not in _load("docker-compose.real.yml")["services"]


def test_bundled_dex_is_optional_and_uses_the_one_admin_template() -> None:
    dex = _load("docker-compose.real.yml")["services"]["dex"]
    assert dex["profiles"] == ["dex"]
    assert dex["environment"]["DEX_CONFIG_TEMPLATE"].endswith("config.real.yaml")
    config = (COMPOSE_DIR / "dex" / "config.real.yaml").read_text(encoding="utf-8")
    assert config.count("- email:") == 1, "the real dex holds exactly one (admin) user"


def test_real_caddy_binds_a_configurable_address_and_uses_the_real_caddyfile() -> None:
    caddy = _load("docker-compose.real.yml")["services"]["caddy"]
    assert all(p.startswith("${SIBYL_BIND_ADDRESS:-127.0.0.1}:") for p in caddy["ports"])
    assert any("Caddyfile.real" in v for v in caddy["volumes"])
    text = (COMPOSE_DIR / "caddy" / "Caddyfile.real").read_text(encoding="utf-8")
    assert "tls {$SIBYL_TLS:internal}" in text
    assert "local_certs" not in text
    assert "header_up X-Forwarded-For {remote_host}" in text
    assert "handle /api/v1/policy/credentials*" in text


def test_images_override_points_every_built_service_at_ghcr() -> None:
    services = _load("docker-compose.images.yml")["services"]
    for name in ("api", "gateway", "console", "sibyl-sim"):
        assert services[name]["image"].startswith("${SIBYL_IMAGE_REGISTRY:-ghcr.io/mk-jkc}/sibyl-")
        assert services[name]["build"] in (None, "null")  # !reset null


def test_real_env_example_holds_no_secret_values() -> None:
    for raw in (COMPOSE_DIR / "real.env.example").read_text(encoding="utf-8").splitlines():
        if raw.strip() and not raw.startswith("#"):
            key, _, value = raw.partition("=")
            if "SECRET" in key or "PASSWORD" in key:
                assert value == "", f"{key} must stay empty in the example"


def test_real_env_files_are_gitignored() -> None:
    ignore = (COMPOSE_DIR / ".gitignore").read_text(encoding="utf-8").split()
    assert {"env-real/", ".env.real"} <= set(ignore)


@pytest.mark.parametrize("script", ["deploy/compose/real.sh", "ops/demo/console.sh"])
def test_launchers_have_help_and_reject_unknown_arguments(script: str) -> None:
    path = str(REPO_ROOT / script)
    assert _bash(path, "--help").returncode == 0
    assert "usage" in _bash(path, "--help").stdout.lower()
    bad = _bash(path, "up", "--nope") if script.endswith("real.sh") else _bash(path, "--nope")
    assert bad.returncode == 2
    assert "unknown" in bad.stderr


def test_real_sh_rejects_unknown_commands() -> None:
    proc = _bash(str(COMPOSE_DIR / "real.sh"), "explode")
    assert proc.returncode == 2 and "unknown command" in proc.stderr


def test_makefile_exposes_both_ways_to_run() -> None:
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    for target in ("demo:", "demo-stack:", "up:", "down:", "logs:", "status:", "key:"):
        assert f"\n{target}" in text
