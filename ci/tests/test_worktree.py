"""ci/worktree.sh: lane worktree helper with 100 x slot port offsets (ROADMAP 4.6)."""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ci" / "worktree.sh"
PORT_KEYS = [
    "SIBYL_PORT_HTTPS",
    "SIBYL_PORT_GATEWAY_TLS",
    "SIBYL_PORT_INGEST_TLS",
    "SIBYL_PORT_SIM",
    "SIBYL_PORT_SIM_DOUBLES",
    "SIBYL_PORT_PG",
    "SIBYL_API_PORT",
    "SIBYL_INGEST_PORT",
    "SIBYL_WORKER_PORT",
    "SIBYL_GATEWAY_PORT",
    "SIBYL_CONSOLE_PORT",
]
RESERVED_HOST_PORTS = {5432, 5433}  # other projects' PG16, the shared PG17 dev cluster


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["bash", str(SCRIPT), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd,
    )


def _dry(lane: str, slot: int, *extra: str) -> dict[str, str]:
    proc = _run("--dry-run", *extra, lane, str(slot))
    assert proc.returncode == 0, proc.stderr
    pairs = (ln.split("=", 1) for ln in proc.stdout.splitlines() if "=" in ln)
    return {k: v for k, v in pairs}


def test_dry_run_computes_names_and_offsets() -> None:
    env = _dry("W1-A", 2, "--wave", "w1")
    assert env["SIBYL_LANE"] == "w1a"
    assert env["SIBYL_SLOT"] == "2"
    assert env["SIBYL_PORT_OFFSET"] == "200"
    assert env["COMPOSE_PROJECT_NAME"] == "sibyl_w1a"
    assert env["SIBYL_DB_NAME"] == "sibyl_w1a"
    assert env["SIBYL_PG_DSN"].endswith("@localhost:5433/sibyl_w1a")
    assert env["SIBYL_BRANCH"] == "lane/w1-w1a"
    assert env["SIBYL_WORKTREE"].endswith("/sibyl-wt/w1a")
    assert env["SIBYL_PORT_HTTPS"] == "8643"
    assert env["SIBYL_PORT_SIM"] == "8500"
    assert env["SIBYL_PORT_SIM_DOUBLES"] == "18282"
    assert env["SIBYL_PUBLIC_URL"] == "https://localhost:8643"
    assert env["SIBYL_EDGE_SUBNET"] == "172.30.2.0/24"
    assert env["SIBYL_CADDY_IP"] == "172.30.2.10"
    assert env["SIBYL_CONSOLE_IP"] == "172.30.2.11"
    assert env["SIBYL_EDGE_IP_RANGE"] == "172.30.2.128/25"


def test_slot_zero_edge_network_matches_compose_defaults(compose: dict[str, Any]) -> None:
    env = _dry("main", 0)
    subnet = compose["networks"]["edge"]["ipam"]["config"][0]["subnet"]
    caddy_ip = compose["services"]["caddy"]["networks"]["edge"]["ipv4_address"]
    assert subnet == "${SIBYL_EDGE_SUBNET:-" + env["SIBYL_EDGE_SUBNET"] + "}"
    assert caddy_ip == "${SIBYL_CADDY_IP:-" + env["SIBYL_CADDY_IP"] + "}"
    ip_range = compose["networks"]["edge"]["ipam"]["config"][0]["ip_range"]
    assert ip_range == "${SIBYL_EDGE_IP_RANGE:-" + env["SIBYL_EDGE_IP_RANGE"] + "}"


@pytest.mark.parametrize("slot", range(10))
def test_every_slot_keeps_pinned_edge_addresses_out_of_the_dynamic_range(slot: int) -> None:
    env = _dry(f"lane{slot}", slot)
    subnet = ipaddress.ip_network(env["SIBYL_EDGE_SUBNET"])
    dynamic = ipaddress.ip_network(env["SIBYL_EDGE_IP_RANGE"])
    assert dynamic.subnet_of(subnet)  # type: ignore[arg-type]
    for key in ("SIBYL_CADDY_IP", "SIBYL_CONSOLE_IP"):
        pinned = ipaddress.ip_address(env[key])
        assert pinned in subnet and pinned not in dynamic, (slot, key)


def test_slot_zero_matches_compose_defaults(compose: dict[str, Any]) -> None:
    env = _dry("main", 0)
    defaults: dict[str, str] = {}
    pattern = re.compile(r"\$\{(SIBYL_PORT_[A-Z_]+):-(\d+)\}")
    for svc in compose["services"].values():
        for port in svc.get("ports", []):
            for key, value in pattern.findall(str(port)):
                defaults[key] = value
    assert defaults, "compose publishes no parameterised ports"
    for key, value in defaults.items():
        assert env[key] == value, key


def test_ports_never_collide_across_slots() -> None:
    seen: dict[int, str] = {}
    for slot in range(10):
        env = _dry(f"lane{slot}", slot)
        for key in PORT_KEYS:
            port = int(env[key])
            assert port not in RESERVED_HOST_PORTS, f"{key} slot {slot} hits {port}"
            assert port not in seen, f"{key} slot {slot} collides with {seen[port]}"
            seen[port] = f"{key}@{slot}"


@pytest.mark.parametrize("slot", ["10", "-1", "abc", ""])
def test_invalid_slot_is_rejected(slot: str) -> None:
    proc = _run("--dry-run", "w1a", slot)
    assert proc.returncode != 0


@pytest.mark.parametrize("lane", ["../evil", "a b", "x;rm", ""])
def test_invalid_lane_is_rejected(lane: str) -> None:
    proc = _run("--dry-run", lane, "1")
    assert proc.returncode != 0


def test_help_exits_zero() -> None:
    proc = _run("--help")
    assert proc.returncode == 0
    assert "usage" in proc.stdout.lower()


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_creates_worktree_branch_and_env_files(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "deploy" / "compose").mkdir(parents=True)
    (repo / "README").write_text("x\n", encoding="utf-8")
    git = ["git", "-C", str(repo), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)  # noqa: S603, S607
    subprocess.run([*git, "add", "README"], check=True)  # noqa: S603
    subprocess.run([*git, "commit", "-q", "-m", "init"], check=True)  # noqa: S603
    root = tmp_path / "wt"
    proc = _run("--repo", str(repo), "--root", str(root), "--wave", "w1", "W1-K", "3")
    assert proc.returncode == 0, proc.stderr
    wt = root / "w1k"
    assert (wt / "README").is_file()
    branch = subprocess.run(  # noqa: S603
        ["git", "-C", str(wt), "branch", "--show-current"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert branch == "lane/w1-w1k"
    lane_env = (wt / ".env.lane").read_text(encoding="utf-8")
    assert "SIBYL_PORT_OFFSET=300" in lane_env
    assert "COMPOSE_PROJECT_NAME=sibyl_w1k" in lane_env
    assert (wt / "deploy" / "compose" / ".env").read_text(encoding="utf-8") == lane_env
    again = _run("--repo", str(repo), "--root", str(root), "W1-K", "3")
    assert again.returncode != 0, "must refuse to overwrite an existing worktree"
