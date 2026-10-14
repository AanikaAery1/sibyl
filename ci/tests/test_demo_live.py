"""Live: ops/demo/up.sh brings the whole demo stack up healthy (INT-2 item 8).

Opt-in: it builds all four images and runs every service, so it runs only with
SIBYL_REQUIRE_DOCKER=1 (and then fails, never skips, without a Docker daemon). Isolated like
test_compose_live.py: a random compose project, free host ports, a random edge subnet, env and
secret files under ci/.out/ (VM-mounted under Colima) and per-run image tags; ops/demo/down.sh
--purge and an image cleanup run afterwards. Set SIBYL_EXTRA_CA_FILE behind a TLS-re-signing proxy.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "deploy" / "compose" / "docker-compose.yml"
UP, DOWN = REPO_ROOT / "ops" / "demo" / "up.sh", REPO_ROOT / "ops" / "demo" / "down.sh"
TOKEN = secrets.token_hex(4)
PROJECT = f"sibyl_demo_{TOKEN}"
TAG = f"demo-{TOKEN}"
SERVICES = [
    "postgres",
    "dex",
    "caddy",
    "api",
    "ingest",
    "worker",
    "gateway",
    "console",
    "sibyl-sim",
]
IMAGES = ["control", "gateway", "console", "sim"]


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(["docker", "info"], capture_output=True, check=False, timeout=20)  # noqa: S607
    return proc.returncode == 0


if os.environ.get("SIBYL_REQUIRE_DOCKER") != "1":
    pytestmark = pytest.mark.skip(
        reason="opt-in: set SIBYL_REQUIRE_DOCKER=1 to bring up the full demo stack"
    )
elif not _docker_up():
    pytest.fail("no Docker daemon (docker info failed) and SIBYL_REQUIRE_DOCKER=1")


def _free_ports(n: int) -> list[int]:
    socks = [socket.socket() for _ in range(n)]
    try:
        for s in socks:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for s in socks:
            s.close()


def _free_subnet() -> ipaddress.IPv4Network:
    ids = subprocess.run(
        ["docker", "network", "ls", "-q"], capture_output=True, text=True, check=True  # noqa: S607
    ).stdout.split()  # fmt: skip
    used: list[ipaddress.IPv4Network] = []
    if ids:
        out = subprocess.run(  # noqa: S603
            ["docker", "network", "inspect", "--format", "{{json .IPAM.Config}}", *ids],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for line in out.splitlines():
            for cfg in json.loads(line) or []:
                if cfg.get("Subnet") and ":" not in cfg["Subnet"]:
                    used.append(ipaddress.ip_network(cfg["Subnet"]))
    for octet in secrets.SystemRandom().sample(range(100, 250), 150):
        net = ipaddress.ip_network(f"172.31.{octet}.0/24")
        if not any(net.overlaps(u) for u in used):
            return net
    raise RuntimeError("no free 172.31.x.0/24 subnet")


@dataclass(frozen=True)
class Demo:
    env_dir: Path
    compose_env: Path
    ports: dict[str, int]
    up_stdout: str

    def compose(self, *args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
        cmd = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE)]
        cmd += ["--env-file", str(self.compose_env), "--profile", "sim", *args]
        env = {**os.environ, "SIBYL_ENV_DIR": str(self.env_dir)}
        return subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, check=False, env=env, timeout=timeout
        )

    def script(
        self, path: Path, *args: str, timeout: int = 2400
    ) -> subprocess.CompletedProcess[str]:
        argv = ["bash", str(path), "--env-dir", str(self.env_dir)]
        argv += ["--compose-env", str(self.compose_env), "--project", PROJECT, *args]
        return subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, check=False, timeout=timeout
        )

    def caddy_ctx(self) -> ssl.SSLContext:
        cert = self.env_dir.parent / "caddy-root.crt"
        if not cert.exists():
            proc = self.compose("cp", "caddy:/data/caddy/pki/authorities/local/root.crt", str(cert))
            assert proc.returncode == 0, proc.stderr
        return ssl.create_default_context(cafile=str(cert))

    def https(self, path: str) -> tuple[int, bytes]:
        url = f"https://localhost:{self.ports['https']}{path}"
        try:
            with urllib.request.urlopen(url, context=self.caddy_ctx(), timeout=15) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as err:
            return err.code, err.read()


@pytest.fixture(scope="module")
def demo() -> Iterator[Demo]:
    root = REPO_ROOT / "ci" / ".out" / f"demo-{TOKEN}"
    env_dir, compose_env = root / "env", root / "compose.env"
    root.mkdir(parents=True)
    https, gw, ingest, sim, doubles, pg = _free_ports(6)
    ports = {"https": https, "gateway": gw, "ingest": ingest, "sim": sim, "doubles": doubles}
    subnet = _free_subnet()
    values = {
        "COMPOSE_PROJECT_NAME": PROJECT,
        "SIBYL_VERSION": TAG,
        "SIBYL_PORT_HTTPS": str(https),
        "SIBYL_PORT_GATEWAY_TLS": str(gw),
        "SIBYL_PORT_INGEST_TLS": str(ingest),
        "SIBYL_PORT_SIM": str(sim),
        "SIBYL_PORT_SIM_DOUBLES": str(doubles),
        "SIBYL_PORT_PG": str(pg),
        "SIBYL_PUBLIC_URL": f"https://localhost:{https}",
        "SIBYL_EDGE_SUBNET": str(subnet),
        "SIBYL_CADDY_IP": str(subnet.network_address + 10),
        "SIBYL_CONSOLE_IP": str(subnet.network_address + 11),
        "SIBYL_EDGE_IP_RANGE": str(list(subnet.subnets(new_prefix=25))[1]),
    }
    stack = Demo(env_dir, compose_env, ports, "")
    try:
        init = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "bash", str(REPO_ROOT / "deploy" / "compose" / "init-env.sh"),
                "--env-dir", str(env_dir), "--compose-env", str(compose_env),
            ],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        assert init.returncode == 0, init.stderr
        lines = [
            ln
            for ln in compose_env.read_text(encoding="utf-8").splitlines()
            if ln.split("=", 1)[0] not in values
        ]
        compose_env.write_text("\n".join([*lines, *(f"{k}={v}" for k, v in values.items())]) + "\n")
        up = stack.script(UP, "--timeout", "300")
        assert up.returncode == 0, (up.stdout + up.stderr)[-5000:]
        yield Demo(env_dir, compose_env, ports, up.stdout)
    finally:
        stack.script(DOWN, "--purge", timeout=300)
        for repo in IMAGES:
            subprocess.run(  # noqa: S603
                ["docker", "image", "rm", "-f", f"sibyl/{repo}:{TAG}"],  # noqa: S607
                capture_output=True,
                check=False,
            )
        shutil.rmtree(root, ignore_errors=True)


def _ps(demo: Demo) -> dict[str, dict[str, object]]:
    proc = demo.compose("ps", "-a", "--format", "json")
    return {r["Service"]: r for r in map(json.loads, proc.stdout.splitlines()) if r}


def test_every_service_is_healthy(demo: Demo) -> None:
    rows = _ps(demo)
    health = {name: rows.get(name, {}).get("Health") for name in SERVICES}
    assert health == dict.fromkeys(SERVICES, "healthy"), health
    assert rows["migrate"]["ExitCode"] == 0


def test_up_prints_the_urls(demo: Demo) -> None:
    p = demo.ports
    out = demo.up_stdout
    assert f"console   https://localhost:{p['https']}" in out
    assert f"gateway   https://localhost:{p['gateway']}/v1" in out
    assert f"ingest    https://localhost:{p['ingest']}/v1" in out
    assert f"sim       http://localhost:{p['sim']}" in out


def test_console_serves_the_ui_and_its_bff_through_caddy(demo: Demo) -> None:
    status, body = demo.https("/healthz")
    assert status == 200 and body.strip() == b"ok"
    # SIBYL_CONSOLE_MODE defaults to live in compose: a live console has no demo persona, so an
    # anonymous session read is a 401 "sign in" problem (demo mode would answer 200 as a persona).
    status, body = demo.https("/api/bff/session")
    assert status == 401, body[:500]
    assert json.loads(body)["type"].endswith("/unauthenticated"), body[:500]


def test_console_bff_reaches_the_api(demo: Demo) -> None:
    """Live mode proxies to http://api:8000; without a session the api answers, not a 502."""
    status, body = demo.https("/api/bff/agents")
    problem = json.loads(body)
    assert "upstream_unavailable" not in str(problem.get("type", "")), problem
    assert status in (401, 403), (status, problem)


def test_api_is_a_live_deployment_in_demo_mode(demo: Demo) -> None:
    probe = "from sibyl_control.core.settings import Settings; s = Settings(); print(s.env, s.demo)"
    proc = demo.compose("exec", "-T", "api", "python", "-c", probe)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split()[-2:] == ["live", "True"]


def test_snapshot_signing_key_is_registered_and_published(demo: Demo) -> None:
    pin = json.loads((demo.env_dir / "public" / "snapshot_pin.json").read_text())
    status, body = demo.https("/.well-known/sibyl-keys.json")
    assert status == 200, body[:500]
    keys = json.loads(body)
    assert keys["kid"] == pin["kid"], "genesis key set is self-signed by the pinned key"
    listed = {k["kid"]: k["public_key"] for k in keys["body"]["keys"]}
    assert listed == {pin["kid"]: pin["public_key"]}


def test_gateway_key_chain_accepts_the_api_key_set_from_its_pin(demo: Demo) -> None:
    """B12 end to end: the pinned genesis verifies what the api signs with the seed secret."""
    probe = (
        "import pathlib, urllib.request\n"
        "from datetime import UTC, datetime\n"
        "from sibyl_gateway.policy.keychain import KeyChain\n"
        "pin = pathlib.Path('/etc/sibyl/snapshot-pin.json').read_text()\n"
        "ks = urllib.request.urlopen('http://api:8000/.well-known/sibyl-keys.json', timeout=5)\n"
        "chain = KeyChain.from_pin_json(pin)\n"
        "print('sequence', chain.accept(ks.read(), now=datetime.now(UTC), persist=False))\n"
    )
    proc = demo.compose("exec", "-T", "gateway", "python", "-c", probe)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.split()[-2:] == ["sequence", "1"]


def test_register_step_is_idempotent_for_both_signing_keys(demo: Demo) -> None:
    pin = (demo.env_dir / "public" / "snapshot_pin.json").read_text()
    anchor = (demo.env_dir / "public" / "anchor_key.json").read_text()
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE),
            "--env-file", str(demo.compose_env), "run", "--rm", "-T", "--no-deps",
            "-e", f"SIBYL_SNAPSHOT_PIN={pin}", "-e", f"SIBYL_ANCHOR_PIN={anchor}",
            "migrate", "python", "-",
        ],
        input=(REPO_ROOT / "ops" / "demo" / "register.py").read_text(),
        capture_output=True, text=True, check=False, timeout=120,
        env={**os.environ, "SIBYL_ENV_DIR": str(demo.env_dir)},
    )  # fmt: skip
    assert proc.returncode == 0, proc.stderr
    assert "snapshot signing key" in proc.stdout and "audit_anchor signing key" in proc.stdout
    assert proc.stdout.count("already active") == 2


def test_worker_anchor_secret_matches_the_registered_audit_anchor_key(demo: Demo) -> None:
    """The worker only signs anchors with a seed whose public key is the active row (lane U)."""
    anchor = json.loads((demo.env_dir / "public" / "anchor_key.json").read_text())
    probe = (
        "import base64, os\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        # `exec` bypasses the entrypoint shim; read what it exports to the worker process.
        "s = open('/run/secrets/SIBYL_ANCHOR_SIGNING_KEY').read().strip()\n"
        "seed = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))\n"
        "pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()\n"
        "print(base64.urlsafe_b64encode(pub).rstrip(b'=').decode())\n"
    )
    proc = demo.compose("exec", "-T", "worker", "python", "-c", probe)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert proc.stdout.split()[-1] == anchor["public_key"]


def test_gateway_trusts_the_sim_doubles_and_keeps_the_system_roots(demo: Demo) -> None:
    probe = (
        "import socket, ssl; "
        "ctx = ssl.create_default_context(cafile='/tmp/sibyl-upstream-ca.pem'); "
        "s = ctx.wrap_socket(socket.create_connection(('sim', 18082), 5), server_hostname='sim'); "
        "print('handshake', s.version(), len(ctx.get_ca_certs()))"
    )
    proc = demo.compose("exec", "-T", "gateway", "python", "-c", probe)
    assert proc.returncode == 0, proc.stderr[-2000:]
    _, version, roots = proc.stdout.split()
    assert version.startswith("TLSv1.")
    assert int(roots) > 50, "system roots stay trusted for real providers"
    logs = demo.compose("logs", "gateway").stdout
    assert "trusting sibyl-sim dev CA" in logs
    for missing in ("SIBYL_KEY_PEPPER missing", "SIBYL_SNAPSHOT_PINNED_KEY", "SIBYL_SCRUB_SALT"):
        assert missing not in logs, f"gateway config problem: {missing}"


def test_sim_doubles_are_published_on_loopback_with_the_dev_ca(demo: Demo, tmp_path: Path) -> None:
    ca = tmp_path / "sim-ca.pem"
    url = f"http://localhost:{demo.ports['sim']}/_sim/tls/ca.pem"
    with urllib.request.urlopen(url, timeout=10) as resp:
        ca.write_bytes(resp.read())
    ctx = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection(("127.0.0.1", demo.ports["doubles"]), 5) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            assert tls.version()


def test_up_is_rerunnable_without_rebuilding(demo: Demo) -> None:
    again = demo.script(UP, "--no-build", "--timeout", "300", timeout=900)
    assert again.returncode == 0, (again.stdout + again.stderr)[-4000:]
    assert "already active" in again.stdout
    health = {name: _ps(demo).get(name, {}).get("Health") for name in SERVICES}
    assert health == dict.fromkeys(SERVICES, "healthy"), health
