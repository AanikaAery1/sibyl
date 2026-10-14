"""Live compose checks against Docker (Colima here).

Runs when `docker info` answers; skips otherwise, or fails when SIBYL_REQUIRE_DOCKER=1.
Each run is isolated: a random compose project, free host ports, a random edge subnet, env and
secret files under ci/.out/ (a VM-mounted path, because compose bind-mounts file secrets), and
per-run image tags. Everything is removed afterwards (`down -v`, images, files).

What it proves (G0 security fixes):
* hardened postgres/dex/caddy/console come up healthy; compose config shows no secret value;
* postgres takes its password from the file secret; dex its client secrets and persona hash;
* Caddy overwrites X-Forwarded-For with the peer and drops Forwarded / X-Real-IP (M4), and the
  gateway-only policy routes are not on the public origin (L10);
* bootstrap (admin creds, profile) then migrate + api come up; each control/gateway process
  sees exactly its secrets through the image entrypoint, and `docker inspect` shows none (M8);
* the non-root gateway writes its snapshot dir and the worker its blob/ledger dirs on fresh
  volumes (M9).
"""

from __future__ import annotations

import base64
import importlib.util
import ipaddress
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = REPO_ROOT / "deploy" / "compose" / "docker-compose.yml"
TOKEN = secrets.token_hex(4)
PROJECT = f"sibyl_ci_{TOKEN}"
TAG = f"ci-{TOKEN}"
INFRA = ["postgres", "dex", "caddy", "console"]
PERSONAS = ["admin", "operator", "auditor"]
ECHO_BODY = "xff={http.request.header.X-Forwarded-For};fwd={http.request.header.Forwarded};" \
    "real={http.request.header.X-Real-IP}"  # fmt: skip
ECHO_IMAGE = (
    "caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d"
)


def _load_matrix() -> dict[str, dict[str, str]]:
    path = Path(__file__).with_name("sibyl_ci_secret_matrix.py")
    spec = importlib.util.spec_from_file_location("sibyl_ci_secret_matrix", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    matrix: dict[str, dict[str, str]] = module.SECRET_MATRIX
    return matrix


SECRET_MATRIX = _load_matrix()


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    proc = subprocess.run(["docker", "info"], capture_output=True, check=False, timeout=20)  # noqa: S607
    return proc.returncode == 0


if not _docker_up():
    if os.environ.get("SIBYL_REQUIRE_DOCKER") == "1":
        pytest.fail("no Docker daemon (docker info failed) and SIBYL_REQUIRE_DOCKER=1")
    pytestmark = pytest.mark.skip(reason="no Docker daemon (docker info failed)")


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
    """A random 172.30.<100-249>.0/24 that no existing Docker network overlaps (slots use 0-9)."""
    ids = subprocess.run(
        ["docker", "network", "ls", "-q"],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
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
        net = ipaddress.ip_network(f"172.30.{octet}.0/24")
        if not any(net.overlaps(u) for u in used):
            return net
    raise RuntimeError("no free 172.30.x.0/24 subnet")


@dataclass(frozen=True)
class Stack:
    root: Path
    env_dir: Path
    compose_env: Path
    override: Path
    values: dict[str, str]

    def compose(
        self, *args: str, timeout: int = 300, extra_env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "SIBYL_ENV_DIR": str(self.env_dir),
            "BUILDX_BAKE_ENTITLEMENTS_FS": "0",
            **(extra_env or {}),
        }
        cmd = [
            "docker",
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(COMPOSE_FILE),
            "-f",
            str(self.override),
        ]
        cmd += ["--env-file", str(self.compose_env), *args]
        return subprocess.run(  # noqa: S603
            cmd, capture_output=True, text=True, check=False, env=env, timeout=timeout
        )

    def secret(self, name: str) -> str:
        return (self.env_dir / "secrets" / name).read_text(encoding="utf-8")

    @property
    def public_url(self) -> str:
        return self.values["SIBYL_PUBLIC_URL"]


@pytest.fixture(scope="module")
def stack() -> Iterator[Stack]:
    root = REPO_ROOT / "ci" / ".out" / f"compose-{TOKEN}"
    env_dir, compose_env = root / "env", root / "compose.env"
    root.mkdir(parents=True)
    try:
        subprocess.run(  # noqa: S603
            [  # noqa: S607
                "bash", str(REPO_ROOT / "deploy" / "compose" / "init-env.sh"),
                "--env-dir", str(env_dir), "--compose-env", str(compose_env),
            ],
            capture_output=True,
            check=True,
        )  # fmt: skip
        https, gw, ingest, sim, pg = _free_ports(5)
        subnet = _free_subnet()
        values = {
            "COMPOSE_PROJECT_NAME": PROJECT,
            "SIBYL_VERSION": TAG,
            "SIBYL_PORT_HTTPS": str(https),
            "SIBYL_PORT_GATEWAY_TLS": str(gw),
            "SIBYL_PORT_INGEST_TLS": str(ingest),
            "SIBYL_PORT_SIM": str(sim),
            "SIBYL_PORT_PG": str(pg),
            "SIBYL_PUBLIC_URL": f"https://localhost:{https}",
            "SIBYL_EDGE_SUBNET": str(subnet),
            "SIBYL_CADDY_IP": str(subnet.network_address + 10),
            "SIBYL_CONSOLE_IP": str(subnet.network_address + 11),
            "SIBYL_EDGE_IP_RANGE": str(list(subnet.subnets(new_prefix=25))[1]),
            "SIBYL_EXTRA_CA_FILE": os.environ.get("SIBYL_EXTRA_CA_FILE", ""),
        }
        lines = [
            ln
            for ln in compose_env.read_text(encoding="utf-8").splitlines()
            if ln.split("=", 1)[0] not in values
        ]
        compose_env.write_text("\n".join([*lines, *(f"{k}={v}" for k, v in values.items())]) + "\n")
        # Test-only upstream in the console's place that echoes the forwarding headers Caddy
        # sends (the real console is exercised by test_demo_live.py). `!reset` drops the build.
        override = root / "override.yml"
        command = json.dumps(["caddy", "respond", "--listen", ":3000", "--body", ECHO_BODY])
        override.write_text(
            "services:\n"
            "  console:\n"
            f"    image: {ECHO_IMAGE}\n"
            "    build: !reset null\n"
            '    cap_add: ["NET_BIND_SERVICE"]\n'
            "    environment:\n"
            "      XDG_DATA_HOME: /tmp/caddy-data\n"
            "      XDG_CONFIG_HOME: /tmp/caddy-config\n"
            f"    command: {command}\n"
        )
        yield Stack(root, env_dir, compose_env, override, values)
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="module")
def running(stack: Stack) -> Iterator[Stack]:
    try:
        up = stack.compose("up", "-d", "--wait", "--wait-timeout", "180", *INFRA, timeout=400)
        assert up.returncode == 0, up.stderr[-2000:]
        yield stack
    finally:
        stack.compose("--profile", "bootstrap", "down", "-v", "--remove-orphans", timeout=180)


@pytest.fixture(scope="module")
def images(running: Stack) -> Iterator[Stack]:
    try:
        build = running.compose("build", "api", "gateway", timeout=1200)
        assert build.returncode == 0, build.stderr[-3000:]
        yield running
    finally:
        for repo in ("control", "gateway"):
            subprocess.run(  # noqa: S603
                ["docker", "image", "rm", "-f", f"sibyl/{repo}:{TAG}"],  # noqa: S607
                capture_output=True,
                check=False,
            )


@pytest.fixture(scope="module")
def control(images: Stack) -> Stack:
    boot = images.compose("run", "--rm", "bootstrap", timeout=300)
    assert boot.returncode == 0, boot.stderr[-2000:]
    up = images.compose(
        "up", "-d", "--wait", "--wait-timeout", "180", "migrate", "api", timeout=400
    )
    assert up.returncode == 0, (up.stderr + images.compose("logs", "migrate", "api").stdout)[-3000:]
    return images


def _caddy_ctx(stack: Stack, tmp_path: Path) -> ssl.SSLContext:
    cert = tmp_path / "root.crt"
    proc = stack.compose("cp", "caddy:/data/caddy/pki/authorities/local/root.crt", str(cert))
    assert proc.returncode == 0, proc.stderr
    return ssl.create_default_context(cafile=str(cert))


# --- config ---------------------------------------------------------------------------------


def test_compose_config_is_valid_for_every_profile(stack: Stack) -> None:
    for extra in ([], ["--profile", "sim"], ["--profile", "bootstrap"]):
        proc = stack.compose(*extra, "config", "--quiet")
        assert proc.returncode == 0, proc.stderr


def test_profiled_services_only_under_their_profile(stack: Stack) -> None:
    base = set(stack.compose("config", "--services").stdout.split())
    with_sim = set(stack.compose("--profile", "sim", "config", "--services").stdout.split())
    with_boot = set(stack.compose("--profile", "bootstrap", "config", "--services").stdout.split())
    assert "sibyl-sim" not in base and "bootstrap" not in base
    assert with_sim - base == {"sibyl-sim"}
    assert with_boot - base == {"bootstrap"}


def test_rendered_config_contains_no_secret_value(stack: Stack) -> None:
    rendered = stack.compose("--profile", "sim", "--profile", "bootstrap", "config").stdout
    assert rendered
    for path in (stack.env_dir / "secrets").iterdir():
        value = path.read_text(encoding="utf-8")
        if value:
            assert value not in rendered, f"{path.name} leaks into the compose config"


# --- infra --------------------------------------------------------------------------------------


def test_infra_services_are_healthy(running: Stack) -> None:
    proc = running.compose("ps", "--format", "json", *INFRA)
    rows = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
    assert {r["Service"]: r.get("Health") for r in rows} == dict.fromkeys(INFRA, "healthy")


def test_postgres_is_17_and_uses_the_password_file(running: Stack) -> None:
    proc = running.compose(
        "exec", "-T", "postgres", "psql", "-U", "postgres", "-Atc", "show server_version_num"
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("17")
    pg_isready = Path(os.environ.get("PGBIN", "/opt/homebrew/opt/postgresql@17/bin")) / "psql"
    if not pg_isready.exists():
        pytest.skip("PG17 client tools not installed")
    port = running.values["SIBYL_PORT_PG"]
    base = [str(pg_isready), "-X", "-At", "-h", "127.0.0.1", "-p", port, "-U", "postgres"]

    def login(password: str) -> int:
        env = {**os.environ, "PGPASSWORD": password, "PGCONNECT_TIMEOUT": "5"}
        return subprocess.run(  # noqa: S603
            [*base, "-d", "postgres", "-c", "select 1"], capture_output=True, env=env, check=False
        ).returncode

    assert login(running.secret("postgres_password")) == 0
    assert login("wrong") != 0


def test_dex_discovery_through_caddy_tls(running: Stack, tmp_path: Path) -> None:
    ctx = _caddy_ctx(running, tmp_path)
    url = f"{running.public_url}/dex/.well-known/openid-configuration"
    with urllib.request.urlopen(url, context=ctx, timeout=10) as resp:  # noqa: S310
        doc = json.load(resp)
    assert doc["issuer"] == f"{running.public_url}/dex"
    assert "S256" in doc.get("code_challenge_methods_supported", [])


@pytest.mark.parametrize("persona", PERSONAS)
def test_persona_can_log_in(running: Stack, tmp_path: Path, persona: str) -> None:
    ctx = _caddy_ctx(running, tmp_path)
    password = (running.env_dir / "demo-password.env").read_text().split("=", 1)[1].strip()
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "username": f"{persona}@demo.sibyl.example",
            "password": password,
            "scope": "openid email",
        }
    ).encode()
    req = urllib.request.Request(f"{running.public_url}/dex/token", data=body, method="POST")  # noqa: S310
    basic = base64.b64encode(f"sibyl-api:{running.secret('dex_api_client_secret')}".encode())
    req.add_header("Authorization", f"Basic {basic.decode()}")
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # noqa: S310
        token = json.load(resp)["id_token"]
    payload = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["email"] == f"{persona}@demo.sibyl.example"


def test_caddy_overwrites_client_forwarding_headers(running: Stack, tmp_path: Path) -> None:
    ctx = _caddy_ctx(running, tmp_path)
    req = urllib.request.Request(f"{running.public_url}/")  # noqa: S310
    for header in ("X-Forwarded-For", "X-Real-IP"):
        req.add_header(header, "6.6.6.6")
    req.add_header("Forwarded", "for=6.6.6.6")
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:  # noqa: S310
        body = resp.read().decode()
    fields = dict(part.split("=", 1) for part in body.split(";"))
    assert "6.6.6.6" not in body, body
    ipaddress.ip_address(fields["xff"])  # exactly one address: the peer Caddy saw
    assert fields["fwd"] == "" and fields["real"] == ""


@pytest.mark.parametrize("route", ["credentials"])
def test_gateway_only_policy_routes_are_404_on_the_public_origin(
    running: Stack, tmp_path: Path, route: str
) -> None:
    ctx = _caddy_ctx(running, tmp_path)
    url = f"{running.public_url}/api/v1/policy/{route}"
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(url, context=ctx, timeout=10)  # noqa: S310
    assert err.value.code == 404


@pytest.mark.parametrize("route", ["snapshot", "keys"])
def test_sdk_policy_routes_are_routed_on_the_public_origin(
    running: Stack, tmp_path: Path, route: str
) -> None:
    """B18: Caddy forwards the snapshot and key set to the api (the SDK polls them).

    This stack may run without the api, so any answer but Caddy's own 404 proves the route;
    the full-stack demo test checks the api's 401/200 behind it.
    """
    ctx = _caddy_ctx(running, tmp_path)
    url = f"{running.public_url}/api/v1/policy/{route}"
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=10) as resp:  # noqa: S310
            code = resp.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    assert code != 404, f"/api/v1/policy/{route} must reach the api (B18)"


# --- control plane, secrets per process, volumes ----------------------------------------------

ENV_PROBE = (
    "import json, os, pathlib; d = pathlib.Path('/run/secrets'); "
    "files = {p.name: p.read_text() for p in d.iterdir()} if d.is_dir() else {}; "
    "env = {k: v for k, v in os.environ.items() if k.startswith(('SIBYL_', 'DEX_'))}; "
    "print(json.dumps({'env': env, 'files': files}))"
)


def test_bootstrap_then_migrate_and_api_come_up(control: Stack) -> None:
    proc = control.compose("ps", "-a", "--format", "json", "migrate", "api")
    rows = {r["Service"]: r for r in map(json.loads, proc.stdout.splitlines()) if r}
    assert rows["migrate"]["ExitCode"] == 0
    assert rows["api"]["Health"] == "healthy"


@pytest.mark.parametrize("service", ["bootstrap", "migrate", "api", "ingest", "worker", "gateway"])
def test_each_process_sees_exactly_its_secrets(images: Stack, service: str) -> None:
    control = images
    proc = control.compose(
        "run", "--rm", "--no-deps", "-T", service, "python", "-c", ENV_PROBE, timeout=120
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    seen = json.loads(proc.stdout.strip().splitlines()[-1])
    env, files = seen["env"], seen["files"]
    expected = SECRET_MATRIX[service]
    assert set(files) == set(expected), f"{service} mounts {sorted(files)}"
    for target, source in expected.items():
        value = control.secret(source)
        assert files[target] == value, f"{service}: /run/secrets/{target}"
        if target.startswith(("SIBYL_", "DEX_")):
            assert env.get(target) == value, f"{service}: {target} not exported"
        elif value:
            assert value not in env.values(), f"{service}: file-only {target} leaked into env"
    granted = set(expected.values())
    for path in (control.env_dir / "secrets").iterdir():
        value = path.read_text()
        if value and path.name not in granted:
            assert value not in env.values(), f"{service} sees {path.name}"


def test_docker_inspect_shows_no_secret_values(control: Stack) -> None:
    cid = control.compose("ps", "-q", "api").stdout.strip()
    inspect = subprocess.run(  # noqa: S603
        ["docker", "inspect", cid],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for path in (control.env_dir / "secrets").iterdir():
        value = path.read_text()
        if value:
            assert value not in inspect, path.name


def test_gateway_writes_its_snapshot_dir_as_non_root(images: Stack) -> None:
    probe = (
        "import os, pathlib; d = pathlib.Path(os.environ['SIBYL_SNAPSHOT_DIR']); "
        "(d / 'last-verified.json').write_text('{}'); st = d.stat(); "
        "print(os.getuid(), st.st_uid, oct(st.st_mode & 0o777))"
    )
    proc = images.compose("run", "--rm", "--no-deps", "-T", "gateway", "python", "-c", probe)
    assert proc.returncode == 0, proc.stderr[-2000:]
    uid, owner, mode = proc.stdout.strip().splitlines()[-1].split()
    assert uid == "10001" and owner == "10001" and mode == "0o750"


def test_worker_writes_the_blob_store_that_api_and_ingest_read(images: Stack) -> None:
    """fs backend: one `blobstore` volume. The worker writes exports, anchors and the erasure
    ledger (ledger/erasure/); the api serves them; ingest writes payloads (lane U, item 2)."""
    token = secrets.token_hex(8)
    write = (
        "import asyncio, os\n"
        "from sibyl_control.core.blob.fs import FsBlobStore\n"
        "store = FsBlobStore(os.environ['SIBYL_BLOB_ROOT'])\n"
        f"asyncio.run(store.put('ledger/erasure/probe-{token}.json', b'{token}',"
        " content_type='application/json', if_absent=True))\n"
        "print('ok')\n"
    )
    read = (
        "import asyncio, os\n"
        "from sibyl_control.core.blob.fs import FsBlobStore\n"
        "store = FsBlobStore(os.environ['SIBYL_BLOB_ROOT'])\n"
        f"print(asyncio.run(store.get('ledger/erasure/probe-{token}.json')).decode())\n"
    )
    proc = images.compose("run", "--rm", "--no-deps", "-T", "worker", "python", "-c", write)
    assert proc.returncode == 0, proc.stderr[-2000:]
    for reader in ("api", "ingest"):
        got = images.compose("run", "--rm", "--no-deps", "-T", reader, "python", "-c", read)
        assert got.returncode == 0, got.stderr[-2000:]
        assert got.stdout.strip().splitlines()[-1] == token, reader


def test_images_do_not_contain_the_extra_ca(images: Stack) -> None:
    ca = os.environ.get("SIBYL_EXTRA_CA_FILE", "")
    if not ca or not Path(ca).expanduser().is_file():
        pytest.skip("no SIBYL_EXTRA_CA_FILE: nothing to scan for")
    lines = Path(ca).expanduser().read_text(encoding="utf-8").splitlines()
    marker = next(ln for ln in lines[2:] if len(ln) >= 60)
    scan = (
        "import os,sys\n"
        f"m={marker!r}.encode()\n"
        "hits=[]\n"
        "for top in ('/etc','/app','/usr/local','/root','/tmp','/run'):\n"
        "  for d,_,fs in os.walk(top):\n"
        "    for f in fs:\n"
        "      p=os.path.join(d,f)\n"
        "      try:\n"
        "        hits += [p] if m in open(p,'rb').read() else []\n"
        "      except OSError: pass\n"
        "print('\\n'.join(hits)); sys.exit(1 if hits else 0)\n"
    )
    for repo in ("control", "gateway"):
        leak = subprocess.run(  # noqa: S603
            ["docker", "run", "--rm", "--entrypoint", "python", f"sibyl/{repo}:{TAG}", "-c", scan],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
        )
        assert leak.returncode == 0, f"extra CA found in sibyl/{repo}: {leak.stdout}"
