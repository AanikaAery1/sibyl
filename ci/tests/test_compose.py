"""Static validation of deploy/compose: services, healthchecks, profiles, wiring.

Docker is not installed on the build host, so these tests are the compose gate
(ROADMAP 4 W0-14, LANES W0-INF). They parse the YAML and assert the contract.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

COMPOSE_DIR = Path(__file__).resolve().parents[2] / "deploy" / "compose"
DOCKER_DIR = COMPOSE_DIR.parent / "docker"
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")

CONTROL_ENTRYPOINTS = {
    "api": "sibyl_control.api",
    "ingest": "sibyl_control.ingest",
    "worker": "sibyl_control.worker",
    "migrate": "sibyl_control.migrate",
}
LONG_RUNNING = ["postgres", "dex", "caddy", "api", "ingest", "worker", "gateway", "console"]
REQUIRED = [*LONG_RUNNING, "migrate", "bootstrap", "sibyl-sim"]


def _command(svc: dict[str, Any]) -> list[str]:
    cmd = svc.get("command", [])
    return cmd.split() if isinstance(cmd, str) else [str(c) for c in cmd]


def _healthcheck_text(svc: dict[str, Any]) -> str:
    test = svc["healthcheck"]["test"]
    return " ".join(test) if isinstance(test, list) else str(test)


def test_compose_has_every_required_service(services: dict[str, Any]) -> None:
    missing = [name for name in REQUIRED if name not in services]
    assert not missing, f"missing services: {missing}"


@pytest.mark.parametrize("name", [*LONG_RUNNING, "sibyl-sim"])
def test_long_running_services_have_healthchecks(services: dict[str, Any], name: str) -> None:
    hc = services[name].get("healthcheck")
    assert hc, f"{name} has no healthcheck"
    assert not hc.get("disable", False)
    for key in ("interval", "timeout", "retries"):
        assert key in hc, f"{name} healthcheck lacks {key}"


@pytest.mark.parametrize("name", ["api", "ingest", "worker", "gateway", "sibyl-sim"])
def test_sibyl_services_probe_healthz(services: dict[str, Any], name: str) -> None:
    assert "/healthz" in _healthcheck_text(services[name])


def test_postgres_is_17_with_pg_isready(services: dict[str, Any]) -> None:
    pg = services["postgres"]
    assert re.match(r"^postgres:17(\.\d+)?(-[a-z0-9]+)?(@sha256:[0-9a-f]{64})?$", pg["image"]), pg[
        "image"
    ]
    assert "pg_isready" in _healthcheck_text(pg)


@pytest.mark.parametrize(("name", "module"), sorted(CONTROL_ENTRYPOINTS.items()))
def test_control_services_share_one_image_with_own_entrypoint(
    services: dict[str, Any], name: str, module: str
) -> None:
    svc = services[name]
    assert svc["image"] == services["api"]["image"], "control plane must be one image"
    cmd = _command(svc)
    assert cmd[:3] == ["python", "-m", module], cmd


def test_only_api_builds_the_control_image(services: dict[str, Any]) -> None:
    builders = [n for n in CONTROL_ENTRYPOINTS if "build" in services[n]]
    assert builders == ["api"], "build once, reuse the tag for the other entrypoints"
    assert services["api"]["build"]["dockerfile"].endswith("control.Dockerfile")


def test_gateway_builds_its_own_image_and_never_waits_for_the_control_plane(
    services: dict[str, Any],
) -> None:
    gw = services["gateway"]
    assert gw["build"]["dockerfile"].endswith("gateway.Dockerfile")
    # The gateway starts from its on-disk snapshot (sre-engineer 4). Its only dependency is the
    # dev-only sim, optional (absent without the profile), so it can trust the sim's fresh CA.
    deps = gw.get("depends_on", {})
    assert set(deps) <= {"sibyl-sim"}, f"gateway waits for {sorted(deps)}"
    if deps:
        assert deps["sibyl-sim"]["required"] is False, "never required outside the sim profile"
        assert deps["sibyl-sim"]["restart"] is True, "a new sim CA needs a gateway restart"
    assert gw.get("stop_grace_period"), "gateway must drain in-flight streams"


def test_gateway_trusts_the_sim_ca_only_through_its_launcher(services: dict[str, Any]) -> None:
    gw = services["gateway"]
    assert _command(gw) == ["sh", "/etc/sibyl-gateway/start.sh"]
    assert "./gateway:/etc/sibyl-gateway:ro" in gw["volumes"]
    assert gw["environment"]["SIBYL_SIM_CA_URL"] == "http://sim:8300/_sim/tls/ca.pem"
    assert gw["environment"]["SIBYL_DEV_HOSTS"] == "sim"
    # An operator CA bundle is optional (unset = system trust); the launcher appends the sim CA
    # to whichever bundle is in effect.
    upstream = gw["environment"]["SIBYL_UPSTREAM_CA_FILE"]
    assert upstream == "${SIBYL_UPSTREAM_CA_HOST_FILE:+/etc/sibyl/upstream-ca.pem}"
    assert {"source": "upstream_ca", "target": "/etc/sibyl/upstream-ca.pem"} in gw["configs"]
    start = (COMPOSE_DIR / "gateway" / "start.sh").read_text(encoding="utf-8")
    assert "exec python -m sibyl_gateway" in start
    assert 'base="${SIBYL_UPSTREAM_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"' in start


def test_console_is_built_from_the_console_tree(services: dict[str, Any]) -> None:
    console = services["console"]
    assert console["image"] == "sibyl/console:${SIBYL_VERSION:-dev}"
    build = console["build"]
    assert build["context"] == "../../console"
    assert build["dockerfile"] == "Dockerfile"
    assert build["secrets"] == ["extra_ca"], "npm ci behind a TLS-re-signing proxy"
    assert DIGEST.search(build["args"]["NODE_IMAGE"]), "base pinned by digest (L10)"
    env = console["environment"]
    assert env["SIBYL_CONSOLE_MODE"] == "${SIBYL_CONSOLE_MODE:-live}"
    assert env["SIBYL_API_URL"] == "http://api:8000"
    assert "/app/.next/cache" in console["tmpfs"], "read-only root, Next writes its cache"
    assert "/healthz" in _healthcheck_text(console)


def test_console_bff_route_is_proxied_before_the_api() -> None:
    text = (COMPOSE_DIR / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    bff = text.index("handle /api/bff/*")
    assert bff < text.index("handle /api/* {"), "the BFF must win over the /api/* proxy"
    block = text[bff : text.index("\n\t}", bff)]
    assert "reverse_proxy console:3000" in block
    assert "flush_interval -1" in block, "SSE through the BFF must not be buffered"


def test_migrations_ship_in_the_image_and_are_passed_explicitly(
    services: dict[str, Any],
) -> None:
    text = (DOCKER_DIR / "control.Dockerfile").read_text()
    assert "COPY --from=builder /src/services/control/migrations /app/migrations" in text
    for name in ("migrate", "bootstrap"):
        cmd = _command(services[name])
        assert cmd[cmd.index("--dir") + 1] == "/app/migrations", name


def test_migrate_is_one_shot_and_gates_the_control_plane(services: dict[str, Any]) -> None:
    assert services["migrate"].get("restart") in ("no", None)
    assert services["migrate"]["depends_on"]["postgres"]["condition"] == "service_healthy"
    for name in ("api", "ingest", "worker"):
        dep = services[name]["depends_on"]
        assert dep["migrate"]["condition"] == "service_completed_successfully", name
        assert dep["postgres"]["condition"] == "service_healthy", name


def test_sim_is_profile_gated_and_on_its_own_port(services: dict[str, Any]) -> None:
    sim = services["sibyl-sim"]
    assert sim.get("profiles") == ["sim"], "sibyl-sim is dev-only (R46)"
    assert any("8300" in str(p) for p in sim.get("ports", [])), "sim has its own port (R32)"
    assert any(":18082" in str(p) for p in sim.get("ports", [])), "doubles port (TLS)"
    for name, svc in services.items():
        if name != "sibyl-sim":
            assert "sim" not in svc.get("profiles", []), f"{name} must not be sim-only"


def test_sim_serves_doubles_with_tls_for_the_dev_host(services: dict[str, Any]) -> None:
    sim = services["sibyl-sim"]
    assert _command(sim) == [
        "python", "-m", "sibyl_sim", "serve", "--host", "0.0.0.0", "--port", "8300",  # noqa: S104
        "--doubles-port", "18082", "--tls-dir", "/var/lib/sibyl/sim-tls", "--tls-host", "sim",
    ]  # fmt: skip
    assert sim["networks"]["edge"]["aliases"] == ["sim"]
    tls = next(t for t in sim["tmpfs"] if t.startswith("/var/lib/sibyl/sim-tls"))
    assert "uid=10001" in tls, "keys stay in a non-persistent dir owned by the sim user"
    assert "depends_on" not in sim, "the gateway waits for the sim, not the other way round"


def test_only_caddy_sim_and_postgres_publish_ports(services: dict[str, Any]) -> None:
    published = {n for n, s in services.items() if s.get("ports")}
    assert published == {"caddy", "sibyl-sim", "postgres"}


def test_published_ports_bind_loopback_only(services: dict[str, Any]) -> None:
    for name, svc in services.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} beyond loopback"


def test_caddy_routes_to_api_gateway_console_ingest_and_dex() -> None:
    caddyfile = (COMPOSE_DIR / "caddy" / "Caddyfile").read_text(encoding="utf-8")
    for upstream in ("api:8000", "gateway:8080", "console:3000", "ingest:8001", "dex:5556"):
        assert f"reverse_proxy {upstream}" in caddyfile or upstream in caddyfile, upstream
    assert "tls internal" in caddyfile


def test_named_volumes_declared_and_used(compose: dict[str, Any]) -> None:
    declared = set(compose.get("volumes", {}))
    for required in ("pgdata", "blobstore", "gateway_snapshot", "caddy_data"):
        assert required in declared, required
    used: set[str] = set()
    for svc in compose["services"].values():
        for vol in svc.get("volumes", []):
            src = vol.split(":", 1)[0] if isinstance(vol, str) else vol.get("source", "")
            if src and not src.startswith((".", "/")):
                used.add(src)
    assert used <= declared, f"undeclared named volumes: {used - declared}"
    assert declared <= used, f"unused named volumes: {declared - used}"


def test_every_env_file_has_a_committed_example(compose: dict[str, Any]) -> None:
    for name, svc in compose["services"].items():
        for entry in svc.get("env_file", []):
            path = entry["path"] if isinstance(entry, dict) else entry
            path = path.replace("${SIBYL_ENV_DIR:-./env}", "env")
            assert path.startswith("env/"), f"{name}: env_file {path} outside env/"
            example = COMPOSE_DIR / f"{path}.example"
            assert example.is_file(), f"{name}: {path} has no {example.name}"


def test_restart_policy_on_long_running_services(services: dict[str, Any]) -> None:
    for name in LONG_RUNNING:
        assert services[name].get("restart") == "unless-stopped", name


def test_control_plane_mounts_blobstore(services: dict[str, Any]) -> None:
    for name in ("api", "ingest", "worker"):
        vols = [v.split(":", 1)[0] for v in services[name].get("volumes", [])]
        assert "blobstore" in vols, name


def test_api_ingest_and_worker_share_one_blob_store(services: dict[str, Any]) -> None:
    """fs backend: exports, audit anchors and the erasure ledger (ledger/erasure/) are written
    by the worker and read by the api; ingest writes payload blobs. One volume, one root."""
    for name in ("api", "ingest", "worker"):
        svc = services[name]
        env = svc["environment"]
        assert env["SIBYL_BLOB_BACKEND"] == "fs", name
        root = env["SIBYL_BLOB_ROOT"]
        assert f"blobstore:{root}" in svc["volumes"], f"{name}: blobstore must be mounted at {root}"
        assert f"blobstore:{root}:ro" not in svc["volumes"], f"{name} writes the store"


def test_dex_config_has_tenants_personas_and_bindings() -> None:
    config = yaml.safe_load((COMPOSE_DIR / "dex" / "config.yaml").read_text(encoding="utf-8"))
    personas = yaml.safe_load((COMPOSE_DIR / "dex" / "personas.yaml").read_text(encoding="utf-8"))
    dex_users = {u["username"] for u in config["staticPasswords"]}
    assert dex_users == {"admin", "operator", "auditor"}
    assert set(personas["tenants"]) == {"meridian", "northstar", "sandbox"}
    bindings = {(b["persona"], b["tenant"]): sorted(b["roles"]) for b in personas["bindings"]}
    for tenant in ("meridian", "northstar", "sandbox"):
        assert bindings[("admin", tenant)] == ["owner"]
    for tenant in ("meridian", "northstar"):
        assert bindings[("operator", tenant)] == ["operator", "security_admin"]
        assert bindings[("auditor", tenant)] == ["auditor"]
    # B3: sandbox stays empty except the Platform Admin (onboarding demo).
    assert {p for p, t in bindings if t == "sandbox"} == {"admin"}
    emails = {u["username"]: u["email"] for u in config["staticPasswords"]}
    assert {p["username"]: p["email"] for p in personas["personas"]} == emails
    ids = {u["username"]: u["userID"] for u in config["staticPasswords"]}
    assert {p["username"]: p["subject"] for p in personas["personas"]} == ids


def test_dex_issuer_and_clients_are_parameterised() -> None:
    config = yaml.safe_load((COMPOSE_DIR / "dex" / "config.yaml").read_text(encoding="utf-8"))
    assert "__SIBYL_PUBLIC_URL__" in config["issuer"]
    client_ids = {c["id"] for c in config["staticClients"]}
    assert {"sibyl-console", "sibyl-cli"} <= client_ids
    for client in config["staticClients"]:
        assert "secret" not in client, "client secrets come from the environment"


# --- G0 security fixes: hardening, networks, trusted proxy, digests, volumes, Caddy ---------


@pytest.mark.parametrize("name", sorted(set(REQUIRED)))
def test_every_service_is_hardened(services: dict[str, Any], name: str) -> None:
    svc = services[name]
    assert "no-new-privileges:true" in svc.get("security_opt", []), name
    assert svc.get("cap_drop") == ["ALL"], name
    assert svc.get("read_only") is True, name
    allowed_caps = {"postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}}
    allowed_caps |= {"caddy": {"NET_BIND_SERVICE"}}
    assert set(svc.get("cap_add", [])) <= allowed_caps.get(name, set()), name


def test_third_party_images_are_pinned_by_digest(services: dict[str, Any]) -> None:
    for name, svc in services.items():
        image = svc["image"]
        if image.startswith("sibyl/"):
            continue
        assert DIGEST.search(image), f"{name}: {image} is not pinned by digest (L10)"


@pytest.mark.parametrize("path", sorted(DOCKER_DIR.glob("*.Dockerfile")), ids=lambda p: p.name)
def test_dockerfile_bases_are_pinned_by_digest(path: Path) -> None:
    args = re.findall(r"^ARG\s+([A-Z_]+_IMAGE)=(\S+)", path.read_text(), re.M)
    assert args, path.name
    for key, ref in args:
        assert DIGEST.search(ref), f"{path.name}: {key}={ref} is not pinned by digest"


def _networks(svc: dict[str, Any]) -> set[str]:
    return set(svc.get("networks", []))


def test_only_postgres_clients_join_the_data_network(services: dict[str, Any]) -> None:
    on_data = {n for n, s in services.items() if "data" in _networks(s)}
    assert on_data == {"postgres", "bootstrap", "migrate", "api", "ingest", "worker"}
    assert _networks(services["postgres"]) == {"data"}
    for name in ("gateway", "dex", "caddy", "console", "sibyl-sim"):
        assert "data" not in _networks(services[name]), f"{name} must not reach Postgres (L8)"


def test_worker_reaches_the_sim_doubles_only_over_the_probe_network(
    compose: dict[str, Any], services: dict[str, Any]
) -> None:
    """Credential probes (B14) run in the worker, which must reach the sim doubles (`sim`)
    without joining `edge` (gateway, Caddy, console): a dedicated internal `probe` network
    holds exactly the worker and the sim, so it adds no route to anything else."""
    on_probe = {n for n, s in services.items() if "probe" in _networks(s)}
    assert on_probe == {"worker", "sibyl-sim"}
    assert _networks(services["worker"]) == {"data", "probe"}
    assert "edge" not in _networks(services["worker"]), "the worker stays off the edge"
    assert services["sibyl-sim"]["networks"]["probe"]["aliases"] == ["sim"]
    probe = compose["networks"]["probe"]
    assert probe["internal"] is True, "probe adds no internet egress of its own"


def test_edge_dynamic_range_excludes_the_pinned_addresses(compose: dict[str, Any]) -> None:
    """Docker hands out dynamic edge addresses only from `ip_range` (upper half), so a
    container that starts first can never take the pinned Caddy/console `.10`/`.11`."""
    ipam = compose["networks"]["edge"]["ipam"]["config"][0]
    assert ipam["ip_range"] == "${SIBYL_EDGE_IP_RANGE:-172.30.0.128/25}"
    subnet = ipaddress.ip_network(_default(ipam["subnet"]))
    dynamic = ipaddress.ip_network(_default(ipam["ip_range"]))
    assert dynamic.subnet_of(subnet)  # type: ignore[arg-type]
    for name in ("caddy", "console"):
        pinned = ipaddress.ip_address(
            _default(compose["services"][name]["networks"]["edge"]["ipv4_address"])
        )
        assert pinned in subnet and pinned not in dynamic, name


def _default(value: str) -> str:
    match = re.fullmatch(r"\$\{[A-Z_]+:-([^}]*)\}", value)
    assert match, value
    return match.group(1)


def test_caddy_is_pinned_and_the_only_trusted_proxy(
    compose: dict[str, Any], services: dict[str, Any]
) -> None:
    """Caddy everywhere (M4); the api also trusts the pinned console BFF, which forwards the
    client address Caddy saw (login/step-up rate limits, audited ip_hash)."""
    caddy_ip = services["caddy"]["networks"]["edge"]["ipv4_address"]
    console_ip = services["console"]["networks"]["edge"]["ipv4_address"]
    subnet = compose["networks"]["edge"]["ipam"]["config"][0]["subnet"]
    assert caddy_ip == "${SIBYL_CADDY_IP:-172.30.0.10}"
    assert console_ip == "${SIBYL_CONSOLE_IP:-172.30.0.11}"
    assert subnet == "${SIBYL_EDGE_SUBNET:-172.30.0.0/24}"
    for name, svc in services.items():
        env = svc.get("environment", {})
        value = env.get("SIBYL_TRUSTED_PROXIES") if isinstance(env, dict) else None
        if name == "api":
            assert value == f"{caddy_ip}/32,{console_ip}/32", "api: Caddy + console BFF"
        elif name in ("ingest", "gateway"):
            assert value == caddy_ip + "/32", f"{name} must trust only Caddy (M4)"
        else:
            assert value is None, name


def test_erasure_ledger_lives_in_the_blob_store_only(
    compose: dict[str, Any], services: dict[str, Any]
) -> None:
    """Lane U: the worker's erasure_ledger loop writes ledger/erasure/ in the BlobStore (signed,
    create-only entries + signed head); the old worker-only file volume is gone, so nobody can
    write a second, unsigned copy that a restore might pick up."""
    assert "erasure_ledger" not in compose.get("volumes", {})
    for name, svc in services.items():
        env = svc.get("environment") or {}
        assert "SIBYL_LEDGER_DIR" not in env, name
        assert not any("/var/lib/sibyl/ledger" in str(v) for v in svc.get("volumes", [])), name


@pytest.mark.parametrize(
    ("dockerfile", "dirs"),
    [
        ("control.Dockerfile", ["/var/lib/sibyl/blob"]),
        ("gateway.Dockerfile", ["/var/lib/sibyl/snapshot"]),
    ],
)
def test_images_own_their_data_dirs(dockerfile: str, dirs: list[str]) -> None:
    text = (DOCKER_DIR / dockerfile).read_text()
    install = next(ln for ln in text.splitlines() if "install -d -o sibyl -g sibyl" in ln)
    for d in dirs:
        assert d in install, f"{dockerfile}: {d} must exist owned by uid 10001 (M9)"


@pytest.mark.parametrize("path", sorted(DOCKER_DIR.glob("*.Dockerfile")), ids=lambda p: p.name)
def test_images_use_the_secrets_entrypoint(path: Path) -> None:
    text = path.read_text()
    assert 'ENTRYPOINT ["/usr/local/bin/sibyl-entrypoint"]' in text
    ignore = path.with_name(path.name + ".dockerignore").read_text().splitlines()
    assert "!deploy/docker/sibyl-entrypoint.sh" in ignore
    assert ignore.index("!deploy/docker/sibyl-entrypoint.sh") > ignore.index("deploy")


def _caddyfile() -> str:
    return (COMPOSE_DIR / "caddy" / "Caddyfile").read_text(encoding="utf-8")


def test_caddy_overwrites_forwarding_headers_on_every_upstream() -> None:
    text = _caddyfile()
    assert "header_up X-Forwarded-For {remote_host}" in text
    assert "header_up -Forwarded" in text and "header_up -X-Real-IP" in text
    assert "trusted_proxies" not in text, "nothing in front of Caddy is trusted"
    proxies = re.findall(r"reverse_proxy \S+( \{[^}]*\})?", text)
    assert proxies and all("import client_ip" in block for block in proxies)


def test_gateway_only_policy_routes_are_not_public() -> None:
    """B18: only the sealed credential bundle is gateway-only; snapshot and keys serve the SDK."""
    text = _caddyfile()
    block = text.index("handle /api/v1/policy/credentials*")
    assert block < text.index("handle /api/*"), "the 404 must precede the /api/* proxy"
    assert "respond 404" in text[block : text.index("}", block)]
    assert "handle /api/v1/policy/*" not in text, "snapshot and keys must stay reachable (B18)"


def _example(name: str) -> dict[str, str]:
    lines = (COMPOSE_DIR / "env" / f"{name}.env.example").read_text(encoding="utf-8").splitlines()
    pairs = (ln.split("=", 1) for ln in lines if ln.strip() and not ln.startswith("#"))
    return {k: v for k, v in pairs}


def test_local_demo_runs_as_a_live_deployment_with_demo_mode_on() -> None:
    """Item 6: D20 break-glass keys are `live` keys and the api refuses keys of another env, so
    the local demo deployment is SIBYL_ENV=live. SIBYL_DEMO=1 stays on: it is the safety
    boundary (R55: credentials and snapshots only for the sibyl-sim doubles)."""
    control, gateway, sim = _example("control"), _example("gateway"), _example("sim")
    assert control["SIBYL_ENV"] == gateway["SIBYL_ENV"] == sim["SIBYL_ENV"] == "live"
    assert control["SIBYL_DEMO"] == "1"
    text = (COMPOSE_DIR / "env" / "control.env.example").read_text(encoding="utf-8")
    assert "local demo" in text.lower(), "say why a laptop stack is `live`"
