"""Opt-in: the full login against a real dex (the compose image), when Docker works.

Run with ``SIBYL_DEX_TESTS=1``. Starts ``ghcr.io/dexidp/dex:v2.44.0`` with a minimal config that
mirrors ``deploy/compose/dex/config.yaml`` (confidential ``sibyl-console`` client, local password
DB, the Platform Admin persona), then drives the browser half by hand: the api's redirect → dex's
local login form → dex's redirect back with a code → ``/auth/callback`` → a session that works on
``/auth/me``. dex's ``sub`` is opaque, so the Platform Admin is pre-invited by email (the
invitation-binding path).
"""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlsplit

import httpx
import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest
from sibyl_control.api.auth.oidc import OidcClient

IMAGE = "ghcr.io/dexidp/dex:v2.44.0"
PASSWORD_HASH = "$2a$10$2b2cU8CPhOTaGrs1HRQuAueS7JTT5ZHsHSzYiFPm1leZck7Mc8T4W"  # "password"  # noqa: S105 (public dex example hash)
EMAIL = "admin@demo.sibyl.example"
CLIENT_SECRET = "dex-live-console-secret"  # noqa: S105  (throwaway test container)


def _docker_ok() -> bool:
    if os.environ.get("SIBYL_DEX_TESTS") != "1" or shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, check=False).returncode == 0  # noqa: S607 (docker from PATH in an opt-in test)


pytestmark = pytest.mark.skipif(
    not _docker_ok(), reason="set SIBYL_DEX_TESTS=1 with a working docker"
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def dex(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    port = _free_port()
    issuer = f"http://127.0.0.1:{port}/dex"
    config = f"""
issuer: {issuer}
storage: {{type: memory}}
web: {{http: 0.0.0.0:5556}}
oauth2: {{responseTypes: [code], skipApprovalScreen: true, passwordConnector: local}}
enablePasswordDB: true
staticClients:
  - id: sibyl-console
    name: Sibyl console
    secret: {CLIENT_SECRET}
    redirectURIs: ["{kit.PUBLIC_URL}/api/v1/auth/callback"]
staticPasswords:
  - email: {EMAIL}
    username: admin
    userID: 0192a000-0000-7000-8000-00000000d001
    hash: "{PASSWORD_HASH}"
"""
    # The config travels in an env var: Colima does not mount the host temp dir into its VM.
    name = f"sibyl-dex-test-{secrets.token_hex(4)}"
    subprocess.run(  # noqa: S603 (fixed argv)
        [  # noqa: S607 (docker from PATH in an opt-in test)
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            name,
            "-p",
            f"127.0.0.1:{port}:5556",
            "-e",
            f"DEX_TEST_CONFIG={config}",
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            'printf "%s" "$DEX_TEST_CONFIG" > /tmp/config.yaml && exec dex serve /tmp/config.yaml',
        ],
        check=True,
        capture_output=True,
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if (
                    httpx.get(f"{issuer}/.well-known/openid-configuration", timeout=2).status_code
                    == 200
                ):
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        else:
            raise AssertionError("dex did not come up")
        yield issuer
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)  # noqa: S603, S607 (fixed argv)


def _browser_login(location: str, redirect_prefix: str) -> tuple[str, str]:
    """Follow dex's local-connector flow until it redirects back to the api with a code."""
    with httpx.Client(follow_redirects=False, timeout=10) as browser:
        url, posted = location, False
        for _ in range(20):
            if url.startswith(redirect_prefix):
                q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
                return q["code"], q["state"]
            resp = browser.get(url)
            if resp.status_code in (302, 303) and "location" in resp.headers:
                url = urljoin(url, resp.headers["location"])
                continue
            assert resp.status_code == 200 and not posted, (resp.status_code, url)
            login = browser.post(url, data={"login": EMAIL, "password": "password"})
            assert login.status_code in (302, 303), login.text[:300]
            url, posted = urljoin(url, login.headers["location"]), True
    raise AssertionError("dex never redirected back")


def test_login_against_real_dex(dex: str, lane_db: Any) -> None:
    tenant, slug = kit.make_tenant(lane_db)
    issuer = kit.add_issuer(lane_db, tenant, dex)
    with lane_db.admin.tx(tenant):
        user = lane_db.admin.fetchval(
            "INSERT INTO sibyl.app_user (tenant_id, oidc_issuer_id, subject, email, status)"
            " VALUES ($1, $2, 'invite:' || sibyl.uuidv7()::text, $3, 'invited') RETURNING id",
            tenant,
            issuer,
            EMAIL,
        )
        lane_db.admin.execute(
            "INSERT INTO sibyl.membership (tenant_id, user_id, role_name) VALUES ($1, $2, 'owner')",
            tenant,
            user,
        )
    fake = kit.FakeIssuer(issuer=dex, client_secret=CLIENT_SECRET)
    with kit.lane_app(lane_db, fake) as lane:
        lane.app.state.sibyl_lane_a["oidc"] = OidcClient(
            httpx.AsyncClient()
        )  # the real network path
        start = lane.client.get(
            "/api/v1/auth/login", params={"tenant": slug}, follow_redirects=False
        )
        assert start.status_code == 302 and start.headers["location"].startswith(f"{dex}/auth?")
        cookie = start.cookies["__Host-sibyl_oidc_state"]
        code, state = _browser_login(
            start.headers["location"], f"{kit.PUBLIC_URL}/api/v1/auth/callback"
        )
        lane.client.cookies.clear()
        done = lane.client.get(
            "/api/v1/auth/callback",
            params={"code": code, "state": state},
            headers={"Cookie": f"__Host-sibyl_oidc_state={cookie}"},
            follow_redirects=False,
        )
        assert done.status_code == 302, done.text
        session = done.cookies["__Host-sibyl_session"]
        bearer = lane.bearer(f"sibyl_sess_{session}")
        me = lane.client.get("/api/v1/auth/me", headers=bearer)
        assert me.status_code == 200 and me.json()["user"]["id"] == str(user)
        assert kit.audit_actions(lane_db, tenant)[-1] == "access.login"

        # Step-up: prompt=login max_age=0 against the real IdP, then a fresh-auth check.
        up = lane.client.post("/api/v1/auth/step-up", headers=bearer, follow_redirects=False)
        assert up.status_code == 302 and "prompt=login" in up.headers["location"]
        cookie = up.cookies["__Host-sibyl_oidc_state"]
        code, state = _browser_login(
            up.headers["location"], f"{kit.PUBLIC_URL}/api/v1/auth/callback"
        )
        lane.client.cookies.clear()
        stepped = lane.client.get(
            "/api/v1/auth/callback",
            params={"code": code, "state": state},
            headers={"Cookie": f"__Host-sibyl_oidc_state={cookie}"},
            follow_redirects=False,
        )
        assert stepped.status_code == 302, stepped.text
        assert lane.client.get("/api/v1/auth/me", headers=bearer).json()["step_up_valid_until"]
    assert kit.audit_actions(lane_db, tenant)[-1] == "access.step_up"
    _ = Path
