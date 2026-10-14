"""Config parsing and process wiring: an empty config boots safely; disk snapshots load."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from sibyl_gateway.config import GatewayConfig
from sibyl_gateway.runtime import build_gateway
from sibyl_gateway.telemetry.scrubcheck import ScrubberUnsafe

from .support import GATEWAY_KEY, GATEWAY_PREFIX, PEPPER, TENANT, TestSigner, body, tenant_block


def test_from_env_parses_and_reports_problems() -> None:
    cfg = GatewayConfig.from_env({})
    assert cfg.http_port == 8080 and cfg.env == "live"
    problems = " ".join(cfg.problems())
    assert "SIBYL_KEY_PEPPER" in problems and "SIBYL_SNAPSHOT_PINNED_KEY" in problems
    full = GatewayConfig.from_env(
        {
            "SIBYL_HTTP_PORT": "9090",
            "SIBYL_KEY_PEPPER": PEPPER.hex(),
            "SIBYL_GATEWAY_TENANT_KEYS": f"{GATEWAY_KEY}, sbl_test_bad",
            "SIBYL_SNAPSHOT_PINNED_KEY": json.dumps(TestSigner().key_set()["keys"][0]),
            "SIBYL_ENV": "live",
            "SIBYL_DEV_HOSTS": "127.0.0.1, sim",
            "SIBYL_CONTROL_URL": "http://api:8000",
            "SIBYL_SCRUB_SALT": "s" * 16,
        }
    )
    assert full.http_port == 9090 and full.pepper == PEPPER
    assert full.streams() == {GATEWAY_PREFIX: GATEWAY_KEY}
    assert full.dev_hosts == ("127.0.0.1", "sim")
    assert full.problems() == [
        "SIBYL_GATEWAY_TENANT_KEYS has malformed or wrong-env keys (ignored)"
    ]
    assert GATEWAY_KEY not in repr(full) and PEPPER.hex() not in repr(full)


def test_live_gateway_refuses_to_start_without_a_scrub_salt() -> None:
    with pytest.raises(ScrubberUnsafe):
        build_gateway(GatewayConfig.from_env({"SIBYL_ENV": "live"}))
    build_gateway(GatewayConfig.from_env({"SIBYL_ENV": "live", "SIBYL_SCRUB_SALT": "x" * 16}))


async def test_empty_config_boots_but_refuses_traffic() -> None:
    app = build_gateway(GatewayConfig.from_env({"SIBYL_ENV": "test"}))
    for hook in app.on_startup:
        await hook()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://g"
        ) as c:
            assert (await c.get("/healthz")).status_code == 200
            assert (await c.get("/readyz")).status_code == 503
            resp = await c.post(
                "/v1/chat/completions", json={}, headers={"X-Sibyl-Key": GATEWAY_KEY}
            )
            assert resp.json()["error"]["code"] == "sibyl_no_snapshot"
    finally:
        for hook in app.on_shutdown:
            await hook()


async def test_persisted_snapshot_serves_after_restart(tmp_path: Path) -> None:
    signer = TestSigner()
    raw, kid, sig = signer.deliver(body(9, tenants={str(TENANT): tenant_block()}))
    import base64

    (tmp_path / "gw.snapshot.json").write_text(
        json.dumps(
            {
                "kid": kid,
                "signature": sig,
                "version": 9,
                "high_water": 9,
                "raw": base64.b64encode(raw).decode(),
            }
        )
    )
    cfg = GatewayConfig.from_env(
        {
            "SIBYL_KEY_PEPPER": PEPPER.hex(),
            "SIBYL_SNAPSHOT_KEYS": json.dumps(signer.key_set()),
            "SIBYL_SNAPSHOT_DIR": str(tmp_path),
            "SIBYL_SCRUB_SALT": "s" * 16,
        }
    )
    app = build_gateway(cfg)
    for hook in app.on_startup:
        await hook()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://g"
        ) as c:
            ready = await c.get("/readyz")
            models = await c.get(
                "/v1/models",
                headers={"X-Sibyl-Key": GATEWAY_KEY, "X-Sibyl-Agent": "quote-assistant"},
            )
        assert ready.status_code == 200 and ready.json()["version"] == 9
        assert models.status_code == 200 and models.json()["data"]
    finally:
        for hook in app.on_shutdown:
            await hook()


async def test_lifespan_protocol_runs_hooks() -> None:
    app = build_gateway(GatewayConfig.from_env({"SIBYL_ENV": "test"}))
    messages = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
    sent: list[str] = []

    async def receive() -> dict[str, str]:
        return next(messages)

    async def send(message: dict[str, str]) -> None:
        sent.append(message["type"])

    await app({"type": "lifespan"}, receive, send)
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
