"""OpenAI-compatible surface, admin API, health, dev TLS and the CLI parser."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography import x509
from sibyl_sim.doubles import SimState, build_state, doubles_app
from sibyl_sim.doubles.cli import _hosts, parser
from sibyl_sim.doubles.knobs import KnobError, Knobs
from sibyl_sim.doubles.tls import generate

CHAT = "/v1/chat/completions"


def body(**extra: Any) -> dict[str, Any]:
    return {"model": "gpt-5-mini", "messages": [{"role": "user", "content": "hi"}], **extra}


async def test_chat_completion_shape(doubles: httpx.AsyncClient) -> None:
    response = await doubles.post(CHAT, json=body())
    data = response.json()
    assert response.status_code == 200 and data["object"] == "chat.completion"
    assert data["model"] == "gpt-5-mini" and data["id"].startswith("chatcmpl-openai-stub-")
    assert data["choices"][0]["message"]["role"] == "assistant"
    assert set(data["usage"]) == {"prompt_tokens", "completion_tokens", "total_tokens"}
    assert response.headers["x-sim-decision"] == "1:normal"


@pytest.mark.parametrize("double", ["openai-stub", "anthropic-stub", "ollama-stub"])
async def test_every_double_speaks_openai(doubles: httpx.AsyncClient, double: str) -> None:
    response = await doubles.post(f"/{double}/v1/chat/completions", json=body(model="m"))
    assert response.status_code == 200
    assert response.json()["id"].startswith(f"chatcmpl-{double}-")
    models = (await doubles.get(f"/{double}/v1/models")).json()
    assert models["object"] == "list" and models["data"]


async def test_unknown_double_and_missing_auth(doubles: httpx.AsyncClient) -> None:
    assert (await doubles.post("/nope/v1/chat/completions", json=body())).status_code == 404
    anonymous = await doubles.post(CHAT, json=body(), headers={"Authorization": ""})
    assert anonymous.status_code == 401
    x_api_key = await doubles.post(
        CHAT, json=body(), headers={"Authorization": "", "x-api-key": "k"}
    )
    assert x_api_key.status_code == 200
    bad = await doubles.post(
        CHAT, content=b"{not json", headers={"content-type": "application/json"}
    )
    assert bad.status_code == 400


async def test_streaming_sse(doubles: httpx.AsyncClient) -> None:
    response = await doubles.post(
        CHAT, json=body(stream=True, stream_options={"include_usage": True})
    )
    assert response.headers["content-type"].startswith("text/event-stream")
    lines = [line[6:] for line in response.text.split("\n\n") if line.startswith("data: ")]
    assert lines[-1] == "[DONE]"
    chunks = [json.loads(line) for line in lines[:-1]]
    assert chunks[0]["choices"][0]["delta"]["role"] == "assistant"
    text = "".join(c["choices"][0]["delta"].get("content", "") for c in chunks if c["choices"])
    plain = (await doubles.post(CHAT, json=body())).json()
    assert text.startswith("[openai-stub] reply #1")
    assert len(text) == len(plain["choices"][0]["message"]["content"])
    assert chunks[-2]["choices"][0]["finish_reason"] == "stop"
    assert chunks[-1]["usage"]["completion_tokens"] > 0


async def test_streaming_tool_calls(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    await control.patch("/_sim/doubles/openai-stub/knobs", json={"tool_loop": {"rate": 1}})
    tools = [{"type": "function", "function": {"name": "f"}}]
    response = await doubles.post(CHAT, json=body(stream=True, tools=tools))
    chunks = [json.loads(x[6:]) for x in response.text.split("\n\n") if x.startswith("data: {")]
    assert chunks[1]["choices"][0]["delta"]["tool_calls"][0]["function"]["name"] == "f"
    assert chunks[-1]["choices"][0]["finish_reason"] == "tool_calls"


async def test_embeddings_are_deterministic(doubles: httpx.AsyncClient) -> None:
    request = {"model": "text-embedding-3-small", "input": ["a", "b"], "dimensions": 12}
    first = (await doubles.post("/v1/embeddings", json=request)).json()
    second = (await doubles.post("/v1/embeddings", json=request)).json()
    assert first["data"] == second["data"]
    assert len(first["data"]) == 2 and len(first["data"][0]["embedding"]) == 12
    assert first["data"][0]["embedding"] != first["data"][1]["embedding"]
    assert first["usage"]["prompt_tokens"] >= 2


async def test_embeddings_honour_errors(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient
) -> None:
    await control.patch("/_sim/doubles/openai-stub/knobs", json={"outage": True})
    assert (await doubles.post("/v1/embeddings", json={"input": "x"})).status_code == 503


# ------------------------------------------------------------------ admin


async def test_admin_put_replaces_patch_merges(control: httpx.AsyncClient) -> None:
    await control.patch("/_sim/doubles/openai-stub/knobs", json={"error_rate": 0.5})
    merged = await control.patch("/_sim/doubles/openai-stub/knobs", json={"refusal_rate": 0.1})
    assert merged.json()["knobs"]["error_rate"] == 0.5
    replaced = await control.put("/_sim/doubles/openai-stub/knobs", json={"refusal_rate": 0.2})
    assert replaced.json()["knobs"]["error_rate"] == 0.0
    assert replaced.json()["knobs"]["refusal_rate"] == 0.2


@pytest.mark.parametrize(
    "patch",
    [
        {"error_rate": 2},
        {"error_rate": True},
        {"bogus": 1},
        {"error_statuses": [200]},
        {"error_statuses": []},
        {"latency": {"dist": "weird"}},
        {"latency": {"dist": "uniform", "min_ms": 5, "max_ms": 1}},
        {"latency": 5},
        {"limit_requests": 0},
        {"outage": "yes"},
        {"tool_loop": {"rate": 2}},
        {"tool_loop": "x"},
        {"missing_models": "gpt"},
        {"overrides": [{"match": {}, "knobs": {}}]},
        {"overrides": [{"match": {"model": "m"}, "knobs": {"overrides": []}}]},
        {"overrides": "x"},
        {"ramp": {"start_headroom": 3}},
    ],
)
async def test_admin_rejects_invalid_knobs(
    control: httpx.AsyncClient, patch: dict[str, Any]
) -> None:
    response = await control.patch("/_sim/doubles/openai-stub/knobs", json=patch)
    assert response.status_code == 422 and response.json()["error"]


async def test_admin_misc(control: httpx.AsyncClient, doubles: httpx.AsyncClient) -> None:
    assert set((await control.get("/_sim/doubles")).json()) == {
        "openai-stub",
        "anthropic-stub",
        "ollama-stub",
    }
    assert (await control.get("/_sim/doubles/nope")).status_code == 404
    assert (await control.patch("/_sim/doubles/nope/knobs", json={})).status_code == 404
    assert (await control.patch("/_sim/doubles/openai-stub/knobs", json=[1])).status_code == 422
    assert (await control.post("/_sim/doubles/openai-stub/outage", json={})).status_code == 422
    assert (
        await control.post("/_sim/doubles/openai-stub/reset", json={"seed": "x"})
    ).status_code == 422
    await doubles.post(CHAT, json=body())
    log = (await control.get("/_sim/doubles/openai-stub/log")).json()["decisions"]
    assert log[0]["status"] == 200 and log[0]["behaviour"] == "normal"
    reset = (await control.post("/_sim/doubles/openai-stub/reset", json={"seed": 99})).json()
    assert reset["seed"] == 99 and reset["stats"] == {}


async def test_admin_token_guard(clock: Any, sleeps: Any) -> None:
    from sibyl_sim.doubles import control_app

    state = build_state(seed=1, clock=clock, sleep=sleeps, admin_token="s3cret")  # noqa: S106 (test token)
    transport = httpx.ASGITransport(app=control_app(state))
    async with httpx.AsyncClient(transport=transport, base_url="http://sim") as client:
        assert (await client.get("/_sim/doubles")).status_code == 401
        assert (await client.get("/_sim/status")).status_code == 401
        ok = await client.get("/_sim/doubles", headers={"Authorization": "Bearer s3cret"})
        assert ok.status_code == 200
        assert (await client.get("/healthz")).status_code == 200


async def test_admin_is_not_on_the_doubles_port(doubles: httpx.AsyncClient) -> None:
    assert (await doubles.get("/_sim/doubles")).status_code == 404
    assert (await doubles.patch("/_sim/doubles/openai-stub/knobs", json={})).status_code in (
        404,
        405,
    )


async def test_healthz_both_apps(
    control: httpx.AsyncClient, doubles: httpx.AsyncClient, state: SimState, tmp_path: Path
) -> None:
    for client in (control, doubles):
        data = (await client.get("/healthz")).json()
        assert data["status"] == "ok" and data["default_double"] == "openai-stub"
    assert (await control.get("/_sim/tls/ca.pem")).status_code == 404
    state.ca_path = str(generate(tmp_path).ca_path)
    pem = await control.get("/_sim/tls/ca.pem")
    assert pem.status_code == 200 and "BEGIN CERTIFICATE" in pem.text


def test_knobs_round_trip() -> None:
    knobs = Knobs.parse({"error_rate": 0.1, "latency": {"dist": "fixed", "ms": 5}})
    assert knobs.error_rate == 0.1 and knobs.latency.ms == 5
    assert Knobs.parse(knobs.to_dict() | {"overrides": []}) == knobs
    with pytest.raises(KnobError):
        Knobs.parse({"nope": 1})


def test_unknown_default_double_is_refused() -> None:
    with pytest.raises(ValueError):
        build_state(seed=1, default_double="nope")


# ------------------------------------------------------------------ TLS + CLI


def test_dev_certificate_chain(tmp_path: Path) -> None:
    certs = generate(tmp_path, ("127.0.0.1", "localhost", "sim"))
    ca = x509.load_pem_x509_certificate(certs.ca_path.read_bytes())
    leaf = x509.load_pem_x509_certificate(certs.cert_path.read_bytes())
    leaf.verify_directly_issued_by(ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "sim" in san.get_values_for_type(x509.DNSName)
    assert oct(certs.key_path.stat().st_mode)[-3:] == "600"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_doubles_serve_https_with_the_dev_ca(tmp_path: Path) -> None:
    import asyncio

    import uvicorn

    certs = generate(tmp_path)
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            doubles_app(build_state(seed=1)),
            host="127.0.0.1",
            port=port,
            log_level="error",
            ssl_certfile=str(certs.cert_path),
            ssl_keyfile=str(certs.key_path),
        )
    )
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)
        context = ssl.create_default_context(cafile=str(certs.ca_path))
        with httpx.Client(verify=context, base_url=f"https://127.0.0.1:{port}") as client:
            response = client.post(CHAT, json=body(), headers={"Authorization": "Bearer k"})
            assert response.status_code == 200
        with (
            pytest.raises(httpx.ConnectError),
            httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=True) as untrusted,
        ):
            untrusted.get("/healthz")
    finally:
        server.should_exit = True
        thread.join(5)


def test_cli_parser_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SIBYL_SIM_TLS_HOSTS", "gateway-sim,extra")
    args = parser().parse_args(["serve", "--host", "0.0.0.0", "--port", "8300"])  # noqa: S104
    assert (args.host, args.port, args.doubles_port) == ("0.0.0.0", 8300, 18082)  # noqa: S104
    hosts = _hosts(["x.local"])
    assert hosts[0] == "127.0.0.1" and {"gateway-sim", "extra", "x.local"} <= set(hosts)


def test_serve_runs_control_and_https_doubles(tmp_path: Path) -> None:
    """`python -m sibyl_sim.doubles serve`: http control port + https doubles port + CA."""
    import subprocess
    import sys

    control_port, doubles_port = _free_port(), _free_port()
    proc = subprocess.Popen(  # noqa: S603 (fixed argv, our own module)
        [
            sys.executable,
            "-m",
            "sibyl_sim.doubles",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(control_port),
            "--doubles-port",
            str(doubles_port),
            "--tls-dir",
            str(tmp_path),
            "--seed",
            "5",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 20
        health: dict[str, Any] = {}
        while time.monotonic() < deadline:
            try:
                health = httpx.get(f"http://127.0.0.1:{control_port}/healthz").json()
                break
            except httpx.TransportError:
                time.sleep(0.1)
        assert health["ca_path"] == str(tmp_path / "ca.pem")
        pem = httpx.get(f"http://127.0.0.1:{control_port}/_sim/tls/ca.pem").text
        context = ssl.create_default_context(cadata=pem)
        response = httpx.post(
            f"https://127.0.0.1:{doubles_port}/v1/chat/completions",
            json=body(),
            headers={"Authorization": "Bearer k"},
            verify=context,
        )
        assert response.status_code == 200
        assert response.json()["id"].startswith("chatcmpl-openai-stub-")
    finally:
        proc.terminate()
        proc.wait(10)
