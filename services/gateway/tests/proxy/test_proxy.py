"""G-hot over a real (socket) fake upstream: passthrough, headers, errors, fallback, limits."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from sibyl_gateway.credentials.sealing import public_bytes, seal, seal_aad
from sibyl_schemas import jsonschema as sj

from ..fakes.upstream import FakeUpstream, Reply
from ..support import BILLING, CRED, GATEWAY_KEY, QUOTE, SIM, TENANT, b64u, make_key, set_agent
from .harness import PROVIDER_KEY, chat, headers, make_gateway

Up = tuple[FakeUpstream, str]
CHAT = "/v1/chat/completions"


def assert_wire_valid(event: dict[str, Any]) -> None:
    errors = list(sj.iter_errors("sibyl-event-wire/1", event))
    assert not errors, errors


async def test_passthrough_is_byte_for_byte_with_sibyl_headers(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    raw = json.dumps(chat(temperature=0.1)).encode()
    async with gw.client() as client:
        resp = await client.post(
            CHAT,
            content=raw,
            headers={
                **headers(GATEWAY_KEY),
                "traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01",
                "Cookie": "session=1",
                "X-Request-Id": "req-42",
                "Content-Type": "application/json",
            },
        )
    assert resp.status_code == 200, resp.text
    assert resp.json()["choices"][0]["message"]["content"] == "hello"
    h = resp.headers
    assert (h["x-sibyl-route"], h["x-sibyl-provider"], h["x-sibyl-model"]) == (
        "primary",
        "openai",
        "gpt-5.4",
    )
    assert h["x-sibyl-agent-id"] == str(QUOTE)
    assert h["x-sibyl-policy-state"] == "fresh" and h["x-sibyl-policy-version"] == "1"
    assert h["x-sibyl-gateway-id"] == "gw-test" and h["x-request-id"] == "req-42"
    assert h["x-sibyl-routing-state"] == "active" and h["x-sibyl-capture-mode"] == "full"
    assert "set-cookie" not in h and "ratelimit" in h
    assert str(TENANT) not in str(dict(h))
    seen = fake.seen[-1]
    assert seen.path == "/v1/chat/completions"
    assert seen.headers["authorization"] == f"Bearer {PROVIDER_KEY}"
    assert not [k for k in seen.headers if k.startswith("x-sibyl-")]
    assert "cookie" not in seen.headers and seen.headers["traceparent"].startswith("00-aaaa")
    assert json.dumps(seen.body).encode() == raw  # unchanged document
    (event,) = gw.events()
    assert_wire_valid(event)
    attrs = event["attrs"]
    assert attrs["status"] == "ok" and attrs["usage"]["input_tokens"] == 5
    assert event["trace_id"] == "a" * 32 and event["parent_span_id"] == "b" * 16
    assert PROVIDER_KEY not in json.dumps(event)


async def test_secrets_in_content_are_scrubbed_before_the_queue(upstream: Up) -> None:
    _, url = upstream
    gw = make_gateway(url)
    leaked = "sk-proj-Ab3dEf9hIj2kLm4nOp6qRs8tUv0wXyZa1bC3"
    async with gw.client() as client:
        resp = await client.post(
            CHAT,
            json=chat(messages=[{"role": "user", "content": leaked}]),
            headers=headers(GATEWAY_KEY),
        )
    assert resp.status_code == 200
    (event,) = gw.events()
    assert leaked not in json.dumps(event)
    assert event["redaction_profile"]["secrets_scrubbed"] >= 1
    assert event["attrs"]["payload_inline"]["parts"] == ["input_messages", "output_messages"]
    assert_wire_valid(event)


async def test_metadata_capture_carries_no_content(upstream: Up) -> None:
    _, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        await client.post(
            CHAT, json=chat(), headers=headers(GATEWAY_KEY, **{"X-Sibyl-Capture": "metadata"})
        )
    (event,) = gw.events()
    assert event["capture_mode"] == "metadata"
    assert "payload_inline" not in event["attrs"] and "content_hashes" not in event["attrs"]


async def test_failover_rewrites_only_the_model(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY, "billing-agent"))
    assert resp.status_code == 200
    assert (
        resp.headers["x-sibyl-route"] == "failover"
        and resp.headers["x-sibyl-model"] == "gpt-5-mini"
    )
    assert fake.seen[-1].body["model"] == "gpt-5-mini"
    assert fake.seen[-1].body["messages"] == chat()["messages"]


async def test_inline_fallback_before_first_byte(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, inline_fallback=True))
    fake.queue(Reply(status=503), Reply(status=502))
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == 200
    assert resp.headers["x-sibyl-route"] == "inline_fallback"
    assert resp.headers["x-sibyl-fallback-attempts"] == "2"
    assert [s.body["model"] for s in fake.seen] == ["gpt-5.4", "gpt-5.4", "gpt-5-mini"]
    (event,) = gw.events()
    assert event["attrs"]["retry"]["inline_fallback_used"] is True
    assert event["attrs"]["route"]["to"] == {"provider": "openai", "model": "gpt-5-mini"}
    assert_wire_valid(event)


RL_HEADERS = {
    "x-ratelimit-limit-requests": "1000",
    "x-ratelimit-remaining-requests": "310",
    "x-ratelimit-reset-requests": "1s",
    "x-ratelimit-limit-tokens": "200000",
    "x-ratelimit-remaining-tokens": "62000",
    "x-ratelimit-reset-tokens": "1s",
}
RL_ATTRS = {
    "limit_requests": 1000,
    "remaining_requests": 310,
    "reset_requests_ms": 1000,
    "limit_tokens": 200000,
    "remaining_tokens": 62000,
    "reset_tokens_ms": 1000,
}


@pytest.mark.parametrize("status", [200, 429])
async def test_upstream_ratelimit_headers_reach_the_event(upstream: Up, status: int) -> None:
    """L3's headroom input (ML.md §1.2): the six ``x-ratelimit-*`` values ride on the event,
    on a served call and on a 429 alike."""
    fake, url = upstream
    gw = make_gateway(url)
    fake.queue(Reply(status=status, headers=RL_HEADERS))
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == status
    (event,) = gw.events()
    assert event["attrs"]["ratelimit"] == RL_ATTRS
    assert_wire_valid(event)


async def test_no_upstream_ratelimit_headers_no_attr(upstream: Up) -> None:
    _, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    (event,) = gw.events()
    assert "ratelimit" not in event["attrs"]


@pytest.mark.parametrize(
    ("reply", "status", "code"),
    [
        (Reply(status=429, retry_after="7"), 429, "upstream_rate_limited"),
        (Reply(status=500), 502, "upstream_error"),
        (Reply(status=302), 502, "upstream_error"),
        (Reply(delay_s=1.0), 504, "upstream_timeout"),
    ],
)
async def test_upstream_failures_map_to_the_error_envelope(
    upstream: Up, reply: Reply, status: int, code: str
) -> None:
    fake, url = upstream
    gw = make_gateway(url, ttfb_s=0.3)
    fake.queue(reply)
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == status
    assert resp.json()["error"]["code"] == code
    assert resp.headers["x-sibyl-error"] == code and resp.headers["x-sibyl-origin"] == "gateway"
    if code == "upstream_rate_limited":
        assert resp.headers["retry-after"] == "7"
    assert len(fake.seen) == 1  # no inline fallback configured, redirects never followed
    (event,) = gw.events()
    assert event["attrs"]["status"] == "error"
    assert_wire_valid(event)
    await asyncio.sleep(0.8)  # let the slow reply finish server-side


async def test_upstream_client_errors_are_relayed_not_retried(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, inline_fallback=True))
    fake.queue(Reply(status=400))
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == 400 and resp.json()["error"]["message"] == "upstream says no"
    assert len(fake.seen) == 1


async def test_header_and_key_rules(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        bad = await client.post(
            CHAT, json=chat(), headers=headers(GATEWAY_KEY, **{"X-Sibyl-Fail-Mode": "open"})
        )
        assert (bad.status_code, bad.json()["error"]["code"]) == (400, "sibyl_header_not_allowed")
        unknown, _ = make_key("Unknown00001")
        bodies = set()
        for key in (unknown, GATEWAY_KEY[:-2] + "zz", ""):
            resp = await client.post(CHAT, json=chat(), headers=headers(key))
            assert resp.status_code == 401
            bodies.add(resp.content)
        assert len(bodies) == 1  # identical 401s (T6)
        fallback = await client.post(
            CHAT, json=chat(), headers=headers(GATEWAY_KEY, **{"X-Sibyl-Fallback": "x"})
        )
        assert fallback.status_code == 400
        assert (
            await client.post(CHAT, content=b"[1]", headers=headers(GATEWAY_KEY))
        ).status_code == 400
    assert fake.seen == []


async def test_failed_auth_is_rate_limited_per_client(upstream: Up) -> None:
    _, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        codes = [
            (await client.post(CHAT, json=chat(), headers=headers("nope"))).status_code
            for _ in range(61)
        ]
    assert codes[:60] == [401] * 60 and codes[60] == 429


async def test_sibyl_only_call_never_forwards_the_sibyl_key(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        resp = await client.post(
            CHAT,
            json=chat(),
            headers={"Authorization": f"Bearer {GATEWAY_KEY}", "X-Sibyl-Agent": "quote-assistant"},
        )
    assert resp.status_code == 400 and resp.json()["error"]["code"] == "sibyl_bad_request"
    assert fake.seen == []


async def test_vaulted_credential_replaces_the_client_credential(upstream: Up) -> None:
    fake, url = upstream

    def to_sim(block: dict[str, Any]) -> None:
        steps = block["agents"][str(BILLING)]["fallback_chain"]["steps"]
        steps[2]["provider_id"] = str(SIM)
        set_agent(block, BILLING, route={"state": "failed_over", "step_position": 3})

    gw = make_gateway(url, to_sim)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from sibyl_gateway.credentials.sealing import b64url_decode

    pub = public_bytes(X25519PublicKey.from_public_bytes(b64url_decode(gw.vault.seal_public_key)))
    sealed = seal(pub, b"sk-vaulted-fallback-secret", seal_aad(TENANT, CRED, 1))
    assert (
        gw.vault.install_bundle(
            TENANT,
            {
                "expires_in_s": 300,
                "items": {
                    str(CRED): {
                        "auth_scheme": "bearer",
                        "secret": sealed,
                        "base_url": url,
                        "key_version": 1,
                    }
                },
            },
        )
        == 1
    )
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY, "billing-agent"))
    assert resp.status_code == 200, resp.text
    seen = fake.seen[-1]
    assert seen.path == "/sim/v1/chat/completions"
    assert seen.headers["authorization"] == "Bearer sk-vaulted-fallback-secret"
    assert PROVIDER_KEY not in json.dumps(seen.headers)
    assert "sk-vaulted" not in json.dumps(gw.events())


async def test_killed_agent_never_reaches_upstream(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(
        url, lambda b: set_agent(b, QUOTE, fail_mode="open", route={"state": "killed"}), age_s=1000
    )  # expired snapshot + fail-open: kill still wins
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "sibyl_agent_killed"
    assert resp.headers["x-sibyl-policy-state"] == "expired"
    assert fake.seen == []
    (event,) = gw.events()
    assert event["attrs"]["status"] == "error" and event["attrs"]["http_status"] == 403
    assert_wire_valid(event)
    (decision,) = gw.events("policy.decision")
    assert decision["attrs"]["action"] == "reject_killed"
    assert_wire_valid(decision)


async def test_expired_fail_open_serves_stale_primary_and_emits_a_windowed_decision(
    upstream: Up,
) -> None:
    _, url = upstream
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, fail_mode="open"), age_s=1000)
    async with gw.client() as client:
        for _ in range(3):
            resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
            assert resp.status_code == 200 and resp.headers["x-sibyl-route"] == "stale_primary"
    assert len(gw.events("policy.decision")) == 1


async def test_agent_rate_inflight_and_budget_limits(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, limits={"rps": 1.0}))
    async with gw.client() as client:
        codes = [
            (await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))).status_code
            for _ in range(3)
        ]
    assert codes == [200, 200, 429]
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, limits={"max_inflight": 1}))
    fake.queue(Reply(delay_s=0.3))
    async with gw.client() as client:
        slow = asyncio.create_task(client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY)))
        await asyncio.sleep(0.1)
        busy = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
        assert (await slow).status_code == 200
    assert busy.status_code == 429 and busy.json()["error"]["code"] == "sibyl_inflight_limit"
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, limits={"spent_usd_month": "9999"}))
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.json()["error"]["code"] == "sibyl_budget_exhausted"


async def test_degraded_safe_no_tools_strips_tools(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, lambda b: set_agent(b, QUOTE, route={"state": "degraded"}))
    tools = [{"type": "function", "function": {"name": "lookup"}}]
    async with gw.client() as client:
        resp = await client.post(
            CHAT, json=chat(tools=tools, tool_choice="auto"), headers=headers(GATEWAY_KEY)
        )
    assert resp.status_code == 200 and resp.headers["x-sibyl-degraded-mode"] == "safe_no_tools"
    assert "tools" not in fake.seen[-1].body and "tool_choice" not in fake.seen[-1].body


async def test_embeddings_and_models(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    async with gw.client() as client:
        emb = await client.post(
            "/v1/embeddings", json={"model": "gpt-5.4", "input": "x"}, headers=headers(GATEWAY_KEY)
        )
        models = await client.get("/v1/models", headers=headers(GATEWAY_KEY))
        get_chat = await client.get(CHAT, headers=headers(GATEWAY_KEY))
    assert emb.status_code == 200 and fake.seen[-1].path == "/v1/embeddings"
    assert [m["id"] for m in models.json()["data"]] == ["claude-sonnet-5", "gpt-5-mini", "gpt-5.4"]
    assert len(fake.seen) == 1  # /v1/models is never proxied
    assert get_chat.status_code == 400
    (event,) = gw.events()
    assert event["attrs"]["operation"] == "embeddings"


async def test_health_and_readiness() -> None:
    empty = make_gateway(None, load=False)
    async with empty.client() as client:
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        ready = await client.get("/readyz")
        assert ready.status_code == 503 and ready.json() == {"snapshot": "none"}
        refused = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
        assert refused.json()["error"]["code"] == "sibyl_no_snapshot"
        assert (await client.get("/nope")).status_code == 404
    loaded = make_gateway("http://127.0.0.1:9")
    async with loaded.client() as client:
        ready = await client.get("/readyz")
    assert ready.status_code == 200 and ready.json()["snapshot"] == "fresh"


async def test_ssrf_blocked_upstream_never_connects() -> None:
    gw = make_gateway("http://10.1.2.3:80")  # private literal, not a dev host
    async with gw.client() as client:
        resp = await client.post(CHAT, json=chat(), headers=headers(GATEWAY_KEY))
    assert resp.status_code == 502 and resp.json()["error"]["code"] == "upstream_error"


def test_b64u_helper_roundtrip() -> None:
    assert b64u(b"\xff") == "_w"
