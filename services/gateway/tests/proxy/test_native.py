"""Native protocol surfaces (D50): Anthropic Messages and Gemini ``generateContent`` with the
same policy semantics as the OpenAI surface: kill switch, quarantine, limits, routing chain,
same-protocol inline fallback, telemetry, protocol-native error envelopes, secrets never
forwarded to the wrong place nor logged."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from sibyl_schemas import jsonschema as sj

from ..fakes.native import (
    anthropic_message,
    anthropic_sse,
    anthropic_stream,
    gemini_chunk,
    gemini_response,
    gemini_sse,
    gemini_stream,
    parse_anthropic_sse,
    parse_gemini_sse,
)
from ..fakes.upstream import FakeUpstream, Reply
from ..support import CRED, GATEWAY_KEY, QUOTE, TENANT, tenant_block
from ..support import body as snapshot_body
from .harness import Harness, make_gateway
from .native_support import (
    ANTHROPIC_KEY,
    GEN,
    GOOGLE_KEY,
    MESSAGES,
    STREAM,
    anthropic_headers,
    assert_wire_valid,
    contents,
    gemini_headers,
    messages,
    native,
)

Up = tuple[FakeUpstream, str]


async def call(gw: Harness, path: str, payload: Any, headers: dict[str, str]) -> Any:
    async with gw.client() as client:
        return await client.post(path, json=payload, headers=headers)


# ------------------------------------------------------------------------------ Anthropic


async def test_anthropic_messages_passthrough_headers_and_telemetry(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    raw = json.dumps(messages(temperature=0.2)).encode()
    async with gw.client() as client:
        resp = await client.post(MESSAGES, content=raw, headers=anthropic_headers())
    assert resp.status_code == 200, resp.text
    assert resp.json() == anthropic_message(model="claude-sonnet-5")
    h = resp.headers
    assert (h["x-sibyl-provider"], h["x-sibyl-model"], h["x-sibyl-route"]) == (
        "anthropic",
        "claude-sonnet-5",
        "primary",
    )
    assert h["x-sibyl-agent-id"] == str(QUOTE) and "spoofed" not in str(dict(h))
    seen = fake.seen[-1]
    assert seen.path == "/anthropic/v1/messages"
    assert seen.headers["x-api-key"] == ANTHROPIC_KEY
    assert seen.headers["anthropic-version"] == "2023-06-01"
    assert seen.headers["anthropic-beta"] == "tools-2026-01-01"
    assert "authorization" not in seen.headers
    assert not [k for k in seen.headers if k.startswith("x-sibyl-")]
    assert json.dumps(seen.body).encode() == raw  # byte-for-byte
    (event,) = gw.events()
    assert_wire_valid(event)
    attrs = event["attrs"]
    assert (attrs["provider"], attrs["operation"], attrs["request_model"]) == (
        "anthropic",
        "chat",
        "claude-sonnet-5",
    )
    assert attrs["response_model"] == "claude-sonnet-5" and attrs["response_id"] == "msg_fake"
    assert attrs["usage"] == {
        "source": "provider",
        "input_tokens": 11,
        "output_tokens": 4,
        "cached_input_tokens": 3,
        "cache_creation_input_tokens": 0,
    }
    assert attrs["finish_reasons"] == ["stop"]
    assert "system_fingerprint" not in attrs  # Anthropic returns no equivalent
    assert ANTHROPIC_KEY not in json.dumps(event)


@pytest.mark.parametrize(
    ("stop", "normalised"),
    [("max_tokens", "length"), ("refusal", "refusal"), ("tool_use", "tool_calls")],
)
async def test_anthropic_stop_reasons_are_normalised(
    upstream: Up, stop: str, normalised: str
) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    fake.queue(Reply(body=anthropic_message(stop=stop)))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.json()["stop_reason"] == stop  # the agent sees the native value
    (event,) = gw.events()
    assert event["attrs"]["finish_reasons"] == [normalised]


async def test_anthropic_streaming_relays_events_and_reads_usage(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    events = anthropic_stream(model="claude-sonnet-5-20261001")
    fake.queue(Reply(events=events))
    resp = await call(gw, MESSAGES, messages(stream=True), anthropic_headers())
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/event-stream")
    assert resp.content == anthropic_sse(events)
    assert parse_anthropic_sse(resp.content)[0]["type"] == "message_start"
    (event,) = gw.events()
    assert_wire_valid(event)
    attrs = event["attrs"]
    assert attrs["streamed"] is True and attrs["response_model"] == "claude-sonnet-5-20261001"
    assert attrs["usage"]["input_tokens"] == 21 and attrs["usage"]["output_tokens"] == 17
    assert attrs["finish_reasons"] == ["stop"]


async def test_anthropic_sibyl_key_in_x_api_key_is_never_forwarded(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    headers = {"x-api-key": GATEWAY_KEY, "anthropic-version": "2023-06-01"}
    resp = await call(gw, MESSAGES, messages(), {**headers, "X-Sibyl-Agent": "quote-assistant"})
    # a Sibyl-only call needs a vaulted route; this agent has none -> native 400, no upstream
    assert resp.status_code == 400
    assert resp.json() == {
        "type": "error",
        "error": {
            "type": "invalid_request_error",
            "message": "The request could not be routed as sent.",
        },
    }
    assert resp.headers["x-sibyl-error"] == "sibyl_bad_request"
    assert fake.seen == []


async def test_anthropic_kill_switch_and_quarantine_refuse_in_native_shape(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic", route={"state": "killed"}))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 403
    body = resp.json()
    assert body["type"] == "error" and body["error"]["type"] == "permission_error"
    assert "kill switch" in body["error"]["message"]
    assert resp.headers["x-sibyl-error"] == "sibyl_agent_killed"
    gw = make_gateway(url, native(url, "anthropic", route={"state": "quarantined"}))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 403 and resp.headers["x-sibyl-error"] == "sibyl_agent_quarantined"
    assert fake.seen == []
    (event,) = gw.events("policy.decision")
    assert event["attrs"]["action"] == "reject_quarantined"


async def test_anthropic_budget_limit_is_a_native_rate_limit_error(upstream: Up) -> None:
    fake, url = upstream
    limits = {"budget_usd_month": "10.0000", "spent_usd_month": "10.0000"}
    gw = make_gateway(url, native(url, "anthropic", limits=limits))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 429
    assert resp.json()["error"]["type"] == "rate_limit_error"
    assert fake.seen == []


async def test_anthropic_inline_fallback_stays_on_the_anthropic_protocol(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic", inline=True))
    fake.queue(Reply(status=529), Reply())
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 200, resp.text
    assert resp.headers["x-sibyl-route"] == "inline_fallback"
    assert resp.headers["x-sibyl-model"] == "claude-haiku-5"
    assert [s.path for s in fake.seen] == ["/anthropic/v1/messages"] * 2  # OpenAI step skipped
    assert fake.seen[1].body["model"] == "claude-haiku-5"
    assert fake.seen[1].headers["x-api-key"] == ANTHROPIC_KEY  # same provider: passthrough
    (event,) = gw.events()
    assert event["attrs"]["retry"]["inline_fallback_used"] is True


async def test_anthropic_upstream_failure_is_a_native_error(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    fake.queue(Reply(status=503))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 502
    assert resp.json()["error"] == {
        "type": "api_error",
        "message": "The upstream provider failed.",
    }
    fake.queue(Reply(status=400))
    resp = await call(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 400  # client errors are relayed, never retried


async def test_anthropic_count_tokens_passthrough_without_generation_telemetry(
    upstream: Up,
) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    resp = await call(gw, "/v1/messages/count_tokens", messages(), anthropic_headers())
    assert resp.status_code == 200 and resp.json() == {"input_tokens": 42}
    assert fake.seen[-1].path == "/anthropic/v1/messages/count_tokens"
    assert gw.events() == []
    gw = make_gateway(url, native(url, "anthropic", route={"state": "killed"}))
    resp = await call(gw, "/v1/messages/count_tokens", messages(), anthropic_headers())
    assert resp.status_code == 403


async def test_native_routes_reject_bad_requests(upstream: Up) -> None:
    _, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    async with gw.client() as client:
        resp = await client.get(MESSAGES, headers=anthropic_headers())
        assert resp.status_code == 400 and resp.json()["type"] == "error"
        resp = await client.post(MESSAGES, content=b"[1]", headers=anthropic_headers())
        assert resp.status_code == 400
        resp = await client.post(
            MESSAGES, json=messages(), headers=anthropic_headers(**{"X-Sibyl-Key": "sbl_bad"})
        )
        assert resp.status_code == 401
        assert resp.json()["error"]["type"] == "authentication_error"


async def test_openai_caller_cannot_reach_an_anthropic_primary(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "anthropic"))
    resp = await call(
        gw,
        "/v1/chat/completions",
        {"model": "claude-sonnet-5", "messages": []},
        {
            "X-Sibyl-Key": GATEWAY_KEY,
            "X-Sibyl-Agent": "quote-assistant",
            "Authorization": "Bearer sk-x",
        },
    )
    assert resp.status_code == 400 and resp.headers["x-sibyl-error"] == "sibyl_bad_request"
    assert resp.json()["error"]["code"] == "sibyl_bad_request"  # OpenAI envelope on that surface
    assert fake.seen == []


# ------------------------------------------------------------------------------ Gemini


async def test_gemini_generate_content_passthrough_and_telemetry(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    resp = await call(gw, GEN, contents(), gemini_headers())
    assert resp.status_code == 200, resp.text
    assert resp.json() == gemini_response()
    assert resp.headers["x-sibyl-provider"] == "gemini"
    seen = fake.seen[-1]
    assert seen.path == "/gemini/v1beta/models/gemini-2.5-pro:generateContent"
    assert seen.headers["x-goog-api-key"] == GOOGLE_KEY and seen.query == ""
    (event,) = gw.events()
    assert_wire_valid(event)
    attrs = event["attrs"]
    assert (attrs["provider"], attrs["operation"], attrs["request_model"]) == (
        "gemini",
        "generate_content",
        "gemini-2.5-pro",
    )
    assert attrs["response_model"] == "gemini-2.5-pro-002" and attrs["response_id"] == "resp-fake"
    assert attrs["usage"] == {
        "source": "provider",
        "input_tokens": 13,
        "output_tokens": 5,
        "cached_input_tokens": 2,
        "reasoning_tokens": 7,
    }
    assert attrs["finish_reasons"] == ["stop"]


async def test_gemini_key_query_param_moves_to_a_header_and_is_never_logged(
    upstream: Up, caplog: pytest.LogCaptureFixture
) -> None:
    fake, url = upstream
    caplog.set_level(logging.DEBUG)
    gw = make_gateway(url, native(url, "gemini"))
    headers = {"X-Sibyl-Key": GATEWAY_KEY, "X-Sibyl-Agent": "quote-assistant"}
    resp = await call(gw, f"{GEN}?key={GOOGLE_KEY}&foo=bar", contents(), headers)
    assert resp.status_code == 200
    seen = fake.seen[-1]
    assert seen.headers["x-goog-api-key"] == GOOGLE_KEY
    assert GOOGLE_KEY not in seen.query and seen.query == ""
    fake.queue(Reply(status=500), Reply(status=500))
    await call(gw, f"{GEN}?key={GOOGLE_KEY}", contents(), headers)
    # the test client's own httpx line names its request URL (http://gw/...?key=): not ours
    gateway_logs = [r.getMessage() for r in caplog.records if "http://gw/" not in r.getMessage()]
    assert any("/gemini/v1beta/models/" in m for m in gateway_logs)  # outbound line is there
    everything = json.dumps(gw.telemetry.pending()) + "\n".join(gateway_logs)
    assert GOOGLE_KEY not in everything and GATEWAY_KEY not in everything


async def test_gemini_sibyl_key_in_the_key_param_is_never_forwarded(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    resp = await call(
        gw, f"{GEN}?key={GATEWAY_KEY}", contents(), {"X-Sibyl-Agent": "quote-assistant"}
    )
    assert resp.status_code == 400 and fake.seen == []
    assert resp.json()["error"]["status"] == "INVALID_ARGUMENT"


async def test_gemini_streaming_sse(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    chunks = gemini_stream()
    fake.queue(Reply(events=chunks))
    resp = await call(gw, f"{STREAM}?alt=sse", contents(), gemini_headers())
    assert resp.status_code == 200 and resp.content == gemini_sse(chunks)
    assert parse_gemini_sse(resp.content) == chunks
    assert fake.seen[-1].query == "alt=sse"
    (event,) = gw.events()
    attrs = event["attrs"]
    assert attrs["streamed"] is True and attrs["usage"]["output_tokens"] == 6
    assert attrs["finish_reasons"] == ["stop"]


async def test_gemini_streaming_json_array(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    chunks = gemini_stream()
    fake.queue(Reply(events=chunks))
    resp = await call(gw, STREAM, contents(), gemini_headers())
    assert resp.json() == chunks and fake.seen[-1].query == ""
    (event,) = gw.events()
    assert event["attrs"]["usage"]["input_tokens"] == 9
    assert event["attrs"]["streamed"] is True


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        (gemini_response(finish="SAFETY"), ["safety"]),
        (gemini_response(finish="MAX_TOKENS"), ["length"]),
        ({"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}}, ["safety"]),
        (
            gemini_chunk({"functionCall": {"name": "x", "args": {}}}, finish="STOP"),
            ["stop", "tool_calls"],
        ),
    ],
)
async def test_gemini_finish_reasons_and_refusals(upstream: Up, doc: Any, expected: Any) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    fake.queue(Reply(body=doc))
    await call(gw, GEN, contents(), gemini_headers())
    (event,) = gw.events()
    assert event["attrs"]["finish_reasons"] == expected


async def test_gemini_kill_switch_refuses_in_native_shape(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini", route={"state": "killed"}))
    resp = await call(gw, GEN, contents(), gemini_headers())
    assert resp.status_code == 403
    assert resp.json() == {
        "error": {
            "code": 403,
            "message": "This agent is stopped by a kill switch.",
            "status": "PERMISSION_DENIED",
        }
    }
    assert fake.seen == []


async def test_gemini_inline_fallback_rewrites_the_model_in_the_path(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini", inline=True))
    fake.queue(Reply(status=503), Reply())
    resp = await call(gw, f"{STREAM}?alt=sse", contents(tools=[{"x": 1}]), gemini_headers())
    assert resp.status_code == 200
    assert [s.path for s in fake.seen] == [
        "/gemini/v1beta/models/gemini-2.5-pro:streamGenerateContent",
        "/gemini/v1beta/models/gemini-2.5-flash:streamGenerateContent",
    ]
    assert fake.seen[1].query == "alt=sse" and fake.seen[1].body == contents(tools=[{"x": 1}])
    assert resp.headers["x-sibyl-model"] == "gemini-2.5-flash"


async def test_gemini_degraded_safe_mode_strips_tools(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini", route={"state": "degraded"}))
    body = contents(tools=[{"functionDeclarations": []}], toolConfig={"mode": "ANY"})
    resp = await call(gw, GEN, body, gemini_headers())
    assert resp.status_code == 200
    assert fake.seen[-1].body == contents()


@pytest.mark.parametrize(
    "path",
    [
        "/v1beta/models/:generateContent",
        "/v1beta/models/a..b:generateContent",
        "/v1beta/models/gemini%2F..%2Fx:generateContent",
        "/v1beta/models/gemini-2.5-pro:countTokens",
        "/v1beta/models/gemini-2.5-pro",
    ],
)
async def test_gemini_rejects_unsafe_or_unknown_model_paths(upstream: Up, path: str) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, "gemini"))
    resp = await call(gw, path, contents(), gemini_headers())
    assert resp.status_code in (400, 404)
    assert fake.seen == []


# ------------------------------------------------------------------------------ vaulted / OAuth

VAULTED = "native-vaulted-fallback-secret-0123456789"


def install_vaulted(gw: Harness, url: str) -> None:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from sibyl_gateway.credentials.sealing import b64url_decode, public_bytes, seal, seal_aad

    pub = public_bytes(X25519PublicKey.from_public_bytes(b64url_decode(gw.vault.seal_public_key)))
    sealed = seal(pub, VAULTED.encode(), seal_aad(TENANT, CRED, 1))
    item = {"auth_scheme": "bearer", "secret": sealed, "base_url": url, "key_version": 1}
    assert gw.vault.install_bundle(TENANT, {"expires_in_s": 300, "items": {str(CRED): item}}) == 1


def vaulted_step(url: str, protocol: str) -> Any:
    base = native(url, protocol, inline=True)

    def mutate(block: dict[str, Any]) -> None:
        base(block)
        block["agents"][str(QUOTE)]["fallback_chain"]["steps"][1]["credential_id"] = str(CRED)

    return mutate


@pytest.mark.parametrize(
    ("protocol", "path", "payload", "sibyl_only", "header"),
    [
        ("anthropic", MESSAGES, messages(), {"x-api-key": GATEWAY_KEY}, "x-api-key"),
        ("gemini", GEN, contents(), {"x-goog-api-key": GATEWAY_KEY}, "x-goog-api-key"),
    ],
)
async def test_sibyl_only_native_call_uses_the_vaulted_credential_in_the_native_header(
    upstream: Up,
    protocol: str,
    path: str,
    payload: Any,
    sibyl_only: dict[str, str],
    header: str,
) -> None:
    fake, url = upstream
    gw = make_gateway(url, vaulted_step(url, protocol))
    install_vaulted(gw, url)
    resp = await call(gw, path, payload, {**sibyl_only, "X-Sibyl-Agent": "quote-assistant"})
    assert resp.status_code == 200, resp.text
    seen = fake.seen[-1]
    assert seen.headers[header] == VAULTED and "authorization" not in seen.headers
    assert GATEWAY_KEY not in json.dumps(seen.headers)
    assert VAULTED not in json.dumps(gw.telemetry.pending())


@pytest.mark.parametrize(
    ("protocol", "path", "payload"),
    [("anthropic", MESSAGES, messages()), ("gemini", GEN, contents())],
)
async def test_native_oauth_bearer_is_passed_through(
    upstream: Up, protocol: str, path: str, payload: Any
) -> None:
    fake, url = upstream
    gw = make_gateway(url, native(url, protocol))
    hdrs = {
        "Authorization": "Bearer ya29.oauth-token",
        "X-Sibyl-Key": GATEWAY_KEY,
        "X-Sibyl-Agent": "quote-assistant",
    }
    resp = await call(gw, path, payload, hdrs)
    assert resp.status_code == 200
    seen = fake.seen[-1]
    assert seen.headers["authorization"] == "Bearer ya29.oauth-token"
    assert "x-api-key" not in seen.headers and "x-goog-api-key" not in seen.headers


# ------------------------------------------------------------------------------ OpenAI extras


async def test_openai_system_fingerprint_and_refusal_reach_telemetry(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    body = {
        "id": "c",
        "object": "chat.completion",
        "model": "gpt-5.4-2026",
        "system_fingerprint": "fp_abc123",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": None, "refusal": "I can't."},
                "finish_reason": "stop",
            }
        ],
    }
    fake.queue(Reply(body=body))
    async with gw.client() as client:
        await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-5.4", "messages": []},
            headers={
                "X-Sibyl-Key": GATEWAY_KEY,
                "X-Sibyl-Agent": "quote-assistant",
                "Authorization": "Bearer sk-x",
            },
        )
    (event,) = gw.events()
    assert_wire_valid(event)
    assert event["attrs"]["system_fingerprint"] == "fp_abc123"
    assert event["attrs"]["finish_reasons"] == ["stop", "refusal"]
    assert event["tenant_id"] == str(TENANT)


# ------------------------------------------------------------------------------ snapshot contract


def test_gemini_provider_snapshot_is_schema_valid() -> None:
    """B26: the ``gemini`` dialect (landed by lane PLUG) is part of ``sibyl.policy_snapshot/1``,
    so a control-plane snapshot carrying a Gemini provider is what the gateway consumes here."""
    block = tenant_block()
    native("https://upstream.example", "gemini")(block)
    doc = snapshot_body(1, tenants={str(TENANT): block})
    assert not list(sj.iter_errors("sibyl.policy_snapshot/1", doc))
