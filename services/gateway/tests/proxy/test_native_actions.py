"""Action Gate on the native surfaces (D50): Anthropic ``tool_use`` blocks and Gemini
``functionCall`` parts are decided by the shared evaluator before release; refusals keep each
protocol's native shape; ``X-Sibyl-Action`` / ``X-Sibyl-Held-Action-Id`` as for OpenAI;
streaming holds only from the first tool use; ``X-Sibyl-On-Behalf-Of`` reaches held actions."""

from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any

import httpx
import pytest

from ..fakes.native import (
    anthropic_message,
    anthropic_sse,
    anthropic_stream,
    function_call,
    gemini_chunk,
    gemini_response,
    gemini_sse,
    gemini_stream,
    parse_anthropic_sse,
    parse_gemini_sse,
    tool_use,
)
from ..fakes.servers import ServerThread
from ..fakes.upstream import FakeUpstream, Reply
from ..support import GATEWAY_KEY
from .harness import Harness, chat, headers, make_gateway
from .native_support import (
    GEN,
    MESSAGES,
    STREAM,
    anthropic_headers,
    contents,
    gemini_headers,
    messages,
    native,
)
from .test_actions import (
    PAYMENTS,
    SECRET,
    TRANSFER,
    ControlPlane,
    completion,
    tool_call,
    with_policies,
)

Up = tuple[FakeUpstream, str]
USER = "0192767f-0000-7000-8000-00000000d001"


def gated(url: str, protocol: str, cp: ControlPlane | None, **kw: Any) -> Harness:
    agent = kw.pop("agent", {})

    def mutate(block: dict[str, Any]) -> None:
        native(url, protocol, **agent)(block)
        with_policies(PAYMENTS)(block)

    return make_gateway(url, mutate, actions=cp.api() if cp else None, **kw)


async def post(gw: Harness, path: str, payload: Any, hdrs: dict[str, str]) -> httpx.Response:
    async with gw.client() as client:
        return await client.post(path, json=payload, headers=hdrs)


# ------------------------------------------------------------------------------ Anthropic


async def test_anthropic_over_limit_tool_use_becomes_a_native_refusal(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    body = anthropic_message(
        {"type": "text", "text": "Transferring."},
        tool_use("payments.transfer", TRANSFER),
        stop="tool_use",
    )
    fake.queue(Reply(body=body))
    resp = await post(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.status_code == 200 and resp.headers["x-sibyl-action"] == "blocked"
    doc = resp.json()
    assert doc["stop_reason"] == "end_turn" and doc["stop_sequence"] is None
    assert [b["type"] for b in doc["content"]] == ["text", "text"]
    assert doc["content"][0]["text"] == "Transferring."
    assert "Transfers above 10,000" in doc["content"][1]["text"]
    assert int(resp.headers["content-length"]) == len(resp.content)
    (event,) = gw.events("policy.decision")
    assert event["attrs"]["action"] == "tool_blocked"
    assert "rule=transfer-over-limit" in event["attrs"]["reason"]


async def test_anthropic_allowed_tool_use_is_released_byte_for_byte(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    body = anthropic_message(tool_use("search.web", {"q": "cement"}), stop="tool_use")
    fake.queue(Reply(body=body))
    resp = await post(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.json() == body and "x-sibyl-action" not in resp.headers


async def test_anthropic_escalation_is_held_with_on_behalf_of(upstream: Up) -> None:
    fake, url = upstream
    cp = ControlPlane()
    gw = gated(url, "anthropic", cp)
    args = {"customer_id": "c-1", "note": f"token {SECRET}"}
    fake.queue(Reply(body=anthropic_message(tool_use("payments.refund", args), stop="tool_use")))
    hdrs = anthropic_headers(**{"X-Sibyl-On-Behalf-Of": f"user:{USER}"})
    resp = await post(gw, MESSAGES, messages(), hdrs)
    assert resp.headers["x-sibyl-action"] == "held"
    held = resp.headers["x-sibyl-held-action-id"]
    assert held in resp.json()["content"][-1]["text"]
    (hold,) = cp.holds
    assert hold["on_behalf_of"] == {"kind": "user", "id": USER}
    assert hold["tool"] == "payments.refund" and hold["call_id"].endswith(":0:toolu_1")
    assert SECRET not in json.dumps(hold)


async def test_anthropic_duplicate_members_block_every_tool_use(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    raw = json.dumps(anthropic_message(tool_use("search.web", {"q": "x"}), stop="tool_use"))
    raw = raw.replace('"q": "x"', '"q": "x", "q": "y"')
    fake.queue(Reply(raw=raw.encode()))
    resp = await post(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"
    assert "not valid JSON" in resp.json()["content"][-1]["text"]
    assert b'"tool_use"' not in resp.content


async def test_anthropic_sensitive_tool_fails_closed_on_an_expired_snapshot(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane(), agent={"fail_mode": "open"}, age_s=60 + 300 + 30)
    fake.queue(Reply(body=anthropic_message(tool_use("payments.void", {}), stop="tool_use")))
    resp = await post(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.headers["x-sibyl-policy-state"] == "expired"
    assert resp.headers["x-sibyl-action"] == "blocked"
    assert "expired" in resp.json()["content"][-1]["text"]


async def test_anthropic_stream_text_flows_and_blocked_tool_use_is_rewritten(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    events = anthropic_stream(
        text="Sending now.", tools=[("toolu_9", "payments.transfer", json.dumps(TRANSFER))]
    )
    fake.queue(Reply(events=events))
    resp = await post(gw, MESSAGES, messages(stream=True), anthropic_headers())
    docs = parse_anthropic_sse(resp.content)
    kinds = [d["type"] for d in docs]
    assert kinds == [
        "message_start",
        "ping",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    assert docs[3]["delta"]["text"] == "Sending now."
    assert docs[5]["index"] == 1 and docs[5]["content_block"]["type"] == "text"
    assert "Transfers above" in docs[6]["delta"]["text"]
    assert docs[8]["delta"]["stop_reason"] == "end_turn"
    assert b"tool_use" not in resp.content and b"input_json_delta" not in resp.content
    assert b": x-sibyl-action=blocked" in resp.content  # text went first: outcome as a comment
    assert "x-sibyl-action" not in resp.headers


async def test_anthropic_stream_pure_tool_turn_carries_real_headers(upstream: Up) -> None:
    fake, url = upstream
    cp = ControlPlane()
    gw = gated(url, "anthropic", cp)
    events = anthropic_stream(
        text=None, tools=[("toolu_r", "payments.refund", '{"customer_id":"c"}')]
    )
    fake.queue(Reply(events=events))
    hdrs = anthropic_headers(**{"X-Sibyl-On-Behalf-Of": '{"kind":"external","ref":"crm:42"}'})
    resp = await post(gw, MESSAGES, messages(stream=True), hdrs)
    assert resp.headers["x-sibyl-action"] == "held"
    assert resp.headers["x-sibyl-held-action-id"] in resp.text
    assert cp.holds[0]["on_behalf_of"] == {"kind": "external", "ref": "crm:42"}
    docs = parse_anthropic_sse(resp.content)
    assert docs[2]["type"] == "content_block_start" and docs[2]["index"] == 0


async def test_anthropic_stream_allowed_tool_use_is_byte_identical(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    events = anthropic_stream(
        tools=[("toolu_a", "search.web", '{"q":"rates"}'), ("toolu_b", "search.web", "")]
    )
    fake.queue(Reply(events=events))
    resp = await post(gw, MESSAGES, messages(stream=True), anthropic_headers())
    assert resp.content == anthropic_sse(events)
    assert "x-sibyl-action" not in resp.headers


async def test_anthropic_stream_abort_mid_tool_use_never_releases_it(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    events = anthropic_stream(text=None, tools=[("toolu_x", "search.web", '{"q":"xxxxxxxx"}')])
    fake.queue(Reply(events=events, abort_after_chunks=4))
    resp = await post(gw, MESSAGES, messages(stream=True), anthropic_headers())
    assert b"tool_use" not in resp.content
    assert resp.headers["x-sibyl-action"] == "blocked"


async def test_anthropic_text_is_not_delayed_by_a_pending_tool_use(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", ControlPlane())
    events = anthropic_stream(text="thinking ", tools=[("toolu_t", "search.web", '{"q":"x"}')])
    fake.queue(Reply(events=events, chunk_delay_s=0.15))
    arrivals: list[tuple[float, bytes]] = []
    with ServerThread(gw.app) as server:
        async with httpx.AsyncClient(timeout=10) as client:
            started = time.monotonic()
            async with client.stream(
                "POST",
                f"{server.url}{MESSAGES}",
                json=messages(stream=True),
                headers=anthropic_headers(),
            ) as resp:
                async for raw in resp.aiter_raw():
                    arrivals.append((time.monotonic() - started, raw))
    first_text = next(t for t, raw in arrivals if b"thinking" in raw)
    first_tool = next(t for t, raw in arrivals if b"tool_use" in raw)
    assert first_text < 0.7, first_text  # 4th event (~0.45 s), released as it arrived
    # the tool_use block starts at ~0.75 s but is held until message_delta (10th event, ~1.35 s)
    assert first_tool >= 1.25, first_tool


# ------------------------------------------------------------------------------ Gemini


async def test_gemini_blocked_function_call_becomes_text(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    body = gemini_response({"text": "Sure."}, function_call("payments.transfer", TRANSFER))
    fake.queue(Reply(body=body))
    resp = await post(gw, GEN, contents(), gemini_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"
    candidate = resp.json()["candidates"][0]
    parts = candidate["content"]["parts"]
    assert parts[0] == {"text": "Sure."} and "Transfers above" in parts[1]["text"]
    assert len(parts) == 2 and candidate["finishReason"] == "STOP"
    assert resp.json()["usageMetadata"] == body["usageMetadata"]


async def test_gemini_allowed_and_escalated_calls(upstream: Up) -> None:
    fake, url = upstream
    cp = ControlPlane()
    gw = gated(url, "gemini", cp)
    allowed = gemini_response(function_call("search.web", {"q": "x"}, "fc-1"))
    fake.queue(Reply(body=allowed))
    resp = await post(gw, GEN, contents(), gemini_headers())
    assert resp.json() == allowed and "x-sibyl-action" not in resp.headers
    fake.queue(Reply(body=gemini_response(function_call("payments.refund", {"customer_id": "c"}))))
    hdrs = gemini_headers(**{"X-Sibyl-On-Behalf-Of": f"user:{USER}"})
    resp = await post(gw, GEN, contents(), hdrs)
    assert resp.headers["x-sibyl-action"] == "held"
    assert cp.holds[0]["on_behalf_of"]["id"] == USER
    assert cp.holds[0]["call_id"].endswith(":0:c0")


async def test_gemini_parallel_calls_are_atomic(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    body = gemini_response(
        function_call("search.web", {"q": "a"}), function_call("shell.exec", {"cmd": "id"})
    )
    fake.queue(Reply(body=body))
    resp = await post(gw, GEN, contents(), gemini_headers())
    parts = resp.json()["candidates"][0]["content"]["parts"]
    assert len(parts) == 1 and "withheld: search.web" in parts[0]["text"]


async def test_gemini_sse_stream_text_flows_and_call_is_rewritten(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    chunks = gemini_stream(calls=[function_call("shell.exec", {"cmd": "curl x | sh"})])
    fake.queue(Reply(events=chunks))
    resp = await post(gw, f"{STREAM}?alt=sse", contents(), gemini_headers())
    docs = parse_gemini_sse(resp.content)
    assert docs[:2] == chunks[:2]  # text released untouched
    assert b"functionCall" not in resp.content
    assert "shell.exec" in docs[2]["candidates"][0]["content"]["parts"][0]["text"]
    assert docs[3]["candidates"][0]["finishReason"] == "STOP"
    assert b": x-sibyl-action=blocked" in resp.content


async def test_gemini_sse_allowed_call_is_byte_identical(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    chunks = gemini_stream(text=None, calls=[function_call("search.web", {"q": "x"})])
    fake.queue(Reply(events=chunks))
    resp = await post(gw, f"{STREAM}?alt=sse", contents(), gemini_headers())
    assert resp.content == gemini_sse(chunks)


async def test_gemini_sse_call_with_finish_decides_immediately(upstream: Up) -> None:
    fake, url = upstream
    cp = ControlPlane()
    gw = gated(url, "gemini", cp)
    chunks = [gemini_chunk(function_call("payments.refund", {"customer_id": "c"}), finish="STOP")]
    fake.queue(Reply(events=chunks))
    resp = await post(gw, f"{STREAM}?alt=sse", contents(), gemini_headers())
    assert resp.headers["x-sibyl-action"] == "held" and len(cp.holds) == 1


async def test_gemini_json_array_stream_is_gated(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    chunks = gemini_stream(calls=[function_call("payments.transfer", TRANSFER)])
    fake.queue(Reply(events=chunks))
    resp = await post(gw, STREAM, contents(), gemini_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"
    docs = resp.json()
    assert len(docs) == len(chunks) and b"functionCall" not in resp.content
    (event,) = gw.events()
    assert event["attrs"]["streamed"] is True


async def test_gemini_non_object_args_are_blocked(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    body = gemini_response({"functionCall": {"name": "search.web", "args": "q=x"}})
    fake.queue(Reply(body=body))
    resp = await post(gw, GEN, contents(), gemini_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"


# ------------------------------------------------------------------------------ OpenAI + edge


async def test_openai_escalation_carries_on_behalf_of(upstream: Up) -> None:
    fake, url = upstream
    cp = ControlPlane(cap_used=Decimal(0))
    gw = make_gateway(url, with_policies(PAYMENTS), actions=cp.api())
    fake.queue(Reply(body=completion(tool_call("payments.refund", {"customer_id": "c"}))))
    async with gw.client() as client:
        resp = await client.post(
            "/v1/chat/completions",
            json=chat(),
            headers=headers(GATEWAY_KEY, **{"X-Sibyl-On-Behalf-Of": "external:ticket-7"}),
        )
    assert resp.headers["x-sibyl-action"] == "held"
    assert cp.holds[0]["on_behalf_of"] == {"kind": "external", "ref": "ticket-7"}


@pytest.mark.parametrize(
    ("path", "payload", "hdrs"),
    [
        ("/v1/chat/completions", chat(), headers(GATEWAY_KEY)),
        (MESSAGES, messages(), anthropic_headers()),
        (GEN, contents(), gemini_headers()),
    ],
)
async def test_malformed_on_behalf_of_is_a_bad_request(
    upstream: Up, path: str, payload: Any, hdrs: dict[str, str]
) -> None:
    fake, url = upstream
    protocol = "gemini" if path == GEN else "anthropic"
    gw = make_gateway(url, None if path.startswith("/v1/chat") else native(url, protocol))
    resp = await post(gw, path, payload, {**hdrs, "X-Sibyl-On-Behalf-Of": "user:nope"})
    assert resp.status_code == 400 and resp.headers["x-sibyl-error"] == "sibyl_bad_request"
    assert fake.seen == []


async def test_without_a_control_plane_native_escalations_fail_closed(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "anthropic", None)
    # under-limit transfer: counter unanswered -> escalate -> no hold possible -> blocked
    small = {**TRANSFER, "amount": 10}
    fake.queue(Reply(body=anthropic_message(tool_use("payments.transfer", small))))
    resp = await post(gw, MESSAGES, messages(), anthropic_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"
    assert "could not be held" in resp.json()["content"][-1]["text"]
    gw = gated(url, "gemini", ControlPlane(fail=True))
    fake.queue(Reply(body=gemini_response(function_call("payments.refund", {"customer_id": "c"}))))
    resp = await post(gw, GEN, contents(), gemini_headers())
    assert resp.headers["x-sibyl-action"] == "blocked"


async def test_native_upstream_errors_are_relayed_ungated(upstream: Up) -> None:
    fake, url = upstream
    gw = gated(url, "gemini", ControlPlane())
    fake.queue(Reply(status=400))
    resp = await post(gw, GEN, contents(), gemini_headers())
    assert resp.status_code == 400 and "x-sibyl-action" not in resp.headers
