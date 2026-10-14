"""Silent refusals (ML.md §8.2 S-08, R37): a provider that answers 200 with refusal prose and
``finish_reason: stop`` is still counted as a refusal, so the R6 refusal share sees it.

The classifier is deliberately conservative: it reads the opening of a short, tool-free
assistant text only, so a genuine answer that merely mentions an inability is not a refusal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import pytest
from sibyl_gateway.proxy.meta import response_meta
from sibyl_gateway.proxy.refusal_text import is_refusal_text

from ..fakes.upstream import FakeUpstream, Reply
from ..support import GATEWAY_KEY
from .harness import make_gateway
from .native_support import assert_wire_valid

Up = tuple[FakeUpstream, str]


@pytest.mark.parametrize(
    "text",
    [
        "I'm sorry, but I can't help with that request.",
        "I\u2019m sorry, but I can\u2019t help with that.",
        "I cannot assist with that.",
        "Sorry, I can't provide that information.",
        "I apologize, but I am unable to comply with this request.",
        "Unfortunately, I'm not able to help with that.",
        "  I won't help with that request.",
        "I'm sorry, I must decline to answer that.",
    ],
)
def test_refusal_openings_are_recognised(text: str) -> None:
    assert is_refusal_text(text)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "The quote is ready for review and includes freight and taxes.",
        "Sibyl blocked the tool call `transfer_funds`: amount over the per-call limit",
        "Here is the summary. I can't stress enough how important the deadline is.",
        "Sure! I can help with that request.",
        # long answers are never classified, whatever their opening
        "I'm sorry, but I can't help with that directly. " + "Here is what you can do. " * 40,
    ],
)
def test_answers_are_not_refusals(text: str) -> None:
    assert not is_refusal_text(text)


@dataclass
class _Relayed:
    head: bytearray
    tail: bytearray = field(default_factory=bytearray)
    content_type: str = "application/json"
    content_encoding: str = ""
    streamed: bool = False


def _chat(content: str | None, *, tool_calls: bool = False, reason: str = "stop") -> bytes:
    message: dict[str, object] = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = [
            {"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}
        ]
    doc = {
        "id": "x",
        "model": "m",
        "choices": [{"index": 0, "message": message, "finish_reason": reason}],
    }
    return json.dumps(doc).encode()


def test_openai_prose_refusal_adds_the_refusal_reason() -> None:
    meta = response_meta(_Relayed(bytearray(_chat("I'm sorry, but I can't help with that."))))
    assert meta["finish_reasons"] == ["stop", "refusal"]


def test_openai_answer_and_tool_turns_keep_their_reasons() -> None:
    answer = response_meta(_Relayed(bytearray(_chat("The quote is ready."))))
    assert answer["finish_reasons"] == ["stop"]
    tools = response_meta(
        _Relayed(bytearray(_chat("I can't help with that.", tool_calls=True, reason="tool_calls")))
    )
    assert tools["finish_reasons"] == ["tool_calls"]


def test_openai_streamed_prose_refusal() -> None:
    chunks = [
        {"id": "x", "model": "m", "choices": [{"index": 0, "delta": {"content": "I'm sorry, "}}]},
        {"id": "x", "model": "m", "choices": [{"index": 0, "delta": {"content": "but I can't"}}]},
        {"id": "x", "model": "m", "choices": [{"index": 0, "delta": {"content": " help."}}]},
        {"id": "x", "model": "m", "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
    ]
    sse = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
    out = _Relayed(bytearray(sse.encode()), content_type="text/event-stream", streamed=True)
    assert response_meta(out)["finish_reasons"] == ["stop", "refusal"]


def test_anthropic_prose_refusal() -> None:
    doc = {
        "type": "message",
        "id": "msg_1",
        "model": "claude",
        "content": [{"type": "text", "text": "I can't help with that request."}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 3, "output_tokens": 9},
    }
    meta = response_meta(_Relayed(bytearray(json.dumps(doc).encode())), "anthropic")
    assert meta["finish_reasons"] == ["stop", "refusal"]


def test_gemini_prose_refusal() -> None:
    doc = {
        "candidates": [
            {
                "content": {"parts": [{"text": "I'm unable to help with that."}]},
                "finishReason": "STOP",
            }
        ],
        "modelVersion": "gemini",
    }
    meta = response_meta(_Relayed(bytearray(json.dumps(doc).encode())), "gemini")
    assert meta["finish_reasons"] == ["stop", "refusal"]


async def test_prose_refusal_reaches_gateway_telemetry(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    fake.queue(Reply(body=json.loads(_chat("I'm sorry, but I can't help with that request."))))
    async with gw.client() as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"model": "gpt-5.4", "messages": []},
            headers={
                "X-Sibyl-Key": GATEWAY_KEY,
                "X-Sibyl-Agent": "quote-assistant",
                "Authorization": "Bearer sk-x",
            },
        )
    assert resp.json()["choices"][0]["finish_reason"] == "stop"  # the agent sees it unchanged
    (event,) = gw.events()
    assert_wire_valid(event)
    assert event["attrs"]["finish_reasons"] == ["stop", "refusal"]
