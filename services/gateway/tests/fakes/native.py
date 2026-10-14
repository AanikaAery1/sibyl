"""Anthropic Messages and Gemini ``generateContent`` doubles for ``FakeUpstream`` (no network).

Default replies are a one-block text answer with usage; ``Reply.body`` replaces the JSON body and
``Reply.events`` scripts the stream (Anthropic: each event dict is sent with its ``event:`` line;
Gemini: each dict is one ``GenerateContentResponse`` chunk, as SSE with ``alt=sse`` or as one
JSON array without it). Builders here are shared by the native proxy and Action Gate tests.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

ANTHROPIC_MESSAGES = "/anthropic/v1/messages"
ANTHROPIC_COUNT = "/anthropic/v1/messages/count_tokens"
GEMINI_PREFIX = "/gemini/v1beta/models/"


# ------------------------------------------------------------------------------ Anthropic


def anthropic_message(
    *blocks: dict[str, Any], model: str = "claude-sonnet-5-20261001", stop: str = "end_turn"
) -> dict[str, Any]:
    return {
        "id": "msg_fake",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": list(blocks) or [{"type": "text", "text": "hello"}],
        "stop_reason": stop,
        "stop_sequence": None,
        "usage": {
            "input_tokens": 11,
            "output_tokens": 4,
            "cache_read_input_tokens": 3,
            "cache_creation_input_tokens": 0,
        },
    }


def tool_use(name: str, args: dict[str, Any], call_id: str = "toolu_1") -> dict[str, Any]:
    return {"type": "tool_use", "id": call_id, "name": name, "input": args}


def anthropic_stream(
    *,
    text: str | None = "Hello there",
    tools: Sequence[tuple[str, str, str]] = (),
    model: str = "claude-sonnet-5-20261001",
    stop: str | None = None,
) -> list[dict[str, Any]]:
    """message_start, an optional text block, then one tool_use block per (id, name, raw json)
    split across two ``input_json_delta`` events, message_delta and message_stop."""
    start = anthropic_message(model=model)
    start["content"], start["stop_reason"] = [], None
    start["usage"] = {"input_tokens": 21, "output_tokens": 1}
    events: list[dict[str, Any]] = [{"type": "message_start", "message": start}, {"type": "ping"}]
    index = 0
    if text is not None:
        events += [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": text},
            },
            {"type": "content_block_stop", "index": 0},
        ]
        index = 1
    for call_id, name, raw in tools:
        half = len(raw) // 2
        events += [
            {
                "type": "content_block_start",
                "index": index,
                "content_block": {"type": "tool_use", "id": call_id, "name": name, "input": {}},
            },
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": raw[:half]},
            },
            {
                "type": "content_block_delta",
                "index": index,
                "delta": {"type": "input_json_delta", "partial_json": raw[half:]},
            },
            {"type": "content_block_stop", "index": index},
        ]
        index += 1
    reason = stop or ("tool_use" if tools else "end_turn")
    events += [
        {
            "type": "message_delta",
            "delta": {"stop_reason": reason, "stop_sequence": None},
            "usage": {"output_tokens": 17},
        },
        {"type": "message_stop"},
    ]
    return events


def anthropic_sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in events)


def parse_anthropic_sse(raw: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = [ln[5:].strip() for ln in block.split(b"\n") if ln.startswith(b"data:")]
        if data:
            out.append(json.loads(b"\n".join(data)))
    return out


# ------------------------------------------------------------------------------ Gemini


def gemini_response(
    *parts: dict[str, Any],
    finish: str = "STOP",
    model_version: str = "gemini-2.5-pro-002",
    usage: bool = True,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "candidates": [
            {
                "content": {"role": "model", "parts": list(parts) or [{"text": "hello"}]},
                "finishReason": finish,
                "index": 0,
            }
        ],
        "modelVersion": model_version,
        "responseId": "resp-fake",
    }
    if usage:
        doc["usageMetadata"] = {
            "promptTokenCount": 13,
            "candidatesTokenCount": 5,
            "totalTokenCount": 18,
            "cachedContentTokenCount": 2,
            "thoughtsTokenCount": 7,
        }
    return doc


def function_call(name: str, args: dict[str, Any], call_id: str | None = None) -> dict[str, Any]:
    call: dict[str, Any] = {"name": name, "args": args}
    if call_id:
        call["id"] = call_id
    return {"functionCall": call}


def gemini_chunk(*parts: dict[str, Any], finish: str | None = None) -> dict[str, Any]:
    candidate: dict[str, Any] = {"content": {"role": "model", "parts": list(parts)}, "index": 0}
    if finish:
        candidate["finishReason"] = finish
    return {"candidates": [candidate], "modelVersion": "gemini-2.5-pro-002", "responseId": "r1"}


def gemini_stream(
    *, text: str | None = "Hel", calls: Sequence[dict[str, Any]] = ()
) -> list[dict[str, Any]]:
    chunks: list[dict[str, Any]] = []
    if text is not None:
        chunks += [gemini_chunk({"text": text}), gemini_chunk({"text": "lo"})]
    if calls:
        chunks.append(gemini_chunk(*calls))
    last = gemini_chunk({"text": ""}, finish="STOP")
    last["usageMetadata"] = {
        "promptTokenCount": 9,
        "candidatesTokenCount": 6,
        "totalTokenCount": 15,
    }
    chunks.append(last)
    return chunks


def gemini_sse(chunks: list[dict[str, Any]]) -> bytes:
    return b"".join(f"data: {json.dumps(c)}\r\n\r\n".encode() for c in chunks)


def parse_gemini_sse(raw: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for block in raw.replace(b"\r\n", b"\n").split(b"\n\n"):
        data = [ln[5:].strip() for ln in block.split(b"\n") if ln.startswith(b"data:")]
        if data:
            out.append(json.loads(b"\n".join(data)))
    return out


# ------------------------------------------------------------------------------ server side


def native_reply(path: str, query: str, doc: dict[str, Any], reply: Any) -> tuple[str, Any] | None:
    """(kind, payload) for a native path, or None for the OpenAI paths.

    kind: ``json`` (payload is a document), ``sse`` (payload is a list of event byte strings,
    sent one per body message), ``array`` (one byte string)."""
    if path.endswith("/v1/messages/count_tokens"):
        return "json", reply.body or {"input_tokens": 42}
    if path.endswith("/v1/messages"):
        if doc.get("stream"):
            events = (
                reply.events
                if reply.events is not None
                else anthropic_stream(model=str(doc.get("model", "claude")))
            )
            return "sse", [anthropic_sse([e]) for e in events]
        return "json", reply.body or anthropic_message(model=str(doc.get("model", "claude")))
    if ":streamGenerateContent" in path:
        chunks = reply.events if reply.events is not None else gemini_stream()
        if "alt=sse" in query:
            return "sse", [gemini_sse([c]) for c in chunks]
        return "array", [json.dumps(chunks).encode()]
    if ":generateContent" in path:
        return "json", reply.body or gemini_response()
    return None
