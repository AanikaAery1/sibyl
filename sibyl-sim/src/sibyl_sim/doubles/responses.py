"""OpenAI-compatible response bodies: chat completions (plain and SSE chunks), embeddings,
models and error envelopes. Pure functions of the request and the engine's decision."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterator, Mapping
from typing import Any

from sibyl_sim.doubles.engine import Decision

REFUSAL = "I'm sorry, but I can't help with that request."
MALFORMED_ARGS = '{"order_id": "A-1", "items": [{"sku": "PAL-40", "qty": '


def error_body(status: int, code: str, message: str | None = None) -> dict[str, Any]:
    kind = {
        429: "rate_limit_error",
        404: "invalid_request_error",
        400: "invalid_request_error",
        401: "authentication_error",
    }.get(status, "server_error" if status >= 500 else "invalid_request_error")
    return {
        "error": {
            "message": message or f"sim double returned {status} ({code})",
            "type": kind,
            "code": code,
            "param": None,
        }
    }


def _last_user_text(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    for message in reversed(messages):
        if isinstance(message, Mapping) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                return " ".join(
                    str(part.get("text", "")) for part in content if isinstance(part, Mapping)
                )
    return ""


def estimate_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4))


def _tool_name(request: Mapping[str, Any], preferred: str | None) -> str:
    if preferred:
        return preferred
    tools = request.get("tools") or []
    first = tools[0] if tools else {}
    return str((first.get("function") or {}).get("name") or first.get("name") or "tool")


def _arguments(decision: Decision, prompt: str) -> str:
    """The proposed call's arguments: one of the knob's list, picked by the prompt's hash."""
    choices = decision.knobs.tool_loop.arguments
    if not choices:
        return '{"order_id": "A-1"}'
    digest = hashlib.sha256(prompt.encode()).digest()
    return choices[int.from_bytes(digest[:4], "big") % len(choices)]


def chat_message(
    double: str, request: Mapping[str, Any], decision: Decision
) -> tuple[dict[str, Any], str]:
    """(assistant message, finish_reason) for a successful decision."""
    prompt = _last_user_text(request.get("messages"))
    text = (
        f"[{double}] reply #{decision.seq}: acknowledged '{prompt[:80]}'. "
        + ("The quote is ready for review and includes freight and taxes. " * 3).strip()
    )
    behaviour = decision.behaviour
    if behaviour == "refusal":
        return {"role": "assistant", "content": REFUSAL}, "stop"
    if behaviour == "truncation":
        cut = max(1, int(len(text) * decision.knobs.truncation_fraction))
        return {"role": "assistant", "content": text[:cut]}, "length"
    if behaviour in ("tool_loop", "schema_failure"):
        name = _tool_name(request, decision.knobs.tool_loop.tool_name)
        args = MALFORMED_ARGS if behaviour == "schema_failure" else _arguments(decision, prompt)
        call = {
            "id": f"call_{decision.seq:06d}",
            "type": "function",
            "function": {"name": name, "arguments": args},
        }
        return {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
    return {"role": "assistant", "content": text}, "stop"


def usage_for(
    request: Mapping[str, Any], message: Mapping[str, Any], multiplier: float
) -> dict[str, int]:
    prompt = json.dumps(request.get("messages", ""), default=str)
    out = message.get("content") or json.dumps(message.get("tool_calls", ""))
    tokens_in = estimate_tokens(prompt)
    tokens_out = max(1, round(estimate_tokens(str(out)) * multiplier))
    return {
        "prompt_tokens": tokens_in,
        "completion_tokens": tokens_out,
        "total_tokens": tokens_in + tokens_out,
    }


def completion(
    double: str, model: str, request: Mapping[str, Any], decision: Decision, created: int
) -> dict[str, Any]:
    message, finish = chat_message(double, request, decision)
    body: dict[str, Any] = {
        "id": f"chatcmpl-{double}-{decision.seq:08d}",
        "object": "chat.completion",
        "created": created,
        "model": decision.knobs.served_model or model,
        "choices": [{"index": 0, "message": message, "finish_reason": finish, "logprobs": None}],
        "usage": usage_for(request, message, decision.knobs.token_multiplier),
    }
    if decision.knobs.system_fingerprint:
        body["system_fingerprint"] = decision.knobs.system_fingerprint
    return body


def stream_chunks(body: Mapping[str, Any], include_usage: bool) -> Iterator[dict[str, Any]]:
    """Split a completion into OpenAI `chat.completion.chunk`s (role, content pieces, finish)."""
    base = {
        "id": body["id"],
        "object": "chat.completion.chunk",
        "created": body["created"],
        "model": body["model"],
    }
    if body.get("system_fingerprint"):
        base["system_fingerprint"] = body["system_fingerprint"]
    choice = body["choices"][0]
    message = choice["message"]
    yield {**base, "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}]}
    if message.get("tool_calls"):
        calls = [{"index": n, **call} for n, call in enumerate(message["tool_calls"])]
        yield {
            **base,
            "choices": [{"index": 0, "delta": {"tool_calls": calls}, "finish_reason": None}],
        }
    else:
        content = message.get("content") or ""
        for start in range(0, len(content), 24):
            yield {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": content[start : start + 24]},
                        "finish_reason": None,
                    }
                ],
            }
    yield {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": choice["finish_reason"]}]}
    if include_usage:
        yield {**base, "choices": [], "usage": body["usage"]}


def embedding_vector(text: str, dimensions: int) -> list[float]:
    out: list[float] = []
    counter = 0
    while len(out) < dimensions:
        digest = hashlib.sha256(f"{counter}:{text}".encode()).digest()
        out.extend((byte - 127.5) / 127.5 for byte in digest)
        counter += 1
    return [round(v, 6) for v in out[:dimensions]]


def embeddings(model: str, request: Mapping[str, Any], multiplier: float) -> dict[str, Any]:
    raw = request.get("input", "")
    inputs = raw if isinstance(raw, list) else [raw]
    dims = request.get("dimensions") or 8
    data = [
        {"object": "embedding", "index": n, "embedding": embedding_vector(str(item), dims)}
        for n, item in enumerate(inputs)
    ]
    tokens = max(1, round(sum(estimate_tokens(str(i)) for i in inputs) * multiplier))
    return {
        "object": "list",
        "data": data,
        "model": model,
        "usage": {"prompt_tokens": tokens, "total_tokens": tokens},
    }


def models(owner: str, names: tuple[str, ...], created: int) -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {"id": name, "object": "model", "created": created, "owned_by": owner} for name in names
        ],
    }
