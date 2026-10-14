"""Telemetry metadata read from a relayed body (identity encoding only), per wire protocol.

Read after the last byte went out, from the bounded head/tail copies the relay kept. Each
protocol's stop reason is normalised to one vocabulary so health and drift features are
protocol-neutral (the rollup matches ``length``/``max_tokens``, ``content_filter``/``refusal``/
``safety`` and ``tool_calls``): ``stop``, ``length``, ``tool_calls``, ``refusal``, ``safety``,
``content_filter``, else the provider's value lower-cased. The agent always sees the native
value; only telemetry is normalised. A tool-free assistant turn that is a prose refusal
(HTTP 200, ``stop``; see ``refusal_text``) adds ``refusal`` to the reasons, as a structured
refusal does.

``system_fingerprint`` (frozen attr, WAVE3) comes from OpenAI's field of that name. Anthropic
and Gemini return no equivalent (Gemini's ``modelVersion`` is the served model and is recorded
as ``response_model``), so the attr is absent for them.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Final, Protocol

from .refusal_text import is_refusal_text

MAX_FINGERPRINT: Final = 128
CAPTURE_HEAD_BYTES: Final = 256 * 1024

_ANTHROPIC_STOP: Final = {
    "end_turn": "stop",
    "stop_sequence": "stop",
    "max_tokens": "length",
    "model_context_window_exceeded": "length",
    "tool_use": "tool_calls",
    "refusal": "refusal",
}
_GEMINI_FINISH: Final = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "safety",
    "RECITATION": "safety",
    "BLOCKLIST": "safety",
    "PROHIBITED_CONTENT": "safety",
    "SPII": "safety",
    "IMAGE_SAFETY": "safety",
}


class Relayed(Protocol):
    head: bytearray
    tail: bytearray
    content_type: str
    content_encoding: str
    streamed: bool


def response_meta(out: Relayed, dialect: str = "openai_compatible") -> dict[str, Any]:
    """Model, id, usage, finish reasons and fingerprint from the relayed body."""
    if out.content_encoding not in ("", "identity"):
        return {}
    docs = list(_documents(out))
    if dialect == "anthropic":
        meta = _anthropic(docs)
    elif dialect == "gemini":
        meta = _gemini(docs)
    else:
        meta = _openai(docs)
    return {k: v for k, v in meta.items() if v is not None and v != []}


def _documents(out: Relayed) -> Iterable[dict[str, Any]]:
    if "text/event-stream" in out.content_type:
        seen: set[bytes] = set()
        for source in (bytes(out.head), bytes(out.tail)):
            for line in source.replace(b"\r\n", b"\n").split(b"\n"):
                data = line[5:].strip() if line.startswith(b"data:") else b""
                if data in (b"", b"[DONE]") or data in seen:
                    continue  # head and tail may overlap on a short stream
                seen.add(data)
                doc = _loads(data)
                if isinstance(doc, dict):
                    yield doc
        return
    if len(out.head) >= CAPTURE_HEAD_BYTES:
        return  # truncated copy: no metadata rather than a guess
    doc = _loads(bytes(out.head))
    if isinstance(doc, dict):
        yield doc
    elif isinstance(doc, list):  # Gemini streamGenerateContent without alt=sse
        yield from (d for d in doc if isinstance(d, dict))


def _loads(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def _add(reasons: list[str], value: str | None) -> None:
    if value and value not in reasons:
        reasons.append(value)


def _int(raw: dict[str, Any], key: str) -> int | None:
    value = raw.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _usage(pairs: dict[str, int | None]) -> dict[str, Any] | None:
    out: dict[str, Any] = {k: v for k, v in pairs.items() if v is not None}
    return {"source": "provider", **out} if out else None


# ------------------------------------------------------------------------------ OpenAI


def _openai(docs: list[dict[str, Any]]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    reasons: list[str] = []
    turns = _Turns()
    for doc in docs:
        meta.setdefault("response_model", doc.get("model"))
        meta.setdefault("response_id", doc.get("id"))
        fingerprint = doc.get("system_fingerprint")
        if isinstance(fingerprint, str) and fingerprint:
            meta.setdefault("system_fingerprint", fingerprint[:MAX_FINGERPRINT])
        usage = doc.get("usage")
        if isinstance(usage, dict):
            meta["usage"] = _openai_usage(usage)
        for choice in doc.get("choices") or ():
            if not isinstance(choice, dict):
                continue
            reason = choice.get("finish_reason")
            _add(reasons, reason if isinstance(reason, str) else None)
            for part in ("message", "delta"):
                body = choice.get(part)
                if isinstance(body, dict) and isinstance(body.get("refusal"), str):
                    _add(reasons, "refusal")
                if isinstance(body, dict):
                    key = choice.get("index", 0)
                    turns.text(key, _openai_text(body.get("content")))
                    if body.get("tool_calls") or body.get("function_call"):
                        turns.tool(key)
    if turns.refused():
        _add(reasons, "refusal")
    meta["finish_reasons"] = reasons
    return meta


def _openai_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # content parts
        return "".join(
            p["text"] for p in content if isinstance(p, dict) and isinstance(p.get("text"), str)
        )
    return ""


class _Turns:
    """Assistant text per choice/candidate, for prose refusals (``refusal_text``)."""

    def __init__(self) -> None:
        self._text: dict[Any, list[str]] = {}
        self._tools: set[Any] = set()

    def text(self, key: Any, value: Any) -> None:
        if isinstance(value, str) and value:
            self._text.setdefault(key, []).append(value)

    def tool(self, key: Any) -> None:
        self._tools.add(key)

    def refused(self) -> bool:
        return any(
            key not in self._tools and is_refusal_text("".join(parts))
            for key, parts in self._text.items()
        )


def _openai_usage(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"source": "provider"}
    for src, dst in (("prompt_tokens", "input_tokens"), ("completion_tokens", "output_tokens")):
        value = _int(raw, src)
        if value is not None:
            out[dst] = value
    details = raw.get("prompt_tokens_details")
    if isinstance(details, dict) and isinstance(details.get("cached_tokens"), int):
        out["cached_input_tokens"] = details["cached_tokens"]
    return out


# ------------------------------------------------------------------------------ Anthropic


def _anthropic(docs: list[dict[str, Any]]) -> dict[str, Any]:
    """A ``message`` document, or the stream: ``message_start`` (id, model, input usage) and
    ``message_delta`` (stop reason, cumulative output tokens)."""
    meta: dict[str, Any] = {}
    reasons: list[str] = []
    usage: dict[str, int | None] = {}
    turns = _Turns()
    for doc in docs:
        kind = doc.get("type")
        message = doc.get("message") if kind == "message_start" else doc
        if isinstance(message, dict) and message.get("type") == "message":
            meta.setdefault("response_model", message.get("model"))
            meta.setdefault("response_id", message.get("id"))
            _anthropic_usage(usage, message.get("usage"))
            _anthropic_stop(reasons, message.get("stop_reason"))
            for block in message.get("content") or ():
                _anthropic_block(turns, block)
        if kind == "message_delta":
            delta = doc.get("delta")
            _anthropic_stop(reasons, delta.get("stop_reason") if isinstance(delta, dict) else None)
            _anthropic_usage(usage, doc.get("usage"))
        elif kind == "content_block_start":
            _anthropic_block(turns, doc.get("content_block"))
        elif kind == "content_block_delta":
            delta = doc.get("delta")
            if isinstance(delta, dict) and delta.get("type") == "text_delta":
                turns.text(0, delta.get("text"))
    if turns.refused():
        _add(reasons, "refusal")
    meta["usage"] = _usage(usage)
    meta["finish_reasons"] = reasons
    return meta


def _anthropic_block(turns: _Turns, block: Any) -> None:
    if not isinstance(block, dict):
        return
    if block.get("type") == "text":
        turns.text(0, block.get("text"))
    elif block.get("type") in ("tool_use", "server_tool_use"):
        turns.tool(0)


def _anthropic_usage(usage: dict[str, int | None], raw: Any) -> None:
    if not isinstance(raw, dict):
        return
    for src, dst in (
        ("input_tokens", "input_tokens"),
        ("output_tokens", "output_tokens"),
        ("cache_read_input_tokens", "cached_input_tokens"),
        ("cache_creation_input_tokens", "cache_creation_input_tokens"),
    ):
        value = _int(raw, src)
        if value is not None:
            usage[dst] = value  # later events carry cumulative counts


def _anthropic_stop(reasons: list[str], raw: Any) -> None:
    if isinstance(raw, str):
        _add(reasons, _ANTHROPIC_STOP.get(raw, raw.lower()))


# ------------------------------------------------------------------------------ Gemini


def _gemini(docs: list[dict[str, Any]]) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    reasons: list[str] = []
    calls = False
    usage: dict[str, int | None] = {}
    turns = _Turns()
    for doc in docs:
        meta.setdefault("response_model", doc.get("modelVersion"))
        meta.setdefault("response_id", doc.get("responseId"))
        raw = doc.get("usageMetadata")
        if isinstance(raw, dict):
            for src, dst in (
                ("promptTokenCount", "input_tokens"),
                ("candidatesTokenCount", "output_tokens"),
                ("cachedContentTokenCount", "cached_input_tokens"),
                ("thoughtsTokenCount", "reasoning_tokens"),
            ):
                value = _int(raw, src)
                if value is not None:
                    usage[dst] = value
        feedback = doc.get("promptFeedback")
        if isinstance(feedback, dict) and feedback.get("blockReason"):
            _add(reasons, "safety")
        for candidate in doc.get("candidates") or ():
            if not isinstance(candidate, dict):
                continue
            finish = candidate.get("finishReason")
            if isinstance(finish, str):
                _add(reasons, _GEMINI_FINISH.get(finish, finish.lower()))
            content = candidate.get("content")
            parts = content.get("parts") if isinstance(content, dict) else None
            key = candidate.get("index", 0)
            for p in parts or ():
                if isinstance(p, dict) and "functionCall" in p:
                    calls = True
                    turns.tool(key)
                elif isinstance(p, dict) and not p.get("thought"):
                    turns.text(key, p.get("text"))
    if calls:
        _add(reasons, "tool_calls")
    if turns.refused():
        _add(reasons, "refusal")
    meta["usage"] = _usage(usage)
    meta["finish_reasons"] = reasons
    return meta
