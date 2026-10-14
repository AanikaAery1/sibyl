"""Action Gate for the native protocols (D50, ACTION-GATE.md §2.2): Anthropic ``tool_use``
content blocks and Gemini ``functionCall`` parts are decided by the shared evaluator before the
response is released, exactly as OpenAI ``tool_calls`` are (``actions.relay``).

Refusals keep each protocol's native shape so an unmodified SDK reads them as an ordinary
answer: Anthropic loses its ``tool_use`` blocks and gains a ``text`` block, ``stop_reason:
"end_turn"``; Gemini's ``functionCall`` parts become one ``text`` part, ``finishReason:
"STOP"``. A message (Anthropic) or candidate (Gemini) with any refused call loses *all* its
calls (parallel calls are atomic). ``X-Sibyl-Action`` / ``X-Sibyl-Held-Action-Id`` are set as
for OpenAI (an SSE comment when text already streamed).

A body that is not strict JSON (duplicate members: a lenient agent parser could read a
different value) blocks every call it proposes.

Streaming: text streams as it arrives. From the first tool-use event on, every event is held
(Anthropic content blocks are indexed, so releasing a later text block ahead of a held tool
block would corrupt the SDK's accumulator) until the turn ends (Anthropic ``message_delta``;
Gemini the finishing chunk) or the upstream ends; then held events are released byte for byte
or rewritten.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Final

import httpx
from sibyl_schemas.canonical import parse_json_strict

from .gate import GateResult, ProposedCall, as_dict, as_int, as_str
from .relay import (
    MAX_HELD_STREAM,
    Emit,
    GateContext,
    SseGate,
    Start,
    _data,
    _split_events,
    decide,
    gated_json,
    read_capped,
)

UNPARSEABLE: Final = object()  # an argument value ``parse_arguments`` always rejects
JsonGate = Callable[[GateContext, httpx.Response], Awaitable[tuple[bytes, GateResult]]]
SseFactory = Callable[[GateContext, Start, Emit], Any]


def _dumps(doc: Any) -> bytes:
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()


def _parse(raw: bytes) -> tuple[Any, bool]:
    """(document, ambiguous): strict I-JSON first; a lenient parse marks the body ambiguous."""
    try:
        return parse_json_strict(raw.decode("utf-8")), False
    except (ValueError, UnicodeDecodeError):
        pass
    try:
        return json.loads(raw), True
    except (ValueError, UnicodeDecodeError):
        return None, True


async def _gated(
    ctx: GateContext,
    response: httpx.Response,
    extract: Callable[[Any, bool], list[ProposedCall]],
    rewrite: Callable[[Any, GateResult], Any],
    oversize: dict[str, Any],
) -> tuple[bytes, GateResult]:
    raw = await read_capped(response)
    if raw is None:
        return _dumps(oversize), GateResult()  # never relayed unchecked
    doc, ambiguous = _parse(raw)
    calls = extract(doc, ambiguous) if doc is not None else []
    if not calls:
        return raw, GateResult()
    result = await decide(ctx, calls)
    if not result.refused_choices:
        return raw, result
    return _dumps(rewrite(doc, result)), result


_OVERSIZE_TEXT: Final = "The response was too large for the Action Gate to inspect."


# ------------------------------------------------------------------------------ Anthropic


def anthropic_calls(doc: Any, ambiguous: bool = False) -> list[ProposedCall]:
    """``tool_use`` blocks of a ``message`` (server-executed tool blocks already ran upstream
    and are not proposals the agent will execute)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("content"), list):
        return []
    out: list[ProposedCall] = []
    for position, block in enumerate(doc["content"]):
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            continue
        args = block.get("input")
        arguments = args if isinstance(args, dict) and not ambiguous else UNPARSEABLE
        call_id = block.get("id") if isinstance(block.get("id"), str) else None
        out.append(ProposedCall(0, position, call_id, as_str(block.get("name")), arguments))
    return out


def anthropic_rewrite(doc: dict[str, Any], result: GateResult) -> dict[str, Any]:
    content = [
        b for b in doc["content"] if not (isinstance(b, dict) and b.get("type") == "tool_use")
    ]
    content.append({"type": "text", "text": result.refusal(0)})
    return {**doc, "content": content, "stop_reason": "end_turn", "stop_sequence": None}


async def anthropic_gated_json(
    ctx: GateContext, response: httpx.Response
) -> tuple[bytes, GateResult]:
    oversize = {"type": "error", "error": {"type": "permission_error", "message": _OVERSIZE_TEXT}}
    return await _gated(ctx, response, anthropic_calls, anthropic_rewrite, oversize)


def _anthropic_sse(doc: dict[str, Any]) -> bytes:
    return f"event: {doc.get('type', 'message')}\ndata: ".encode() + _dumps(doc) + b"\n\n"


@dataclass
class _StreamCall:
    call_id: str | None
    name: str
    raw: str = ""
    broken: bool = False


@dataclass
class _HeldEvent:
    raw: bytes
    doc: dict[str, Any] | None


class _HoldingGate:
    """Shared streaming mechanics: defer the status line, queue neutral events, hold from the
    first tool-use event until the decision, then release or rewrite."""

    def __init__(self, ctx: GateContext, start: Start, emit: Emit) -> None:
        self.ctx = ctx
        self._start = start
        self._emit = emit
        self._buffer = bytearray()
        self._queued: list[bytes] = []
        self._held: list[_HeldEvent] = []
        self._held_bytes = 0
        self.holding = False
        self.started = False
        self.result: GateResult | None = None

    async def feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        for event in _split_events(self._buffer):
            await self._event(event, _doc(event))

    async def close(self) -> None:
        if self._buffer:
            event = bytes(self._buffer) + b"\n\n"
            self._buffer.clear()
            await self._event(event, _doc(event))
        if self.holding:
            await self._decide()
        await self._flush()

    async def _event(self, raw: bytes, doc: dict[str, Any] | None) -> None:
        raise NotImplementedError

    def _proposed(self) -> list[ProposedCall]:
        raise NotImplementedError

    async def _release_refused(self, result: GateResult) -> None:
        raise NotImplementedError

    def _reset(self) -> None:
        return None

    def hold(self, raw: bytes, doc: dict[str, Any] | None) -> None:
        self.holding = True
        self._held.append(_HeldEvent(raw, doc))
        self._held_bytes += len(raw)

    @property
    def over_cap(self) -> bool:
        return self._held_bytes > MAX_HELD_STREAM

    async def neutral(self, raw: bytes) -> None:
        if self.started:
            await self._emit(raw)
        else:
            self._queued.append(raw)

    async def text(self, raw: bytes) -> None:
        await self._flush()
        await self._emit(raw)

    async def _flush(self, extra: list[tuple[str, str]] | None = None) -> None:
        if not self.started:
            self.started = True
            await self._start(extra or [])
        for raw in self._queued:
            await self._emit(raw)
        self._queued.clear()

    async def _decide(self) -> None:
        result = await decide(self.ctx, self._proposed())
        self.result = _merge(self.result, result)
        await self._flush(result.headers())
        if result.refused_choices:
            await self._release_refused(result)
        else:
            for held in self._held:
                await self._emit(held.raw)
        headers = result.headers()
        if headers:
            await self._emit((": " + " ".join(f"{k}={v}" for k, v in headers) + "\n\n").encode())
        self._held.clear()
        self._held_bytes = 0
        self.holding = False
        self._reset()


def _merge(previous: GateResult | None, result: GateResult) -> GateResult:
    if previous is None:
        return result
    return GateResult([*previous.verdicts, *result.verdicts])


def _doc(event: bytes) -> dict[str, Any] | None:
    data = _data(event)
    if not data:
        return None
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


_ANTHROPIC_NEUTRAL: Final = frozenset({"message_start", "ping", "content_block_start"})


class AnthropicSseGate(_HoldingGate):
    def __init__(self, ctx: GateContext, start: Start, emit: Emit) -> None:
        super().__init__(ctx, start, emit)
        self._calls: dict[int, _StreamCall] = {}

    def _reset(self) -> None:
        self._calls = {}

    async def _event(self, raw: bytes, doc: dict[str, Any] | None) -> None:
        kind = doc.get("type") if doc is not None else None
        block = as_dict(doc.get("content_block")) if doc is not None else {}
        if not self.holding and not (
            kind == "content_block_start" and block.get("type") == "tool_use"
        ):
            if kind in _ANTHROPIC_NEUTRAL or doc is None:
                await self.neutral(raw)
            else:
                await self.text(raw)
            return
        self.hold(raw, doc)
        assert doc is not None
        index = as_int(doc.get("index"), -1)
        if kind == "content_block_start" and block.get("type") == "tool_use":
            call_id = block.get("id") if isinstance(block.get("id"), str) else None
            self._calls[index] = _StreamCall(call_id, as_str(block.get("name")))
        elif kind == "content_block_delta" and index in self._calls:
            delta = as_dict(doc.get("delta"))
            partial = delta.get("partial_json")
            if delta.get("type") == "input_json_delta" and isinstance(partial, str):
                self._calls[index].raw += partial
            else:
                self._calls[index].broken = True
        if self.over_cap and self._calls:
            next(iter(self._calls.values())).broken = True
        if kind == "message_delta":
            await self._decide()

    def _proposed(self) -> list[ProposedCall]:
        out: list[ProposedCall] = []
        for index, call in sorted(self._calls.items()):
            arguments: Any = UNPARSEABLE if call.broken else (call.raw or "{}")
            out.append(ProposedCall(0, index, call.call_id, call.name, arguments))
        return out

    async def _release_refused(self, result: GateResult) -> None:
        first = min(self._calls) if self._calls else 0
        synthesized = False

        async def refusal() -> None:
            nonlocal synthesized
            if synthesized:
                return
            synthesized = True
            text = result.refusal(0)
            for doc in (
                {
                    "type": "content_block_start",
                    "index": first,
                    "content_block": {"type": "text", "text": ""},
                },
                {
                    "type": "content_block_delta",
                    "index": first,
                    "delta": {"type": "text_delta", "text": text},
                },
                {"type": "content_block_stop", "index": first},
            ):
                await self._emit(_anthropic_sse(doc))

        for held in self._held:
            doc = held.doc
            kind = doc.get("type") if doc is not None else None
            if kind in ("content_block_start", "content_block_delta", "content_block_stop"):
                if doc is not None and as_int(doc.get("index"), first) >= first:
                    continue  # every block from the first tool use on is withdrawn
            if kind == "message_delta" and doc is not None:
                await refusal()
                delta = {**as_dict(doc.get("delta")), "stop_reason": "end_turn"}
                delta["stop_sequence"] = None
                await self._emit(_anthropic_sse({**doc, "delta": delta}))
                continue
            await self._emit(held.raw)
        await refusal()


# ------------------------------------------------------------------------------ Gemini


def _candidates(doc: Any) -> list[tuple[int, dict[str, Any]]]:
    if not isinstance(doc, dict) or not isinstance(doc.get("candidates"), list):
        return []
    return [
        (as_int(c.get("index"), position), c)
        for position, c in enumerate(doc["candidates"])
        if isinstance(c, dict)
    ]


def _parts(candidate: dict[str, Any]) -> list[Any]:
    parts = as_dict(candidate.get("content")).get("parts")
    return parts if isinstance(parts, list) else []


def _is_call(part: Any) -> bool:
    return isinstance(part, dict) and "functionCall" in part


def gemini_calls(doc: Any, ambiguous: bool = False) -> list[ProposedCall]:
    """``functionCall`` parts of one response, or of every chunk of a JSON-array stream."""
    chunks = doc if isinstance(doc, list) else [doc]
    counters: dict[int, int] = {}
    out: list[ProposedCall] = []
    for chunk in chunks:
        for index, candidate in _candidates(chunk):
            for part in _parts(candidate):
                if not _is_call(part):
                    continue
                fn = part["functionCall"]
                fn = fn if isinstance(fn, dict) else {}
                args = fn.get("args", {})
                arguments = args if isinstance(args, dict) and not ambiguous else UNPARSEABLE
                call_id = fn.get("id") if isinstance(fn.get("id"), str) else None
                position = counters.get(index, 0)
                counters[index] = position + 1
                out.append(
                    ProposedCall(index, position, call_id, as_str(fn.get("name")), arguments)
                )
    return out


def gemini_rewrite_chunk(
    chunk: dict[str, Any], result: GateResult, placed: set[int]
) -> dict[str, Any]:
    """Refused candidates: the first ``functionCall`` (across chunks: ``placed``) becomes the
    refusal text, later ones are dropped, ``finishReason`` becomes ``STOP``."""
    refused = result.refused_choices
    candidates: list[Any] = []
    for index, candidate in _candidates(chunk):
        if index not in refused:
            candidates.append(candidate)
            continue
        parts: list[Any] = []
        for part in _parts(candidate):
            if not _is_call(part):
                parts.append(part)
            elif index not in placed:
                placed.add(index)
                parts.append({"text": result.refusal(index)})
        content = {**as_dict(candidate.get("content")), "parts": parts}
        rewritten = {**candidate, "content": content}
        if "finishReason" in candidate:
            rewritten["finishReason"] = "STOP"
        candidates.append(rewritten)
    return {**chunk, "candidates": candidates}


def gemini_rewrite(doc: Any, result: GateResult) -> Any:
    placed: set[int] = set()
    if isinstance(doc, list):
        return [gemini_rewrite_chunk(c, result, placed) if isinstance(c, dict) else c for c in doc]
    return gemini_rewrite_chunk(doc, result, placed)


async def gemini_gated_json(ctx: GateContext, response: httpx.Response) -> tuple[bytes, GateResult]:
    oversize = {"error": {"code": 403, "message": _OVERSIZE_TEXT, "status": "PERMISSION_DENIED"}}
    return await _gated(ctx, response, gemini_calls, gemini_rewrite, oversize)


class GeminiSseGate(_HoldingGate):
    def __init__(self, ctx: GateContext, start: Start, emit: Emit) -> None:
        super().__init__(ctx, start, emit)
        self._pending: dict[int, bool] = {}  # candidate index -> finished
        self._broken = False

    def _reset(self) -> None:
        self._pending = {}
        self._broken = False

    async def _event(self, raw: bytes, doc: dict[str, Any] | None) -> None:
        candidates = _candidates(doc)
        calling = {i for i, c in candidates if any(_is_call(p) for p in _parts(c))}
        if not self.holding and not calling:
            text = any(
                isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"]
                for _, c in candidates
                for p in _parts(c)
            )
            await (self.text(raw) if text else self.neutral(raw))
            return
        self.hold(raw, doc)
        for index in calling:
            self._pending.setdefault(index, False)
        for index, candidate in candidates:
            if index in self._pending and candidate.get("finishReason"):
                self._pending[index] = True
        self._broken = self._broken or self.over_cap
        if self._pending and all(self._pending.values()):
            await self._decide()

    def _proposed(self) -> list[ProposedCall]:
        calls = gemini_calls([h.doc for h in self._held if h.doc is not None])
        if self._broken:
            calls = [
                ProposedCall(c.choice, c.position, c.call_id, c.name, UNPARSEABLE) for c in calls
            ]
        return calls

    async def _release_refused(self, result: GateResult) -> None:
        placed: set[int] = set()
        for held in self._held:
            if held.doc is None:
                await self._emit(held.raw)
                continue
            await self._emit(
                b"data: " + _dumps(gemini_rewrite_chunk(held.doc, result, placed)) + b"\n\n"
            )


# ------------------------------------------------------------------------------ selection


@dataclass(frozen=True)
class _Gates:
    json: JsonGate
    sse: SseFactory


_GATES: Final = {
    "openai": _Gates(gated_json, SseGate),
    "anthropic": _Gates(anthropic_gated_json, AnthropicSseGate),
    "gemini": _Gates(gemini_gated_json, GeminiSseGate),
}


def gate_for(protocol: str) -> tuple[JsonGate, SseFactory]:
    gates = _GATES[protocol]
    return gates.json, gates.sse


__all__ = [
    "AnthropicSseGate",
    "GeminiSseGate",
    "anthropic_calls",
    "anthropic_gated_json",
    "gate_for",
    "gemini_calls",
    "gemini_gated_json",
    "gemini_rewrite",
]
