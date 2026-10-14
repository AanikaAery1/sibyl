"""Gated relays for agents with action policies (chat completions, 2xx only).

Non-streaming: the body is read (decoded, capped), its tool calls decided, and either the
original bytes or the refusal rewrite is sent with ``X-Sibyl-Action`` headers.

Streaming (SSE): text deltas still stream; only events carrying ``tool_calls`` /
``function_call`` deltas are held. The status line is deferred until the first text delta or
the decision, so a pure tool-call turn carries ``X-Sibyl-Action`` as a real header; when text
already went out the outcome travels as an SSE comment (``: x-sibyl-action=...``). The decision
is applied when every choice with tool calls has finished (or the upstream ends): allowed
calls are released byte for byte in order, refused choices get a synthesized refusal content
delta with ``finish_reason: "stop"``. ``[DONE]`` is held behind the decision.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from ..policy.view import Serve
from .gate import (
    GateResult,
    ProposedCall,
    ToolCallGate,
    as_dict,
    as_int,
    calls_in_message,
    proposed_calls,
    rewrite_completion,
)

MAX_GATED_BODY: Final = 16 * 1024 * 1024
MAX_HELD_STREAM: Final = 4 * 1024 * 1024
Emit = Callable[[bytes], Awaitable[None]]
Start = Callable[[list[tuple[str, str]]], Awaitable[None]]


@dataclass
class GateContext:
    gate: ToolCallGate
    serve: Serve
    request_id: str
    on_behalf_of: dict[str, str] | None = None


async def decide(ctx: GateContext, calls: list[ProposedCall]) -> GateResult:
    assert ctx.serve.actions is not None
    return await ctx.gate.decide(
        ctx.serve.actions,
        calls,
        request_id=ctx.request_id,
        tenant_id=ctx.serve.tenant_id,
        agent_id=str(ctx.serve.agent_id),
        policy_state=ctx.serve.policy.state,
        on_behalf_of=ctx.on_behalf_of,
    )


async def read_capped(response: httpx.Response) -> bytes | None:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > MAX_GATED_BODY:
            return None
    return bytes(body)


async def gated_json(ctx: GateContext, response: httpx.Response) -> tuple[bytes, GateResult]:
    """(body to send, result). An over-cap body is refused rather than relayed unchecked."""
    raw = await read_capped(response)
    if raw is None:
        refusal = {
            "error": {
                "message": "The response was too large for the Action Gate to inspect.",
                "type": "permission_error",
                "param": None,
                "code": "sibyl_action_blocked",
            }
        }
        result = GateResult()
        return json.dumps(refusal).encode(), result
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return raw, GateResult()
    calls = proposed_calls(doc)
    if not calls:
        return raw, GateResult()
    result = await decide(ctx, calls)
    if not result.refused_choices:
        return raw, result
    rewritten = rewrite_completion(doc, result)
    return json.dumps(rewritten, separators=(",", ":"), ensure_ascii=False).encode(), result


# ------------------------------------------------------------------------------- SSE


@dataclass
class _Held:
    raw: bytes
    doc: dict[str, Any] | None  # None for [DONE]


@dataclass
class _Choice:
    calls: dict[int, dict[str, Any]] = field(default_factory=dict)
    finished: bool = False


def _split_events(buffer: bytearray) -> list[bytes]:
    """Complete SSE events (terminated by a blank line, LF or CRLF), removed from ``buffer``."""
    events: list[bytes] = []
    while True:
        found = [(at, len(sep)) for sep in (b"\n\n", b"\r\n\r\n") if (at := buffer.find(sep)) != -1]
        if not found:
            return events
        at, size = min(found)
        events.append(bytes(buffer[: at + size]))
        del buffer[: at + size]


def _data(event: bytes) -> bytes | None:
    lines = [ln for ln in event.splitlines() if ln.startswith(b"data:")]
    if not lines:
        return None
    return b"\n".join(ln[5:].strip() for ln in lines)


class SseGate:
    """Feed decoded upstream bytes; emits what may go downstream, in order."""

    def __init__(self, ctx: GateContext, start: Start, emit: Emit) -> None:
        self.ctx = ctx
        self._start = start
        self._emit = emit
        self._buffer = bytearray()
        self._queued: list[bytes] = []  # neutral events before the status line
        self._held: list[_Held] = []
        self._held_bytes = 0
        self._choices: dict[int, _Choice] = {}
        self.started = False
        self.result: GateResult | None = None
        self._template: dict[str, Any] = {}

    async def feed(self, chunk: bytes) -> None:
        self._buffer.extend(chunk)
        for event in _split_events(self._buffer):
            await self._event(event)

    async def close(self) -> None:
        if self._buffer:
            await self._event(bytes(self._buffer) + b"\n\n")
            self._buffer.clear()
        if self._held or self._choices:
            await self._decide()
        await self._flush_start()
        for raw in self._queued:
            await self._emit(raw)
        self._queued.clear()

    async def _event(self, event: bytes) -> None:
        data = _data(event)
        if data == b"[DONE]":
            if self._pending():
                self._hold(event, None)
            else:
                await self._pass(event)
            return
        doc: Any = None
        if data:
            try:
                doc = json.loads(data)
            except (ValueError, UnicodeDecodeError):
                doc = None
        if not isinstance(doc, dict) or not isinstance(doc.get("choices"), list):
            await self._neutral(event)
            return
        for key in ("id", "object", "created", "model", "system_fingerprint"):
            if key in doc:
                self._template.setdefault(key, doc[key])
        tool_event = False
        text_event = False
        for position, choice in enumerate(doc["choices"]):
            if not isinstance(choice, dict):
                continue
            index = as_int(choice.get("index"), position)
            delta = as_dict(choice.get("delta"))
            if delta.get("tool_calls") or delta.get("function_call"):
                tool_event = True
                self._accumulate(index, delta)
            if isinstance(delta.get("content"), str) and delta["content"]:
                text_event = True
            if choice.get("finish_reason") is not None and index in self._choices:
                self._choices[index].finished = True
                tool_event = True  # the finish of a tool-call choice waits for the decision
        if tool_event:
            self._hold(event, doc)
            if self._choices and all(c.finished for c in self._choices.values()):
                await self._decide()
        elif text_event:
            await self._flush_start()
            for raw in self._queued:
                await self._emit(raw)
            self._queued.clear()
            await self._emit(event)
        else:
            await self._neutral(event)

    def _pending(self) -> bool:
        return bool(self._held)

    def _hold(self, event: bytes, doc: dict[str, Any] | None) -> None:
        self._held.append(_Held(event, doc))
        self._held_bytes += len(event)

    async def _neutral(self, event: bytes) -> None:
        if self.started:
            await self._emit(event)
        else:
            self._queued.append(event)

    async def _pass(self, event: bytes) -> None:
        await self._flush_start()
        for raw in self._queued:
            await self._emit(raw)
        self._queued.clear()
        await self._emit(event)

    def _accumulate(self, index: int, delta: dict[str, Any]) -> None:
        state = self._choices.setdefault(index, _Choice())
        entries = delta.get("tool_calls") or []
        legacy = delta.get("function_call")
        if isinstance(legacy, dict):
            entries = [*entries, {"index": -1, "function": legacy}]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            slot = as_int(entry.get("index"), 0)
            call = state.calls.setdefault(slot, {"id": None, "name": "", "arguments": ""})
            if isinstance(entry.get("id"), str):
                call["id"] = entry["id"]
            fn = as_dict(entry.get("function"))
            if isinstance(fn.get("name"), str):
                call["name"] += fn["name"]
            if isinstance(fn.get("arguments"), str):
                call["arguments"] += fn["arguments"]
        if self._held_bytes > MAX_HELD_STREAM:  # checked per accumulated delta
            # too much held: an unparseable sentinel call forces a block for this choice
            state.calls.setdefault(10**6, {"id": None, "name": "", "arguments": 0})

    def _proposed(self) -> list[ProposedCall]:
        out: list[ProposedCall] = []
        for index, state in sorted(self._choices.items()):
            message = {
                "tool_calls": [
                    {"id": c["id"], "function": {"name": c["name"], "arguments": c["arguments"]}}
                    for _, c in sorted(state.calls.items())
                ]
            }
            out.extend(calls_in_message(index, message))
        return out

    async def _decide(self) -> None:
        result = await decide(self.ctx, self._proposed())
        self.result = result
        refused = result.refused_choices
        await self._flush_start(result.headers())
        for raw in self._queued:
            await self._emit(raw)
        self._queued.clear()
        done: list[bytes] = []
        for held in self._held:
            if held.doc is None:
                done.append(held.raw)
                continue
            if not refused:
                await self._emit(held.raw)
                continue
            kept = [
                c
                for p, c in enumerate(held.doc["choices"])
                if as_int(as_dict(c).get("index"), p) not in refused
            ]
            if kept:
                await self._emit(_sse({**held.doc, "choices": kept}))
        for index in sorted(refused):
            chunk = {
                **self._template,
                "choices": [
                    {
                        "index": index,
                        "delta": {"role": "assistant", "content": result.refusal(index)},
                        "finish_reason": "stop",
                    }
                ],
            }
            await self._emit(_sse(chunk))
        headers = result.headers()
        if headers:
            note = " ".join(f"{k}={v}" for k, v in headers)
            await self._emit(f": {note}\n\n".encode())
        for raw in done:
            await self._emit(raw)
        self._held.clear()
        self._held_bytes = 0
        self._choices.clear()

    async def _flush_start(self, extra: list[tuple[str, str]] | None = None) -> None:
        if not self.started:
            self.started = True
            await self._start(extra or [])


def _sse(doc: dict[str, Any]) -> bytes:
    return b"data: " + json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode() + b"\n\n"
