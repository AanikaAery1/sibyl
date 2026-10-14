"""A fake OpenAI-compatible upstream (pure ASGI) with injectable faults.

``FakeUpstream.plan`` is a queue of ``Reply`` objects consumed one per request (the default
reply answers when it is empty): status, latency before headers, per-chunk delay, streaming,
429 with ``Retry-After``, a mid-stream abort, a redirect. Every request is recorded with its
headers and body so tests can assert what the gateway forwarded.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .native import native_reply


@dataclass
class Reply:
    status: int = 200
    delay_s: float = 0.0
    chunk_delay_s: float = 0.0
    chunks: int = 3
    retry_after: str | None = None
    abort_after_chunks: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] | None = None
    first_chunk_delay_s: float = 0.0
    events: list[dict[str, Any]] | None = None  # scripted SSE chunks (then [DONE])
    raw: bytes | None = None  # exact JSON body bytes (e.g. duplicate members)


@dataclass
class Seen:
    path: str
    headers: dict[str, str]
    body: dict[str, Any]
    query: str = ""


class FakeUpstream:
    def __init__(self) -> None:
        self.plan: deque[Reply] = deque()
        self.default = Reply()
        self.seen: list[Seen] = []

    def queue(self, *replies: Reply) -> None:
        self.plan.extend(replies)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                else:
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        doc = json.loads(body or b"{}")
        query = scope.get("query_string", b"").decode()
        self.seen.append(Seen(scope["path"], headers, doc, query))
        reply = self.plan.popleft() if self.plan else self.default
        if reply.delay_s:
            await asyncio.sleep(reply.delay_s)
        native = native_reply(scope["path"], query, doc, reply)
        if reply.status >= 300:
            await self._error(send, reply)
        elif native is not None:
            await self._native(send, reply, *native)
        elif scope["path"].endswith("/embeddings"):
            await self._json(
                send,
                reply,
                {
                    "object": "list",
                    "model": doc.get("model"),
                    "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
                    "usage": {"prompt_tokens": 3, "total_tokens": 3},
                },
            )
        elif doc.get("stream"):
            await self._stream(send, reply, doc)
        else:
            await self._json(send, reply, reply.body or _completion(doc))

    async def _error(self, send: Any, reply: Reply) -> None:
        headers = [(b"content-type", b"application/json")]
        if reply.retry_after:
            headers.append((b"retry-after", reply.retry_after.encode()))
        if 300 <= reply.status < 400:
            headers.append((b"location", b"http://169.254.169.254/latest/meta-data"))
        headers += [(k.encode(), v.encode()) for k, v in reply.headers.items()]
        payload = json.dumps({"error": {"message": "upstream says no", "type": "server_error"}})
        await send({"type": "http.response.start", "status": reply.status, "headers": headers})
        await send({"type": "http.response.body", "body": payload.encode()})

    async def _json(self, send: Any, reply: Reply, payload: dict[str, Any]) -> None:
        raw = reply.raw if reply.raw is not None else json.dumps(payload).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"set-cookie", b"track=1"),
            (b"x-sibyl-route", b"spoofed"),
        ]
        headers += [(k.encode(), v.encode()) for k, v in reply.headers.items()]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": raw})

    async def _native(self, send: Any, reply: Reply, kind: str, payload: Any) -> None:
        if kind == "json":
            await self._json(send, reply, payload)
            return
        content_type = b"text/event-stream" if kind == "sse" else b"application/json"
        headers = [(b"content-type", content_type), (b"x-sibyl-route", b"spoofed")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        for index, piece in enumerate(payload):
            if index and reply.chunk_delay_s:
                await asyncio.sleep(reply.chunk_delay_s)
            if reply.abort_after_chunks is not None and index >= reply.abort_after_chunks:
                raise RuntimeError("upstream aborts mid-stream")
            await _send_event(send, piece)
        await send({"type": "http.response.body", "body": b""})

    async def _scripted(self, send: Any, reply: Reply) -> None:
        await _scripted_events(send, reply)

    async def _stream(self, send: Any, reply: Reply, doc: dict[str, Any]) -> None:
        headers = [(b"content-type", b"text/event-stream"), (b"cache-control", b"no-cache")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        if reply.events is not None:
            await self._scripted(send, reply)
            return
        model = doc.get("model", "m")
        for index in range(reply.chunks):
            if index == 0 and reply.first_chunk_delay_s:
                await asyncio.sleep(reply.first_chunk_delay_s)
            elif index and reply.chunk_delay_s:
                await asyncio.sleep(reply.chunk_delay_s)
            if reply.abort_after_chunks is not None and index >= reply.abort_after_chunks:
                raise RuntimeError("upstream aborts mid-stream")
            chunk = {
                "id": "chatcmpl-fake",
                "object": "chat.completion.chunk",
                "model": model,
                "choices": [
                    {"index": 0, "delta": {"content": f"tok{index} "}, "finish_reason": None}
                ],
            }
            await send(
                {
                    "type": "http.response.body",
                    "more_body": True,
                    "body": f"data: {json.dumps(chunk)}\n\n".encode(),
                }
            )
        final = {
            "id": "chatcmpl-fake",
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": reply.chunks},
        }
        await send(
            {
                "type": "http.response.body",
                "more_body": True,
                "body": f"data: {json.dumps(final)}\n\ndata: [DONE]\n\n".encode(),
            }
        )
        await send({"type": "http.response.body", "body": b""})


async def _send_event(send: Any, payload: bytes) -> None:
    await send({"type": "http.response.body", "more_body": True, "body": payload})


async def _scripted_events(send: Any, reply: Reply) -> None:
    assert reply.events is not None
    for index, event in enumerate(reply.events):
        if index and reply.chunk_delay_s:
            await asyncio.sleep(reply.chunk_delay_s)
        if reply.abort_after_chunks is not None and index >= reply.abort_after_chunks:
            raise RuntimeError("upstream aborts mid-stream")
        await _send_event(send, f"data: {json.dumps(event)}\n\n".encode())
    await _send_event(send, b"data: [DONE]\n\n")
    await send({"type": "http.response.body", "body": b""})


def _completion(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "model": doc.get("model", "m"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1, "total_tokens": 6},
    }
