"""Upstream attempts and the unbuffered relay (API.md §3.5 step 5).

Targets are tried in order, each up to ``max_attempts`` times, and only **before the first
byte**: connect errors, timeouts, 429 and 5xx move on to the next attempt. Once an upstream
status line is accepted the response is relayed chunk by chunk as it arrives (``aiter_raw``,
no decoding, no buffering) and nothing is retried. A bounded copy of the body is kept for
usage extraction and capture, processed only after the last byte has been sent.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..actions.gate import GateResult, ToolCallGate
from ..actions.native import gate_for
from ..actions.relay import GateContext
from ..policy.view import CredentialRef, PolicyView, Serve, UpstreamTarget
from .http import Headers, Send, downstream_headers, encode
from .meta import CAPTURE_HEAD_BYTES
from .meta import response_meta as response_meta
from .protocols import OPENAI, Header, Route, WireProtocol
from .ratelimit import ratelimit_from_headers
from .ssrf import SsrfBlocked
from .upstream import UpstreamClient

TAIL_BYTES = 16 * 1024


@dataclass
class ProxyCall:
    operation: str
    path_suffix: str
    body: bytes
    parsed: dict[str, Any]
    model: str | None
    client_credential: Header | None  # the caller's provider credential header
    passthrough_headers: list[tuple[str, str]]
    request_id: str = ""
    route: Route | None = None  # None = OpenAI chat/embeddings by ``path_suffix``
    query: str = ""  # upstream query string (Gemini ``alt=sse`` only)
    on_behalf_of: dict[str, str] | None = None  # X-Sibyl-On-Behalf-Of, for held actions

    @property
    def protocol(self) -> WireProtocol:
        return self.route.protocol if self.route is not None else OPENAI


@dataclass
class Outcome:
    committed: bool = False
    http_status: int | None = None
    error_code: str | None = None
    error_type: str | None = None
    target: UpstreamTarget | None = None
    attempts: int = 0
    ttfb_s: float | None = None
    streamed: bool = False
    content_type: str = ""
    content_encoding: str = ""
    head: bytearray = field(default_factory=bytearray, repr=False)
    tail: bytearray = field(default_factory=bytearray, repr=False)
    upstream_retry_after: str | None = None
    ratelimit: dict[str, int] | None = None  # the last upstream response's rate-limit state
    ratelimit_target: UpstreamTarget | None = None  # ... and the target that reported it
    skipped: list[str] = field(default_factory=list)
    actions: GateResult | None = None  # Action Gate verdicts (agents with action policies)


def body_for(call: ProxyCall, target: UpstreamTarget, strip_tools: bool) -> bytes:
    """Byte-for-byte passthrough unless the route changes the model or strips tools. Gemini
    carries the model in the URL, so only stripping changes its body."""
    protocol = call.protocol
    model_change = protocol.model_in_body and target.model != call.model
    if not model_change and not strip_tools:
        return call.body
    doc = dict(call.parsed)
    if protocol.model_in_body:
        doc["model"] = target.model
    if strip_tools:
        for name in protocol.tool_keys:
            doc.pop(name, None)
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()


def _url(call: ProxyCall, target: UpstreamTarget) -> str | None:
    if call.route is None:
        return target.base_url.rstrip("/") + call.path_suffix
    return call.protocol.url(target.base_url, call.route, target.model, call.query)


def _auth(view: PolicyView, call: ProxyCall, target: UpstreamTarget) -> Header | None:
    if target.credential == "passthrough":
        return call.client_credential
    assert isinstance(target.credential, CredentialRef)
    handle = view.credential(target.credential)
    if handle is None:
        return None
    try:
        secret = handle.reveal().decode("utf-8", errors="strict")
    except (RuntimeError, UnicodeDecodeError):  # zeroised under us (contracts-v1.1) or garbage
        return None
    if not secret:
        return None
    return call.protocol.vaulted(secret)


class Forwarder:
    def __init__(
        self, view: PolicyView, upstream: UpstreamClient, gate: ToolCallGate | None = None
    ) -> None:
        self._view = view
        self._upstream = upstream
        self._gate = gate

    async def forward(
        self,
        call: ProxyCall,
        serve: Serve,
        send: Send,
        sibyl_headers: list[tuple[str, str]],
        started: float,
    ) -> Outcome:
        out = Outcome()
        for target in serve.targets:
            if target.dialect != call.protocol.dialect:
                out.skipped.append("dialect_unsupported")  # routing already filters these
                continue
            if not self._upstream.allowed(target.base_url):
                out.skipped.append("base_url_not_allowlisted")
                continue
            url = _url(call, target)
            if url is None:
                out.skipped.append("model_not_addressable")
                continue
            auth = _auth(self._view, call, target)
            if auth is None:
                out.skipped.append("no_credential")
                continue
            content = body_for(call, target, serve.strip_tools)
            headers = [*call.passthrough_headers, auth]
            for _ in range(target.max_attempts):
                out.attempts += 1
                response = await self._attempt(out, target, url, headers, content)
                if response is None:
                    continue
                if self._gated(call, serve, response):
                    assert self._gate is not None
                    ctx = GateContext(self._gate, serve, call.request_id, call.on_behalf_of)
                    await self._relay_gated(
                        out, response, target, send, sibyl_headers, started, ctx, call
                    )
                else:
                    await self._relay(out, response, target, send, sibyl_headers, started)
                if call.route is not None and call.route.stream:
                    out.streamed = True  # Gemini streamGenerateContent, SSE or JSON array
                return out
        return out

    def _gated(self, call: ProxyCall, serve: Serve, response: httpx.Response) -> bool:
        return (
            self._gate is not None
            and serve.actions is not None
            and call.operation in call.protocol.gated_operations
            and 200 <= response.status_code < 300
        )

    async def _relay_gated(
        self,
        out: Outcome,
        response: httpx.Response,
        target: UpstreamTarget,
        send: Send,
        sibyl_headers: list[tuple[str, str]],
        started: float,
        ctx: GateContext,
        call: ProxyCall,
    ) -> None:
        """Action Gate relay (``actions.relay`` / ``actions.native``): the body is decoded, so
        the upstream's content-encoding and length are dropped; tool calls are decided before
        release, in the calling protocol's own shapes."""
        gated_json, sse_gate = gate_for(call.protocol.name)
        out.committed, out.target = True, target
        out.http_status = response.status_code
        out.error_code = out.error_type = None
        out.content_type = response.headers.get("content-type", "")
        out.content_encoding = ""
        out.streamed = "text/event-stream" in out.content_type
        base: Headers = [
            (k, v)
            for k, v in downstream_headers(response.headers.multi_items())
            if k not in (b"content-length", b"content-encoding")
        ]
        base.extend(encode(retarget(sibyl_headers, target, out.attempts)))

        async def start(extra: list[tuple[str, str]], length: int | None = None) -> None:
            headers = [*base, *encode(extra)]
            if length is not None:
                headers.append((b"content-length", str(length).encode()))
            await send(
                {"type": "http.response.start", "status": out.http_status, "headers": headers}
            )
            out.ttfb_s = time.perf_counter() - started

        async def emit(chunk: bytes) -> None:
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
            _capture(out, chunk)

        try:
            if not out.streamed:
                body, result = await gated_json(ctx, response)
                out.actions = result if result.verdicts else None
                await start(result.headers(), len(body))
                await send({"type": "http.response.body", "body": body, "more_body": False})
                _capture(out, body)
                return
            gate = sse_gate(ctx, start, emit)
            try:
                async for chunk in response.aiter_bytes():
                    await gate.feed(chunk)
            except httpx.HTTPError as exc:
                out.error_type = type(exc).__name__  # upstream broke: decide what was held
            await gate.close()
            out.actions = gate.result
        finally:
            await response.aclose()
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    async def _attempt(
        self,
        out: Outcome,
        target: UpstreamTarget,
        url: str,
        headers: list[tuple[str, str]],
        content: bytes,
    ) -> httpx.Response | None:
        try:
            response = await self._upstream.send(self._upstream.build(url, headers, content))
        except httpx.TimeoutException:
            out.error_code, out.error_type = "upstream_timeout", "timeout"
            return None
        except (httpx.TransportError, SsrfBlocked) as exc:
            out.error_code, out.error_type = "upstream_error", type(exc).__name__
            return None
        status = response.status_code
        out.ratelimit = ratelimit_from_headers(response.headers)
        out.ratelimit_target = target
        if 300 <= status < 400:  # redirects are never followed nor relayed (SSRF, T1)
            await response.aclose()
            out.http_status, out.error_type, out.error_code = status, str(status), "upstream_error"
            return None
        if status == 429 or status >= 500:
            out.upstream_retry_after = response.headers.get("retry-after")
            await response.aclose()
            out.http_status = status
            out.error_type = str(status)
            out.error_code = "upstream_rate_limited" if status == 429 else "upstream_error"
            return None
        return response

    async def _relay(
        self,
        out: Outcome,
        response: httpx.Response,
        target: UpstreamTarget,
        send: Send,
        sibyl_headers: list[tuple[str, str]],
        started: float,
    ) -> None:
        out.committed, out.target = True, target
        out.http_status = response.status_code
        out.error_code = out.error_type = None
        out.content_type = response.headers.get("content-type", "")
        out.content_encoding = response.headers.get("content-encoding", "")
        out.streamed = "text/event-stream" in out.content_type
        if response.status_code >= 400:
            out.error_type = str(response.status_code)
        headers: Headers = downstream_headers(response.headers.multi_items())
        headers.extend(encode(retarget(sibyl_headers, target, out.attempts)))
        try:
            await send(
                {"type": "http.response.start", "status": response.status_code, "headers": headers}
            )
            out.ttfb_s = time.perf_counter() - started
            async for chunk in response.aiter_raw():
                if not chunk:
                    continue
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
                if len(out.head) < CAPTURE_HEAD_BYTES:
                    out.head.extend(chunk[: CAPTURE_HEAD_BYTES - len(out.head)])
                out.tail.extend(chunk)
                if len(out.tail) > TAIL_BYTES:
                    del out.tail[: len(out.tail) - TAIL_BYTES]
        except httpx.HTTPError as exc:
            out.error_type = type(exc).__name__  # upstream broke mid-stream: end the body
        finally:
            await response.aclose()
        await send({"type": "http.response.body", "body": b"", "more_body": False})


def _capture(out: Outcome, chunk: bytes) -> None:
    if len(out.head) < CAPTURE_HEAD_BYTES:
        out.head.extend(chunk[: CAPTURE_HEAD_BYTES - len(out.head)])
    out.tail.extend(chunk)
    if len(out.tail) > TAIL_BYTES:
        del out.tail[: len(out.tail) - TAIL_BYTES]


def retarget(
    sibyl_headers: list[tuple[str, str]], target: UpstreamTarget, attempts: int
) -> list[tuple[str, str]]:
    """``X-Sibyl-Route/Provider/Model`` name what actually served (API §3.4)."""
    actual = {
        "x-sibyl-route": target.route,
        "x-sibyl-provider": target.provider_slug,
        "x-sibyl-model": target.model,
    }
    out = [(k, actual.get(k.lower(), v)) for k, v in sibyl_headers]
    if attempts > 1:
        out.append(("x-sibyl-fallback-attempts", str(attempts - 1)))
    return out
