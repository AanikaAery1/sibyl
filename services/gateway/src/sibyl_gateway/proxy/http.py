"""ASGI plumbing for the data plane: header handling and the OpenAI error envelope (§3.3-3.5)."""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from typing import Any, Literal

from ..policy.view import ERROR_MAP, RETRY_AFTER_S

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
Headers = list[tuple[bytes, bytes]]

SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
# Never forwarded upstream: hop-by-hop, credentials we manage, cookies, Sibyl's own headers.
_DROP_UPSTREAM = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-connection",
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "api-key",
        "cookie",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "x-request-id",
    }
)
# Never relayed back from upstream.
_DROP_DOWNSTREAM = frozenset(
    {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "set-cookie",
        "server",
        "trailer",
        "upgrade",
        "proxy-authenticate",
        "alt-svc",
    }
)

_MESSAGES: dict[str, str] = {
    "sibyl_header_not_allowed": "A request header is not accepted by the gateway.",
    "sibyl_bad_request": "The request could not be routed as sent.",
    "sibyl_key_invalid": "Invalid Sibyl API key.",
    "sibyl_agent_mismatch": "This key is bound to a different agent.",
    "sibyl_scope_missing": "This key may not call the gateway.",
    "sibyl_agent_killed": "This agent is stopped by a kill switch.",
    "sibyl_agent_quarantined": "This agent is quarantined.",
    "sibyl_policy_blocked": "The agent's identity policy blocks this request.",
    "sibyl_model_not_allowed": "The requested model is not allowed for this agent.",
    "sibyl_agent_unknown": "The agent could not be resolved.",
    "sibyl_rate_limited": "Rate limit exceeded.",
    "sibyl_inflight_limit": "Too many concurrent requests for this agent.",
    "sibyl_budget_exhausted": "The agent's monthly budget is exhausted.",
    "upstream_rate_limited": "The upstream provider is rate limiting.",
    "upstream_error": "The upstream provider failed.",
    "sibyl_policy_expired": "Policy is expired and this agent fails closed.",
    "sibyl_no_snapshot": "The gateway has no policy yet.",
    "sibyl_agent_handed_off": "This agent's work is handed off to people.",
    "sibyl_agent_queued": "This agent only queues work right now.",
    "sibyl_breaker_open": "The upstream circuit is open.",
    "upstream_timeout": "The upstream provider did not answer in time.",
}
_AUTH_CODES = frozenset({"sibyl_key_invalid", "sibyl_key_revoked", "sibyl_key_expired"})


def header_map(scope: Scope) -> dict[str, str]:
    """Lower-cased request headers; repeated headers are comma-joined (RFC 9110 §5.3)."""
    out: dict[str, str] = {}
    for raw_key, raw_value in scope.get("headers", ()):
        key = raw_key.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        out[key] = f"{out[key]}, {value}" if key in out else value
    return out


def upstream_headers(scope: Scope) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for raw_key, raw_value in scope.get("headers", ()):
        key = raw_key.decode("latin-1").lower()
        if key in _DROP_UPSTREAM or key.startswith("x-sibyl-"):
            continue
        out.append((key, raw_value.decode("latin-1")))
    return out


def downstream_headers(items: Iterable[tuple[str, str]]) -> Headers:
    out: Headers = []
    for key, value in items:
        lower = key.lower()
        if lower in _DROP_DOWNSTREAM or lower.startswith("x-sibyl-"):
            continue
        out.append((lower.encode("latin-1"), value.encode("latin-1")))
    return out


def encode(headers: Iterable[tuple[str, str]]) -> Headers:
    return [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in headers]


ErrorStyle = Literal["openai", "anthropic", "gemini"]
# google.rpc.Code names for the HTTP statuses the gateway renders (Gemini error envelope).
_GRPC_STATUS = {
    400: "INVALID_ARGUMENT",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    429: "RESOURCE_EXHAUSTED",
    502: "UNAVAILABLE",
    503: "UNAVAILABLE",
    504: "DEADLINE_EXCEEDED",
}


def error_body(code: str, style: ErrorStyle = "openai") -> tuple[int, bytes]:
    """The calling protocol's own error envelope, so an unmodified SDK raises its usual typed
    error. All 401 causes render the identical body (STRIDE T6). The Sibyl code always travels
    in ``X-Sibyl-Error``; the OpenAI envelope also carries it as ``error.code``."""
    shown = "sibyl_key_invalid" if code in _AUTH_CODES else code
    status, kind = ERROR_MAP[shown]
    message = _MESSAGES.get(shown, "Request failed.")
    body: dict[str, Any]
    if style == "anthropic":
        body = {"type": "error", "error": {"type": kind, "message": message}}
    elif style == "gemini":
        grpc = _GRPC_STATUS.get(status, "INTERNAL")
        body = {"error": {"code": status, "message": message, "status": grpc}}
    else:
        body = {"error": {"message": message, "type": kind, "param": None, "code": shown}}
    return status, json.dumps(body, separators=(",", ":")).encode()


async def send_error(
    send: Send,
    code: str,
    extra: Iterable[tuple[str, str]] = (),
    retry_after_s: int | None = None,
    style: ErrorStyle = "openai",
) -> int:
    status, body = error_body(code, style)
    shown = "sibyl_key_invalid" if code in _AUTH_CODES else code
    headers = [
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
        ("x-sibyl-error", shown),
        ("x-sibyl-origin", "gateway"),
        *extra,
    ]
    retry = retry_after_s if retry_after_s is not None else RETRY_AFTER_S.get(code)
    if retry is not None and not any(k.lower() == "retry-after" for k, _ in headers):
        headers.append(("retry-after", str(retry)))
    await send({"type": "http.response.start", "status": status, "headers": encode(headers)})
    await send({"type": "http.response.body", "body": body})
    return status


async def send_json(
    send: Send, status: int, payload: Any, extra: Iterable[tuple[str, str]] = ()
) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode()
    headers = [("content-type", "application/json"), ("content-length", str(len(body))), *extra]
    await send({"type": "http.response.start", "status": status, "headers": encode(headers)})
    await send({"type": "http.response.body", "body": body})


class BodyTooLarge(Exception):
    pass


async def read_body(receive: Receive, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            raise ConnectionResetError("client went away")
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            raise BodyTooLarge
        chunks.append(chunk)
        if not message.get("more_body", False):
            return b"".join(chunks)
