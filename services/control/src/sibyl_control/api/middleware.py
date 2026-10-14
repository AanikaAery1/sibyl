"""Pure-ASGI request context middleware (streaming/SSE safe).

Per request: a safe ``X-Request-Id`` (echoed or minted), the real client IP (``X-Forwarded-For``
believed only from ``SIBYL_TRUSTED_PROXIES``, security M4), refusal of credentials in the query
string (400 ``credential_in_url``, never logged), security headers (API.md §2.9), the API version
header, rate-limit headers and the audit receipt that handlers place on ``request.state``.

Object rules fail closed (security M3): when a guarded handler answers 2xx without evaluating
every object rule its contract declares, the response is replaced by a 500 problem before any of
it is sent, and the miss is logged as an error.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Awaitable, Callable, MutableMapping, Sequence
from typing import Any
from urllib.parse import parse_qsl
from uuid import uuid4

from ..core.apikeys import reject_credentials_in_url
from ..core.audit import RECEIPT_HEADER
from ..core.clientip import Network, client_ip
from ..core.problems import PROBLEM_MEDIA_TYPE, ProblemError

log = logging.getLogger("sibyl.api")
AUTH_CONTEXT_STATE = "auth_context"  # set by deps.guard
CLIENT_IP_STATE = "client_ip"

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SECURITY_HEADERS: dict[str, str] = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
}


def _header(scope: Scope, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return str(value.decode("latin-1"))
    return None


def _headers(scope: Scope, name: bytes) -> list[str]:
    return [v.decode("latin-1") for k, v in scope.get("headers", []) if k.lower() == name]


def _unchecked_rules(state: dict[str, Any]) -> frozenset[str]:
    ctx = state.get(AUTH_CONTEXT_STATE)
    if ctx is None:
        return frozenset()
    missing: frozenset[str] = ctx.unchecked_rules()
    return missing


class RequestContextMiddleware:
    def __init__(
        self, app: ASGIApp, *, api_version: str, trusted_proxies: Sequence[Network] = ()
    ) -> None:
        self.app = app
        self.api_version = api_version
        self.trusted_proxies = tuple(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        incoming = _header(scope, b"x-request-id")
        request_id = incoming if incoming and _SAFE_REQUEST_ID.match(incoming) else str(uuid4())
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        peer = scope.get("client")
        state[CLIENT_IP_STATE] = client_ip(
            peer[0] if peer else None, _headers(scope, b"x-forwarded-for"), self.trusted_proxies
        )
        query = scope.get("query_string", b"").decode("latin-1")
        try:
            reject_credentials_in_url(parse_qsl(query, keep_blank_values=True))
        except ProblemError as err:
            await self._send_problem(send, err, scope["path"], request_id)
            return
        blocked = False

        async def send_with_headers(message: Message) -> None:
            nonlocal blocked
            if blocked:
                return  # the handler's body is dropped; the 500 was already sent
            if message["type"] == "http.response.start" and 200 <= message["status"] < 300:
                missing = _unchecked_rules(state)
                if missing:
                    blocked = True
                    ctx = state[AUTH_CONTEXT_STATE]
                    log.error(
                        "object rules not evaluated; response withheld",
                        extra={"operation_id": ctx.op.operation_id, "rules": sorted(missing)},
                    )
                    err = ProblemError("internal_error")
                    await self._send_problem(send, err, scope["path"], request_id, state)
                    return
            if message["type"] == "http.response.start":
                message["headers"] = self._decorate(message, state, request_id)
            await send(message)

        await self.app(scope, receive, send_with_headers)

    def _decorate(
        self, message: Message, state: dict[str, Any], request_id: str
    ) -> list[tuple[bytes, bytes]]:
        headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
        present = {k.lower() for k, _ in headers}

        def add(name: str, value: str) -> None:
            if name.encode() not in present:
                headers.append((name.encode(), value.encode("latin-1")))

        add("x-request-id", request_id)
        for name, value in SECURITY_HEADERS.items():
            add(name, value)
        add("cache-control", "no-store")
        add("x-sibyl-api-version", self.api_version)
        for name, value in (state.get("rate_headers") or {}).items():
            add(name.lower(), value)
        receipt = state.get("audit_receipt")
        if receipt and 200 <= message["status"] < 300:
            add(RECEIPT_HEADER.lower(), receipt)
        return headers

    async def _send_problem(
        self,
        send: Send,
        err: ProblemError,
        path: str,
        rid: str,
        state: dict[str, Any] | None = None,
    ) -> None:
        body = json.dumps(err.to_body(instance=path, request_id=rid)).encode()
        start: Message = {
            "type": "http.response.start",
            "status": err.status,
            "headers": [(b"content-type", PROBLEM_MEDIA_TYPE.encode())],
        }
        kept = {"rate_headers": state.get("rate_headers")} if state else {}
        start["headers"] = self._decorate(start, kept, rid)
        await send(start)
        await send({"type": "http.response.body", "body": body})
