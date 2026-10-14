"""`sentinel-stub`: the language-model provider double Sibyl Sentinel talks to in the harness.

Routes on the doubles app (https, the dev CA), one per wire dialect Sentinel speaks, so a
tenant's Sentinel `base_url` of `https://127.0.0.1:<doubles port>/sentinel-stub` works for every
provider exactly as the vendor URL would:

    POST /sentinel-stub/v1/messages                               Anthropic Messages
    POST /sentinel-stub/v1/chat/completions                       OpenAI Chat Completions
    POST /sentinel-stub/v1beta/models/{model}:generateContent     Gemini

Two modes:

* **scripted** (default, CI): a schema-valid structured answer from `sentinel_answers`,
  deterministic per seed; usage is counted from the prompt and answer lengths.
* **proxy** (`SIBYL_SENTINEL_EVAL=1`, real-provider evaluation): a request whose key is not a
  sim key (`sk-sim-...`) is forwarded unchanged to the vendor's API host; the vendor's answer is
  returned as is. The key passes through in memory only; it is never recorded or logged.

Either way every request body is **recorded** (never its headers or key: a 16-hex SHA-256
fingerprint of the key attributes it to a tenant), with the task, the answer and the latency,
so the oracle can check what Sentinel sent: `GET /_sim/doubles/sentinel-stub/requests` on the
sim control port, or `live_stub(<doubles port>)` in-process (the oracle has no sim-control URL).
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from sibyl_sim.doubles import sentinel_answers as sa

NAME: Final = "sentinel-stub"
SIM_KEY_PREFIX: Final = "sk-sim-"
MAX_RECORDS: Final = 1000
UPSTREAM: Final[dict[str, str]] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "gemini": "https://generativelanguage.googleapis.com",
}
FORWARD_HEADERS: Final = frozenset(
    {"content-type", "accept", "x-api-key", "anthropic-version", "anthropic-beta"}
    | {"authorization", "x-goog-api-key"}
)
PROXY_TIMEOUT_S: Final = 120.0
EVAL_ENV: Final = "SIBYL_SENTINEL_EVAL"
EVAL_CA_ENV: Final = "SIBYL_SENTINEL_EVAL_CA_FILE"


def key_fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def sim_key(tenant: str) -> str:
    """The dev-only Sentinel key a persona configures in scripted mode (not a secret)."""
    return f"{SIM_KEY_PREFIX}sentinel-{tenant}-not-a-secret"


@dataclass
class SentinelStub:
    seed: int
    clock: Callable[[], float] = time.time
    proxy: bool = False
    upstream: dict[str, str] = field(default_factory=lambda: dict(UPSTREAM))
    upstream_transport: httpx.AsyncBaseTransport | None = None
    ca_file: str | None = None
    records: list[dict[str, Any]] = field(default_factory=list)
    seq: int = 0

    @classmethod
    def from_env(cls, seed: int, clock: Callable[[], float] = time.time) -> SentinelStub:
        return cls(
            seed,
            clock,
            proxy=os.environ.get(EVAL_ENV) == "1",
            ca_file=os.environ.get(EVAL_CA_ENV) or None,
        )

    @property
    def mode(self) -> str:
        return "proxy" if self.proxy else "scripted"

    def reset(self) -> None:
        self.records.clear()
        self.seq = 0

    def snapshot(self, since: float | None = None) -> dict[str, Any]:
        rows = [r for r in self.records if since is None or r["wall"] >= since]
        return {"name": NAME, "mode": self.mode, "requests": rows}

    def _record(self, row: dict[str, Any]) -> None:
        self.records.append(row)
        del self.records[:-MAX_RECORDS]

    # ------------------------------------------------------------------ one request

    async def handle(
        self, dialect: sa.Dialect, request: Request, path_model: str | None
    ) -> Response:
        started = time.monotonic()
        key = _credential(request)
        if key is None:
            return JSONResponse(_error(dialect, 401, "missing API key"), 401)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse(_error(dialect, 400, "invalid JSON"), 400)
        if not isinstance(body, dict):
            return JSONResponse(_error(dialect, 400, "JSON object expected"), 400)
        self.seq += 1
        row: dict[str, Any] = {
            "seq": self.seq,
            "wall": self.clock(),
            "dialect": dialect,
            "path": request.url.path,
            "key_fp": key_fingerprint(key),
            "model": sa.model_of(dialect, body, path_model),
            "body": body,
        }
        try:
            row["task"] = sa.detect_task(dialect, body).value
        except sa.StubRequestError:
            row["task"] = None
        if self.proxy and not key.startswith(SIM_KEY_PREFIX):
            response = await self._forward(dialect, request, body, row)
        else:
            response = self._scripted(dialect, body, row)
        row["latency_ms"] = round((time.monotonic() - started) * 1000, 1)
        self._record(row)
        return response

    def _scripted(self, dialect: sa.Dialect, body: dict[str, Any], row: dict[str, Any]) -> Response:
        row["mode"] = "scripted"
        try:
            task = sa.detect_task(dialect, body)
            out = sa.answer(task, sa.agent_data(dialect, body), self.seed)
        except sa.StubRequestError as exc:
            row |= {"status": 400, "error": str(exc)}
            return JSONResponse(_error(dialect, 400, str(exc)), 400)
        text = json.dumps(out, sort_keys=True)
        usage = sa.usage_for(sa.prompt_text(dialect, body), text)
        row |= {"status": 200, "answer": out, "usage": list(usage)}
        return JSONResponse(sa.wire_response(dialect, row["model"], text, usage, self.seq))

    async def _forward(
        self, dialect: sa.Dialect, request: Request, body: dict[str, Any], row: dict[str, Any]
    ) -> Response:
        row["mode"] = "proxy"
        suffix = request.url.path.removeprefix(f"/{NAME}")
        url = self.upstream[dialect] + suffix
        headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
        try:
            async with httpx.AsyncClient(
                transport=self.upstream_transport,
                verify=self._verify(),
                timeout=PROXY_TIMEOUT_S,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                upstream = await client.post(url, json=body, headers=headers)
        except httpx.HTTPError as exc:
            row |= {"status": 502, "error": type(exc).__name__}
            return JSONResponse(_error(dialect, 502, "upstream unreachable"), 502)
        row["status"] = upstream.status_code
        try:
            payload = upstream.json()
        except ValueError:
            payload = None
        if upstream.status_code == 200 and isinstance(payload, dict):
            text = _answer_text(dialect, payload)
            row["answer_text"] = text[:20_000]
            try:
                row["answer"] = json.loads(text)
            except ValueError:
                row["answer"] = None
            row["usage"] = list(_usage(dialect, payload))
        return Response(
            upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )

    def _verify(self) -> ssl.SSLContext | bool:
        if self.upstream_transport is not None:
            return True
        import certifi

        context = ssl.create_default_context(cafile=certifi.where())
        if self.ca_file:
            context.load_verify_locations(cafile=self.ca_file)  # corporate TLS inspection CA
        return context


def _credential(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and auth[7:].strip():
        return auth[7:].strip()
    return request.headers.get("x-api-key") or request.headers.get("x-goog-api-key") or None


def _error(dialect: sa.Dialect, status: int, message: str) -> dict[str, Any]:
    kind = {400: "invalid_request_error", 401: "authentication_error"}.get(status, "api_error")
    if dialect == "gemini":
        return {"error": {"code": status, "message": message, "status": kind.upper()}}
    return {"error": {"type": kind, "message": message}}


def _answer_text(dialect: sa.Dialect, payload: dict[str, Any]) -> str:
    try:
        if dialect == "anthropic":
            return "".join(b.get("text", "") for b in payload["content"] if b.get("type") == "text")
        if dialect == "openai":
            return str(payload["choices"][0]["message"].get("content") or "")
        parts = payload["candidates"][0]["content"]["parts"]
        return "".join(p.get("text", "") for p in parts if not p.get("thought"))
    except (KeyError, IndexError, TypeError):
        return ""


def _usage(dialect: sa.Dialect, payload: dict[str, Any]) -> tuple[int, int]:
    if dialect == "anthropic":
        u = payload.get("usage") or {}
        return int(u.get("input_tokens", 0)), int(u.get("output_tokens", 0))
    if dialect == "openai":
        u = payload.get("usage") or {}
        return int(u.get("prompt_tokens", 0)), int(u.get("completion_tokens", 0))
    u = payload.get("usageMetadata") or {}
    return int(u.get("promptTokenCount", 0)), int(u.get("candidatesTokenCount", 0))


# ------------------------------------------------------------------ in-process registry

_LIVE: dict[int, SentinelStub] = {}


def _register(request: Request, stub: SentinelStub) -> None:
    server = request.scope.get("server")
    if server and len(server) == 2 and isinstance(server[1], int):
        _LIVE[server[1]] = stub


def live_stub(port: int) -> SentinelStub | None:
    """The stub serving the doubles port `port` in this process (the in-process oracle's
    window; stale stubs of earlier runs are told apart by the records' wall time)."""
    return _LIVE.get(port)


# ------------------------------------------------------------------ routes


def provider_routes(get: Callable[[], SentinelStub]) -> list[Route]:
    """Mounted before the generic `/{double}/v1/*` routes of the doubles app."""

    def endpoint(dialect: sa.Dialect) -> Callable[[Request], Any]:
        async def handle(request: Request) -> Response:
            stub = get()
            _register(request, stub)
            path_model = None
            if dialect == "gemini":
                raw = str(request.path_params.get("model_action", ""))
                model, _, action = raw.partition(":")
                if action != "generateContent":
                    return JSONResponse(_error(dialect, 404, "unknown method"), 404)
                path_model = model
            return await stub.handle(dialect, request, path_model)

        return handle

    return [
        Route(f"/{NAME}/v1/messages", endpoint("anthropic"), methods=["POST"]),
        Route(f"/{NAME}/v1/chat/completions", endpoint("openai"), methods=["POST"]),
        Route(f"/{NAME}/v1beta/models/{{model_action}}", endpoint("gemini"), methods=["POST"]),
    ]


def admin_routes(get: Callable[[], SentinelStub], guard: Callable[[Request], Any]) -> list[Route]:
    async def requests(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied  # type: ignore[no-any-return]
        since = request.query_params.get("since")
        try:
            cut = float(since) if since is not None else None
        except ValueError:
            return JSONResponse({"error": "since must be a unix time"}, status_code=422)
        return JSONResponse(get().snapshot(cut))

    async def reset(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied  # type: ignore[no-any-return]
        get().reset()
        return JSONResponse({"name": NAME, "mode": get().mode, "requests": []})

    return [
        Route(f"/_sim/doubles/{NAME}/requests", requests, methods=["GET"]),
        Route(f"/_sim/doubles/{NAME}/reset", reset, methods=["POST"]),
    ]


__all__ = [
    "NAME",
    "SentinelStub",
    "admin_routes",
    "key_fingerprint",
    "live_stub",
    "provider_routes",
    "sim_key",
]
