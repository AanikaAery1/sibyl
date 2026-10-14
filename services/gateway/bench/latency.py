"""In-process latency micro-benchmark for the gateway hot path (W0-15 floor, lane G).

What it measures: the time the gateway adds to one call, excluding the upstream. The upstream
is an in-memory ``httpx.MockTransport`` answering instantly, so a request runs the full G-hot
and G-policy path (key HMAC, decision, limits, header build, upstream request through the real
httpx client, relay, error mapping) with zero network time. ``baseline`` is the same upstream
exchange done directly through the same httpx client; ``added = gateway - baseline``.
Latency is client-perceived: until the last body message is handed to the server
(``more_body=False``); the post-flush telemetry work is reported separately as ``tail_cpu``.

Budget (enforced by ``tests/test_bench.py``): sequential added p99 < 5 ms, and with 200
concurrent streams p95 < 15 ms / p99 < 50 ms (the ROADMAP §1.3 / ADR-1 gate, here in-process
without sockets). Run: ``uv run python services/gateway/bench/latency.py [--n 2000]``.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import hashlib
import hmac
import json
import os
import statistics
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_gateway.limits import Limits
from sibyl_gateway.policy.service import SnapshotPolicyView
from sibyl_gateway.policy.store import SnapshotStore
from sibyl_gateway.policy.verify import PinnedKeySet
from sibyl_gateway.proxy.app import GatewayApp
from sibyl_gateway.proxy.upstream import UpstreamClient
from sibyl_gateway.telemetry.events import EventFactory
from sibyl_gateway.telemetry.queue import TelemetryQueue
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.scrub import SecretsScrubber

PREFIX = "BenchKey0001"
AGENT = "quote-assistant"
COMPLETION = json.dumps(
    {
        "id": "x",
        "object": "chat.completion",
        "model": "gpt-5.4",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "hello"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1},
    }
).encode()
SSE = [
    f'data: {{"model":"gpt-5.4","choices":[{{"delta":{{"content":"t{i}"}}}}]}}\n\n'.encode()
    for i in range(8)
] + [b"data: [DONE]\n\n"]
_CALL = {
    "id": "call_1",
    "type": "function",
    "function": {"name": "search.web", "arguments": '{"q": "cement prices in Pune"}'},
}
COMPLETION_TOOLS = json.dumps(
    {
        "id": "x",
        "object": "chat.completion",
        "model": "gpt-5.4",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": None, "tool_calls": [_CALL]},
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 9},
    }
).encode()
_FIRST = {"index": 0, "id": "call_1", "type": "function", "function": {"name": "search.web"}}
_TOOL_DELTAS: list[dict[str, Any]] = [
    {"role": "assistant", "content": None},
    {"tool_calls": [{**_FIRST, "function": {"name": "search.web", "arguments": ""}}]},
    {"tool_calls": [{"index": 0, "function": {"arguments": '{"q": "cement '}}]},
    {"tool_calls": [{"index": 0, "function": {"arguments": 'prices in Pune"}'}}]},
]
_FINISH = {
    "model": "gpt-5.4",
    "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}],
}
SSE_TOOLS = [
    b"data: "
    + json.dumps({"model": "gpt-5.4", "choices": [{"index": 0, "delta": d}]}).encode()
    + b"\n\n"
    for d in _TOOL_DELTAS
] + [b"data: " + json.dumps(_FINISH).encode() + b"\n\n", b"data: [DONE]\n\n"]


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class _Chunks(httpx.AsyncByteStream):
    """A live (unread) upstream body, as a socket transport would hand it over."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk


_DELAY = {"s": 0.0}
_TOOLS = {"on": False}


async def _upstream(request: httpx.Request) -> httpx.Response:
    if _DELAY["s"]:
        await asyncio.sleep(_DELAY["s"])
    tools = _TOOLS["on"]
    if b'"stream":true' in request.content:
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            stream=_Chunks(SSE_TOOLS if tools else SSE),
        )
    return httpx.Response(
        200,
        headers={"content-type": "application/json"},
        stream=_Chunks([COMPLETION_TOOLS if tools else COMPLETION]),
    )


def build(
    capture: str = "metadata", actions: bool = False
) -> tuple[GatewayApp, str, UpstreamClient]:
    """A gateway over a signed one-tenant snapshot (schemas fixture) and an instant upstream.
    ``actions``: every agent carries the 8-rule payments action policy (allowlist enforced)
    and every response proposes a tool call the Action Gate must decide (it is allowed)."""
    pepper = os.urandom(32)
    secret = _b64u(os.urandom(32))
    key = f"sbl_live_{PREFIX}_{secret}"
    signing = Ed25519PrivateKey.generate()
    template = load_fixture("snapshot", "valid/snapshot_body.json")
    tenant_id, block = next(iter(copy.deepcopy(template["tenants"]).items()))
    block["api_keys"] = {
        PREFIX: {
            "key_id": "0192f0c1-0000-7000-8000-0000000000b1",
            "secret_hash": hmac.new(pepper, secret.encode(), hashlib.sha256).hexdigest(),
            "env": "live",
            "scopes": ["gateway:proxy"],
            "agent_id": None,
            "status": "active",
            "expires_at": _iso(datetime.now(UTC) + timedelta(days=30)),
        }
    }
    policy = load_fixture("action_gate", "vectors.json")["policies"]["payments"]
    for agent in block["agents"].values():
        agent["capture"]["mode"] = capture
        agent["limits"].update({"rps": None, "max_inflight": None})
        if actions:
            agent["action_policies"] = [policy["policy_id"]]
    if actions:
        block["action_policies"] = {policy["policy_id"]: policy}
    now = datetime.now(UTC)
    body = {
        "schema": "sibyl.policy_snapshot/1",
        "version": 1,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(seconds=600)),
        "ttl_s": 600,
        "grace_s": 300,
        "kid": "bench",
        "tenants": {tenant_id: block},
    }
    raw = canonicalize(body)
    public = signing.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys = PinnedKeySet.from_document({"keys": [{"kid": "bench", "public_key": _b64u(public)}]})
    store = SnapshotStore(keys)
    store.offer("bench", raw, kid="bench", signature=_b64u(signing.sign(raw)))
    view = SnapshotPolicyView(store, pepper=pepper, env="live")
    upstream = UpstreamClient(transport=httpx.MockTransport(_upstream))
    events = EventFactory("bench", SecretsScrubber(b"bench-salt-0123456789"))
    app = GatewayApp(
        view,
        upstream,
        events,
        TelemetryQueue(None, max_events=10**7),
        gateway_id="bench",
        limits=Limits(),
    )
    app.limits.key = lambda key_id: _UNLIMITED  # type: ignore[method-assign]
    return app, key, upstream


class _Unlimited:
    allowed = True

    def headers(self, name: str) -> list[tuple[str, str]]:
        return []


_UNLIMITED = _Unlimited()


async def gateway_call(app: GatewayApp, key: str, payload: bytes) -> tuple[float, float, int]:
    """(seconds to last body byte, seconds until the app returned, status)."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/v1/chat/completions",
        "query_string": b"",
        "headers": [
            (b"x-sibyl-key", key.encode()),
            (b"x-sibyl-agent", AGENT.encode()),
            (b"authorization", b"Bearer sk-proj-bench"),
            (b"content-type", b"application/json"),
        ],
        "client": ("127.0.0.1", 5000),
    }
    sent = False
    done_at = 0.0
    status = 0

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            await asyncio.sleep(3600)
        sent = True
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        nonlocal done_at, status
        if message["type"] == "http.response.start":
            status = message["status"]
        elif not message.get("more_body", False):
            done_at = time.perf_counter()

    started = time.perf_counter()
    await app(scope, receive, send)
    return done_at - started, time.perf_counter() - started, status


async def baseline_call(upstream: UpstreamClient, payload: bytes) -> float:
    started = time.perf_counter()
    request = upstream.build(
        "https://api.openai.com/v1/chat/completions",
        [("authorization", "Bearer sk-proj-bench")],
        payload,
    )
    response = await upstream.send(request)
    async for _ in response.aiter_raw():
        pass
    await response.aclose()
    return time.perf_counter() - started


def pct(values: list[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(q / 100 * (len(ordered) - 1)))]


async def run(
    n: int = 2000,
    concurrency: int = 200,
    stream: bool = False,
    delay_s: float = 0.02,
    actions: bool = False,
) -> dict[str, Any]:
    """Sequential phase: instant upstream. Concurrent phase: ``concurrency`` calls in flight
    together against an upstream that answers after ``delay_s``; reported minus ``delay_s``.
    ``actions``: Action Gate on (policies plus a proposed tool call in every response)."""
    _DELAY["s"] = 0.0
    _TOOLS["on"] = actions
    app, key, upstream = build(actions=actions)
    payload = json.dumps(
        {"model": "gpt-5.4", "stream": stream, "messages": [{"role": "user", "content": "hello"}]}
    ).encode()
    for _ in range(50):  # warm-up: imports, pools, caches
        await gateway_call(app, key, payload)
        await baseline_call(upstream, payload)
    base = [await baseline_call(upstream, payload) for _ in range(n)]
    seq = [await gateway_call(app, key, payload) for _ in range(n)]
    assert all(s == 200 for _, _, s in seq), "bench calls must succeed"
    base_p50 = statistics.median(base)
    flushed = [f for f, _, _ in seq]
    tail = [t - f for f, t, _ in seq]
    conc: list[float] = []
    _DELAY["s"] = delay_s
    try:
        for _ in range(max(1, n // concurrency)):
            calls = (gateway_call(app, key, payload) for _ in range(concurrency))
            batch = await asyncio.gather(*calls)
            assert all(s == 200 for _, _, s in batch)
            conc.extend(f - delay_s for f, _, _ in batch)
    finally:
        _DELAY["s"] = 0.0
        _TOOLS["on"] = False
    ms = 1000.0
    return {
        "n": n,
        "stream": stream,
        "actions": actions,
        "baseline_p50_ms": round(base_p50 * ms, 3),
        "added_p50_ms": round((statistics.median(flushed) - base_p50) * ms, 3),
        "added_p95_ms": round((pct(flushed, 95) - base_p50) * ms, 3),
        "added_p99_ms": round((pct(flushed, 99) - base_p50) * ms, 3),
        "tail_cpu_p50_ms": round(statistics.median(tail) * ms, 3),
        "concurrency": concurrency,
        "upstream_delay_ms": delay_s * ms,
        "concurrent_added_p50_ms": round(statistics.median(conc) * ms, 3),
        "concurrent_added_p95_ms": round(pct(conc, 95) * ms, 3),
        "concurrent_added_p99_ms": round(pct(conc, 99) * ms, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--n", type=int, default=2000)
    parser.add_argument("--concurrency", type=int, default=200)
    args = parser.parse_args()
    for actions in (False, True):
        for stream in (False, True):
            result = asyncio.run(run(args.n, args.concurrency, stream, actions=actions))
            print(json.dumps(result))


if __name__ == "__main__":
    main()
