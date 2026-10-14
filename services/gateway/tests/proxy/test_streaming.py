"""Streaming SSE passthrough over real sockets (gateway and upstream both on loopback).

Proves: the first byte is relayed as soon as upstream sends it (no buffering), chunks keep their
pacing, telemetry is built only after the last byte, and a full or slow telemetry path never
delays the response.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
from sibyl_gateway.telemetry.queue import TelemetryQueue

from ..fakes.servers import ServerThread
from ..fakes.upstream import FakeUpstream, Reply
from ..support import GATEWAY_KEY
from .harness import chat, headers, make_gateway

Up = tuple[FakeUpstream, str]


async def _stream(
    url: str, payload: dict[str, Any]
) -> tuple[list[tuple[float, bytes]], float, httpx.Headers]:
    arrivals: list[tuple[float, bytes]] = []
    async with httpx.AsyncClient(timeout=10) as client:
        started = time.monotonic()
        async with client.stream(
            "POST", f"{url}/v1/chat/completions", json=payload, headers=headers(GATEWAY_KEY)
        ) as resp:
            response_headers = resp.headers
            async for chunk in resp.aiter_raw():
                arrivals.append((time.monotonic(), chunk))
    return arrivals, started, response_headers


async def test_first_byte_is_not_delayed_and_chunks_keep_their_pacing(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    built_at: list[float] = []
    original = gw.app.events.gen_ai_request

    def spy(record: Any) -> dict[str, Any]:
        built_at.append(time.monotonic())
        return original(record)

    gw.app.events.gen_ai_request = spy  # type: ignore[method-assign]
    fake.queue(Reply(chunks=4, chunk_delay_s=0.4))
    with ServerThread(gw.app) as server:
        arrivals, started, response_headers = await _stream(server.url, chat(stream=True))
    assert response_headers["content-type"].startswith("text/event-stream")
    assert response_headers["x-sibyl-route"] == "primary"
    first_at = arrivals[0][0] - started
    total = arrivals[-1][0] - started
    assert first_at < 0.3, f"first byte after {first_at:.3f}s"
    assert total >= 1.1, "relay must not complete before upstream does"
    assert len(arrivals) >= 4, "chunks must be relayed one by one, not buffered"
    body = b"".join(chunk for _, chunk in arrivals)
    assert body.count(b"data: ") == 6 and body.endswith(b"data: [DONE]\n\n")
    assert built_at and built_at[0] >= arrivals[-1][0] - 0.05, "telemetry built after last byte"
    (event,) = gw.events()
    attrs = event["attrs"]
    assert attrs["streamed"] is True and attrs["usage"]["output_tokens"] == 4
    assert attrs["finish_reasons"] == ["stop"] and attrs["ttfb_ms"] < 300


async def test_saturated_telemetry_never_blocks_the_stream(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    gw.app.telemetry = TelemetryQueue(None, max_events=0)  # every offer is a drop
    fake.queue(Reply(chunks=2, chunk_delay_s=0.2))
    with ServerThread(gw.app) as server:
        arrivals, started, _ = await _stream(server.url, chat(stream=True))
    assert arrivals[0][0] - started < 0.3
    assert gw.app.telemetry.stats.dropped == 1 and len(gw.app.telemetry) == 0


async def test_upstream_abort_mid_stream_ends_the_body_and_records_an_error(upstream: Up) -> None:
    fake, url = upstream
    gw = make_gateway(url)
    fake.queue(Reply(chunks=4, abort_after_chunks=2))
    with ServerThread(gw.app) as server:
        try:
            arrivals, _, _ = await _stream(server.url, chat(stream=True))
        except httpx.HTTPError:
            arrivals = []
    received = b"".join(chunk for _, chunk in arrivals)
    assert b"[DONE]" not in received
    (event,) = gw.events()
    assert event["attrs"]["error_type"] != "" and event["attrs"]["http_status"] == 200
