"""Throughput micro-benchmark: events/s through one ingest process (in-process ASGI, real PG17,
fs BlobStore, full normaliser: scrub, seal, derive, validate, commit).

Numbers print with ``-s``; the assertion is a deliberately low floor so CI load cannot flake
it. Run: ``uv run pytest services/control/tests/ingest/test_benchmark.py -s``.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from sibyl_control.ingest.flusher import flush_tenant
from sibyl_control.ingest.ids import uuid7

from .conftest import World
from .otlp_build import chat_attrs, span, traces
from .test_replay import _batch, _feedback

# Timing budget: ci/run.sh runs `serial` tests alone after the parallel suite, so other
# workers never share the CPU while it measures.
pytestmark = pytest.mark.serial

FLOOR_EVENTS_PER_S = 100


def _with_payload(i: int) -> dict:
    event = _feedback(i)
    body = json.dumps({"input_messages": [{"role": "user", "content": f"quote request {i} " * 20}]})
    event.update({"type": "tool.call", "event_id": str(uuid7())})
    event["attrs"] = {
        "tool_name": "lookup",
        "tool_type": "function",
        "status": "ok",
        "latency_ms": 12,
        "payload_inline": {
            "encoding": "base64",
            "data": base64.b64encode(body.encode()).decode(),
            "content_type": "application/json",
            "parts": ["tool_args"],
        },
    }
    return event


async def _rate(world: World, path: str, bodies: list[bytes], per_batch: int) -> float:
    started = time.perf_counter()
    for body in bodies:
        resp = await world.post(path, body)
        assert resp.status_code in (200, 202), resp.text[:300]
    return per_batch * len(bodies) / (time.perf_counter() - started)


async def test_ingest_throughput(world: World) -> None:
    await world.admin.execute(
        "UPDATE sibyl.tenant SET ingest_rate_limit = $2::text::jsonb WHERE id = $1",
        world.tenant_id,
        '{"events_per_s": 100000, "burst": 1000000}',
    )
    results = {}
    results["events: feedback, no body (5 x 1000)"] = await _rate(
        world, "/v1/events", [_batch([_feedback(i) for i in range(1000)]) for _ in range(5)], 1000
    )
    results["events: tool.call + sealed body (3 x 1000)"] = await _rate(
        world,
        "/v1/events",
        [_batch([_with_payload(i) for i in range(1000)]) for _ in range(3)],
        1000,
    )
    spans = [
        traces(
            [
                span(chat_attrs(**{"gen_ai.input.messages": '[{"role":"user","content":"hello"}]'}))
                for _ in range(2000)
            ]
        )
        for _ in range(2)
    ]
    results["otlp json: chat spans + sealed body, staged (2 x 2000)"] = await _rate(
        world, "/v1/otlp/traces", spans, 2000
    )
    started = time.perf_counter()
    later = datetime.now(UTC) + timedelta(minutes=1)
    flushed = await flush_tenant(world.db, world.tenant_id, world.services.cfg, now=later)
    flushed += await flush_tenant(world.db, world.tenant_id, world.services.cfg, now=later)
    flushed += await flush_tenant(world.db, world.tenant_id, world.services.cfg, now=later)
    flushed += await flush_tenant(world.db, world.tenant_id, world.services.cfg, now=later)
    results["call_merge flush (calls/s)"] = (
        flushed / (time.perf_counter() - started) if flushed else 0.0
    )
    for name, rate in results.items():
        print(f"BENCH {name}: {rate:,.0f}/s")
    assert min(v for k, v in results.items() if "flush" not in k) >= FLOOR_EVENTS_PER_S
