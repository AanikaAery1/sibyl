"""Bounded non-blocking telemetry queue, batch sender and ingest sink; event documents."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from typing import Any
from uuid import UUID

import httpx
import pytest
from sibyl_gateway.telemetry.events import CallRecord, EventFactory, parse_traceparent, uuid7
from sibyl_gateway.telemetry.queue import HttpIngestSink, TelemetryQueue
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.scrub import SecretsScrubber

from ..support import TENANT

FACTORY = EventFactory("gw-1", SecretsScrubber(hashlib.sha256(b"s").digest()))


def event(n: int = 0) -> dict[str, Any]:
    return {"n": n}


def test_offer_never_blocks_and_counts_drops() -> None:
    queue = TelemetryQueue(None, max_events=3)
    started = time.perf_counter()
    results = [queue.offer(event(i)) for i in range(5)]
    assert time.perf_counter() - started < 0.01
    assert results == [True, True, True, False, False]
    assert queue.stats.dropped == 2 and len(queue) == 3


async def test_sender_batches_and_retries_then_drops() -> None:
    sent: list[int] = []
    failures = {"left": 2}

    async def sink(batch: Any) -> None:
        if failures["left"]:
            failures["left"] -= 1
            raise RuntimeError("ingest down")
        sent.append(len(batch))

    queue = TelemetryQueue(sink, batch_size=2, flush_s=0.01, max_retries=3)
    for i in range(5):
        queue.offer(event(i))
    queue.start()
    for _ in range(200):
        if sum(sent) == 5:
            break
        await asyncio.sleep(0.02)
    await queue.stop()
    assert sum(sent) == 5 and max(sent) <= 2 and queue.stats.failed_batches == 2

    async def dead(batch: Any) -> None:
        raise RuntimeError("down")

    lossy = TelemetryQueue(dead, max_retries=0)
    lossy.offer(event())
    await lossy.flush()
    assert lossy.stats.dropped == 1


async def test_ingest_sink_posts_the_wire_batch() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(202 if len(seen) == 1 else 503)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        sink = HttpIngestSink("http://ingest:8001/", "sbl_test_key", client)
        assert "sbl_test_key" not in repr(sink)
        await sink([event(1)])
        with pytest.raises(RuntimeError):
            await sink([event(2)])
    assert seen[0].url.path == "/v1/events"
    assert seen[0].headers["authorization"] == "Bearer sbl_test_key"
    assert json.loads(seen[0].content) == {"schema": "sibyl-event/1", "events": [{"n": 1}]}


def test_uuid7_and_traceparent() -> None:
    first, second = uuid7(), uuid7()
    assert first.version == 7 and first != second
    assert parse_traceparent("00-" + "1" * 32 + "-" + "2" * 16 + "-01") == ("1" * 32, "2" * 16)
    trace, parent = parse_traceparent("garbage")
    assert len(trace) == 32 and parent is None


def _record(**kw: Any) -> CallRecord:
    now = time.time()
    base: dict[str, Any] = dict(
        tenant_id=TENANT,
        agent_id=UUID(int=5),
        operation="chat.completions",
        provider="openai",
        request_model="gpt",
        status="ok",
        started=now - 0.2,
        ended=now,
        route="primary",
        capture_mode="metadata",
        policy_state="fresh",
        policy_version=3,
        fail_mode="open",
    )
    base.update(kw)
    return CallRecord(**base)


@pytest.mark.parametrize("mode", ["metadata", "redacted", "full"])
def test_gen_ai_request_is_wire_valid_for_every_capture_mode(mode: str) -> None:
    rec = _record(
        capture_mode=mode,
        request_body=b'{"a":"Bearer abcdefghijklmnopqrstuvwxyz0123"}',
        response_body=b"{}",
        profile_hash="a" * 64,
        task_id=str(UUID(int=9)),
    )
    doc = FACTORY.gen_ai_request(rec)
    assert not list(sj.iter_errors("sibyl-event-wire/1", doc))
    assert ("payload_inline" in doc["attrs"]) is (mode != "metadata")
    assert "abcdefghijklmnopqrstuvwxyz0123" not in json.dumps(doc)


def test_provisional_agent_gets_a_stable_uuid_and_discovery_event() -> None:
    first = FACTORY.gen_ai_request(_record(agent_id="unclaimed/3f9a1c0e"))
    second = FACTORY.gen_ai_request(_record(agent_id="unclaimed/3f9a1c0e"))
    assert first["agent_id"] == second["agent_id"] and second["seq"] == first["seq"] + 1
    found = FACTORY.agent_discovered(
        TENANT,
        "unclaimed/3f9a1c0e",
        candidate="invoice-bot",
        candidate_hash="0" * 16,
        via="gateway_header",
        fail_mode="open",
        call_id=uuid7(),
        traceparent=None,
        policy_version=1,
    )
    assert found["attrs"]["resolved_agent_id"] == first["agent_id"]
    assert not list(sj.iter_errors("sibyl-event-wire/1", found))
    decision = FACTORY.policy_decision(
        TENANT,
        UUID(int=5),
        action="forward_stale",
        state="expired",
        fail_mode="open",
        reason="x",
        http_status=200,
        policy_version=1,
    )
    assert not list(sj.iter_errors("sibyl-event-wire/1", decision))
