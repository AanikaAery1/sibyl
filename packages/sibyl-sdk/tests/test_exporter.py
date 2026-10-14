"""Exporter: lanes, overflow, Retry-After, drop on 4xx, replay with the same batch id,
spool, bounded shutdown, fork re-init, never blocking the caller (API §8.4, §8.7)."""

from __future__ import annotations

import gzip
import os
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sibyl._config import ExporterConfig
from sibyl._exporter import Exporter
from sibyl._otlp import LogRecord
from sibyl._spans import Span
from sibyl.testing import Ingest, OffsetClock, attrs, wait_for

KEY = "sbl_test_Bd3Fg5Hj7Kl9_" + "A" * 43


def make(
    ingest: Ingest,
    clock: OffsetClock | None = None,
    *,
    finalize_event: Any = None,
    finalize_span: Any = None,
    **cfg: Any,
) -> Exporter:
    defaults: dict[str, Any] = {
        "schedule_delay": timedelta(milliseconds=20),
        "export_timeout": timedelta(seconds=1),
        "heartbeat_interval": timedelta(hours=1),
        "buffer_report_interval": timedelta(hours=1),
    }
    defaults.update(cfg)
    kwargs: dict[str, Any] = {}
    if finalize_event is not None:
        kwargs["finalize_event"] = finalize_event
    if finalize_span is not None:
        kwargs["finalize_span"] = finalize_span
    return Exporter(
        endpoint="http://ingest.test",
        api_key=KEY,
        config=ExporterConfig(**defaults),
        resource={"service.name": "test", "sibyl.emitter_id": "sdk:test:1"},
        sdk_version="0.1.0",
        agent_header=lambda: "quote-assistant",
        clock=clock or OffsetClock(),
        transport=ingest.transport,
        **kwargs,
    )


def span(name: str = "chat m", critical: bool = False) -> Span:
    s = Span(name, critical=critical)
    s.set("gen_ai.operation.name", "chat")
    s.end()
    return s


def push(exp: Exporter, s: Span) -> None:
    exp.enqueue("span", s, size=s.approx_bytes, critical=s.critical)


def event(n: int) -> dict[str, Any]:
    return {"schema": "sibyl-event/1", "type": "feedback", "n": n}


def test_spans_are_posted_as_gzip_otlp_json_with_headers(ingest: Ingest) -> None:
    exp = make(ingest)
    push(exp, span())
    assert exp.flush(2)
    (req,) = ingest.posts("/v1/otlp/traces")
    assert req.headers["content-encoding"] == "gzip"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    assert req.headers["x-sibyl-agent"] == "quote-assistant"
    assert req.headers["user-agent"].startswith("sibyl-sdk/0.1.0 python/")
    assert len(req.headers["x-sibyl-batch-id"]) == 36
    resource = req.body["resourceSpans"][0]["resource"]
    assert attrs(resource)["service.name"] == "test"
    (otlp_span,) = ingest.spans()
    assert len(otlp_span["traceId"]) == 32 and len(otlp_span["spanId"]) == 16
    assert attrs(otlp_span)["gen_ai.operation.name"] == "chat"
    exp.shutdown(1)


def test_events_go_to_v1_events_with_schema_header(ingest: Ingest) -> None:
    exp = make(ingest)
    exp.enqueue("event", event(1), size=50)
    assert exp.flush(2)
    (req,) = ingest.posts("/v1/events")
    assert req.headers["x-sibyl-schema"] == "sibyl-event/1"
    assert req.body == {"schema": "sibyl-event/1", "events": [event(1)]}
    exp.shutdown(1)


def test_critical_lane_drains_first(ingest: Ingest) -> None:
    exp = make(ingest, schedule_delay=timedelta(seconds=30), batch_size=1000)
    push(exp, span("telemetry"))
    push(exp, span("critical", critical=True))
    assert exp.flush(2)
    names = [s["name"] for s in ingest.spans()]
    assert names == ["critical", "telemetry"]
    exp.shutdown(1)


def test_overflow_drops_oldest_and_counts(ingest: Ingest) -> None:
    exp = make(ingest, schedule_delay=timedelta(seconds=30), max_queue_spans=3, batch_size=1000)
    for n in range(5):
        push(exp, span(f"s{n}"))
    stats = exp.stats()
    assert stats.dropped_by_reason.get("overflow") == 2
    assert exp.flush(2)
    assert [s["name"] for s in ingest.spans()] == ["s2", "s3", "s4"]
    exp.shutdown(1)


def test_byte_cap_also_drops_oldest(ingest: Ingest) -> None:
    exp = make(ingest, schedule_delay=timedelta(seconds=30), max_queue_bytes=400, batch_size=1000)
    for n in range(4):
        push(exp, span(f"s{n}"))
    assert exp.stats().queued_bytes <= 400
    assert exp.stats().dropped_spans >= 1
    exp.shutdown(1)


def test_enqueue_never_blocks_even_when_ingest_hangs(ingest: Ingest) -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        time.sleep(0.5)
        return httpx.Response(200)

    ingest.default = slow
    exp = make(ingest)
    started = time.perf_counter()
    for _ in range(2000):
        push(exp, span())
    per_call = (time.perf_counter() - started) / 2000
    assert per_call < 0.001  # p99 budget is 1 ms per wrapper; enqueue is far below it
    exp.shutdown(0.2)


def test_retry_after_pauses_and_replays_with_same_batch_id(
    ingest: Ingest, clock: OffsetClock
) -> None:
    ingest.script = [lambda r: httpx.Response(429, headers={"Retry-After": "30"})]
    exp = make(ingest, clock, export_timeout=timedelta(seconds=60))
    push(exp, span())
    assert wait_for(lambda: len(ingest.requests) == 1)
    stats = exp.stats()
    assert stats.backpressure_until is not None
    assert not exp.flush(0.2)  # paused: nothing sent
    assert len(ingest.requests) == 1
    clock.advance(31)
    assert exp.flush(2)
    first, second = ingest.posts("/v1/otlp/traces")
    assert first.headers["x-sibyl-batch-id"] == second.headers["x-sibyl-batch-id"]
    exp.shutdown(1)


def test_retry_after_http_date_is_honoured(ingest: Ingest, clock: OffsetClock) -> None:
    from email.utils import formatdate

    when = formatdate(clock.time() + 60, usegmt=True)
    ingest.script = [lambda r: httpx.Response(503, headers={"Retry-After": when})]
    exp = make(ingest, clock)
    push(exp, span())
    assert wait_for(lambda: exp.stats().backpressure_until is not None)
    until = exp.stats().backpressure_until
    assert until is not None and until.timestamp() - clock.time() > 50
    exp.shutdown(0.2)


@pytest.mark.parametrize("status", [400, 401, 403, 413, 422])
def test_non_retryable_4xx_is_dropped_and_counted(ingest: Ingest, status: int) -> None:
    ingest.script = [lambda r, s=status: httpx.Response(s)]
    exp = make(ingest)
    push(exp, span())
    assert exp.flush(2)
    assert exp.stats().dropped_by_reason == {f"rejected_{status}": 1}
    push(exp, span())
    assert exp.flush(2)
    assert len(ingest.posts("/v1/otlp/traces")) == 2  # not retried
    exp.shutdown(1)


def test_timeout_keeps_batch_and_replays_same_id(ingest: Ingest, clock: OffsetClock) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    ingest.script = [boom]
    exp = make(ingest, clock, export_timeout=timedelta(seconds=60))
    push(exp, span())
    assert wait_for(lambda: len(ingest.requests) == 1)
    clock.advance(5)
    assert exp.flush(2)
    first, second = ingest.posts("/v1/otlp/traces")
    assert first.headers["x-sibyl-batch-id"] == second.headers["x-sibyl-batch-id"]
    assert exp.stats().last_error is not None
    exp.shutdown(1)


def test_pending_batch_without_spool_expires_after_three_timeouts(
    ingest: Ingest, clock: OffsetClock
) -> None:
    ingest.default = lambda r: httpx.Response(503, headers={"Retry-After": "1"})
    exp = make(ingest, clock)
    push(exp, span())
    assert wait_for(lambda: len(ingest.requests) >= 1)
    clock.advance(5)  # export_timeout 1 s x 3 elapsed
    ingest.default = lambda r: httpx.Response(200)
    assert exp.flush(2)
    assert exp.stats().dropped_by_reason.get("retry_expired") == 1
    exp.shutdown(1)


def test_tenant_erasing_stops_the_exporter(ingest: Ingest) -> None:
    ingest.script = [
        lambda r: httpx.Response(
            429, headers={"Retry-After": "3600", "X-Sibyl-Backpressure": "tenant_erasing"}
        )
    ]
    exp = make(ingest)
    push(exp, span())
    assert wait_for(lambda: len(ingest.requests) == 1)
    push(exp, span())
    assert exp.flush(1)
    assert len(ingest.requests) == 1
    assert exp.stats().dropped_by_reason.get("disabled") == 1
    exp.shutdown(1)


def test_spool_persists_failed_batch_and_replays_oldest_first(
    ingest: Ingest, clock: OffsetClock, tmp_path: Path
) -> None:
    ingest.script = [lambda r: httpx.Response(503, headers={"Retry-After": "10"})]
    exp = make(ingest, clock, spool_dir=str(tmp_path))
    push(exp, span("spooled"))
    assert wait_for(lambda: any(p.suffix == ".gz" for p in tmp_path.iterdir()))
    (segment,) = [p for p in tmp_path.iterdir() if p.suffix == ".gz"]
    batch_id = segment.name.split("-", 1)[1].split(".")[0]
    assert exp.stats().spooled_bytes > 0
    clock.advance(11)
    assert exp.flush(2)
    replayed = ingest.posts("/v1/otlp/traces")[-1]
    assert replayed.headers["x-sibyl-batch-id"] == batch_id
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".gz"]
    assert wait_for(lambda: bool(ingest.logs()) or (exp.flush(0.1) and bool(ingest.logs())))
    replay = [r for r in ingest.logs() if r["eventName"] == "sibyl.sdk.replay"]
    assert attrs(replay[0])["events_replayed"] == 1
    exp.shutdown(1)


def test_spool_survives_restart(ingest: Ingest, clock: OffsetClock, tmp_path: Path) -> None:
    ingest.default = lambda r: httpx.Response(503, headers={"Retry-After": "100"})
    first = make(ingest, clock, spool_dir=str(tmp_path))
    push(first, span("before-crash"))
    assert wait_for(lambda: any(p.suffix == ".gz" for p in tmp_path.iterdir()))
    first.shutdown(0.1)
    fresh = Ingest()
    second = make(fresh, clock, spool_dir=str(tmp_path))
    push(second, span("after"))
    assert second.flush(2)
    assert [s["name"] for s in fresh.spans()] == ["before-crash", "after"]
    second.shutdown(1)


def test_corrupt_spool_segment_is_dropped(ingest: Ingest, tmp_path: Path) -> None:
    (
        tmp_path / f"{int(time.time() * 1000):013d}-{'0' * 8}-0000-7000-8000-{'0' * 12}.traces.gz"
    ).write_bytes(b"not gzip")
    exp = make(ingest, spool_dir=str(tmp_path))
    push(exp, span())
    assert exp.flush(2)
    assert not [p for p in tmp_path.iterdir() if p.suffix == ".gz"]
    assert exp._spool is not None and exp._spool.corrupt_segments == 1
    exp.shutdown(1)


def test_spool_cap_deletes_oldest(tmp_path: Path) -> None:
    from sibyl._spool import Spool

    spool = Spool(str(tmp_path), max_bytes=100, max_age_s=3600)
    body = gzip.compress(b"x" * 10)
    for n in range(5):
        spool.write(
            batch_id=f"0192767f-0000-7000-8000-{n:012d}",
            kind="traces",
            body_gz=body,
            items=2,
            now_ms=1_000_000 + n,
        )
    segments = spool.segments()
    assert spool.total_bytes() <= 100
    assert segments[-1].batch_id.endswith("4")
    assert spool.dropped_items == 2 * (5 - len(segments))
    spool.enforce_caps(now_ms=1_000_000 + 3600 * 1000 + 10)
    assert spool.segments() == []


def test_shutdown_is_bounded_when_ingest_hangs(ingest: Ingest, tmp_path: Path) -> None:
    def hang(request: httpx.Request) -> httpx.Response:
        time.sleep(3)
        return httpx.Response(200)

    ingest.default = hang
    exp = make(ingest, export_timeout=timedelta(seconds=5))
    push(exp, span())
    started = time.monotonic()
    exp.shutdown(0.3)
    assert time.monotonic() - started < 1.0


def test_shutdown_spools_leftovers(ingest: Ingest, tmp_path: Path) -> None:
    ingest.default = lambda r: httpx.Response(503, headers={"Retry-After": "100"})
    exp = make(
        ingest, spool_dir=str(tmp_path), schedule_delay=timedelta(seconds=30), batch_size=1000
    )
    push(exp, span("a"))
    exp.shutdown(0.2)
    assert [p for p in tmp_path.iterdir() if p.suffix == ".gz"]


def test_finalizers_can_drop(ingest: Ingest) -> None:
    exp = make(ingest, finalize_event=lambda e: None, finalize_span=lambda s: False)
    exp.enqueue("event", event(1), size=10)
    push(exp, span())
    assert exp.flush(2)
    assert ingest.requests == []
    assert exp.stats().dropped_by_reason == {"finalize": 2}
    exp.shutdown(1)


def test_ingest_rejections_are_counted(ingest: Ingest) -> None:
    ingest.script = [
        lambda r: httpx.Response(202, json={"rejected": [{"index": 0, "reason": "x"}]})
    ]
    exp = make(ingest)
    exp.enqueue("event", event(1), size=10)
    assert exp.flush(2)
    assert exp.stats().rejected_events == 1
    exp.shutdown(1)


def test_heartbeat_and_buffer_report(ingest: Ingest, clock: OffsetClock) -> None:
    exp = make(
        ingest,
        clock,
        heartbeat_interval=timedelta(seconds=10),
        buffer_report_interval=timedelta(seconds=60),
    )
    push(exp, span())
    assert exp.flush(2)
    clock.advance(61)

    def heartbeats() -> list[Any]:
        return [
            r
            for r in ingest.posts("/v1/otlp/traces")
            if not r.body["resourceSpans"][0]["scopeSpans"]
        ]

    assert wait_for(lambda: bool(heartbeats()))
    assert wait_for(lambda: any(r["eventName"] == "sibyl.sdk.buffer" for r in ingest.logs()))
    exp.shutdown(1)


def test_buffer_report_after_100_drops(ingest: Ingest) -> None:
    exp = make(ingest, max_queue_spans=1, batch_size=1000, schedule_delay=timedelta(seconds=30))
    for _ in range(105):
        push(exp, span())
    assert exp.flush(2)
    exp.flush(1)
    reports = [r for r in ingest.logs() if r["eventName"] == "sibyl.sdk.buffer"]
    assert reports and attrs(reports[0])["sibyl.sdk.dropped_spans"] >= 100
    exp.shutdown(1)


def test_log_records_go_to_otlp_logs(ingest: Ingest) -> None:
    exp = make(ingest)
    record = LogRecord(event_name="sibyl.sdk.buffer", time_ns=1, attributes={"a": 1})
    exp.enqueue("log", record, size=record.approx_bytes, critical=True)
    assert exp.flush(2)
    (log,) = ingest.logs()
    assert log["eventName"] == "sibyl.sdk.buffer"
    assert attrs(log)["event.name"] == "sibyl.sdk.buffer"
    exp.shutdown(1)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.filterwarnings("ignore:This process .* is multi-threaded:DeprecationWarning")
def test_fork_child_gets_a_fresh_worker(ingest: Ingest) -> None:
    exp = make(ingest, schedule_delay=timedelta(seconds=30), batch_size=1000)
    push(exp, span("parent"))
    pid = os.fork()
    if pid == 0:  # child: queue is empty, a new worker exports the child's span
        ok = len(exp._telemetry) == 0 and exp._thread is None
        push(exp, span("child"))
        ok = ok and exp._thread is not None and exp.flush(2)
        os._exit(0 if ok else 1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    assert exp.flush(2)
    assert "parent" in [s["name"] for s in ingest.spans()]
    exp.shutdown(1)
