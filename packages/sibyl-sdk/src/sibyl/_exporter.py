"""Bounded, non-blocking exporter with a critical and a telemetry lane (API §8.4).

The caller's thread only appends to a ring (O(1)); one daemon worker batches, gzips and
POSTs with an `X-Sibyl-Batch-Id`. 429/503 honour `Retry-After` and pause both lanes; other
4xx drop and count; timeouts keep the batch (same batch id) for replay, in the disk spool
when configured. `shutdown()` is bounded; the worker is re-created after `fork()`.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import random
import threading
import weakref
from collections import Counter, deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Final

import httpx

from sibyl._config import CRITICAL_LANE_MAX, ExporterConfig
from sibyl._ids import SYSTEM_CLOCK, Clock, uuid7
from sibyl._lanes import Lane, QueuedItem, retry_after_seconds
from sibyl._otlp import LogRecord, logs_request, traces_request
from sibyl._spans import Span
from sibyl._spool import BatchKind, Segment, Spool

log = logging.getLogger("sibyl")

PATHS: Final[dict[BatchKind, str]] = {
    "traces": "/v1/otlp/traces",
    "logs": "/v1/otlp/logs",
    "events": "/v1/events",
}
RETRYABLE: Final = frozenset({429, 502, 503, 504})
MAX_PENDING_BATCHES: Final = 16
MAX_BACKOFF_S: Final = 30.0
BUFFER_REPORT_DROP_STEP: Final = 100


class Sent(Enum):
    OK = "ok"
    DROPPED = "dropped"
    RETRY = "retry"


@dataclass(frozen=True)
class ExporterStats:
    queued_spans: int
    queued_bytes: int
    dropped_spans: int
    spooled_bytes: int
    last_export_at: datetime | None
    last_error: str | None
    backpressure_until: datetime | None
    dropped_by_reason: Mapping[str, int] = field(default_factory=dict)
    exported_batches: int = 0
    rejected_events: int = 0


@dataclass
class _Batch:
    batch_id: str
    kind: BatchKind
    body_gz: bytes
    items: int
    first_failed: float | None = None
    segment: Segment | None = None


EventFinalizer = Callable[[dict[str, Any]], dict[str, Any] | None]
"""Late binding on the worker thread: identity, deferred scrub. None drops the event."""
SpanFinalizer = Callable[[Span], bool]
"""Scrubs deferred span content on the worker thread; False drops the span."""
_LIVE: weakref.WeakSet[Exporter] = weakref.WeakSet()


class Exporter:
    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        config: ExporterConfig,
        resource: Mapping[str, Any],
        sdk_version: str,
        agent_header: Callable[[], str | None] = lambda: None,
        finalize_event: EventFinalizer = lambda event: event,
        finalize_span: SpanFinalizer = lambda span: True,
        clock: Clock = SYSTEM_CLOCK,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._api_key = api_key
        self._cfg = config
        self._resource = dict(resource)
        self._version = sdk_version
        self._agent_header = agent_header
        self._finalize = finalize_event
        self._finalize_span = finalize_span
        self._clock = clock
        self._transport = transport
        self._spool = (
            Spool(config.spool_dir, config.spool_max_bytes, config.spool_max_age.total_seconds())
            if config.spool_dir
            else None
        )
        self._setup_state()
        _LIVE.add(self)
        self._ensure_worker()

    # ---------------------------------------------------------------- state / fork

    def _setup_state(self) -> None:
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._telemetry = Lane(self._cfg.max_queue_spans, self._cfg.max_queue_bytes)
        self._critical = Lane(CRITICAL_LANE_MAX, self._cfg.max_queue_bytes)
        self._pending: deque[_Batch] = deque()
        self._spill: list[QueuedItem] = []
        self._dropped: Counter[str] = Counter()
        self._in_flight = 0
        self._stopping = False
        self._disabled: str | None = None
        self._flush_requested = False
        self._paused_until = 0.0
        self._backoff = 0.0
        self._last_export_at: float | None = None
        self._last_error: str | None = None
        self._last_send_mono = self._clock.monotonic()
        self._last_report_mono = self._clock.monotonic()
        self._dropped_at_report = 0
        self._exported_batches = 0
        self._rejected_events = 0
        self._thread: threading.Thread | None = None
        self._http: httpx.Client | None = None

    def _after_fork_in_child(self) -> None:
        """The child keeps nothing queued by the parent (the parent exports it)."""
        self._setup_state()

    def _ensure_worker(self) -> None:
        if self._thread is not None or self._stopping:
            return
        thread = threading.Thread(target=self._run, name="sibyl-exporter", daemon=True)
        self._thread = thread
        thread.start()

    def _client(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._endpoint,
                timeout=self._cfg.export_timeout.total_seconds(),
                transport=self._transport,
                follow_redirects=False,
            )
        return self._http

    # ---------------------------------------------------------------- caller side

    def enqueue(
        self,
        kind: str,
        payload: Span | LogRecord | dict[str, Any],
        *,
        size: int,
        critical: bool = False,
    ) -> None:
        """O(1) and never blocks beyond a short lock; overflow drops the oldest item."""
        item = QueuedItem(kind=kind, payload=payload, size=size)  # type: ignore[arg-type]
        with self._cv:
            if self._disabled or self._stopping:
                self._dropped["disabled"] += 1
                return
            lane = self._critical if critical and self._cfg.critical_lane else self._telemetry
            evicted = lane.push(item)
            if evicted:
                self._overflow(evicted, critical=lane is self._critical)
            if self._thread is None:
                self._ensure_worker()
            if len(lane) >= self._cfg.batch_size:
                self._cv.notify()

    def _overflow(self, evicted: list[QueuedItem], *, critical: bool) -> None:
        """Called under the lock: critical items spill to the spool on the worker thread."""
        if critical and self._spool is not None:
            self._spill.extend(evicted)
            excess = len(self._spill) - CRITICAL_LANE_MAX
            if excess > 0:
                del self._spill[:excess]
                self._dropped["overflow"] += excess
            return
        self._dropped["overflow"] += len(evicted)

    def flush(self, timeout: float | None = None) -> bool:
        limit = self._cfg.shutdown_flush_timeout.total_seconds() * 5 if timeout is None else timeout
        deadline = self._clock.monotonic() + limit
        with self._cv:
            self._flush_requested = True
            self._cv.notify_all()
            while not self._idle_locked():
                remaining = deadline - self._clock.monotonic()
                if remaining <= 0 or self._thread is None:
                    return self._idle_locked()
                self._cv.wait(timeout=min(remaining, 0.05))
            return True

    def shutdown(self, timeout: float | None = None) -> None:
        limit = self._cfg.shutdown_flush_timeout.total_seconds() if timeout is None else timeout
        started = self._clock.monotonic()
        self.flush(limit)
        with self._cv:
            self._stopping = True
            self._cv.notify_all()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(max(0.0, limit - (self._clock.monotonic() - started)))
        with self._cv:
            leftovers = self._spill + self._critical.clear() + self._telemetry.clear()
            self._spill = []
        if leftovers and self._spool is not None:
            self._spool_items(leftovers)
        elif leftovers:
            self._dropped["shutdown"] += len(leftovers)
        _LIVE.discard(self)

    def disable(self, reason: str) -> None:
        with self._cv:
            self._disabled = reason
            dropped = self._critical.clear() + self._telemetry.clear()
            self._dropped["disabled"] += len(dropped)
            self._cv.notify_all()

    def stats(self) -> ExporterStats:
        with self._cv:
            queued = len(self._critical) + len(self._telemetry)
            queued_bytes = self._critical.bytes + self._telemetry.bytes
            dropped = Counter(self._dropped)
        if self._spool is not None:
            dropped["spool_cap"] += self._spool.dropped_items
        pause = self._paused_until - self._clock.monotonic()
        return ExporterStats(
            queued_spans=queued,
            queued_bytes=queued_bytes,
            dropped_spans=sum(dropped.values()),
            spooled_bytes=self._spool.total_bytes() if self._spool else 0,
            last_export_at=_dt(self._last_export_at),
            last_error=self._last_error,
            backpressure_until=_dt(self._clock.time() + pause) if pause > 0 else None,
            dropped_by_reason=dict(dropped),
            exported_batches=self._exported_batches,
            rejected_events=self._rejected_events,
        )

    def _idle_locked(self) -> bool:
        return (
            not len(self._critical)
            and not len(self._telemetry)
            and not self._pending
            and not self._spill
            and self._in_flight == 0
            and not (self._spool is not None and self._spool.has_segments())
        ) or self._disabled is not None

    # ---------------------------------------------------------------- worker

    def _run(self) -> None:
        delay = self._cfg.schedule_delay.total_seconds()
        while True:
            with self._cv:
                if not self._ready_locked():
                    self._cv.wait(timeout=delay)
                if self._stopping and (self._idle_locked() or self._paused()):
                    self._cv.notify_all()
                    return
                self._in_flight += 1
            try:
                self._cycle()
            except Exception:  # the worker must survive anything
                log.exception("sibyl: exporter cycle failed")
            finally:
                with self._cv:
                    self._in_flight -= 1
                    self._flush_requested = not self._idle_locked() and self._flush_requested
                    self._cv.notify_all()
            if self._paused():
                with self._cv:
                    wait = self._paused_until - self._clock.monotonic()
                    if wait > 0 and not self._stopping:
                        self._cv.wait(timeout=min(wait, delay))

    def _ready_locked(self) -> bool:
        return (
            self._stopping
            or self._flush_requested
            or len(self._critical) >= self._cfg.batch_size
            or len(self._telemetry) >= self._cfg.batch_size
        )

    def _paused(self) -> bool:
        return self._paused_until > self._clock.monotonic()

    def _cycle(self) -> None:
        with self._cv:
            spill, self._spill = self._spill, []
        if spill:
            self._spool_items(spill)
        if self._disabled or self._paused():
            return
        sent_any = self._retry_pending() and self._replay_spool()
        if not sent_any:
            return
        for lane in (self._critical, self._telemetry):
            while True:
                with self._cv:
                    items = lane.take(self._cfg.batch_size)
                if not items:
                    break
                for batch in self._build(items):
                    if self._send(batch) is Sent.RETRY:
                        self._park(batch)
                        return
        self._housekeeping()

    def _retry_pending(self) -> bool:
        while True:
            with self._cv:
                if not self._pending:
                    return True
                batch = self._pending[0]
            if self._expired(batch):
                with self._cv:
                    self._pending.popleft()
                    self._dropped["retry_expired"] += batch.items
                continue
            if self._send(batch) is Sent.RETRY:
                return False
            with self._cv:
                self._pending.popleft()

    def _replay_spool(self) -> bool:
        if self._spool is None:
            return True
        replayed = 0
        dropped_before = self._spool.dropped_items
        for segment in self._spool.segments():
            body = self._spool.read(segment)
            if body is None:
                continue
            batch = _Batch(segment.batch_id, segment.kind, body, segment.items, segment=segment)
            outcome = self._send(batch)
            if outcome is Sent.RETRY:
                return False
            self._spool.remove(segment, dropped=outcome is Sent.DROPPED)
            replayed += segment.items if outcome is Sent.OK else 0
        if replayed:
            self._report(
                "sibyl.sdk.replay",
                {
                    "events_replayed": replayed,
                    "events_dropped": self._spool.dropped_items - dropped_before,
                },
            )
        return True

    def _expired(self, batch: _Batch) -> bool:
        limit = self._cfg.export_timeout.total_seconds() * 3
        return batch.first_failed is not None and (
            self._clock.monotonic() - batch.first_failed > limit
        )

    def _build(self, items: list[QueuedItem]) -> list[_Batch]:
        spans: list[Span] = []
        events: list[dict[str, Any]] = []
        logs: list[LogRecord] = []
        for item in items:
            payload = item.payload
            if isinstance(payload, Span):
                if self._finalize_span(payload):
                    spans.append(payload)
                else:
                    self._count_drop("finalize")
            elif isinstance(payload, LogRecord):
                logs.append(payload)
            else:
                event = self._finalize(dict(payload))
                if event is None:
                    self._count_drop("finalize")
                else:
                    events.append(event)
        batches: list[_Batch] = []
        if spans:
            body = traces_request(spans, self._resource, self._version)
            batches.append(self._batch("traces", body, len(spans)))
        if events:
            batches.append(
                self._batch("events", {"schema": "sibyl-event/1", "events": events}, len(events))
            )
        if logs:
            body = logs_request(logs, self._resource, self._version)
            batches.append(self._batch("logs", body, len(logs)))
        return batches

    def _count_drop(self, reason: str, count: int = 1) -> None:
        with self._cv:
            self._dropped[reason] += count

    def _batch(self, kind: BatchKind, body: dict[str, Any], items: int) -> _Batch:
        raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return _Batch(str(uuid7()), kind, gzip.compress(raw, compresslevel=5), items)

    def _headers(self, batch: _Batch) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "X-Sibyl-Batch-Id": batch.batch_id,
            "User-Agent": f"sibyl-sdk/{self._version} python/{_python_version()}",
        }
        if batch.kind == "events":
            headers["X-Sibyl-Schema"] = "sibyl-event/1"
        agent = self._agent_header()
        if agent:
            headers["X-Sibyl-Agent"] = agent
        return headers

    def _send(self, batch: _Batch) -> Sent:
        try:
            response = self._client().post(
                PATHS[batch.kind], content=batch.body_gz, headers=self._headers(batch)
            )
        except httpx.HTTPError as exc:
            self._last_error = f"{type(exc).__name__}"
            self._back_off(None)
            return Sent.RETRY
        self._last_send_mono = self._clock.monotonic()
        status = response.status_code
        if 200 <= status < 300:
            self._on_success(batch, response)
            return Sent.OK
        self._last_error = f"HTTP {status}"
        if status in RETRYABLE:
            if response.headers.get("x-sibyl-backpressure") == "tenant_erasing":
                self.disable("tenant_erasing")
                return Sent.DROPPED
            self._back_off(retry_after_seconds(response.headers, self._clock.time()))
            return Sent.RETRY
        with self._cv:
            self._dropped[f"rejected_{status}"] += batch.items
        if status in (401, 403):
            log.error("sibyl: ingest refused the API key (HTTP %s); telemetry dropped", status)
        return Sent.DROPPED

    def _on_success(self, batch: _Batch, response: httpx.Response) -> None:
        self._last_export_at = self._clock.time()
        self._exported_batches += 1
        self._backoff = 0.0
        if batch.kind == "events":
            try:
                rejected = response.json().get("rejected", [])
            except (ValueError, AttributeError):
                rejected = []
            self._rejected_events += len(rejected) if isinstance(rejected, list) else 0

    def _back_off(self, retry_after: float | None) -> None:
        if retry_after is None:
            self._backoff = min(MAX_BACKOFF_S, max(1.0, self._backoff * 2))
            wait = self._backoff * (0.5 + random.random() / 2)  # noqa: S311 (jitter)
        else:
            wait = retry_after
        self._paused_until = self._clock.monotonic() + wait

    def _park(self, batch: _Batch) -> None:
        if batch.first_failed is None:
            batch.first_failed = self._clock.monotonic()
        if self._spool is not None:
            self._spool.write(
                batch_id=batch.batch_id,
                kind=batch.kind,
                body_gz=batch.body_gz,
                items=batch.items,
                now_ms=int(self._clock.time() * 1000),
            )
            return
        with self._cv:
            self._pending.append(batch)
            while len(self._pending) > MAX_PENDING_BATCHES:
                self._dropped["retry_overflow"] += self._pending.popleft().items

    def _spool_items(self, items: list[QueuedItem]) -> None:
        if self._spool is None:
            return
        for batch in self._build(items):
            self._spool.write(
                batch_id=batch.batch_id,
                kind=batch.kind,
                body_gz=batch.body_gz,
                items=batch.items,
                now_ms=int(self._clock.time() * 1000),
            )

    # ---------------------------------------------------------------- reports

    def _housekeeping(self) -> None:
        now = self._clock.monotonic()
        with self._cv:
            dropped = sum(self._dropped.values())
        due = now - self._last_report_mono >= self._cfg.buffer_report_interval.total_seconds()
        if due or dropped - self._dropped_at_report >= BUFFER_REPORT_DROP_STEP:
            self._last_report_mono = now
            self._dropped_at_report = dropped
            stats = self.stats()
            self._report(
                "sibyl.sdk.buffer",
                {
                    "sibyl.sdk.dropped_spans": stats.dropped_spans,
                    "sibyl.sdk.buffer_bytes": stats.queued_bytes,
                    "sibyl.sdk.spool_bytes": stats.spooled_bytes,
                },
            )
        idle = now - self._last_send_mono >= self._cfg.heartbeat_interval.total_seconds()
        if idle and not self._paused():
            self._heartbeat()

    def _report(self, name: str, attributes: dict[str, Any]) -> None:
        attrs = {**attributes, "sibyl.emitter_id": str(self._resource.get("sibyl.emitter_id"))}
        record = LogRecord(event_name=name, time_ns=int(self._clock.time() * 1e9), attributes=attrs)
        self.enqueue("log", record, size=record.approx_bytes, critical=True)

    def _heartbeat(self) -> None:
        """R28: an idle emitter sends an empty OTLP batch so ingest can detect gaps."""
        batch = self._batch("traces", traces_request([], self._resource, self._version), 0)
        if self._send(batch) is Sent.RETRY:
            return


def _dt(epoch: float | None) -> datetime | None:
    return None if epoch is None else datetime.fromtimestamp(epoch, tz=UTC)


def _python_version() -> str:
    import platform

    return platform.python_version()


def _reinit_after_fork() -> None:
    for exporter in list(_LIVE):
        exporter._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reinit_after_fork)
