"""`Client`: one per process, owning the exporter, the policy poller and the scrubber."""

from __future__ import annotations

import atexit
import itertools
import logging
import os
import socket
import threading
from collections.abc import Sequence
from datetime import timedelta
from typing import Any
from uuid import UUID

import httpx

from sibyl._actions import ActionConfig, ActionEnforcer
from sibyl._config import Settings
from sibyl._emit import envelope, finalize_event, finalize_span
from sibyl._exporter import Exporter, ExporterStats
from sibyl._ids import SYSTEM_CLOCK, Clock, is_uuid, rfc3339
from sibyl._policy import Decision, PolicyManager
from sibyl._scrub import ScrubHook, ScrubPipeline
from sibyl._snapshot import PolicySnapshot
from sibyl._spans import KIND_INTERNAL, Span, SpanContext, current_context
from sibyl._types import CaptureMode, most_restrictive
from sibyl._version import __version__

log = logging.getLogger("sibyl")


class Client:
    """Handle returned by `sibyl.init()`; safe to share across threads."""

    def __init__(
        self,
        settings: Settings,
        *,
        hooks: Sequence[ScrubHook] = (),
        clock: Clock = SYSTEM_CLOCK,
        transport: httpx.BaseTransport | None = None,
        start: bool = True,
        actions: ActionConfig | None = None,
    ) -> None:
        self.settings = settings
        self.clock = clock
        self.endpoint = settings.endpoint
        self.emitter_id = f"sdk:{socket.gethostname()[:64]}:{os.getpid()}"
        self._seq = itertools.count(1)
        self._seq_lock = threading.Lock()
        self._refused: str | None = None
        self.scrub = ScrubPipeline(settings.scrub_salt, hooks)
        resource: dict[str, Any] = {
            "service.name": settings.resource_attributes.get("service.name", "sibyl-agent"),
            "telemetry.sdk.name": "sibyl-sdk",
            "telemetry.sdk.language": "python",
            "telemetry.sdk.version": __version__,
            "sibyl.sdk.version": __version__,
            "sibyl.emitter_id": self.emitter_id,
            "sibyl.env": settings.env,
            **settings.resource_attributes,
        }
        if settings.agent_ref:
            resource["sibyl.agent_id"] = settings.agent_ref
        self.exporter = Exporter(
            endpoint=settings.endpoint,
            api_key=settings.api_key,
            config=settings.exporter,
            resource=resource,
            sdk_version=__version__,
            agent_header=self.agent_header,
            finalize_event=lambda event: finalize_event(self, event),
            finalize_span=lambda span: finalize_span(self, span),
            clock=clock,
            transport=transport,
        )
        self.policy = PolicyManager(
            settings,
            clock=clock,
            transport=transport,
            emit_decision=self._emit_decision,
            on_forbidden_key=self._refuse_key,
        )
        self.actions = ActionEnforcer(self, actions or ActionConfig(), transport=transport)
        self._closed = False
        if start:
            self.policy.start()
        atexit.register(self._atexit)

    # ------------------------------------------------------------------ identity

    @property
    def snapshot(self) -> PolicySnapshot | None:
        return self.policy.current()

    @property
    def agent_id(self) -> UUID | None:
        snap = self.snapshot
        if snap is not None:
            return snap.agent_id
        ref = self.settings.agent_ref
        return UUID(ref) if ref and is_uuid(ref) else None

    @property
    def tenant_id(self) -> UUID | None:
        snap = self.snapshot
        return snap.tenant_id if snap is not None else None

    @property
    def capture_mode(self) -> CaptureMode:
        """D12: explicit `init()` mode, tightened by the registry's agent policy."""
        snap = self.snapshot
        if snap is None:
            return self.settings.capture_mode
        return most_restrictive(self.settings.capture_mode, snap.capture_mode)

    def agent_header(self) -> str | None:
        agent = self.agent_id
        return str(agent) if agent else self.settings.agent_ref

    def agent_name(self) -> str:
        snap = self.snapshot
        return snap.slug if snap else (self.settings.agent_ref or "agent")

    def next_seq(self) -> int:
        with self._seq_lock:
            return next(self._seq)

    def policy_state(self) -> dict[str, Any]:
        attrs = self.policy.policy_attributes()
        state: dict[str, Any] = {"state": attrs["sibyl.policy.state"]}
        if "sibyl.policy.version" in attrs:
            state["policy_version"] = attrs["sibyl.policy.version"]
        state["fail_mode"] = attrs["sibyl.policy.fail_mode"]
        if "sibyl.policy.snapshot_age_s" in attrs:
            state["snapshot_age_s"] = attrs["sibyl.policy.snapshot_age_s"]
        return state

    # ------------------------------------------------------------------ emission

    def start_span(
        self,
        name: str,
        *,
        kind: int = KIND_INTERNAL,
        critical: bool = False,
        parent: SpanContext | None = None,
        capture_mode: CaptureMode | None = None,
    ) -> Span:
        span = Span(
            name,
            kind=kind,
            parent=parent or current_context(),
            critical=critical,
            on_end=self._on_span_end,
        )
        mode = (
            most_restrictive(capture_mode, self.capture_mode)
            if capture_mode
            else (self.capture_mode)
        )
        span.set_many(
            {
                "sibyl.source": "sdk",
                "sibyl.emitter_id": self.emitter_id,
                "sibyl.seq": self.next_seq(),
                "sibyl.env": self.settings.env,
                "sibyl.capture.mode": mode,
                "sibyl.sdk.version": __version__,
                **self.policy.policy_attributes(),
            }
        )
        agent = self.agent_header()
        if agent:
            span.set("sibyl.agent_id", agent)
        return span

    def _on_span_end(self, span: Span) -> None:
        if self._closed:
            return
        self.exporter.enqueue("span", span, size=span.approx_bytes, critical=span.critical)

    def emit_event(self, event: dict[str, Any], *, critical: bool = False) -> None:
        if self._closed:
            return
        size = 512 + sum(len(str(v)) for v in event["attrs"].values())
        self.exporter.enqueue("event", event, size=size, critical=critical)

    def _emit_decision(self, decision: Decision) -> None:
        attrs = {k: v for k, v in decision.items() if k != "snapshot_issued_at"}
        issued = decision.get("snapshot_issued_at")
        if issued is not None:
            attrs["snapshot_issued_at"] = rfc3339(issued.timestamp())
        ctx = current_context()
        self.emit_event(
            envelope(self, "policy.decision", attrs, trace_id=ctx.trace_id if ctx else None),
            critical=True,
        )

    def _refuse_key(self, reason: str) -> None:
        if self._refused is None:
            self._refused = reason
            log.error("sibyl: %s; telemetry disabled (use an ingest key)", reason)
            self.exporter.disable("forbidden_key_scope")

    # ------------------------------------------------------------------ lifecycle

    def has_scope(self, scope: str) -> bool | None:
        snap = self.snapshot
        return None if snap is None or not snap.key_scopes else scope in snap.key_scopes

    def flush(self, timeout: timedelta | None = None) -> bool:
        return self.exporter.flush(None if timeout is None else timeout.total_seconds())

    def shutdown(self, timeout: timedelta | None = None) -> None:
        if self._closed:
            return
        seconds = (
            self.settings.exporter.shutdown_flush_timeout.total_seconds()
            if timeout is None
            else timeout.total_seconds()
        )
        self.policy.stop(min(seconds, 0.5))
        self.actions.close()
        self.exporter.shutdown(seconds)
        self._closed = True
        atexit.unregister(self._atexit)

    def _atexit(self) -> None:
        self.shutdown()

    def stats(self) -> ExporterStats:
        return self.exporter.stats()
