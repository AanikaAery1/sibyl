"""Pre-registered worker loop table (ROADMAP §4.1). No lane edits this file.

Each lane implements ``async def tick(ctx: LoopContext) -> None`` at the target named here, in
its own directory (``worker/rollup/``, ``worker/saga/`` …). Until then the loop resolves to
``None`` and the runner reports it as not implemented. A tick does one bounded unit of work per
tenant (``ctx.db.tenant_tx`` per tenant, never a cross-tenant query) and returns.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

POLICY_CHANNEL = "sibyl_policy"
OUTBOX_CHANNEL = "sibyl_outbox"
_W = "sibyl_control.worker"


@dataclass(frozen=True)
class LoopContext:
    name: str
    db: Any  # core.db.Database
    settings: Any  # core.settings.Settings
    log: logging.Logger


Tick = Callable[[LoopContext], Awaitable[None]]


@dataclass(frozen=True)
class LoopSpec:
    name: str
    owner: str  # lane
    interval_s: float
    target: str  # "module.path:function"
    channel: str | None = None  # NOTIFY channel that wakes the loop early
    note: str = ""
    timeout_s: float | None = None  # per-tick deadline; default max(60 s, interval)

    def __post_init__(self) -> None:
        if self.interval_s <= 0:
            raise ValueError("interval_s must be positive")
        if self.timeout_s is not None and self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")


LOOPS: tuple[LoopSpec, ...] = (
    LoopSpec("rollup", "H", 10, f"{_W}.rollup:tick", note="events -> agent_metrics_*"),
    LoopSpec("scoring", "H", 10, f"{_W}.scoring:tick", note="health_snapshot, alerts R1-R8"),
    LoopSpec("status_poller", "H", 60, f"{_W}.status_poller:tick", note="provider_status"),
    LoopSpec("predict", "P", 10, f"{_W}.predict:tick", note="L1-L7 horizons, prediction rows"),
    LoopSpec("alerts", "P", 10, f"{_W}.alerts:tick", note="alert lifecycle, hysteresis"),
    LoopSpec("saga", "S", 1, f"{_W}.saga:tick", OUTBOX_CHANNEL, "failover steps, SKIP LOCKED"),
    LoopSpec("approvals", "S", 5, f"{_W}.approvals:tick", note="approval timeouts (D13/D22)"),
    LoopSpec("failback", "S", 30, f"{_W}.failback:tick", note="failback probe and canary"),
    LoopSpec("handoff", "S", 30, f"{_W}.handoff:tick", note="task build and expiry"),
    LoopSpec("partitions", "U", 3600, f"{_W}.housekeeping.partitions:tick"),
    LoopSpec("retention", "U", 3600, f"{_W}.housekeeping.retention:tick"),
    LoopSpec(
        "anchors",
        "U",
        3600,
        f"{_W}.housekeeping.anchors:tick",
        OUTBOX_CHANNEL,
        "hourly anchors; audit.anchor_now (break-glass) within 10 s",
    ),
    LoopSpec("erasure_exec", "U", 10, f"{_W}.housekeeping.erasure_exec:tick"),
    LoopSpec("erasure_ledger", "U", 60, f"{_W}.housekeeping.erasure_ledger:tick"),
    LoopSpec(
        "jobs",
        "INT-1",
        2,
        f"{_W}.jobs:tick",
        OUTBOX_CHANNEL,
        "async jobs (B14): credential probe, audit verify/export; job.requested wakes it",
    ),
    LoopSpec(
        "held_actions",
        "AG-CORE",
        5,
        f"{_W}.held_actions:tick",
        note="D48 Action Gate: expire pending holds as deny at hold_timeout_s",
    ),
    LoopSpec("drift", "DRIFT", 60, f"{_W}.drift:tick", note="D51 model drift, watch-only alerts"),
    LoopSpec(
        "sentinel",
        "SENTINEL",
        60,
        f"{_W}.sentinel:tick",
        note="D52 Sibyl Sentinel: advisory findings on the tenant's own LLM key (opt-in, budgeted)",
        timeout_s=600,
    ),
    LoopSpec("action_counters", "AG-LIVE", 3600, f"{_W}.held_actions.counters:tick"),
    LoopSpec(
        "webhooks",
        "EXTMON",
        5,
        f"{_W}.webhooks:tick",
        OUTBOX_CHANNEL,
        "D53 monitor webhooks: external_finding alerts, signed deliveries with retries",
        timeout_s=120,
    ),
)


def resolve_tick(spec: LoopSpec) -> Tick | None:
    """Import the tick; a module the owning lane has not written yet resolves to ``None``."""
    module_name, _, attr = spec.target.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name and module_name.startswith(exc.name):
            return None
        raise
    tick = getattr(module, attr, None)
    return tick if callable(tick) else None
