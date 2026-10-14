"""Worker loops for the in-process stack: the product's `LOOPS` table, run by the product's
`LoopRunner`, with one adapter.

`status_poller.tick` reads its feed allowlist from `SIBYL_STATUS_*` env and trusts the system
CA store; in-process the doubles serve the feeds over https with a per-run dev CA, so the
adapter calls the same `poll()` with that CA and the doubles' host allowlisted. No other loop
is touched. Cadences stay the product's unless `eval_tick_s` is set (the dev-only equivalent
of `SIBYL_EVAL_TICK_S`, R45: never a clock override).

Drift (D51) freezes a baseline only after 6 h and >= 500 calls and judges 1 h windows, which no
harness run can reach on the wall clock. A scenario that declares a `drift:` block (S-31) runs
the product's own `drift.runner.run_tenant` with those windows scaled down (`DriftConfig`
values only; same detector, same clock, same alerts). Every other scenario runs the product
drift loop untouched.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sibyl_control.core.ratelimit import InMemoryRateLimiter, RateDecision, RatePolicy
from sibyl_control.core.settings import Settings
from sibyl_control.worker.loops import LOOPS, LoopSpec
from sibyl_control.worker.status_poller import PollerSettings, poll
from sibyl_control.worker.status_poller.fetch import FetchPolicy

STATUS_ADAPTER = "sibyl_sim.harness.inprocess.loops:status_poller"
DRIFT_ADAPTER = "sibyl_sim.harness.inprocess.loops:drift"
DRIFT_DURATIONS = frozenset({"baseline_min_span", "baseline_max_span", "eval_window", "eval_every"})
DRIFT_COUNTS = frozenset(
    {"baseline_min_samples", "eval_min_samples", "tool_min_samples", "identity_min_count"}
    | {"raise_after", "clear_after", "identity_clear_after"}
)
EVAL_LOOPS = frozenset({"rollup", "scoring", "predict", "alerts"})


class HarnessWorkerSettings(Settings):
    """Control settings plus what the status-poller adapter needs (never read from env)."""

    sim_ca_file: str | None = None
    sim_dev_hosts: tuple[str, ...] = ()
    sim_drift: dict[str, float] | None = None  # scaled DriftConfig values (S-31), else None


async def status_poller(ctx: Any) -> None:
    settings: HarnessWorkerSettings = ctx.settings
    verify: ssl.SSLContext | bool = (
        ssl.create_default_context(cafile=settings.sim_ca_file) if settings.sim_ca_file else True
    )
    hosts = frozenset(h.lower() for h in settings.sim_dev_hosts)
    async with httpx.AsyncClient(follow_redirects=False, trust_env=False, verify=verify) as client:
        result = await poll(
            ctx.db,
            client=client,
            policy=FetchPolicy(dev_hosts=hosts),
            settings=PollerSettings(dev_hosts=sorted(hosts)),
        )
    if result.failed:
        ctx.log.warning("status poller: %d feed(s) failed", result.failed)


def drift_config(overrides: Mapping[str, float]) -> Any:
    """The product's `DriftConfig` with scaled windows (`*_s` keys are seconds)."""
    from sibyl_control.worker.drift.config import DEFAULT_CONFIG

    values: dict[str, Any] = {}
    for key, value in overrides.items():
        name = key.removesuffix("_s")
        if name in DRIFT_DURATIONS:
            values[name] = timedelta(seconds=float(value))
        elif name in DRIFT_COUNTS:
            values[name] = int(value)
        else:
            raise ValueError(f"unknown drift setting {key!r}")
    return replace(DEFAULT_CONFIG, **values)


async def drift(ctx: Any) -> None:
    """`worker.drift.tick` with the scenario's scaled `DriftConfig` (see the module doc)."""
    from sibyl_control.worker.drift.runner import run_tenant
    from sibyl_control.worker.rollup.tenancy import active_tenants, try_lock

    cfg = drift_config(ctx.settings.sim_drift or {})
    for tenant in await active_tenants(ctx.db):
        try:
            async with ctx.db.tenant_tx(tenant) as conn:
                if await try_lock(conn, "drift", tenant):
                    await run_tenant(conn, tenant, cfg=cfg)
        except Exception:
            ctx.log.exception("sim drift loop failed for tenant %s", tenant)


def harness_specs(
    *,
    eval_tick_s: float | None = None,
    status_poll_s: float | None = None,
    drift: Mapping[str, float] | None = None,
) -> tuple[LoopSpec, ...]:
    specs: list[LoopSpec] = []
    for spec in LOOPS:
        if spec.name == "status_poller":
            spec = replace(spec, target=STATUS_ADAPTER, interval_s=status_poll_s or spec.interval_s)
        elif spec.name == "drift" and drift:
            every = float(drift.get("eval_every_s", spec.interval_s))
            spec = replace(spec, target=DRIFT_ADAPTER, interval_s=min(spec.interval_s, every))
        elif eval_tick_s is not None and spec.name in EVAL_LOOPS:
            spec = replace(spec, interval_s=eval_tick_s)
        specs.append(spec)
    return tuple(specs)


class SwitchableLimiter:
    """The production limiter, plus a switch that makes ingest's own backpressure path answer
    `tenant_rate_limit` for chosen tenants (S-19). The 429, its headers and the SDK's retry are
    the product's; only the load is simulated."""

    def __init__(self, inner: InMemoryRateLimiter | None = None) -> None:
        self._inner = inner or InMemoryRateLimiter()
        self._paused_until: dict[str, datetime] = {}
        self.denied = 0

    def pause(self, tenant_id: str, until: datetime) -> None:
        self._paused_until[f"tenant:{tenant_id}"] = until

    def resume(self, tenant_id: str) -> None:
        self._paused_until.pop(f"tenant:{tenant_id}", None)

    def _paused(self, key: str, policy: RatePolicy) -> RateDecision | None:
        until = self._paused_until.get(key)
        if policy.name != "ingest_tenant_events" or until is None:
            return None
        left = (until - datetime.now(UTC)).total_seconds()
        if left <= 0:
            self._paused_until.pop(key, None)
            return None
        self.denied += 1
        return RateDecision(False, policy, 0, max(1, int(left)), max(1, int(left)))

    async def hit(self, key: str, policy: RatePolicy, cost: int = 1) -> RateDecision:
        return self._paused(key, policy) or await self._inner.hit(key, policy, cost)

    async def peek(self, key: str, policy: RatePolicy) -> RateDecision:
        return self._paused(key, policy) or await self._inner.peek(key, policy)


Clock = Callable[[], datetime]
__all__: Sequence[str] = ("HarnessWorkerSettings", "SwitchableLimiter", "harness_specs")
