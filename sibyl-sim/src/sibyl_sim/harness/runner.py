"""Run one scenario at one seed against a running stack and judge it.

    lanes -> plans + ground truth -> SSE up -> actors + chaos + personas + health polls
          -> stop traffic -> settle -> final reads -> verdicts -> gates -> golden -> artefacts

The stack is anything with `world`, `endpoints` and the harness hooks (`StackHandle`): the
in-process stack today, compose URLs later. The runner itself only speaks HTTP.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpx

from ..actors import history
from ..actors.agents import Actor, GatewayActor, SdkActor
from ..actors.personas import PersonaRunner
from ..actors.traffic import Arrival, plan_arrivals
from ..golden import series as golden
from ..oracle.predicates import Verdict, evaluate_all, missing_lanes
from ..oracle.reader import STREAM_PERSONA, ApiReader, SseCollector, window_start
from ..oracle.record import RunRecord, SseEvent
from ..oracle.timing import MAX_DATA_LAG_S, MAX_DILATION
from ..reports.gates import RunOutcome, gate_run, run_status
from ..scenarios.model import AgentRef, Scenario
from .budgets import apply_budgets, apply_cadences
from .chaos import ChaosDriver
from .clock import RunClock
from .labels import write_ground_truth
from .lag import LagMeter
from .world import Endpoints, World

log = logging.getLogger("sibyl_sim.harness")
SSE_CONNECT_TIMEOUT_S = 15.0
API_TIMEOUT_S = 30.0
PHASE_1_5 = "requires Phase 1.5 (ROADMAP §3.4 cut)"
LANE_LOOPS: Mapping[str, tuple[str, ...]] = {
    "S": ("saga", "approvals", "failback", "handoff"),
    "P": ("predict", "alerts"),
    "U": ("anchors",),
}


class StackHandle(Protocol):
    world: World | None
    endpoints: Endpoints | None

    def pause_ingest(self, tenant_id: str, seconds: float) -> None: ...

    def loop_status(self) -> dict[str, Any]: ...


@dataclass
class RunOptions:
    out_dir: Path
    update_golden: bool = False
    golden_root: Path = golden.DATA_DIR
    tolerance: golden.Tolerance = field(default_factory=golden.Tolerance)
    force_lanes: Mapping[str, bool] | None = None  # tests only


class _Hooks:
    def __init__(self, stack: StackHandle, world: World, actors: dict[AgentRef, Actor]) -> None:
        self.stack, self.world, self.actors = stack, world, actors

    def pause_ingest(self, tenant: str, seconds: float) -> None:
        self.stack.pause_ingest(str(self.world.tenant(tenant).id), seconds)

    def actor_set(self, ref: AgentRef, patch: dict[str, Any]) -> None:
        actor = self.actors.get(ref)
        if actor is not None:
            actor.set(patch)

    def agents_of(self, tenant: str) -> list[AgentRef]:
        return [AgentRef(tenant, slug) for slug in sorted(self.world.tenant(tenant).agents)]


def available_lanes(probed: Mapping[str, bool], loops: Mapping[str, Any]) -> dict[str, bool]:
    """A lane is present when its API answers (no 501) and, in-process, its loops exist."""
    out = {}
    for lane, ok in probed.items():
        needed = LANE_LOOPS.get(lane, ())
        implemented = all((loops.get(name) or {}).get("implemented", True) for name in needed)
        out[lane] = bool(ok and (implemented if loops else True))
    return out


def plans_for(scenario: Scenario, world: World, seed: int) -> dict[AgentRef, list[Arrival]]:
    plans: dict[AgentRef, list[Arrival]] = {}
    for tenant in world.tenants.values():
        plan = scenario.tenant(tenant.slug)
        for slug in sorted(tenant.agents):
            ref = AgentRef(tenant.slug, slug)
            profile = scenario.profile(plan.agents.get(slug, plan.default_profile))
            plans[ref] = plan_arrivals(
                seed, scenario.id, ref, profile, duration_s=scenario.duration_s
            )
    return plans


async def run_scenario(
    scenario: Scenario, seed: int, stack: StackHandle, opts: RunOptions
) -> RunOutcome:
    started = time.monotonic()
    if scenario.phase != "1":
        return RunOutcome(scenario.id, seed, "skip", reason=PHASE_1_5)
    world, endpoints = stack.world, stack.endpoints
    assert world is not None and endpoints is not None
    run_dir = opts.out_dir / f"{scenario.id}-{seed}"
    run_dir.mkdir(parents=True, exist_ok=True)
    verify: ssl.SSLContext | bool = (
        ssl.create_default_context(cafile=endpoints.ca_file) if endpoints.ca_file else True
    )
    limits = httpx.Limits(max_connections=400, max_keepalive_connections=100)
    async with (
        # 30 s: the api waits for a database connection under load; a person waits too
        httpx.AsyncClient(trust_env=False, limits=limits, timeout=API_TIMEOUT_S) as api_client,
        httpx.AsyncClient(trust_env=False, verify=verify, limits=limits) as upstream,
    ):
        clock = RunClock()
        reader = ApiReader(api_client, endpoints.api, world, clock)
        probed = opts.force_lanes or await reader.probe_lanes()
        lanes = available_lanes(probed, stack.loop_status() if opts.force_lanes is None else {})
        missing = missing_lanes(scenario.requires, lanes)
        if missing:
            reason = f"requires {', '.join(missing)} (lane not merged; allowlisted until G2)"
            return RunOutcome(scenario.id, seed, "skip", reason=reason)
        rec = await _drive(
            scenario, seed, stack, world, endpoints, api_client, upstream, clock, lanes, run_dir
        )
    verdicts = evaluate_all(scenario, rec) + persona_verdicts(rec.persona_log)
    gates = gate_run(scenario, rec, verdicts)
    outcome = RunOutcome(scenario.id, seed, run_status(verdicts, gates), verdicts, gates)
    outcome.summary = _summary(rec)
    sanity = _sanity(scenario, rec)
    if sanity:
        outcome.status = "error"
        outcome.reason = "; ".join(sanity)
    doc = golden.canonical(scenario, rec)
    (run_dir / "series.json").write_text(json.dumps(doc, indent=1, sort_keys=True), "utf-8")
    known = golden.load(opts.golden_root, scenario.id, seed)
    if opts.update_golden and outcome.status != "error":
        golden.save(opts.golden_root, scenario.id, seed, doc)
    elif known is not None:
        outcome.golden = golden.compare(known, doc, opts.tolerance)
    outcome.wall_s = round(time.monotonic() - started, 1)
    _write_record(run_dir, rec, outcome)
    return outcome


async def _drive(
    scenario: Scenario,
    seed: int,
    stack: StackHandle,
    world: World,
    endpoints: Endpoints,
    api_client: httpx.AsyncClient,
    upstream: httpx.AsyncClient,
    clock: RunClock,
    lanes: dict[str, bool],
    run_dir: Path,
) -> RunRecord:
    plans = plans_for(scenario, world, seed)
    providers = {ref: world.tenant(ref.tenant).agent(ref.slug).provider for ref in plans}
    write_ground_truth(run_dir, scenario, seed, plans, providers)
    rec = RunRecord(
        scenario.id,
        seed,
        datetime.now(UTC).isoformat(timespec="seconds"),
        scenario.duration_s,
        world,
        lanes=dict(lanes),
    )
    stop = asyncio.Event()
    sse_tasks, collectors = [], []
    for tenant in world.tenants.values():
        persona = STREAM_PERSONA[tenant.slug]
        collector = SseCollector(
            api_client, endpoints.api, tenant.slug, tenant.token(persona), clock, rec.sse
        )
        collectors.append(collector)
        sse_tasks.append(asyncio.create_task(collector.run(stop)))
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(
            asyncio.gather(*(c.connected.wait() for c in collectors)), SSE_CONNECT_TIMEOUT_S
        )
    if not all(c.connected.is_set() for c in collectors):
        rec.notes.append(
            "SSE: not every tenant stream connected: " + str([c.errors for c in collectors])
        )
    if scenario.warmup_min:
        replayed = await history.replay(
            api_client,
            endpoints,
            world,
            seed=seed,
            scenario=scenario.id,
            minutes=scenario.warmup_min,
            per_agent=scenario.warmup_agents,
        )
        warm = await _wait_warm(ApiReader(api_client, endpoints.api, world, clock), world)
        rec.notes.append(f"warm-up: {replayed} history events replayed; warm={warm}")
    clock = RunClock()  # t = 0 is when traffic starts
    for c in collectors:
        c.clock = clock
    rec.sse.clear()  # warm-up frames are not part of the scenario
    if scenario.budgets:  # after the warm-up, so budget alerts fire inside the scenario
        rec.notes.extend(await apply_budgets(api_client, endpoints.api, world, scenario.budgets))
    if scenario.cadences:  # after the warm-up too: R9 judges silence inside the scenario only
        rec.notes.extend(await apply_cadences(api_client, endpoints.api, world, scenario.cadences))
    reader = ApiReader(api_client, endpoints.api, world, clock)
    actors = _actors(scenario, world, endpoints, plans, clock, upstream)
    hooks = _Hooks(stack, world, actors)
    sim_client = httpx.AsyncClient(base_url=endpoints.sim_control, trust_env=False)
    driver = ChaosDriver(sim_client, hooks)
    personas = PersonaRunner(api_client, endpoints.api, world, clock)
    timeline: list[dict[str, Any]] = []
    actor_stop = asyncio.Event()
    meter = LagMeter(stack, clock)
    meter_stop = asyncio.Event()
    meter_task = asyncio.create_task(meter.run(meter_stop))
    try:
        await _reset_sim(sim_client)
        actor_tasks = [asyncio.create_task(a.run(actor_stop)) for a in actors.values()]
        side = [
            asyncio.create_task(_chaos(scenario, driver, clock, timeline)),
            asyncio.create_task(_personas(scenario, personas, clock, lanes, timeline)),
            asyncio.create_task(_poll_health(scenario, reader, clock, rec, actor_stop)),
        ]
        await clock.until(scenario.duration_s)
        actor_stop.set()
        await asyncio.gather(*actor_tasks, return_exceptions=True)
        for task in side:
            task.cancel()
        await asyncio.gather(*side, return_exceptions=True)
        await asyncio.gather(*(a.close() for a in actors.values()), return_exceptions=True)
        await clock.until(scenario.duration_s + scenario.settle_s)
        meter_stop.set()
        await meter_task
        await _end_personas(scenario, personas, lanes, timeline)
        await _final_reads(scenario, reader, rec, clock, lanes)
    finally:
        meter_stop.set()
        stop.set()
        for task in sse_tasks:
            task.cancel()
        await asyncio.gather(*sse_tasks, return_exceptions=True)
        await sim_client.aclose()
    rec.actors = {ref: a.stats for ref, a in actors.items()}
    rec.timing = meter.result(_pre_stimulus_lateness(scenario, rec))
    rec.persona_log = personas.log
    rec.sse.sort(key=lambda e: e.t)
    _write_timeline(run_dir, timeline, rec)
    return rec


CRITICAL_VERBS = frozenset(
    {"self_approve", "label_write_attempt"}
)  # four eyes, the Auditor read-only


def persona_verdicts(log: list[dict[str, Any]]) -> list[Verdict]:
    """Each persona call is judged: its `expect_status` if the script names one (409
    self_approval, 422 verdict_required, 403 for the Auditor), otherwise a 2xx."""
    out = []
    for row in log:
        want = row.get("expect_status")
        got = int(row.get("status") or 0)
        ok = got == int(want) if want is not None else 200 <= got < 300
        severity = "CRITICAL" if row["verb"] in CRITICAL_VERBS else "HIGH"
        name = f"persona({row['persona']}.{row['verb']}@{row['t']:.0f})"
        detail = f"{row['verb']} -> {got} {row.get('code') or ''}".strip()
        if want is not None:
            detail += f" (want {want})"
        out.append(Verdict(name, "persona", severity, "pass" if ok else "fail", detail))
    return out


WARM_TIMEOUT_S = 120.0
WARM_REQUESTS = 50  # ML §3.8 min_requests_1h
WARM_SCORING_S = 12.0  # one scoring tick (10 s) plus jitter


async def _wait_warm(reader: ApiReader, world: World) -> bool:
    """Until one agent per active tenant has left provisional (rollup + scoring caught up)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WARM_TIMEOUT_S
    probes = [AgentRef(t.slug, sorted(t.agents)[0]) for t in world.tenants.values() if t.agents]
    while loop.time() < deadline:
        counts = [await reader.requests_last_hour(ref) for ref in probes]
        if all(n >= WARM_REQUESTS for n in counts):
            # rollup has the hour; one scoring tick later the engine sees a warm agent (the
            # API's provisional flag can lag up to the 60 s snapshot heartbeat)
            await asyncio.sleep(WARM_SCORING_S)
            return True
        await asyncio.sleep(2)
    return False


def _actors(
    scenario: Scenario,
    world: World,
    endpoints: Endpoints,
    plans: Mapping[AgentRef, list[Arrival]],
    clock: RunClock,
    upstream: httpx.AsyncClient,
) -> dict[AgentRef, Actor]:
    actors: dict[AgentRef, Actor] = {}
    for ref, plan in plans.items():
        tenant = world.tenant(ref.tenant)
        tplan = scenario.tenant(ref.tenant)
        profile = scenario.profile(tplan.agents.get(ref.slug, tplan.default_profile))
        if not plan:
            continue
        info = tenant.agent(ref.slug)
        args = (ref, info, tenant, profile, list(plan), endpoints, clock)
        if profile.via == "sdk":
            actors[ref] = SdkActor(*args, client=upstream, pin=endpoints.sdk_pin)
        else:
            actors[ref] = GatewayActor(*args, client=upstream)
    return actors


async def _reset_sim(client: httpx.AsyncClient) -> None:
    for name in ("openai-stub", "anthropic-stub", "ollama-stub"):
        await client.post(f"/_sim/doubles/{name}/reset", json={})
    for feed in ("openai", "anthropic", "ollama"):
        await client.post(f"/_sim/status/{feed}/reset", json={})


async def _chaos(
    scenario: Scenario, driver: ChaosDriver, clock: RunClock, timeline: list[dict[str, Any]]
) -> None:
    for step in scenario.chaos:
        await clock.until(step.at)
        row = await driver.apply(step)
        timeline.append({"row": "chaos", "t_applied": clock.now(), **row})


async def _personas(
    scenario: Scenario,
    personas: PersonaRunner,
    clock: RunClock,
    lanes: Mapping[str, bool],
    timeline: list[dict[str, Any]],
) -> None:
    for step in sorted((s for s in scenario.personas if s.at != "end"), key=lambda s: float(s.at)):
        if missing_lanes(step.requires, lanes):
            continue
        await clock.until(float(step.at))
        timeline.append({"row": "persona", **await personas.run(step)})


async def _end_personas(
    scenario: Scenario,
    personas: PersonaRunner,
    lanes: Mapping[str, bool],
    timeline: list[dict[str, Any]],
) -> None:
    for step in scenario.personas:
        if step.at == "end" and not missing_lanes(step.requires, lanes):
            timeline.append({"row": "persona", **await personas.run(step)})


def _tracked(scenario: Scenario) -> list[AgentRef]:
    return golden.tracked(scenario)


async def _poll_health(
    scenario: Scenario, reader: ApiReader, clock: RunClock, rec: RunRecord, stop: asyncio.Event
) -> None:
    refs = _tracked(scenario)
    while not stop.is_set():
        for ref in refs:
            read = await reader.health(ref)
            if read is not None:
                rec.health.setdefault(ref, []).append(read)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), scenario.health_poll_s)


async def _final_reads(
    scenario: Scenario, reader: ApiReader, rec: RunRecord, clock: RunClock, lanes: dict[str, bool]
) -> None:
    for tenant in rec.world.tenants:
        rec.listed_agents[tenant] = await reader.list_agents(tenant)
        for slug in sorted(rec.world.tenant(tenant).agents):
            ref = AgentRef(tenant, slug)
            read = await reader.health(ref)
            if read is not None:
                rec.health.setdefault(ref, []).append(read)
    since = window_start(clock.started_wall)
    wanted = {
        AgentRef.parse(e.args["agent"])
        for e in scenario.expect
        if e.predicate in ("event_seen", "no_duplicates") and "agent" in e.args
    }
    for e in scenario.expect:  # observed: the tenant's own traffic, stored since t = 0
        if e.predicate == "observed":
            wanted |= {
                AgentRef(e.args["tenant"], s) for s in rec.world.tenant(e.args["tenant"]).agents
            }
    for ref in sorted(wanted):
        rec.events[ref] = await reader.events(ref, since)
    if lanes.get("S"):
        for ref in _tracked(scenario):
            rec.transitions[ref] = await reader.transitions(ref, clock.started_wall)
    rec.cross_reads = await reader.cross_reads()
    rec.lane_reads = await reader.lane_reads(lanes, clock.started_wall)
    rec.lane_reads["evidence"] = await reader.evidence(rec.health)


def _pre_stimulus_lateness(scenario: Scenario, rec: RunRecord) -> list[float]:
    """How late actors sent arrivals planned before the first chaos step (the whole run when
    there is none): host lag, not a backlog the scenario's own chaos built (B38)."""
    first = min((float(c.at) for c in scenario.chaos), default=float(scenario.duration_s))
    return [late for s in rec.actors.values() for t, late in s.late if t < first]


def _sanity(scenario: Scenario, rec: RunRecord) -> list[str]:
    """The harness checks itself: a run whose chaos was refused or whose traffic never flowed
    proves nothing about the product, nor does one on a host too loaded to keep time (B38)."""
    problems = [n for n in rec.notes if n.startswith("SSE")]
    if not rec.timing.conclusive:
        problems.append(
            f"inconclusive: product eval ticks ran x{rec.timing.dilation:g} slower than"
            f" calibrated (periods {dict(rec.timing.periods)}, cap x{MAX_DILATION:g}) and its"
            f" data lagged {rec.timing.data_lag_s:g} s (cap {MAX_DATA_LAG_S:g} s);"
            " host or database too loaded to judge deadlines, rerun on a quieter runner"
        )
    active = [ref for ref, s in rec.actors.items() if s.requests > 0]
    if not active:
        problems.append("no actor sent traffic")
    return problems


def _summary(rec: RunRecord) -> dict[str, Any]:
    sse = Counter(f"{e.tenant}:{e.event}" for e in rec.sse)
    actors = {
        str(ref): {
            "via": s.via,
            "requests": s.requests,
            "statuses": dict(s.statuses),
            "routes": dict(s.routes),
            "errors": dict(s.errors),
            "tool_calls": s.tool_calls,
            "actions": dict(Counter(a["outcome"] for a in s.actions)),
        }
        for ref, s in sorted(rec.actors.items())
        if s.requests
    }
    schema_errors = sorted(
        {err for series in rec.health.values() for r in series for err in r.schema_errors}
    )
    return {
        "sse": dict(sorted(sse.items())),
        "actors": actors,
        "lanes": rec.lanes,
        "cross_reads": [asdict(r) | {"foreign": str(r.foreign)} for r in rec.cross_reads],
        "health_schema_errors": schema_errors[:5],
        "timing": rec.timing.as_dict(),
        "personas": rec.persona_log,
        "notes": rec.notes,
    }


def _write_timeline(run_dir: Path, timeline: list[dict[str, Any]], rec: RunRecord) -> None:
    rows = list(timeline) + [
        {"row": "sse", "t": e.t, "tenant": e.tenant, "event": e.event, "data": e.data}
        for e in rec.sse
    ]
    (run_dir / "timeline.jsonl").write_text(
        "".join(json.dumps(r, default=str, sort_keys=True) + "\n" for r in rows), "utf-8"
    )


def _write_record(run_dir: Path, rec: RunRecord, outcome: RunOutcome) -> None:
    doc = {
        "scenario": rec.scenario,
        "seed": rec.seed,
        "status": outcome.status,
        "reason": outcome.reason,
        "summary": outcome.summary,
        "verdicts": [asdict(v) for v in outcome.verdicts],
        "gates": [asdict(g) for g in outcome.gates],
        "golden": outcome.golden,
        "actions": {str(ref): s.actions for ref, s in sorted(rec.actors.items()) if s.actions},
        "health_final": {
            str(ref): (
                lambda r: {"status": r.status, "score": r.score, "events_seen": r.events_seen}
            )(series[-1])
            for ref, series in rec.health.items()
            if series
        },
    }
    (run_dir / "record.json").write_text(json.dumps(doc, indent=1, default=str), "utf-8")


__all__ = ["RunOptions", "SseEvent", "StackHandle", "available_lanes", "plans_for", "run_scenario"]
