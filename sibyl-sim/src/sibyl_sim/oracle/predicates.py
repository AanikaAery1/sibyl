"""Oracle predicates (qa-expert §1.5, ML §8.1): every `expect` key maps to exactly one function
here, so a failing scenario names the predicate and the first offending object.

A predicate is `(record, scenario, args) -> Verdict`. It reads only the `RunRecord` (API reads
and the actors' wire view). Rule arguments accept codes (`error_rate`) or short codes (`R1`).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from ..scenarios.model import AgentRef, Expectation, Scenario
from . import sentinel
from .record import HealthRead, RunRecord, SseEvent

SHORT_CODES: Final[Mapping[str, str]] = {
    "R1": "error_rate",
    "R2": "p95_latency",
    "R3": "consecutive_failures",
    "R4": "provider_status",
    "R5": "budget_breach",
    "R6": "refusal_share",
    "R7": "truncation_share",
    "R8": "schema_fail_share",
    "R9": "heartbeat_missing",
    "L1": "error_trend",
    "L2": "latency_trend",
    "L3": "ratelimit_proximity",
    "L4": "budget_proximity",
    "L5": "fallback_pressure",
    "L6": "refusal_trend",
    "L7": "continuity_unverified",
}
ALERT_SEVERITY_RANK: Final = {"info": 0, "warning": 1, "critical": 2}
BAND_RANK: Final = {"healthy": 0, "watch": 1, "degraded": 2, "failed": 3}
CONTINUING: Final = frozenset({"failed_over", "degraded"})
EXPLANATION_MAX: Final = 300


@dataclass(frozen=True)
class Verdict:
    name: str
    predicate: str
    severity: str
    status: str  # pass | fail | skip | error
    detail: str = ""
    measured: Mapping[str, Any] = field(default_factory=dict)
    offending: Any = None

    @property
    def ok(self) -> bool:
        return self.status in ("pass", "skip", "report")


class PredicateError(Exception):
    """The expectation itself is wrong (unknown agent, bad argument): status `error`."""


Check = Callable[[RunRecord, Scenario, Mapping[str, Any]], tuple[bool, str, dict[str, Any], Any]]


# ------------------------------------------------------------------------------ helpers


def rule_codes(raw: Any) -> list[str]:
    values = raw if isinstance(raw, list) else [raw]
    return [SHORT_CODES.get(str(v), str(v)) for v in values if v is not None]


def _agent(rec: RunRecord, raw: Any) -> AgentRef:
    ref = AgentRef.parse(raw)
    try:
        rec.world.tenant(ref.tenant).agent(ref.slug)
    except KeyError as exc:
        raise PredicateError(f"unknown agent {raw!r}: {exc}") from None
    return ref


def _onset(scenario: Scenario, ref: AgentRef, before: float | None = None) -> float | None:
    onsets = [
        lab.t
        for lab in scenario.labels
        if lab.agent == ref and lab.kind == "onset" and (before is None or lab.t <= before)
    ]
    return max(onsets) if onsets else None


def _agent_alerts(rec: RunRecord, ref: AgentRef, codes: Sequence[str] = ()) -> list[SseEvent]:
    aid = rec.agent_id(ref)
    return [
        e
        for e in rec.alerts_fired(ref.tenant)
        if e.agent_id == aid and (not codes or e.data.get("rule") in codes)
    ]


def _transitions_of(rec: RunRecord, ref: AgentRef) -> list[SseEvent]:
    aid = rec.agent_id(ref)
    return [e for e in rec.events_of(ref.tenant, "health.transition") if e.agent_id == aid]


def _stimulus(s: Scenario) -> float:
    """When the scenario's stimulus starts: the first chaos step or onset label (else 0)."""
    starts = [float(c.at) for c in s.chaos] + [lab.t for lab in s.labels if lab.kind == "onset"]
    return min(starts, default=0.0)


def _by(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> float:
    """The scenario's ``by_t`` stretched by the run's measured tick lag (B38); without a
    ``by_t`` the check runs to the end of the scenario, which is not a deadline."""
    if "by_t" not in args:
        return float(s.duration_s)
    return rec.timing.deadline(float(args["by_t"]), onset=_stimulus(s))


def _late(rec: RunRecord, args: Mapping[str, Any], deadline: float) -> str:
    by_t = float(args.get("by_t", deadline))
    if deadline == by_t:
        return f"by_t={by_t:g}"
    return f"by_t={by_t:g}, deadline {deadline} ({rec.timing.describe()})"


def _short(event: SseEvent) -> dict[str, Any]:
    return {"t": event.t, "event": event.event, **event.data}


# ---------------------------------------------------------------------------- wave 1


def _detect_provider(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    tenant = str(args.get("tenant", "meridian"))
    pid = rec.world.tenant(tenant).providers.get(str(args.get("provider")))
    if pid is None:
        raise PredicateError(f"{tenant} has no provider {args.get('provider')!r}")
    codes = rule_codes(args.get("rule"))
    hits = [
        e
        for e in rec.alerts_fired(tenant)
        if e.data.get("provider_id") == str(pid) and (not codes or e.data.get("rule") in codes)
    ]
    if not hits:
        return False, f"no provider alert {codes} for {args.get('provider')}", {}, None
    first = hits[0]
    measured = {"t": first.t, "rule": first.data.get("rule")}
    deadline = _by(rec, s, args)
    if first.t > deadline:
        detail = f"provider alert at t={first.t} > {_late(rec, args, deadline)}"
        return False, detail, measured, _short(first)
    return (
        True,
        f"{first.data.get('rule')} on {args.get('provider')} at t={first.t}",
        measured,
        None,
    )


def detect(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    if "provider" in args:
        return _detect_provider(rec, s, args)
    ref = _agent(rec, args.get("agent"))
    codes = rule_codes(args.get("rule"))
    by_t = _by(rec, s, args)
    alerts = _agent_alerts(rec, ref, codes)
    if not alerts:
        return False, f"no alert.fired for {ref} with rule in {codes}", {}, None
    first = alerts[0]
    onset = _onset(s, ref, first.t)
    measured = {"t": first.t, "rule": first.data.get("rule"), "tier": rec.tier(ref)}
    if onset is not None:
        measured["ttd_s"] = round(first.t - onset, 3)
        measured["onset_t"] = onset
    if "by_t" in args:
        measured["deadline_t"] = by_t
    if first.t > by_t:
        return (
            False,
            f"first {first.data.get('rule')} alert at t={first.t} > {_late(rec, args, by_t)}",
            measured,
            _short(first),
        )
    return True, f"{first.data.get('rule')} at t={first.t}", measured, None


def no_alert(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    codes = rule_codes(args.get("rule")) if args.get("rule") else []
    after = float(args.get("from_t", 0))
    hits = [e for e in _agent_alerts(rec, ref, codes) if e.t >= after]
    if hits:
        return (
            False,
            f"{hits[0].data.get('rule')} fired for {ref} at t={hits[0].t}",
            {"count": len(hits)},
            hits[0].data,
        )
    return True, "no matching alert", {}, None


def quiet(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    tenant = str(args.get("tenant"))
    ceiling = ALERT_SEVERITY_RANK[str(args.get("max_severity", "info"))]
    scope = str(args.get("scope", "all"))  # agent: provider-scope status alerts are shared
    loud = [
        e
        for e in rec.alerts_fired(tenant)
        if ALERT_SEVERITY_RANK.get(str(e.data.get("severity")), 2) > ceiling
        and (scope == "all" or e.data.get("scope") == scope)
    ]
    if scope == "all":
        loud += rec.events_of(tenant, "provider_incident.opened")
    loud.sort(key=lambda e: e.t)
    if loud:
        first = loud[0]
        return False, f"{tenant}: {first.event} at t={first.t}", {"count": len(loud)}, _short(first)
    return True, f"{tenant}: nothing above {args.get('max_severity', 'info')}", {}, None


def isolated(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    tenant = str(args.get("tenant"))
    own = {str(a.id) for a in rec.world.tenant(tenant).agents.values()}
    for item in rec.listed_agents.get(tenant, []):
        if str(item.get("id")) not in own:
            return (
                False,
                f"{tenant} lists an agent it never registered: {item.get('slug')}",
                {},
                item,
            )
    for event in rec.events_of(tenant):
        if event.agent_id and event.agent_id not in own:
            other = rec.ref_of(event.agent_id)
            return (
                False,
                f"{tenant} SSE {event.event} names {other or event.agent_id}",
                {},
                _short(event),
            )
    for read in rec.cross_reads:
        if read.tenant == tenant and read.status != 404:
            return False, f"{tenant} read {read.foreign} -> {read.status} (want 404)", {}, read
    probes = sum(1 for r in rec.cross_reads if r.tenant == tenant)
    return True, f"{tenant}: no foreign rows, {probes} cross-tenant reads all 404", {}, None


def observed(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    """Anti-vacuity for isolation: a tenant's traffic must reach its own tenant."""
    tenant = str(args.get("tenant"))
    minimum = int(args.get("min_events", 1))
    blind = []
    for slug in rec.world.tenant(tenant).agents:
        ref = AgentRef(tenant, slug)
        stats = rec.actors.get(ref)
        if stats is None or stats.requests == 0:
            continue
        stored = [e for e in rec.events.get(ref, []) if e.get("event_type") == "gen_ai.request"]
        if len(stored) < minimum:
            blind.append(slug)
    if blind:
        return (
            False,
            f"{tenant}: traffic sent but not seen for {', '.join(sorted(blind))}",
            {"blind": blind},
            blind[0],
        )
    return True, f"{tenant}: every active agent observed", {}, None


def _explained(read: HealthRead) -> str | None:
    real = [f for f in read.factors if not str(f.get("rule", "")).startswith("_")]
    clamp = sum(int(f.get("penalty") or 0) for f in read.factors if f.get("rule") == "_clamp")
    penalised = [f for f in real if int(f.get("penalty") or 0) > 0]
    if not penalised:
        # a band the score alone does not give (recovery hysteresis, a floor) is explained only
        # by a zero-penalty band factor that names this very band and says why (ML.md §3.6)
        stated = [
            f
            for f in real
            if f.get("direction") == "equals"
            and f.get("value") == read.status
            and str(f.get("explanation") or "").strip()
            and len(str(f.get("explanation"))) <= EXPLANATION_MAX
        ]
        if not stated:
            return "no penalised factor on a non-healthy snapshot"
        clamp_ok = abs(100 + clamp - read.score) <= 1
        return None if clamp_ok else f"100 - Σpenalty(0) + clamp({clamp}) != score({read.score})"
    for f in penalised:
        text = f.get("explanation")
        if not text or len(str(text)) > EXPLANATION_MAX:
            return f"factor {f.get('rule')} has no usable explanation"
        if "value" not in f or "threshold" not in f:
            return f"factor {f.get('rule')} lacks value or threshold"
    total = sum(int(f.get("penalty") or 0) for f in real)
    if not any(f.get("rule") == "_clamp" for f in read.factors):
        clamp = max(0, total - 100)  # B-04: stripped from the API, derived (ML.md §3.1)
    if abs(100 - total + clamp - read.score) > 1:
        return f"100 - Σpenalty({total}) + clamp({clamp}) != score({read.score})"
    return None


def explainable(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    reads = [r for series in rec.health.values() for r in series if r.status != "healthy"]
    bad = [(r, why) for r in reads if (why := _explained(r)) is not None]
    completeness = 1.0 if not reads else 1 - len(bad) / len(reads)
    evidence = rec.lane_reads.get("evidence") or {}
    measured = {
        "completeness": round(completeness, 4),
        "snapshots": len(reads),
        "evidence_checked": len(evidence),
    }
    broken = sorted(link for link, status in evidence.items() if status != 200)
    if broken:  # ML §3.6: a factor whose evidence link does not resolve is unexplained
        return False, f"evidence link answered {evidence[broken[0]]}: {broken[0]}", measured, broken
    if bad:
        read, why = bad[0]
        offending = {
            "agent": str(read.agent),
            "status": read.status,
            "score": read.score,
            "factors": [
                {k: f.get(k) for k in ("rule", "penalty", "kind", "value", "explanation") if k in f}
                for f in read.factors
            ][:6],
        }
        return False, f"{read.agent} t={read.t}: {why}", measured, offending
    return True, f"{len(reads)} non-healthy snapshots fully explained", measured, None


def health(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    series = rec.health.get(ref) or []
    if not series:
        return False, f"no health read for {ref}", {}, None
    pool = series if args.get("when") == "ever" else series[-1:]
    wanted = args.get("status")
    lo, hi = int(args.get("min_score", 0)), int(args.get("max_score", 100))
    for read in pool:
        if (not wanted or read.status in wanted) and lo <= read.score <= hi:
            return (
                True,
                f"{ref} {read.status} {read.score} at t={read.t}",
                {"score": read.score},
                None,
            )
    last = series[-1]
    return (
        False,
        f"{ref} is {last.status} {last.score}; want status {wanted} score [{lo}, {hi}]",
        {"score": last.score},
        None,
    )


def band_episodes(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    left = [e for e in _transitions_of(rec, ref) if e.data.get("from_status") == "healthy"]
    n = len(left)
    measured = {"episodes": n, "transitions": len(_transitions_of(rec, ref))}
    if "exactly" in args and n != int(args["exactly"]):
        return (
            False,
            f"{ref} left healthy {n} times (want exactly {args['exactly']})",
            measured,
            [e.t for e in left],
        )
    if "max" in args and n > int(args["max"]):
        return (
            False,
            f"{ref} left healthy {n} times (max {args['max']})",
            measured,
            [e.t for e in left],
        )
    return True, f"{ref} left healthy {n} time(s)", measured, None


def provider_incident(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    tenant = str(args.get("tenant", "meridian"))
    pid = rec.world.tenant(tenant).providers.get(str(args.get("provider")))
    if pid is None:
        raise PredicateError(f"{tenant} has no provider {args.get('provider')!r}")
    opened = [
        e
        for e in rec.events_of(tenant, "provider_incident.opened")
        if e.data.get("provider_id") == str(pid)
    ]
    if not opened:
        return False, f"no provider_incident.opened for {args.get('provider')}", {}, None
    first = opened[0]
    incident = first.data.get("provider_incident_id")
    members = {
        e.agent_id
        for e in rec.events_of(tenant, "alert.updated", "alert.fired")
        if e.data.get("provider_incident_id") == incident and e.agent_id
    }
    measured = {"t": first.t, "agents": len(members)}
    deadline = _by(rec, s, args)
    if first.t > deadline:
        detail = f"incident opened at t={first.t} > {_late(rec, args, deadline)}"
        return False, detail, measured, _short(first)
    if len(members) < int(args.get("min_agents", 1)):
        return (
            False,
            f"incident collects {len(members)} agents (< {args.get('min_agents')})",
            measured,
            None,
        )
    return True, f"incident at t={first.t} with {len(members)} agents", measured, None


def recommended_action(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    want = str(args.get("action"))
    seen = {str(e.data.get("recommended_action")) for e in _transitions_of(rec, ref)}
    seen |= {str(r.recommended_action) for r in rec.health.get(ref, [])}
    if want in seen:
        return True, f"{ref} recommended {want}", {}, None
    return (
        False,
        f"{ref} never recommended {want} (saw {sorted(seen - {'None'})})",
        {},
        sorted(seen),
    )


def failure_mode(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    want = str(args.get("mode"))
    seen = {str(r.predicted_failure_mode) for r in rec.health.get(ref, [])}
    if want in seen:
        return True, f"{ref} failure mode {want}", {}, None
    return False, f"{ref} never reported failure mode {want} (saw {sorted(seen)})", {}, sorted(seen)


def gateway_route(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    stats = rec.actors.get(ref)
    total = sum(stats.routes.values()) if stats else 0
    hits = stats.routes.get(str(args.get("route")), 0) if stats else 0
    share = hits / total if total else 0.0
    measured = {"share": round(share, 4), "count": hits, "total": total}
    if hits < int(args.get("min_count", 1)) or share < float(args.get("min_share", 0)):
        return (
            False,
            f"{ref}: route {args.get('route')} on {hits}/{total} calls",
            measured,
            dict(stats.routes) if stats else None,
        )
    return True, f"{ref}: route {args.get('route')} on {hits}/{total} calls", measured, None


def event_seen(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    kind = str(args.get("event_type"))
    hits = [e for e in rec.events.get(ref, []) if e.get("event_type") == kind]
    if not hits:
        return False, f"no {kind} event for {ref}", {}, None
    return True, f"{len(hits)} {kind} event(s) for {ref}", {"count": len(hits)}, None


def no_duplicates(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    seen: set[str] = set()
    calls = [
        e.get("call_id") for e in rec.events.get(ref, []) if e.get("event_type") == "gen_ai.request"
    ]
    for call in calls:
        if call is None:
            continue
        if call in seen:
            return False, f"{ref}: call_id {call} stored twice", {"calls": len(calls)}, call
        seen.add(call)
    return True, f"{ref}: {len(calls)} calls, no duplicate call_id", {"calls": len(calls)}, None


def scores_at_least(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    tenant = str(args.get("tenant"))
    minimum = int(args.get("min", 90))
    low = []
    for slug in rec.world.tenant(tenant).agents:
        final = rec.final_health(AgentRef(tenant, slug))
        if final is not None and final.score < minimum:
            low.append((slug, final.score))
    if low:
        return (
            False,
            f"{tenant}: {low[0][0]} scored {low[0][1]} (< {minimum})",
            {"low": low},
            low[0],
        )
    return True, f"{tenant}: every score >= {minimum}", {}, None


def contract(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    bad = [r for series in rec.health.values() for r in series if r.schema_errors]
    if bad:
        first = bad[0]
        detail = f"{len(bad)} health documents violate sibyl-health/1, e.g. {first.agent}"
        return False, detail, {"invalid": len(bad)}, list(first.schema_errors)
    reads = sum(len(series) for series in rec.health.values())
    return True, f"{reads} health documents conform to sibyl-health/1", {}, None


# ---------------------------------------------------------------------------- wave 2 lanes


def _rule_transitions(rec: RunRecord, ref: AgentRef) -> list[Mapping[str, Any]]:
    return [t for t in rec.transitions.get(ref, []) if t.get("actor_kind") in ("rule", "policy")]


def action(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    want = str(args.get("to_state"))
    # a transition before t=0 is the seeded registration (`-> active`), not an action of the run
    hits = [
        t
        for t in rec.transitions.get(ref, [])
        if t.get("to_state") == want and (t.get("t") is None or float(t["t"]) >= 0)
    ]
    if args.get("actor"):
        hits = [t for t in hits if t.get("actor_kind") == args["actor"]]
    if not hits:
        return False, f"{ref} never reached {want}", {}, rec.transitions.get(ref, [])[:3]
    first = hits[0]
    deadline = _by(rec, s, args)
    if float(first.get("t", 0)) > deadline:
        return (
            False,
            f"{ref} reached {want} at t={first.get('t')} > {_late(rec, args, deadline)}",
            {"t": first.get("t"), "deadline_t": deadline},
            first,
        )
    return True, f"{ref} reached {want} at t={first.get('t')}", {"t": first.get("t")}, None


def no_action(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    kinds = set(args.get("states") or ("failed_over", "quarantined", "killed"))
    after = float(args.get("from_t", 0))  # e.g. nothing automated after a kill
    before = float(args.get("to_t", 1e18))  # e.g. only inside an operator hold
    hits = [
        t
        for t in _rule_transitions(rec, ref)
        if t.get("to_state") in kinds and after <= float(t.get("t") or 0) < before
    ]
    if hits:
        return (
            False,
            f"{ref} automated {hits[0].get('to_state')} at t={hits[0].get('t')}",
            {},
            hits[0],
        )
    return True, f"{ref}: no automated {sorted(kinds)}", {}, None


def single_failover(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    n = sum(1 for t in _rule_transitions(rec, ref) if t.get("to_state") == "failed_over")
    if n != 1:
        return False, f"{ref}: {n} automated failovers (want exactly 1)", {"failovers": n}, None
    return True, f"{ref}: exactly one automated failover", {"failovers": 1}, None


def tier_gate(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    mode = str(args.get("mode", "approval"))
    aid = rec.agent_id(ref)
    approvals = [a for a in rec.lane_reads.get("approvals", []) if str(a.get("agent_id")) == aid]
    failovers = [t for t in _rule_transitions(rec, ref) if t.get("to_state") == "failed_over"]
    if mode == "automatic":
        if approvals:
            return False, f"{ref}: approval requested on an automatic tier", {}, approvals[0]
        return True, f"{ref}: no approval row", {}, None
    if not approvals:
        return False, f"{ref}: no approval requested", {}, None
    requested = float(approvals[0].get("t", 0))
    early = [t for t in failovers if float(t.get("t", 0)) < requested]
    if early:
        return False, f"{ref}: failed over at t={early[0].get('t')} before approval", {}, early[0]
    return True, f"{ref}: approval at t={requested} before any failover", {}, None


def rto(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    onset = _onset(s, ref)
    if onset is None:
        raise PredicateError(f"rto needs an onset label for {ref}")
    deadline = onset + float(args.get("rto_s", 900))
    aid = rec.agent_id(ref)
    states = [t for t in rec.transitions.get(ref, []) if t.get("to_state") in CONTINUING]
    tasks = [
        t
        for t in rec.lane_reads.get("queue", [])
        if str(t.get("agent_id")) == aid and t.get("claimed_t") is not None
    ]
    times = [float(t.get("t", 1e18)) for t in states] + [float(t["claimed_t"]) for t in tasks]
    if not times or min(times) > deadline:
        return False, f"{ref}: no continuing state or claimed task by t={deadline}", {}, None
    return (
        True,
        f"{ref}: continuity at t={min(times)} (deadline {deadline})",
        {"t": min(times)},
        None,
    )


def handoff(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    aid = rec.agent_id(ref)
    tasks = [t for t in rec.lane_reads.get("queue", []) if str(t.get("agent_id")) == aid]
    if not tasks:
        return False, f"{ref}: no handoff task", {}, None
    want = args.get("fidelity")
    if want and not any(t.get("fidelity") == want for t in tasks):
        return False, f"{ref}: no task with fidelity {want}", {}, tasks[0]
    return True, f"{ref}: {len(tasks)} handoff task(s)", {}, None


def gateway_refused(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    stats = rec.actors.get(ref)
    code = str(args.get("code", "sibyl_agent_killed"))
    seen = stats.first_seen.get(f"error:{code}") if stats else None
    if seen is None:
        return (
            False,
            f"{ref}: gateway never answered {code}",
            {},
            dict(stats.errors) if stats else None,
        )
    after = float(args.get("after_t", 0))
    within = float(args.get("within_s", 1e9))
    if seen - after > within:
        return (
            False,
            f"{ref}: {code} first at t={seen}, {seen - after:.1f}s after t={after}",
            {"t": seen},
            None,
        )
    return (
        True,
        f"{ref}: {code} at t={seen}",
        {"t": seen, "latency_s": round(seen - after, 3)},
        None,
    )


def predict(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    ref = _agent(rec, args.get("agent"))
    codes = rule_codes(args.get("rule"))
    by_t = _by(rec, s, args)
    leading = [e for e in _agent_alerts(rec, ref, codes) if e.t <= by_t]
    if not leading:
        return False, f"{ref}: no leading alert {codes} by t={by_t}", {}, None
    onset = _onset(s, ref)
    measured = {"t": leading[0].t}
    if onset is not None:
        measured["lead_s"] = round(onset - leading[0].t, 3)
    return True, f"{ref}: {leading[0].data.get('rule')} at t={leading[0].t}", measured, None


def verdict_loop(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    closed = [a for a in rec.lane_reads.get("alerts", []) if a.get("state") == "resolved"]
    verdicted = [a for a in closed if a.get("verdict")]
    share = len(verdicted) / len(closed) if closed else 1.0
    if share < float(args.get("min_share", 0.9)):
        return False, f"verdicted share {share:.2f}", {"share": share}, None
    return True, f"verdicted share {share:.2f}", {"share": share}, None


# ------------------------------------------------------------------- Action Gate (A-5)

PII_PATTERNS: Final = (
    re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}"),
    re.compile(r"\+?[0-9][0-9 ()-]{8,18}[0-9]"),
)
ACTION_OUTCOMES: Final = ("executed", "blocked", "held", "denied")
TIMED_OUT: Final = frozenset({"expired", "timeout"})


def _has_pii(value: Any) -> bool:
    text = json.dumps(value, default=str)
    return any(p.search(text) for p in PII_PATTERNS)


def _args_of(action: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = action.get("args")
    return raw if isinstance(raw, Mapping) else {}


def _forbidden(action: Mapping[str, Any], rule: Mapping[str, Any]) -> bool:
    """The scenario's own reading of "never without a person" (independent of the product's
    evaluator): tool name, optionally a numeric field above a limit, or PII in the arguments."""
    if action["tool"] != rule.get("tool"):
        return False
    args = _args_of(action)
    if "gt" in rule:
        value: Any = args.get(str(rule["field"]))
        try:
            return float(value) > float(rule["gt"])
        except (TypeError, ValueError):
            return True  # an amount nobody could read is not authorised either
    if rule.get("contains_pii"):
        return _has_pii(args)
    return True


def approved_holds(rec: RunRecord, tenant: str) -> set[str]:
    """Held actions a person approved through the API (2xx), from the persona log."""
    return {
        str(hid)
        for row in rec.persona_log
        if row.get("verb") == "decide_held"
        and row.get("decision", "approve") == "approve"
        and row.get("tenant") == tenant
        for hid in row.get("decided") or ()
    }


def unauthorised(
    acts: Sequence[Mapping[str, Any]], args: Mapping[str, Any], approved: set[str]
) -> list[Mapping[str, Any]]:
    """Executions no policy-plus-person authorised, in time order (a cap counts unapproved
    executions only)."""
    out: list[Mapping[str, Any]] = []
    cap = args.get("cap") or None
    spent = 0.0
    for act in sorted(acts, key=lambda a: a["t"]):
        if act["outcome"] != "executed":
            continue
        held = act.get("held_action_id")
        if held:
            if str(held) not in approved:
                out.append(act)  # went ahead on a hold no person approved
            continue
        if any(_forbidden(act, rule) for rule in args.get("forbid") or ()):
            out.append(act)
            continue
        if cap and act["tool"] == cap.get("tool"):
            spent += float(_args_of(act).get(str(cap.get("field"))) or 0)
            if spent > float(cap["max"]):
                out.append(act)
    return out


def actions(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    """Zero unauthorised actions executed (ACTION-GATE §5), plus the cases the scenario must
    have exercised (`min` counts per outcome; `approved` = executed after a person's yes)."""
    ref = _agent(rec, args.get("agent"))
    stats = rec.actors.get(ref)
    acts = list(stats.actions) if stats else []
    approved = approved_holds(rec, ref.tenant)
    bad = unauthorised(acts, args, approved)
    counts = {k: sum(1 for a in acts if a["outcome"] == k) for k in ACTION_OUTCOMES}
    counts["approved"] = sum(
        1 for a in acts if a["outcome"] == "executed" and str(a.get("held_action_id")) in approved
    )
    # the hold nobody answered: a deny on timeout, not a person's deny nor a hold that never
    # existed; the server says `expired`, an enforcement point whose own wait (hold_timeout_s)
    # ends just before the server's expiry tick says `timeout`
    counts["expired"] = sum(
        1
        for a in acts
        if a["outcome"] == "denied" and a.get("held_action_id") and a.get("state") in TIMED_OUT
    )
    measured = {**counts, "unauthorised": len(bad), "proposed": len(acts)}
    if bad:
        return False, f"{ref}: {len(bad)} unauthorised action(s) executed", measured, bad[:5]
    short = [
        f"{k} {counts.get(k, 0)} < {n}"
        for k, n in (args.get("min") or {}).items()
        if counts.get(k, 0) < int(n)
    ]
    if short:
        return False, f"{ref}: case not exercised: {', '.join(short)}", measured, None
    seen = ", ".join(f"{k} {v}" for k, v in counts.items() if v)
    return True, f"{ref}: 0 unauthorised; {seen}", measured, None


def audit_has(rec: RunRecord, s: Scenario, args: Mapping[str, Any]) -> Any:
    actions = {str(a.get("action")) for a in rec.lane_reads.get("audit", [])}
    missing = [v for v in args.get("verbs", []) if v not in actions]
    if missing:
        return False, f"audit log lacks {missing}", {}, missing
    return True, f"audit has {sorted(args.get('verbs', []))}", {}, None


PREDICATE_FUNCS: Final[Mapping[str, Check]] = {
    "detect": detect,
    "no_alert": no_alert,
    "quiet": quiet,
    "isolated": isolated,
    "observed": observed,
    "explainable": explainable,
    "health": health,
    "band_episodes": band_episodes,
    "provider_incident": provider_incident,
    "recommended_action": recommended_action,
    "failure_mode": failure_mode,
    "gateway_route": gateway_route,
    "event_seen": event_seen,
    "no_duplicates": no_duplicates,
    "scores_at_least": scores_at_least,
    "contract": contract,
    "action": action,
    "no_action": no_action,
    "single_failover": single_failover,
    "tier_gate": tier_gate,
    "rto": rto,
    "handoff": handoff,
    "gateway_refused": gateway_refused,
    "predict": predict,
    "verdict_loop": verdict_loop,
    "audit_has": audit_has,
    "actions": actions,
    "sentinel_findings": sentinel.sentinel_findings,
    "sentinel_advisory": sentinel.sentinel_advisory,
    "sentinel_budget": sentinel.sentinel_budget,
    "sentinel_capture": sentinel.sentinel_capture,
    "sentinel_quality": sentinel.sentinel_quality,
}


def evaluate(exp: Expectation, rec: RunRecord, scenario: Scenario) -> Verdict:
    func = PREDICATE_FUNCS[exp.predicate]
    try:
        passed, detail, measured, offending = func(rec, scenario, exp.args)
    except PredicateError as exc:
        return Verdict(exp.name, exp.predicate, exp.severity, "error", str(exc))
    status = "pass" if passed else ("report" if exp.report_only else "fail")
    if status == "report":
        detail = f"report-only ({exp.note or 'gate not armed'}): {detail}"
    return Verdict(exp.name, exp.predicate, exp.severity, status, detail, measured, offending)


def missing_lanes(required: Iterable[str], lanes: Mapping[str, bool]) -> list[str]:
    return [lane for lane in required if not lanes.get(lane, False)]


def evaluate_all(scenario: Scenario, rec: RunRecord) -> list[Verdict]:
    out: list[Verdict] = []
    for exp in scenario.expect:
        missing = missing_lanes(exp.requires, rec.lanes)
        if missing:
            out.append(
                Verdict(
                    exp.name,
                    exp.predicate,
                    exp.severity,
                    "skip",
                    f"requires {', '.join(missing)} (lane not merged; allowlisted until G2)",
                )
            )
            continue
        out.append(evaluate(exp, rec, scenario))
    return out
