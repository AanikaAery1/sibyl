"""Golden series (qa-expert §4.1, ML §8.4).

Per scenario and seed: the tracked agents' health transitions, alert fires and final health,
provider incidents and a per-tenant count for the steady tenants, with every timestamp turned
into an offset in scoring ticks. A run is compared with tolerances (default ±2 ticks, score ±2;
the design's ±1 tick assumes a shared clock, and rollup and scoring each run on their own
jittered 10 s cadence here). A new rule code or a new transition is never "within tolerance":
it is a deliberate golden update with a reason (R50).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..oracle.record import RunRecord
from ..scenarios.model import AgentRef, Scenario

DATA_DIR = Path(__file__).parent / "data"
SCHEMA = "sibyl-sim-golden/1"


@dataclass(frozen=True)
class Tolerance:
    ticks: int = 2
    score: int = 2


def tracked(scenario: Scenario) -> list[AgentRef]:
    refs = {lab.agent for lab in scenario.labels}
    for exp in scenario.expect:
        raw = exp.args.get("agent")
        if isinstance(raw, str):
            refs.add(AgentRef.parse(raw))
    return sorted(refs)


def _tick(t: float, tick_s: float) -> int:
    return round(t / tick_s)


def canonical(scenario: Scenario, rec: RunRecord, *, tick_s: float = 10.0) -> dict[str, Any]:
    agents: dict[str, Any] = {}
    for ref in tracked(scenario):
        try:
            aid = rec.agent_id(ref)
        except KeyError:
            continue
        mine = [e for e in rec.sse if e.agent_id == aid]
        alerts: list[list[Any]] = []
        seen_rules: set[str] = set()
        for e in sorted(mine, key=lambda e: e.t):
            rule = str(e.data.get("rule"))
            if e.event == "alert.fired" and rule not in seen_rules:
                seen_rules.add(rule)
                alerts.append([_tick(e.t, tick_s), rule])
        transitions = [
            [_tick(e.t, tick_s), e.data.get("from_status"), e.data.get("to_status")]
            for e in sorted(mine, key=lambda e: e.t)
            if e.event == "health.transition"
        ]
        final = rec.final_health(ref)
        agents[str(ref)] = {
            "alerts": alerts,
            "transitions": transitions,
            "final": {"status": final.status, "score": final.score} if final else None,
        }
    slugs = {str(pid): slug for slug, pid in rec.world.tenant("meridian").providers.items()}
    incidents = [
        [_tick(e.t, tick_s), slugs.get(str(e.data.get("provider_id")), "?")]
        for e in sorted(rec.events_of("meridian", "provider_incident.opened"), key=lambda e: e.t)
    ]
    tenants = {
        slug: {
            "alerts": len(rec.alerts_fired(slug)),
            "transitions": len(rec.events_of(slug, "health.transition")),
        }
        for slug in rec.world.tenants
        if slug != "meridian"
    }
    return {
        "schema": SCHEMA,
        "scenario": scenario.id,
        "seed": rec.seed,
        "tick_s": tick_s,
        "agents": agents,
        "incidents": incidents,
        "tenants": tenants,
    }


def _by_rule(rows: list[list[Any]]) -> dict[str, int]:
    return {str(rule): int(tick) for tick, rule in rows}


def compare(golden: Mapping[str, Any], actual: Mapping[str, Any], tol: Tolerance) -> list[str]:
    diffs: list[str] = []
    for name in sorted(set(golden["agents"]) | set(actual["agents"])):
        g, a = golden["agents"].get(name), actual["agents"].get(name)
        if g is None or a is None:
            diffs.append(f"{name}: tracked agent {'added' if g is None else 'removed'}")
            continue
        g_alerts, a_alerts = _by_rule(g["alerts"]), _by_rule(a["alerts"])
        for rule in sorted(set(g_alerts) | set(a_alerts)):
            if rule not in a_alerts:
                diffs.append(f"{name}: alert {rule} no longer fires")
            elif rule not in g_alerts:
                diffs.append(f"{name}: new alert {rule} at tick {a_alerts[rule]}")
            elif abs(g_alerts[rule] - a_alerts[rule]) > tol.ticks:
                diffs.append(f"{name}: alert {rule} tick {g_alerts[rule]} -> {a_alerts[rule]}")
        g_path = [(f, t) for _, f, t in g["transitions"]]
        a_path = [(f, t) for _, f, t in a["transitions"]]
        if g_path != a_path:
            diffs.append(f"{name}: transitions {g_path} -> {a_path}")
        else:
            for (gt, f, t), (at, _, _) in zip(g["transitions"], a["transitions"], strict=True):
                if abs(gt - at) > tol.ticks:
                    diffs.append(f"{name}: transition {f}->{t} tick {gt} -> {at}")
        gf, af = g.get("final"), a.get("final")
        if (gf is None) != (af is None):
            diffs.append(f"{name}: final health {gf} -> {af}")
        elif gf and af:
            if gf["status"] != af["status"]:
                diffs.append(f"{name}: final status {gf['status']} -> {af['status']}")
            if abs(int(gf["score"]) - int(af["score"])) > tol.score:
                diffs.append(f"{name}: final score {gf['score']} -> {af['score']}")
    g_inc = [p for _, p in golden.get("incidents", [])]
    a_inc = [p for _, p in actual.get("incidents", [])]
    if g_inc != a_inc:
        diffs.append(f"provider incidents {g_inc} -> {a_inc}")
    if golden.get("tenants") != actual.get("tenants"):
        diffs.append(f"steady tenants {golden.get('tenants')} -> {actual.get('tenants')}")
    return diffs


def path_for(root: Path, scenario: str, seed: int) -> Path:
    return root / scenario / f"{seed}.json"


def save(root: Path, scenario: str, seed: int, doc: Mapping[str, Any]) -> Path:
    path = path_for(root, scenario, seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", "utf-8")
    return path


def load(root: Path, scenario: str, seed: int) -> dict[str, Any] | None:
    path = path_for(root, scenario, seed)
    if not path.is_file():
        return None
    doc: dict[str, Any] = json.loads(path.read_text("utf-8"))
    return doc
