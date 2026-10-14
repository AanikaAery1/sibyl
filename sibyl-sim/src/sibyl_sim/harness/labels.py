"""Ground-truth writer: `labels-<scenario>-<seed>.jsonl` beside the run, never in Postgres
(qa-expert §1.1 rule 6; DATAMODEL seed rule: the simulator never writes derived tables).

Three row kinds, all functions of (scenario file, seed) only, so two runs with the same seed
write byte-identical files: `label` (ground truth with its injection and expectations),
`chaos` (the scripted timeline) and `plan` (per-agent traffic plan digest). Wall-clock facts
(when a knob was actually applied, what the actors saw) go to `timeline.jsonl` instead.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..actors.traffic import Arrival
from ..scenarios.model import AgentRef, ChaosStep, Scenario


def _chaos_label(n: int, step: ChaosStep) -> str:
    what = ",".join(sorted(step.patch)) or ("reset" if step.reset else "pause")
    return f"chaos[{n}] {step.kind}:{step.target} {what}"


def _touches(step: ChaosStep, ref: AgentRef, provider: str | None) -> bool:
    if step.kind == "actor":
        return step.target == str(ref)
    if step.kind == "ingest":
        return step.target == ref.tenant
    if step.agents:
        return ref in step.agents
    if step.tenants:
        return ref.tenant in step.tenants
    return step.kind == "double" and (provider is None or provider == step.target)


def ground_truth_rows(
    scenario: Scenario, seed: int, providers: Mapping[AgentRef, str] | None = None
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    providers = providers or {}
    for label in scenario.labels:
        injected = [
            _chaos_label(n, step)
            for n, step in enumerate(scenario.chaos)
            if step.at <= label.t and _touches(step, label.agent, providers.get(label.agent))
        ]
        expected = [
            {"predicate": e.predicate, **{k: v for k, v in e.args.items() if k != "agent"}}
            for e in scenario.expect
            if e.args.get("agent") in (label.agent.slug, str(label.agent))
        ]
        rows.append(
            {
                "row": "label",
                "scenario": scenario.id,
                "seed": seed,
                "t_sim": label.t,
                "tenant": label.agent.tenant,
                "agent": label.agent.slug,
                "kind": label.kind,
                "failure_mode": label.failure_mode,
                "injected_by": injected[-1:] if label.kind == "onset" else injected,
                "expected": expected if label.kind == "onset" else [],
            }
            | ({"masked": True} if label.masked else {})
        )
    for n, step in enumerate(scenario.chaos):
        rows.append(
            {
                "row": "chaos",
                "scenario": scenario.id,
                "seed": seed,
                "n": n,
                "t_sim": step.at,
                "target": f"{step.kind}:{step.target}",
                "set": dict(step.patch),
                "reset": step.reset,
                "agents": [str(a) for a in step.agents],
                "tenants": list(step.tenants),
                "pause_s": step.pause_s,
            }
        )
    return rows


def plan_rows(
    scenario: Scenario, seed: int, plans: Mapping[AgentRef, Sequence[Arrival]]
) -> list[dict[str, Any]]:
    rows = []
    for ref in sorted(plans):
        plan = plans[ref]
        digest = hashlib.sha256(
            "\n".join(f"{a.n}|{a.t}|{a.request_id}|{a.prompt}" for a in plan).encode()
        ).hexdigest()
        rows.append(
            {
                "row": "plan",
                "scenario": scenario.id,
                "seed": seed,
                "agent": str(ref),
                "calls": len(plan),
                "first_request_id": plan[0].request_id if plan else None,
                "digest": digest,
            }
        )
    return rows


def write_ground_truth(
    directory: Path,
    scenario: Scenario,
    seed: int,
    plans: Mapping[AgentRef, Sequence[Arrival]],
    providers: Mapping[AgentRef, str] | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"labels-{scenario.id}-{seed}.jsonl"
    rows = ground_truth_rows(scenario, seed, providers) + plan_rows(scenario, seed, plans)
    path.write_text(
        "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in rows),
        "utf-8",
    )
    return path
