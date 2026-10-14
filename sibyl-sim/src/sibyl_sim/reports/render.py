"""The run report: markdown for people, JSON for CI (qa-expert §4.4).

Verdict: `block` on any CRITICAL, `warn` on HIGH, `pass` otherwise (MEDIUM is carried with a
ticket per ROADMAP §6.1). Skipped scenarios are listed with their allowlisted reason; bridges
(compensations for known product defects) are printed on every report until they disappear.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .gates import SEVERITY_ORDER, RunOutcome, severity_counts, worst_over_seeds

SCHEMA = "sibyl-sim-report/1"


@dataclass
class Suite:
    outcomes: list[RunOutcome]
    build: str = "unknown"
    bridges: tuple[str, ...] = ()
    wall_s: float = 0.0
    notes: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))


def _by_scenario(suite: Suite) -> dict[str, list[RunOutcome]]:
    grouped: dict[str, list[RunOutcome]] = defaultdict(list)
    for outcome in suite.outcomes:
        grouped[outcome.scenario].append(outcome)
    return dict(grouped)


def _verdict(counts: dict[str, int]) -> str:
    if counts.get("CRITICAL"):
        return "block"
    if counts.get("HIGH"):
        return "warn"
    return "pass"


def _ttd(outcomes: list[RunOutcome]) -> dict[str, dict[str, float]]:
    worst: dict[str, dict[str, float]] = defaultdict(dict)
    for o in outcomes:
        for g in o.gates:
            if g.gate.startswith("ttd_") and g.value is not None and g.tier:
                cls = g.gate.removeprefix("ttd_")
                key = str(g.tier)
                worst[cls][key] = max(worst[cls].get(key, 0.0), g.value)
    return dict(worst)


def summary(suite: Suite) -> dict[str, Any]:
    counts = severity_counts(suite.outcomes)
    scenarios = []
    for sid, outcomes in _by_scenario(suite).items():
        worst = worst_over_seeds(outcomes)
        scenarios.append(
            {
                "id": sid,
                "status": worst.status,
                "worst_seed": worst.seed,
                "seeds": [o.seed for o in outcomes],
                "wall_s": round(sum(o.wall_s for o in outcomes), 1),
                "reason": worst.reason,
                "failures": [
                    {"severity": sev, "name": name, "detail": detail}
                    for sev, name, detail in worst.failures()
                ],
                "verdicts": [
                    {
                        "name": v.name,
                        "status": v.status,
                        "severity": v.severity,
                        "detail": v.detail,
                        "measured": dict(v.measured),
                    }
                    for v in worst.verdicts
                ],
                "gates": [
                    {
                        "gate": g.gate,
                        "tier": g.tier,
                        "value": g.value,
                        "threshold": g.threshold,
                        "passed": g.passed,
                        "severity": g.severity,
                    }
                    for g in worst.gates
                ],
                "golden": list(worst.golden),
                "summary": worst.summary,
            }
        )
    return {
        "schema": SCHEMA,
        "build": suite.build,
        "started_at": suite.started_at,
        "wall_s": round(suite.wall_s, 1),
        "severity": counts,
        "verdict": _verdict(counts),
        "ttd_worst_s": _ttd(suite.outcomes),
        "bridges": list(suite.bridges),
        "scenarios": scenarios,
        "notes": suite.notes,
    }


def render_markdown(suite: Suite) -> str:
    doc = summary(suite)
    counts = doc["severity"]
    runs = len(suite.outcomes)
    lines = [
        f"# sibyl-sim report · build {doc['build']} · rules/v1 · {runs} runs · "
        f"{doc['wall_s'] / 60:.1f} min",
        "",
        "## Gate",
        " · ".join(f"{sev} {counts.get(sev, 0)}" for sev in SEVERITY_ORDER[:3])
        + f" → **{doc['verdict']}**",
        "",
    ]
    if doc["bridges"]:
        lines += ["## Bridges (known product defects compensated by the harness)", ""]
        lines += [f"- {b}" for b in doc["bridges"]] + [""]
    ttd = doc["ttd_worst_s"]
    if ttd:
        lines += [
            "## Time to detect (worst seed, seconds)",
            "",
            "| class | tier | TTD |",
            "|---|---|---|",
        ]
        for cls, tiers in sorted(ttd.items()):
            for tier, value in sorted(tiers.items()):
                lines.append(f"| {cls} | t{tier} | {value} |")
        lines.append("")
    lines += [
        "## Scenarios",
        "",
        "| scenario | status | worst seed | wall s | failures |",
        "|---|---|---|---|---|",
    ]
    for s in doc["scenarios"]:
        fails = "; ".join(f"{f['severity']} {f['name']}" for f in s["failures"]) or "-"
        if s["status"] == "skip":
            fails = s["reason"]
        lines.append(f"| {s['id']} | {s['status']} | {s['worst_seed']} | {s['wall_s']} | {fails} |")
    lines.append("")
    for s in doc["scenarios"]:
        if s["status"] == "skip":
            continue
        lines += [f"### {s['id']}", ""]
        for v in s["verdicts"]:
            mark = {
                "pass": "ok",
                "fail": "FAIL",
                "skip": "skip",
                "error": "ERROR",
                "report": "report",
            }[v["status"]]
            measured = ", ".join(f"{k}={val}" for k, val in v["measured"].items())
            lines.append(
                f"- [{mark}] {v['severity']} `{v['name']}`: {v['detail']}"
                + (f" ({measured})" if measured else "")
            )
        for g in s["gates"]:
            if not g["passed"]:
                tier = f" t{g['tier']}" if g["tier"] else ""
                lines.append(
                    f"- [GATE] {g['severity']} {g['gate']}{tier}: {g['value']} vs {g['threshold']}"
                )
        if s["golden"]:
            lines += ["- golden diffs:"] + [f"  - {d}" for d in s["golden"]]
        lines.append("")
    if doc["notes"]:
        lines += ["## Notes", ""] + [f"- {n}" for n in doc["notes"]] + [""]
    return "\n".join(lines)


def write(suite: Suite, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    md = directory / "report.md"
    js = directory / "summary.json"
    md.write_text(render_markdown(suite), "utf-8")
    js.write_text(json.dumps(summary(suite), indent=1, default=str) + "\n", "utf-8")
    return md, js
