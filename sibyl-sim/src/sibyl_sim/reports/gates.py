"""Acceptance gates (ML §8.3): per-tier time-to-detect, detection precision/recall,
explainability, isolation leaks; judged on the worst seed, never the mean.

Severity on a miss: isolation leak, approval-gating miss, explainability < 100 % -> CRITICAL;
false failover / RTO / predicates marked HIGH -> HIGH; TTD and precision/recall -> MEDIUM.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from ..oracle.predicates import SHORT_CODES, Verdict
from ..oracle.record import RunRecord
from ..scenarios.model import AgentRef, Scenario

TTD_GATES: Final[dict[str, dict[int, float]]] = {
    "hard": {1: 60.0, 2: 90.0, 3: 120.0},
    "silent": {1: 600.0, 2: 600.0, 3: 900.0},
}
RECALL: Final = {1: 0.95, 2: 0.95, 3: 0.90}
PRECISION: Final = {1: 0.90, 2: 0.85, 3: 0.80}
WATCH_ONLY: Final = frozenset({"silent_drift", "model_change", "sentinel_finding"})  # D51, D52
LEADING: Final = (
    frozenset(code for short, code in SHORT_CODES.items() if short.startswith("L")) | WATCH_ONLY
)
ISOLATION_PREDICATES: Final = frozenset({"isolated", "observed"})
SEVERITY_ORDER: Final = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


@dataclass(frozen=True)
class GateResult:
    gate: str
    tier: int | None
    value: float | None
    threshold: float | None
    severity: str
    passed: bool
    detail: str = ""
    derived: bool = False  # restates failing verdicts (isolation, explainability): not recounted


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None


@dataclass
class RunOutcome:
    scenario: str
    seed: int
    status: str  # pass | fail | skip | error
    verdicts: list[Verdict] = field(default_factory=list)
    gates: list[GateResult] = field(default_factory=list)
    wall_s: float = 0.0
    reason: str = ""
    golden: list[str] = field(default_factory=list)  # golden diffs (empty = match)
    summary: dict[str, Any] = field(default_factory=dict)

    def failures(self) -> list[tuple[str, str, str]]:
        """(severity, name, detail) for every failed verdict and missed gate."""
        out = [
            (v.severity, v.name, v.detail) for v in self.verdicts if v.status in ("fail", "error")
        ]
        out += [
            (g.severity, f"{g.gate}" + (f"[t{g.tier}]" if g.tier else ""), g.detail)
            for g in self.gates
            if not g.passed and not g.derived
        ]
        return out


def _windows(scenario: Scenario) -> dict[AgentRef, list[tuple[float, float]]]:
    """Per labelled agent: [onset, recovery or end] windows that need a detection."""
    out: dict[AgentRef, list[tuple[float, float]]] = {}
    for label in sorted(scenario.labels, key=lambda lab: lab.t):
        if label.kind != "onset":
            continue
        ends = [
            r.t
            for r in scenario.labels
            if r.agent == label.agent and r.kind == "recovery" and r.t >= label.t
        ]
        end = min(ends) if ends else scenario.duration_s
        out.setdefault(label.agent, []).append((label.t, end + 60.0))  # 1 min grace after recovery
    return out


def _tolerated(scenario: Scenario) -> dict[AgentRef, list[tuple[float, float]]]:
    """[precursor, onset): an alert there is neither required nor a false positive; an alert
    before the precursor is an FP (ML §8.3: early is not free)."""
    out: dict[AgentRef, list[tuple[float, float]]] = {}
    for label in scenario.labels:
        if label.kind == "precursor":
            onsets = [o.t for o in scenario.labels if o.agent == label.agent and o.kind == "onset"]
            end = min((t for t in onsets if t >= label.t), default=scenario.duration_s)
            out.setdefault(label.agent, []).append((label.t, end))
    return out


def _masked(scenario: Scenario) -> dict[AgentRef, list[float]]:
    """Onset times of the labels marked ``masked`` (ruling B35)."""
    out: dict[AgentRef, list[float]] = {}
    for label in scenario.labels:
        if label.kind == "onset" and label.masked:
            out.setdefault(label.agent, []).append(label.t)
    return out


def _failed_at(rec: RunRecord, ref: AgentRef) -> list[float]:
    """When the agent's own band was ``failed`` (transitions over SSE and polled reads)."""
    aid = rec.agent_id(ref)
    seen = [
        e.t
        for e in rec.events_of(ref.tenant, "health.transition")
        if e.agent_id == aid and e.data.get("to_status") == "failed"
    ]
    return seen + [r.t for r in rec.health.get(ref, []) if r.status == "failed"]


def masked_detected(rec: RunRecord, ref: AgentRef, lo: float, hi: float) -> bool:
    """B35: a fully masked outage is detected when a provider-scope detected alert fires for
    the agent's own provider and the agent's band reaches ``failed`` in the window; with no
    status page to flip, the leading fallback-pressure alert (L5) is the only signal there is."""
    agent = rec.world.tenant(ref.tenant).agent(ref.slug)
    provider = rec.world.tenant(ref.tenant).providers.get(agent.provider)
    alerts = [e for e in rec.alerts_fired(ref.tenant) if lo <= e.t <= hi]
    r4 = any(
        e.data.get("scope") == "provider"
        and e.data.get("rule") not in LEADING
        and provider is not None
        and e.data.get("provider_id") == str(provider)
        for e in alerts
    )
    if r4 and any(lo <= t <= hi for t in _failed_at(rec, ref)):
        return True
    aid = rec.agent_id(ref)
    return any(e.agent_id == aid and e.data.get("rule") == "fallback_pressure" for e in alerts)


def detection_counts(scenario: Scenario, rec: RunRecord) -> dict[int, Counts]:
    """One label matches at most one alert; cooldown re-fires on the same label are one TP."""
    counts: dict[int, Counts] = {1: Counts(), 2: Counts(), 3: Counts()}
    windows = _windows(scenario)
    matched: set[tuple[AgentRef, int]] = set()
    for event in sorted(rec.sse, key=lambda e: e.t):
        if event.event != "alert.fired" or event.data.get("scope") != "agent":
            continue
        if event.data.get("rule") in LEADING:
            continue
        ref = rec.ref_of(event.agent_id)
        if ref is None or ref.tenant != "meridian":
            continue  # other tenants are the isolation gate's business
        tier = rec.tier(ref)
        hit = next(
            (n for n, (lo, hi) in enumerate(windows.get(ref, [])) if lo <= event.t <= hi), None
        )
        if hit is None:
            spans = _tolerated(scenario).get(ref, [])
            if not any(lo <= event.t < hi for lo, hi in spans):
                counts[tier].fp += 1
        elif (ref, hit) not in matched:
            matched.add((ref, hit))
            counts[tier].tp += 1
    masked = _masked(scenario)
    for ref, spans in windows.items():
        if ref.tenant != "meridian":
            continue
        for n, (lo, hi) in enumerate(spans):
            if (ref, n) in matched:
                continue
            if lo in masked.get(ref, ()) and masked_detected(rec, ref, lo, hi):
                counts[rec.tier(ref)].tp += 1
            else:
                counts[rec.tier(ref)].fn += 1
    return counts


def _ttd_gates(scenario: Scenario, rec: RunRecord, verdicts: Sequence[Verdict]) -> list[GateResult]:
    """Worst TTD per tier against its limit, stretched by the run's measured tick lag (B38)."""
    limits = TTD_GATES.get(scenario.gate_class)
    if not limits:
        return []
    worst: dict[int, float] = {}
    for v in verdicts:
        if v.predicate != "detect" or "ttd_s" not in v.measured:
            continue
        tier = int(v.measured["tier"])
        worst[tier] = max(worst.get(tier, 0.0), float(v.measured["ttd_s"]))
    missing = {
        int(v.measured.get("tier", 0))
        for v in verdicts
        if v.predicate == "detect" and v.status == "fail" and "ttd_s" not in v.measured
    }
    out = []
    for tier in sorted(set(worst) | (missing - {0})):
        value = worst.get(tier)
        limit = rec.timing.limit(limits[tier])
        ok = value is not None and value <= limit
        scaled = "" if limit == limits[tier] else f" ({limits[tier]:g}s, {rec.timing.describe()})"
        detail = (
            f"worst TTD {value}s vs {limit}s{scaled}" if value is not None else "never detected"
        )
        out.append(
            GateResult(f"ttd_{scenario.gate_class}", tier, value, limit, "MEDIUM", ok, detail)
        )
    return out


def _pr_gates(scenario: Scenario, rec: RunRecord) -> list[GateResult]:
    out = []
    for tier, c in detection_counts(scenario, rec).items():
        if c.recall is not None:
            ok = c.recall >= RECALL[tier]
            detail = f"tp={c.tp} fn={c.fn}"
            out.append(
                GateResult("recall", tier, round(c.recall, 4), RECALL[tier], "MEDIUM", ok, detail)
            )
        if c.precision is not None:
            ok = c.precision >= PRECISION[tier]
            detail = f"tp={c.tp} fp={c.fp}"
            out.append(
                GateResult(
                    "precision", tier, round(c.precision, 4), PRECISION[tier], "MEDIUM", ok, detail
                )
            )
    return out


def _leaks(verdicts: Iterable[Verdict]) -> GateResult:
    leaks = [
        v
        for v in verdicts
        if v.status == "fail"
        and (
            v.predicate in ISOLATION_PREDICATES
            or (v.predicate in ("quiet", "scores_at_least") and v.severity == "CRITICAL")
        )
    ]
    detail = "; ".join(v.detail for v in leaks)[:400] or "no leak"
    return GateResult(
        "isolation_leaks", None, float(len(leaks)), 0.0, "CRITICAL", not leaks, detail, derived=True
    )


def _explainability(verdicts: Iterable[Verdict]) -> list[GateResult]:
    out = []
    for v in verdicts:
        if v.predicate == "explainable" and v.status in ("pass", "fail"):
            value = float(v.measured.get("completeness", 1.0))
            out.append(
                GateResult(
                    "explainability", None, value, 1.0, "CRITICAL", value >= 1.0, v.detail, True
                )
            )
    return out


def _unauthorised(verdicts: Iterable[Verdict]) -> list[GateResult]:
    """ACTION-GATE §5: zero unauthorised actions executed, over every `actions` expectation."""
    acts = [v for v in verdicts if v.predicate == "actions" and v.status in ("pass", "fail")]
    if not acts:
        return []
    total = sum(int(v.measured.get("unauthorised", 0)) for v in acts)
    detail = "; ".join(v.detail for v in acts if v.measured.get("unauthorised"))[:400]
    return [
        GateResult(
            "unauthorised_actions",
            None,
            float(total),
            0.0,
            "CRITICAL",
            total == 0,
            detail or "0 unauthorised actions executed",
            derived=True,
        )
    ]


def gate_run(scenario: Scenario, rec: RunRecord, verdicts: Sequence[Verdict]) -> list[GateResult]:
    return [
        *_ttd_gates(scenario, rec, verdicts),
        *_pr_gates(scenario, rec),
        *_explainability(verdicts),
        _leaks(verdicts),
        *_unauthorised(verdicts),
    ]


def run_status(verdicts: Sequence[Verdict], gates: Sequence[GateResult]) -> str:
    if any(v.status == "error" for v in verdicts):
        return "error"
    if any(v.status == "fail" for v in verdicts) or any(not g.passed for g in gates):
        return "fail"
    return "pass"


def worst_over_seeds(outcomes: Sequence[RunOutcome]) -> RunOutcome:
    rank = {"error": 0, "fail": 1, "pass": 2, "skip": 3}

    def key(o: RunOutcome) -> tuple[int, int]:
        worst_sev = min(
            (SEVERITY_ORDER.index(sev) for sev, _, _ in o.failures()), default=len(SEVERITY_ORDER)
        )
        return rank.get(o.status, 9), worst_sev

    return min(outcomes, key=key)


def severity_counts(outcomes: Iterable[RunOutcome]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for outcome in outcomes:
        for severity, _, _ in outcome.failures():
            counts[severity] = counts.get(severity, 0) + 1
    return counts
