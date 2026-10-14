"""The pure health engine for one agent and one tick (ML.md §3).

``evaluate(inputs, prior_state, config, now)`` is a pure function: the same inputs and prior
state always give the same evaluation, so production equals replay. The state that must survive
a restart (band and rule hysteresis counters, flap transitions, pins) is serialised into the
``_hysteresis`` bookkeeping factor of ``health_snapshot.factors`` and read back next tick.

Arithmetic (§3.1): ``penalty_i = round(cap_i(tier) x severity_i)`` (integers, so the identity is
exact), ``score = clamp(100 - Σ penalty, 0, 100)`` and the excess is recorded as ``_clamp``:
``100 - Σ penalty + clamp == score`` holds on every evaluation.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from itertools import pairwise
from types import MappingProxyType
from typing import Any
from uuid import UUID

from .config import BAND_RANK, BANDS, EngineConfig, band_for_score, better, worse
from .features import AgentInputs
from .rules import RuleOutcome, evaluate_detected

HEARTBEAT_S = 60
SCORE_MOVE = 3
PROVISIONAL_ACTIVE_MINUTES = 30
SILENT_ROUTING_STATES = frozenset({"killed", "quarantined"})


def _epoch(ts: datetime) -> float:
    return ts.timestamp()


@dataclass(frozen=True)
class RuleState:
    fired: bool = False
    count: int = 0  # consecutive breaching ticks while not fired; clean ticks while fired


@dataclass(frozen=True)
class EngineState:
    """What one tick hands the next. ``last_*`` fields are snapshot metadata, not state."""

    band: str | None = None
    pending: int = 0  # consecutive ticks toward ``pending_to``
    pending_to: str | None = None
    failed_ticks: int = 0
    rules: Mapping[str, RuleState] = field(default_factory=lambda: MappingProxyType({}))
    transitions: tuple[tuple[float, str, str], ...] = ()  # (at, from, to)
    pin_band: str | None = None
    pin_until: float | None = None
    factor_set: tuple[str, ...] = ()
    horizon_bands: tuple[tuple[str, str], ...] = ()
    # the rules that last penalised a non-healthy band; they explain a recovery hold that
    # outlives their own hysteresis (R9 clears in 3 ticks, a tier-1 band improves in 18)
    held_by: tuple[str, ...] = ()
    last_written_at: datetime | None = None
    last_score: int | None = None

    def core(self) -> tuple[Any, ...]:
        return (
            self.band,
            self.pending,
            self.pending_to,
            self.failed_ticks,
            tuple(sorted((k, v.fired, v.count) for k, v in self.rules.items())),
            self.transitions,
            self.pin_band,
            self.pin_until,
            self.factor_set,
            self.horizon_bands,
            self.held_by,
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, EngineState) and self.core() == other.core()

    def __hash__(self) -> int:
        return hash(self.core())

    def mark_written(self, at: datetime, score: int) -> EngineState:
        return replace(self, last_written_at=at, last_score=score)

    def to_bookkeeping(self) -> dict[str, Any]:
        return {
            "rule": "_hysteresis",
            "band": self.band,
            "pending": [self.pending, self.pending_to],
            "failed_ticks": self.failed_ticks,
            "rules": {k: [int(v.fired), v.count] for k, v in sorted(self.rules.items())},
            "transitions": [list(x) for x in self.transitions],
            "pin": [self.pin_band, self.pin_until],
            "factor_set": list(self.factor_set),
            "horizon_bands": [list(h) for h in self.horizon_bands],
            "held_by": list(self.held_by),
        }

    @classmethod
    def from_bookkeeping(
        cls,
        doc: Mapping[str, Any] | None,
        *,
        written_at: datetime | None = None,
        score: int | None = None,
        band: str | None = None,
    ) -> EngineState:
        if not doc:
            return cls(band=band, last_written_at=written_at, last_score=score)
        pending = doc.get("pending") or [0, None]
        pin = doc.get("pin") or [None, None]
        return cls(
            band=doc.get("band") or band,
            pending=int(pending[0] or 0),
            pending_to=pending[1],
            failed_ticks=int(doc.get("failed_ticks") or 0),
            rules=MappingProxyType(
                {k: RuleState(bool(v[0]), int(v[1])) for k, v in (doc.get("rules") or {}).items()}
            ),
            transitions=tuple(
                (float(x[0]), str(x[1]), str(x[2]))
                for x in doc.get("transitions") or ()
                if len(x) == 3
            ),
            pin_band=pin[0],
            pin_until=None if pin[1] is None else float(pin[1]),
            factor_set=tuple(doc.get("factor_set") or ()),
            horizon_bands=tuple((str(k), str(v)) for k, v in doc.get("horizon_bands") or ()),
            held_by=tuple(str(x) for x in doc.get("held_by") or ()),
            last_written_at=written_at,
            last_score=score,
        )


@dataclass(frozen=True)
class Evaluation:
    agent_id: UUID
    tier: int
    score: int
    clamp: int
    band: str
    target_band: str
    provisional: bool
    factors: list[dict[str, Any]]
    outcomes: Mapping[str, RuleOutcome]
    state: EngineState
    from_band: str | None
    band_changed: bool
    very_fast: bool
    flapping_started: bool
    newly_fired: frozenset[str]
    newly_cleared: frozenset[str]
    fired: frozenset[str]
    recommended_action: str
    floor: str | None
    horizons: Mapping[str, Any] = field(default_factory=dict)
    predicted_failure_mode: str | None = None

    def bookkeeping(self) -> list[dict[str, Any]]:
        out = [self.state.to_bookkeeping()]
        if self.clamp:
            out.append({"rule": "_clamp", "penalty": self.clamp})
        return out

    @property
    def rules_fired(self) -> list[str]:
        return sorted(self.fired | {f["rule"] for f in self.factors if f["penalty"] > 0})


def explain_identity(ev: Evaluation) -> int:
    """``100 - Σ penalty + clamp - score``; zero on every evaluation (qa §3.2 gate)."""
    return 100 - sum(int(f["penalty"]) for f in ev.factors) + ev.clamp - ev.score


# ------------------------------------------------------------------------------ pieces


def _factor(out: RuleOutcome, cap: float, penalty: int) -> dict[str, Any]:
    return {
        "rule": out.code,
        "weight": 0.0 if out.alert_only else round(cap / 100, 4),
        "penalty": penalty,
        "value": out.value if out.value is not None else 0.0,
        "threshold": out.threshold if out.threshold is not None else 0.0,
        "direction": out.direction,
        "kind": out.kind,
        "explanation": out.explanation or out.code,
        "evidence": out.evidence or "/api/v1/events",
    }


def _floor_factor(out: RuleOutcome, cap: float, band: str) -> dict[str, Any]:
    base = _factor(out, cap, 0)
    return {
        **base,
        "value": band,
        "threshold": band,
        "direction": "equals",
        "explanation": f"Band floor {band}: {out.explanation}"[:300],
    }


def _lagging(inp: AgentInputs, cfg: EngineConfig) -> bool:
    return inp.rollup_lag_s > float(cfg.scoring.get("rollup_lag_leading_refusal_s", 120))


def _provisional(inp: AgentInputs, cfg: EngineConfig, now: datetime) -> bool:
    p = cfg.section("provisional")
    age_days = (now - inp.created_at).total_seconds() / 86400
    young = age_days < float(p.get("min_age_days", 1)) and (
        inp.active_minutes_1h < PROVISIONAL_ACTIVE_MINUTES
    )
    return (
        inp.request_count_1h < int(p.get("min_requests_1h", 50))
        or inp.coverage < float(p.get("min_coverage", 0.8))
        or not inp.has_plan
        or young
        or _lagging(inp, cfg)
    )


def _hold_factors(
    band: str,
    target: str,
    clean: int,
    need: int,
    fired: frozenset[str],
    outcomes: Mapping[str, RuleOutcome],
    cfg: EngineConfig,
    tier: int,
) -> list[dict[str, Any]]:
    """Zero-penalty factors explaining a band the score alone would not give (ML.md §3.6).

    After a failover the agent serves cleanly (score 100) while the band improves only after
    ``need`` clean ticks; the snapshot names the rules still firing and the progress, so a
    non-healthy snapshot is never left without a reason.
    """
    out: list[dict[str, Any]] = []
    for code in sorted(fired):
        hit = outcomes.get(code)
        if hit is None or hit.score_only:
            continue
        state = "still firing" if hit.severity > 0 else "no longer breaching"
        why = (
            f"Band held at {band} while recovering ({clean} of {need} clean ticks to {target}); "
            f"{code} {state}: {hit.explanation or code}"
        )
        out.append(
            {
                **_factor(hit, cfg.rule(code).cap(tier), 0),
                "value": band,
                "threshold": target,
                "direction": "equals",
                "explanation": why[:300],
            }
        )
    return out


def _proven(inp: AgentInputs, cfg: EngineConfig, now: datetime, prior: EngineState) -> str | None:
    """Why a detected failure floor on a cold-start agent is evidence, not noise (or ``None``).

    The provisional cap (ML.md §3.8) keeps a new agent's teething errors out of automation. It
    must not hide a hard outage on an agent that has shown a working baseline: one that is past
    ``min_age_days`` (a quiet hour does not make an old agent new), or that served at least
    ``hard_failure_min_ok_1h`` healthy calls in the last hour (default ``min_requests_1h``), or
    whose band is already ``failed`` (a long outage ages the healthy calls out of the hour; the
    lift holds while the floor does). Never without a continuity plan (nothing to fail over to,
    and the operator has not onboarded it), on low coverage or on stale rollups.
    """
    p = cfg.section("provisional")
    if not inp.has_plan or inp.coverage < float(p.get("min_coverage", 0.8)) or _lagging(inp, cfg):
        return None
    if (now - inp.created_at).total_seconds() / 86400 >= float(p.get("min_age_days", 1)):
        return f"agent older than {p.get('min_age_days', 1)} day(s)"
    ok_1h = max(0, inp.request_count_1h - inp.error_count_1h)
    need = int(p.get("hard_failure_min_ok_1h", p.get("min_requests_1h", 50)))
    if ok_1h >= need:
        return f"{ok_1h} healthy calls in the last hour (needs {need})"
    if prior.band == "failed":
        return "failure persisting since the cap was lifted"
    return None


def _rule_step(
    prior: RuleState, breach: bool, h_in: int, h_out: int
) -> tuple[RuleState, bool, bool]:
    """(next state, newly fired, newly cleared)."""
    if not prior.fired:
        count = min(prior.count + 1, h_in) if breach else 0
        if breach and count >= h_in:
            return RuleState(True, 0), True, False
        return RuleState(False, count), False, False
    count = 0 if breach else min(prior.count + 1, h_out)
    if not breach and count >= h_out:
        return RuleState(False, 0), False, True
    return RuleState(True, count), False, False


def _band_step(
    prior: EngineState, target: str, worsen_ticks: int, improve_ticks: int
) -> tuple[str, int, str | None]:
    current = prior.band
    if current is None:
        return target, 0, None
    if target == current:
        return current, 0, None
    worsening = BAND_RANK[target] > BAND_RANK[current]
    same_direction = prior.pending_to is not None and (
        (BAND_RANK[prior.pending_to] > BAND_RANK[current]) == worsening
    )
    count = (prior.pending if same_direction else 0) + 1
    need = worsen_ticks if worsening else improve_ticks
    if count >= need:
        return target, 0, None
    return current, count, target


def _recommended(
    factors: Sequence[dict[str, Any]], outcomes: Mapping[str, RuleOutcome], tier: int, band: str
) -> str:
    top = next((f for f in factors if f["penalty"] > 0), None)
    if top is None:
        return "none" if band == "healthy" else "watch"
    rule = str(top["rule"])
    hint = outcomes[rule].hint if rule in outcomes else None
    if rule == "provider_status" or hint == "provider":
        return "reroute_to_fallback"
    if rule == "fallback_pressure":
        return "reroute_to_fallback"  # the primary is failing calls the fallback step rescues
    if rule in ("ratelimit_proximity", "budget_breach", "budget_proximity"):
        return "throttle"
    if rule == "context_saturation":
        return "trim_context"
    if rule == "tool_loop":
        return "await_approval" if tier == 1 else "quarantine"
    if rule == "quality_proxy":
        return "handoff" if tier == 1 else "watch"
    if band == "failed":
        return "reroute_to_fallback"
    return "watch"


def _reversals(transitions: Sequence[tuple[float, str, str]]) -> int:
    """Direction changes between successive band transitions.

    A staged recovery (failed -> degraded -> healthy) is three transitions but no oscillation;
    only an up/down/up pattern (>= 2 reversals) is a flap (editor reconciliation of §3.7).
    """
    signs = [BAND_RANK[to] > BAND_RANK[frm] for _, frm, to in transitions]
    return sum(1 for a, b in pairwise(signs) if a != b)


def _flap(
    prior: EngineState,
    band: str,
    changed: bool,
    inp: AgentInputs,
    cfg: EngineConfig,
    now: float,
) -> tuple[tuple[tuple[float, str, str], ...], str | None, float | None, bool]:
    flap = cfg.section("flap")
    window = float(flap.get("window_s", 600))
    transitions = tuple(x for x in prior.transitions if now - x[0] < window)
    if changed and prior.band is not None:
        transitions = (*transitions, (now, prior.band, band))
    pin_band, pin_until = prior.pin_band, prior.pin_until
    if pin_until is not None and now >= pin_until:
        pin_band, pin_until = None, None
    started = False
    many_bands = (
        len(transitions) >= int(flap.get("band_transitions", 3)) and _reversals(transitions) >= 2
    )
    many_routes = inp.routing_transitions_10m >= int(flap.get("routing_transitions", 2))
    if pin_until is None and (many_bands or many_routes):
        tier = inp.tier
        direction = list(flap.get("pin_direction", ["worse", "worse", "better"]))[tier - 1]
        seen = [b for x in transitions for b in x[1:]] + [band]
        pick = worse if direction == "worse" else better
        chosen = seen[0]
        for b in seen[1:]:
            chosen = pick(chosen, b)
        pin_band = chosen
        pin_until = now + float(list(flap.get("pin_s", [1200, 900, 900]))[tier - 1])
        started = True
    return transitions, pin_band, pin_until, started


# ---------------------------------------------------------------------------- evaluate


def evaluate(
    inp: AgentInputs,
    prior: EngineState | None,
    cfg: EngineConfig,
    now: datetime,
    *,
    leading: Iterable[RuleOutcome] = (),
) -> Evaluation:
    prior = prior or EngineState()
    tier = inp.tier
    cold = _provisional(inp, cfg, now)
    outcomes: dict[str, RuleOutcome] = {o.code: o for o in evaluate_detected(inp, cfg, now)}
    for lead in leading:
        if cfg.has_rule(lead.code) and not cold:  # leading rules stay off through cold start
            outcomes[lead.code] = lead

    factors: list[dict[str, Any]] = []
    total = 0
    for out in outcomes.values():
        if not out.evaluated:
            continue
        cap = cfg.rule(out.code).cap(tier)
        penalty = 0 if out.alert_only else round(cap * out.severity)
        if penalty > 0 or (out.alert_only and out.severity > 0):
            factors.append(_factor(out, cap, penalty))
            total += penalty
    score = max(0, min(100, 100 - total))
    clamp = max(0, total - 100)

    # rule hysteresis (alerts); quality_proxy is score-only and never alerts
    rules: dict[str, RuleState] = {}
    newly_fired: set[str] = set()
    newly_cleared: set[str] = set()
    for code, out in outcomes.items():
        if out.score_only:
            continue
        spec = cfg.rule(code)
        rule_state, just_fired, just_cleared = _rule_step(
            prior.rules.get(code, RuleState()),
            out.evaluated and out.severity > 0,
            spec.h_in(tier),
            spec.h_out(tier),
        )
        rules[code] = rule_state
        if just_fired:
            newly_fired.add(code)
        if just_cleared:
            newly_cleared.add(code)
    fired = frozenset(code for code, s in rules.items() if s.fired)

    # floors: failed from the detected-failure conditions; degraded from any critical rule
    floor: str | None = None
    floor_factors: list[dict[str, Any]] = []
    for out in outcomes.values():
        if out.floor == "failed" and out.evaluated:
            floor = "failed"
            floor_factors.append(_floor_factor(out, cfg.rule(out.code).cap(tier), "failed"))
    if floor is None:
        # keyed on the OUTCOME's kind (lane P CR): a leading outcome sharing a detected rule's
        # code (the provider-status facet on ``maintenance``) never trips the degraded floor
        for code in sorted(fired):
            hit = outcomes.get(code)
            if hit is not None and cfg.rule(code).severity == "critical" and hit.kind == "detected":
                floor = "degraded"
                floor_factors.append(_floor_factor(hit, cfg.rule(code).cap(tier), "degraded"))
                break

    # a detected failure floor on a proven agent lifts the cold-start cap (``_proven``)
    lift = _proven(inp, cfg, now, prior) if cold and floor is not None else None
    provisional = cold and lift is None
    if lift is not None:
        floor_factors = [
            {**f, "explanation": f"{f['explanation']} (cold-start cap lifted: {lift})"[:300]}
            for f in floor_factors
        ]

    target = band_for_score(cfg, tier, score, current=prior.band)
    if floor is not None:
        target = worse(target, floor)
    if provisional:
        target = better(target, str(cfg.section("provisional").get("max_band", "watch")))

    penal = [f for f in factors if f["penalty"] > 0]
    leading_only = bool(penal) and all(f["kind"] == "leading" for f in penal)
    worsen_kind = "worsen_leading" if leading_only else "worsen_detected"
    band, pending, pending_to = _band_step(
        prior,
        target,
        cfg.hysteresis_ticks(worsen_kind, tier),
        cfg.hysteresis_ticks("improve", tier),
    )

    now_s = _epoch(now)
    pinned_band = band
    if prior.pin_until is not None and now_s < prior.pin_until and prior.pin_band:
        pinned_band = _apply_pin(band, prior.pin_band, tier, cfg, floor)
    changed = prior.band is None or pinned_band != prior.band
    transitions, pin_band, pin_until, started = _flap(prior, pinned_band, changed, inp, cfg, now_s)
    if started and pin_band:
        pinned_band = _apply_pin(pinned_band, pin_band, tier, cfg, floor)
        changed = prior.band is None or pinned_band != prior.band
    band = pinned_band

    failed_ticks = prior.failed_ticks + 1 if band == "failed" else 0
    factors = sorted(factors, key=lambda f: (-f["penalty"], f["rule"])) + floor_factors
    factor_set = tuple(sorted(f["rule"] for f in factors if f["penalty"] > 0))
    # B-07: a floor explains only its own band; recovery hysteresis (or a pin) can hold the
    # band worse than a live floor (failed under a degraded floor), and that must be explained
    if band != "healthy" and not factor_set and all(f["value"] != band for f in floor_factors):
        need = cfg.hysteresis_ticks("improve", tier)
        holding = fired or frozenset(prior.held_by)
        factors = factors + _hold_factors(band, target, pending, need, holding, outcomes, cfg, tier)
    if band == "healthy":
        held_by: tuple[str, ...] = ()
    else:
        held_by = factor_set or prior.held_by
    state = EngineState(
        band=band,
        pending=pending,
        pending_to=pending_to,
        failed_ticks=failed_ticks,
        rules=MappingProxyType(rules),
        transitions=transitions,
        pin_band=pin_band,
        pin_until=pin_until,
        factor_set=factor_set,
        horizon_bands=prior.horizon_bands,
        held_by=held_by,
        last_written_at=prior.last_written_at,
        last_score=prior.last_score,
    )
    return Evaluation(
        agent_id=inp.agent_id,
        tier=tier,
        score=score,
        clamp=clamp,
        band=band,
        target_band=target,
        provisional=provisional,
        factors=factors,
        outcomes=MappingProxyType(outcomes),
        state=state,
        from_band=prior.band,
        band_changed=changed,
        very_fast=failed_ticks >= 2,
        flapping_started=started,
        newly_fired=frozenset(newly_fired),
        newly_cleared=frozenset(newly_cleared),
        fired=fired,
        recommended_action=_recommended(factors, outcomes, tier, band),
        floor=floor,
    )


def _apply_pin(band: str, pin: str, tier: int, cfg: EngineConfig, floor: str | None) -> str:
    """Tiers 1-2 hold the worse band (may still worsen); tier 3 the better (R48).

    A detected-failure floor still wins on every tier: a pin never hides a hard outage.
    """
    direction = list(cfg.section("flap").get("pin_direction", ["worse", "worse", "better"]))[
        tier - 1
    ]
    held = worse(band, pin) if direction == "worse" else better(band, pin)
    if floor == "failed":
        held = worse(held, "failed")
    return held


def with_horizons(
    ev: Evaluation, horizons: Mapping[str, Any], failure_mode: str | None
) -> Evaluation:
    """Attach lane P's horizons; a horizon band change becomes a write-on-change trigger."""
    bands = tuple(
        sorted(
            (str(k), str(v.get("probability_band")))
            for k, v in horizons.items()
            if isinstance(v, Mapping)
        )
    )
    return replace(
        ev,
        horizons=dict(horizons),
        predicted_failure_mode=failure_mode,
        state=replace(ev.state, horizon_bands=bands),
    )


def should_write(prior: EngineState | None, ev: Evaluation, now: datetime) -> str | None:
    """``change`` / ``heartbeat`` / ``None`` (ML.md §7.1 write-on-change + 60 s heartbeat)."""
    if prior is None or prior.band is None or prior.last_score is None:
        return "change"
    if (
        ev.band_changed
        or abs(ev.score - prior.last_score) >= SCORE_MOVE
        or ev.state.core() != prior.core()
    ):
        return "change"
    if (
        prior.last_written_at is None
        or (now - prior.last_written_at).total_seconds() >= HEARTBEAT_S
    ):
        return "heartbeat"
    return None


__all__ = [
    "BANDS",
    "EngineState",
    "Evaluation",
    "RuleState",
    "evaluate",
    "explain_identity",
    "should_write",
    "with_horizons",
]
