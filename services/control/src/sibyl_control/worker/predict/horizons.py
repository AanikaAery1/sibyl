"""The ``rules/v1`` horizon predictor (ML.md §4.2, §4.4): risk per 15 m / 1 h / 24 h.

Inputs per horizon ``H``:

* every **fired** leading rule (after its hysteresis) with ``H_i <= H``; the 24 h horizon takes
  only the slow rules (here the L4 24 h facet), as §4.2 says, not every faster rule;
* the provider-status facet (15 m and 1 h) on an agent not yet erroring;
* detected carry-over: band ``failed`` puts 1.0 into 15 m and 1 h, ``degraded`` 0.4 into 15 m,
  attributed to the top detected factor.

``R_H`` = noisy-OR, quantised to the frozen bands. Confidence describes the evidence, not the
probability. Editor note: §4.4 says "``r_i >= 0.5``" for medium/high, which no leading rule can
reach (caps <= 30, so ``r_i <= 0.3``); this reads it as ``severity_i >= 0.5``.

Output: the ``sibyl-health/1`` ``horizons`` object (``probability_band``, ``source``,
``confidence``, ``contributing_rules``, ``predicted_failure_mode``), plus the document-level
failure mode (nearest horizon with ``R_H >= 0.15``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..scoring.config import EngineConfig
from ..scoring.engine import Evaluation
from ..scoring.features import AgentInputs
from .bands import cuts_of, noisy_or, quantise
from .catalog import (
    DETECTED_MODE,
    HORIZON_KEYS,
    LEADING_HORIZON_S,
    PROVIDER_FACET,
    family,
)
from .feed import AgentFeed
from .leading import _error_mode, budget_facets, provider_facet

CARRY_FAILED = 1.0
CARRY_DEGRADED = 0.4
STRONG_SEVERITY = 0.5
PROVIDER_FRESH_S = 600
HIGH_COVERAGE = 0.95
MEDIUM_COVERAGE = 0.8


@dataclass(frozen=True)
class Contribution:
    rule: str
    r: float
    severity: float
    family: str
    mode: str | None
    leading: bool
    carry: bool = False
    min_samples: int = 0


def _carry_over(ev: Evaluation, cfg: EngineConfig, inp: AgentInputs) -> tuple[float, str | None]:
    scoring = cfg.section("carry_over")
    if ev.band == "failed":
        value = float(scoring.get("failed_band_risk", CARRY_FAILED))
    elif ev.band == "degraded":
        value = float(scoring.get("degraded_band_risk", CARRY_DEGRADED))
    else:
        return 0.0, None
    top = next(
        (f["rule"] for f in ev.factors if f.get("kind") == "detected" and f["penalty"] > 0),
        next((f["rule"] for f in ev.factors if f.get("kind") == "detected"), None),
    )
    return value, top


def _detected_mode(code: str | None, inp: AgentInputs) -> str | None:
    if code is None:
        return None
    if code == "error_rate":
        return _error_mode(inp)
    return DETECTED_MODE.get(code)


def contributions(
    inp: AgentInputs, ev: Evaluation, cfg: EngineConfig, feed: AgentFeed
) -> dict[str, list[Contribution]]:
    tier = inp.tier
    out: dict[str, list[Contribution]] = {k: [] for k in HORIZON_KEYS}
    for code, outcome in ev.outcomes.items():
        if outcome.kind != "leading" or code not in ev.fired or outcome.severity <= 0:
            continue
        spec = cfg.rule(code)
        cap = spec.cap(tier) / 100
        fam = family(code, cfg)
        mode = outcome.hint
        if code == "budget_proximity":
            facets = budget_facets(inp, feed, spec)
            if facets is None:
                continue
            for key, sev in (("1h", facets.severity_1h), ("24h", facets.severity_24h)):
                if sev > 0:
                    out[key].append(
                        Contribution(code, sev * cap, sev, fam, mode, True, False, spec.min_samples)
                    )
            continue
        horizon = LEADING_HORIZON_S.get(code, 900)
        item = Contribution(
            code, outcome.severity * cap, outcome.severity, fam, mode, True, False, spec.min_samples
        )
        if horizon <= 900:
            out["15m"].append(item)
        if horizon <= 3600:
            out["1h"].append(item)
        if horizon >= 86400:
            out["24h"].append(item)

    if not ev.provisional:
        sev = provider_facet(inp, cfg)
        if sev > 0:
            cap = cfg.rule(PROVIDER_FACET).cap(tier) / 100
            item = Contribution(
                PROVIDER_FACET,
                sev * cap,
                sev,
                family(PROVIDER_FACET, cfg),
                "provider_outage",
                True,
                False,
                cfg.rule(PROVIDER_FACET).min_samples,
            )
            out["15m"].append(item)
            out["1h"].append(item)

    carry, top = _carry_over(ev, cfg, inp)
    if carry > 0:
        rule = top or "error_rate"
        item = Contribution(
            rule, carry, 1.0, family(rule, cfg), _detected_mode(top, inp), False, True
        )
        out["15m"].append(item)
        if ev.band == "failed":
            out["1h"].append(item)
    return out


def _confidence(
    key: str, items: list[Contribution], inp: AgentInputs, ev: Evaluation, cfg: EngineConfig
) -> str:
    if key == "24h" or not items:
        return "low"
    if ev.floor is not None and any(c.carry for c in items):
        return "high"
    r1 = cfg.rules.get("error_rate")
    t1 = r1.threshold(inp.tier) if r1 else None
    if (
        any(c.rule == PROVIDER_FACET for c in items)
        and inp.provider_status in ("partial_outage", "major_outage")
        and inp.provider_status_age_s is not None
        and inp.provider_status_age_s < PROVIDER_FRESH_S
        and t1 is not None
        and (inp.provider_error_rate_fleet or 0.0) > t1
    ):
        return "high"
    strong = [c for c in items if c.leading and c.severity >= STRONG_SEVERITY]
    if len({c.family for c in strong}) >= 2 and inp.coverage >= HIGH_COVERAGE:
        return "high"
    if (
        strong
        and not ev.provisional
        and inp.coverage >= MEDIUM_COVERAGE
        and inp.w5.request_count >= 2 * max(c.min_samples for c in strong)
    ):
        return "medium"
    return "low"


def predict_horizons(
    inp: AgentInputs, ev: Evaluation, cfg: EngineConfig, now: datetime, feed: AgentFeed
) -> tuple[dict[str, Any], str | None]:
    """``(horizons, predicted_failure_mode)`` for one agent's evaluation."""
    cuts = cuts_of(cfg.scoring)
    source = str(cfg.scoring.get("rules_source", "rules/v1"))
    by_key = contributions(inp, ev, cfg, feed)
    horizons: dict[str, Any] = {}
    doc_mode: str | None = None
    for key in HORIZON_KEYS:
        items = sorted(by_key[key], key=lambda c: (-c.r, c.rule))
        risk = noisy_or(c.r for c in items)
        band = quantise(risk, cuts)
        names: list[str] = []
        for c in items:
            if c.r > 0 and c.rule not in names:
                names.append(c.rule)
        mode = next((c.mode for c in items if c.r > 0 and c.mode), None)
        horizons[key] = {
            "probability_band": band,
            "source": source,
            "confidence": _confidence(key, items, inp, ev, cfg),
            "contributing_rules": names,
            "predicted_failure_mode": mode,
        }
        if doc_mode is None and risk >= cuts["band_0_25"]:
            doc_mode = mode
    return horizons, doc_mode


def families_of(rules: list[str], cfg: EngineConfig | None = None) -> set[str]:
    return {family(r, cfg) for r in rules}


def band_of(horizons: Mapping[str, Any], key: str = "15m") -> str:
    entry = horizons.get(key) or {}
    return str(entry.get("probability_band", "0.05"))
