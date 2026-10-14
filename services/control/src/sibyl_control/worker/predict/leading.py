"""Leading rules L1-L5 and the provider-status leading facet (ML.md §4.1, §4.3).

Pure functions of ``AgentInputs`` (the open window and statics) plus an ``AgentFeed`` (closed
buckets and trend state). Each returns a ``RuleOutcome`` with ``kind="leading"`` that the engine
scores with ``cap x severity``, puts through the rule's hysteresis and fires/resolves alerts for;
the horizons predictor then reads the same severities, so health and risk cannot disagree.

Interpretations recorded for the chair (ML.md leaves them open):

* "slope > 0 for 3 windows" = the last three closed-5m deltas are all positive (four buckets).
* A CUSUM alarm with the level below the arming fraction still needs a severity, or it could
  never fire: it uses the ``drift_cusum`` curve, ``clamp((S+ - h) / h) x 0.5``.
* L2's baseline-relative path arms at ``vs_baseline`` (1.5) and saturates at R2's
  ``relative_threshold`` (2.0).
* L4 has two facets: spend projected one hour ahead >= 0.9 (horizon 1 h) and spend projected
  24 h ahead >= 1.0 (horizon 24 h); both use ``clamp((projected - 0.9) / 0.1)``. The burn rate is
  the larger of the last 5 closed minutes and the last hour.
* The provider-status facet is not scored (see ``provider_facet``).
* L5 (restored from the Tier B1 cut, wave 3) reads the open 5-minute window like L3's 429 share:
  calls the gateway rescued with the inline fallback step plus calls refused on an open breaker,
  over all calls. Its failure mode is ``provider_outage``: the agent's own error rate stays at
  zero while the fallback hides a failing primary, so without L5 that outage is invisible.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from itertools import pairwise

from ..scoring.config import EngineConfig, RuleSpec
from ..scoring.features import AgentInputs
from ..scoring.rules import RuleOutcome, evidence, pct
from .bands import clamp
from .catalog import PHASE1_LEADING, PROVIDER_FACET, TREND_WINDOWS
from .feed import AgentFeed

MAX_EXPLANATION = 300
EPS = 1e-9
SHARE_429_SATURATION_MULTIPLE = 3
L5_SATURATION_SPAN = 0.4
LEADING_STATUSES = ("maintenance", "degraded_performance", "partial_outage")


def _skip(rule: RuleSpec, why: str) -> RuleOutcome:
    return RuleOutcome(rule.code, "leading", False, 0.0, explanation=why[:MAX_EXPLANATION])


def _text(s: str) -> str:
    return s[:MAX_EXPLANATION]


def rising(series: Sequence[float | None], windows: int = TREND_WINDOWS) -> bool:
    """The last ``windows`` window-to-window deltas are all positive."""
    tail = list(series)[-(windows + 1) :]
    if len(tail) < windows + 1 or any(x is None for x in tail):
        return False
    return all(b > a for a, b in pairwise(tail))  # type: ignore[operator]


def cusum_severity(s_pos: float, h: float) -> float:
    """The ``drift_cusum`` curve: 0 at ``h``, 0.5 at ``2h``."""
    if h <= 0 or s_pos <= h:
        return 0.0
    return clamp((s_pos - h) / h) * 0.5


def level_severity(level: float, threshold: float, arm: float) -> float:
    """``clamp((level / t - arm) / (1 - arm))``: 0 at the arming fraction, 1 at the threshold."""
    if threshold <= 0 or arm >= 1:
        return 0.0
    return clamp((level / threshold - arm) / (1 - arm))


def lsq_slope(points: Sequence[tuple[float, float]]) -> float | None:
    """Least-squares slope of ``(x, y)`` points (``None`` below three points)."""
    if len(points) < 3:
        return None
    n = len(points)
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((x - mx) ** 2 for x, _ in points)
    if den <= EPS:
        return None
    return sum((x - mx) * (y - my) for x, y in points) / den


def _cusum_h(cfg: EngineConfig) -> float:
    return float(cfg.section("trend").get("cusum_h", 5))


def _error_mode(inp: AgentInputs) -> str:
    """Dominant error class of the open window (ML.md §4.3, L1's failure mode)."""
    w = inp.w5
    classes = {
        "provider_outage": w.server_error_count + w.rate_limit_count,
        "latency_degradation": w.timeout_count,
        "permission_error": w.blocked_count,
        "tool_failure": w.tool_error_count,
    }
    mode, count = max(classes.items(), key=lambda kv: (kv[1], kv[0] == "provider_outage"))
    return mode if count > 0 else "provider_outage"


# --------------------------------------------------------------------------- L1 / L2


@dataclass(frozen=True)
class _TrendCase:
    """One trend rule's inputs: the closed series, its trend state and the detected threshold."""

    series: Sequence[float | None]
    ewma: float
    cusum: float
    threshold: float
    noun: str
    unit: Callable[[float], str]
    evidence: str
    mode: str
    extra: tuple[float, str] | None = None


def _trend_outcome(rule: RuleSpec, cfg: EngineConfig, case: _TrendCase) -> RuleOutcome:
    arm = float(rule.params.get("level_vs_detected_threshold", 0.5))
    h = _cusum_h(cfg)
    sev_level = level_severity(case.ewma, case.threshold, arm)
    paths: list[str] = []
    severity = 0.0
    if rising(case.series) and case.ewma >= arm * case.threshold:
        severity = sev_level
        paths.append(f"rising for {TREND_WINDOWS} windows")
    if case.cusum > h:
        severity = max(severity, sev_level, cusum_severity(case.cusum, h))
        paths.append(f"CUSUM {case.cusum:.1f} > {h:g}")
    if case.extra is not None and case.extra[0] > 0:
        severity = max(severity, case.extra[0])
        paths.append(case.extra[1])
    why = (
        f"{case.noun} EWMA {case.unit(case.ewma)}; arms at {pct(arm)} of the detected threshold "
        f"{case.unit(case.threshold)}"
    )
    why += f"; {', '.join(paths)}" if paths else "; not rising"
    return RuleOutcome(
        rule.code,
        "leading",
        True,
        round(severity, 4),
        round(case.ewma, 4),
        round(arm * case.threshold, 4),
        explanation=_text(why),
        evidence=case.evidence,
        hint=case.mode,
    )


def _few_samples(rule: RuleSpec, f: AgentFeed) -> RuleOutcome | None:
    if f.closed_requests >= rule.min_samples:
        return None
    return _skip(
        rule,
        f"{f.closed_requests} requests in the last closed 5 minutes; needs {rule.min_samples}",
    )


def error_trend(inp: AgentInputs, f: AgentFeed, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    rule = cfg.rule("error_trend")
    r1 = cfg.rules.get("error_rate")
    t = r1.threshold(inp.tier) if r1 else None
    if t is None:
        return _skip(rule, "no error_rate threshold for this tier")
    few = _few_samples(rule, f)
    if few is not None:
        return few
    tv = f.trends.get("error_rate")
    if tv is None or tv.ewma is None:
        return _skip(rule, "no error-rate trend state yet")
    case = _TrendCase(
        f.error_series,
        tv.ewma,
        tv.cusum_pos,
        t,
        "Error rate",
        pct,
        evidence(inp.agent_id, now, 900, status="error"),
        _error_mode(inp),
    )
    return _trend_outcome(rule, cfg, case)


def latency_trend(inp: AgentInputs, f: AgentFeed, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    rule = cfg.rule("latency_trend")
    r2 = cfg.rules.get("p95_latency")
    if r2 is None:
        return _skip(rule, "no p95_latency rule")
    few = _few_samples(rule, f)
    if few is not None:
        return few
    tv = f.trends.get("latency_p95_ms")
    if tv is None or tv.ewma is None:
        return _skip(rule, "no latency trend state yet")
    case = _TrendCase(
        f.p95_series,
        tv.ewma,
        tv.cusum_pos,
        float(r2.threshold_by_model_class.get(inp.model_class, 20000)),
        "p95 latency",
        lambda x: f"{x:.0f} ms",
        evidence(inp.agent_id, now, 900, event_type="gen_ai.request"),
        "latency_degradation",
        _relative(inp, f, rule, r2),
    )
    return _trend_outcome(rule, cfg, case)


def _relative(
    inp: AgentInputs, f: AgentFeed, rule: RuleSpec, r2: RuleSpec
) -> tuple[float, str] | None:
    base = inp.baselines.get("latency_p95_ms")
    if not base or not inp.baseline_ref.startswith("own/"):
        return None
    tail = [x for x in f.p95_series[-2:] if x is not None]
    if len(tail) < 2 or tail[-1] <= tail[-2]:
        return None
    ratio = tail[-1] / base
    arm = float(rule.params.get("vs_baseline", 1.5))
    sat = float(r2.params.get("relative_threshold", 2))
    if ratio < arm or sat <= arm:
        return None
    return clamp((ratio - arm) / (sat - arm)), f"{ratio:.2f}x the own baseline and rising"


# ------------------------------------------------------------------------------- L3


def headroom_now(inp: AgentInputs, f: AgentFeed) -> float | None:
    if f.headroom_points:
        return min(f.headroom_points, key=lambda p: p[0])[1]
    return inp.w5.ratelimit_headroom_min


def time_to_exhaustion_s(f: AgentFeed, head: float | None) -> float | None:
    """``headroom / burn`` from the closed-minute headroom series (``None`` when not falling)."""
    if head is None:
        return None
    slope = lsq_slope([(-age, value) for age, value in f.headroom_points])
    if slope is None or slope >= -EPS:
        return None
    return max(0.0, head / -slope)


def ratelimit_proximity(
    inp: AgentInputs, f: AgentFeed, cfg: EngineConfig, now: datetime
) -> RuleOutcome:
    rule = cfg.rule("ratelimit_proximity")
    t = rule.threshold(inp.tier)
    share_t = float(rule.params.get("share_429", 0.05))
    tte_t = float(rule.params.get("time_to_exhaustion_s", 900))
    head = headroom_now(inp, f)
    w = inp.w5
    share = w.ratio("rate_limit_count") if w.request_count >= rule.min_samples else None
    if head is None and share is None:
        return _skip(rule, "no rate-limit headroom reported and too few requests for a 429 share")
    tte = time_to_exhaustion_s(f, head)
    parts: list[tuple[float, str]] = []
    if head is not None and t is not None and head < t:
        parts.append((clamp((t - head) / t), f"headroom {pct(head)} below {pct(t)}"))
    if share is not None and share > share_t:
        sat = SHARE_429_SATURATION_MULTIPLE * share_t
        parts.append((clamp(share / sat), f"429 share {pct(share)} above {pct(share_t)}"))
    if tte is not None and tte < tte_t:
        parts.append((clamp((tte_t - tte) / tte_t), f"exhaustion in ~{tte / 60:.0f} min"))
    severity = max((s for s, _ in parts), default=0.0)
    shown = "unknown" if head is None else pct(head)
    why = f"Rate-limit headroom {shown}" + (
        f"; {', '.join(p for _, p in parts)}" if parts else "; comfortable"
    )
    return RuleOutcome(
        rule.code,
        "leading",
        True,
        round(severity, 4),
        round(head, 4) if head is not None else round(share or 0.0, 4),
        t if t is not None else share_t,
        direction="below" if head is not None else "above",
        explanation=_text(why),
        evidence=evidence(inp.agent_id, now, 900, event_type="gen_ai.request"),
        hint="provider_outage",
    )


# ------------------------------------------------------------------------------- L4


@dataclass(frozen=True)
class BudgetFacets:
    projected_1h: float
    projected_24h: float
    severity_1h: float
    severity_24h: float


def budget_facets(inp: AgentInputs, f: AgentFeed, rule: RuleSpec) -> BudgetFacets | None:
    t1 = float(rule.params.get("projected_1h", 0.9))
    t24 = float(rule.params.get("month_projected_24h", 1))
    if f.budget_usd:
        p1 = (f.mtd_cost_usd + f.cost_rate_usd_s * 3600) / f.budget_usd
        p24 = (f.mtd_cost_usd + f.cost_rate_usd_s * 86400) / f.budget_usd
    elif inp.spend_ratio is not None:
        p1 = p24 = inp.spend_ratio  # no burn rate without the feed: the level is a lower bound
    else:
        return None
    span = max(1 - t1, EPS)
    s1 = clamp((p1 - t1) / span) if p1 >= t1 else 0.0
    s24 = clamp((p24 - t1) / span) if p24 >= t24 else 0.0
    return BudgetFacets(p1, p24, s1, s24)


def budget_proximity(
    inp: AgentInputs, f: AgentFeed, cfg: EngineConfig, now: datetime
) -> RuleOutcome:
    rule = cfg.rule("budget_proximity")
    facets = budget_facets(inp, f, rule)
    if facets is None:
        return _skip(rule, "no monthly budget in the continuity plan")
    severity = max(facets.severity_1h, facets.severity_24h)
    why = (
        f"Spend projected at {pct(facets.projected_1h)} of the monthly budget in 1 h and "
        f"{pct(facets.projected_24h)} in 24 h"
    )
    return RuleOutcome(
        rule.code,
        "leading",
        True,
        round(severity, 4),
        round(facets.projected_1h, 4),
        float(rule.params.get("projected_1h", 0.9)),
        explanation=_text(why),
        evidence=evidence(inp.agent_id, now, 3600, event_type="gen_ai.request"),
        hint="cost_runaway",
    )


# ------------------------------------------------------------------- provider facet


def provider_facet(inp: AgentInputs, cfg: EngineConfig) -> float:
    """Provider-status leading facet: ordinal severity for ``maintenance`` /
    ``degraded_performance`` / ``partial_outage`` on an agent not yet erroring.

    Horizons only, never a score factor: it shares the code ``provider_status`` with R4, whose
    seed severity is ``critical`` and kind ``detected``, and the engine's floor treats any fired
    critical detected rule as a ``degraded`` floor (change request: key the floor on the
    outcome's kind, then this facet can be scored like the other leading rules).
    """
    if not cfg.has_rule(PROVIDER_FACET) or inp.provider_status is None:
        return 0.0
    leading_at = tuple(cfg.rule(PROVIDER_FACET).params.get("leading_at") or LEADING_STATUSES)
    if inp.provider_status not in leading_at:
        return 0.0
    r1 = cfg.rules.get("error_rate")
    t = r1.threshold(inp.tier) if r1 else None
    err = inp.w5.ratio("error_count")
    if t is not None and err is not None and err >= t:
        return 0.0  # already erroring: the detected rules own it
    return cfg.provider_status_ordinal(inp.provider_status)


# ------------------------------------------------------------------------------- L5


def fallback_pressure(
    inp: AgentInputs, f: AgentFeed, cfg: EngineConfig, now: datetime
) -> RuleOutcome:
    """``clamp((share - t) / 0.4)`` of the inline-fallback + open-breaker share (ML.md §4.3)."""
    rule = cfg.rule("fallback_pressure")
    t = rule.threshold(inp.tier)
    w = inp.w5
    if t is None:
        return _skip(rule, "no threshold for this tier")
    if w.request_count < rule.min_samples:
        return _skip(rule, f"{w.request_count} requests in 5 minutes; needs {rule.min_samples}")
    rescued, refused = w.inline_fallback_count, w.breaker_open_count
    share = min(1.0, (rescued + refused) / w.request_count)
    why = (
        f"{pct(share)} of calls over the last 5 minutes needed the inline fallback ({rescued})"
        f" or met an open breaker ({refused}); threshold {pct(t)}"
    )
    return RuleOutcome(
        rule.code,
        "leading",
        True,
        round(clamp((share - t) / L5_SATURATION_SPAN), 4),
        round(share, 4),
        t,
        explanation=_text(why),
        evidence=evidence(inp.agent_id, now, 300, event_type="gen_ai.request"),
        hint="provider_outage",
    )


# ------------------------------------------------------------------------- entry point

Evaluator = Callable[[AgentInputs, AgentFeed, EngineConfig, datetime], RuleOutcome]

LEADING: dict[str, Evaluator] = {
    "error_trend": error_trend,
    "latency_trend": latency_trend,
    "ratelimit_proximity": ratelimit_proximity,
    "budget_proximity": budget_proximity,
    "fallback_pressure": fallback_pressure,
}
assert tuple(LEADING) == PHASE1_LEADING


def evaluate_leading(
    inp: AgentInputs, feed: AgentFeed, cfg: EngineConfig, now: datetime
) -> list[RuleOutcome]:
    """Every enabled Phase 1 leading rule for one agent, in a stable order."""
    return [run(inp, feed, cfg, now) for code, run in LEADING.items() if cfg.has_rule(code)]
