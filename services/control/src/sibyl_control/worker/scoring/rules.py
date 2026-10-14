"""Detected rules R1-R9, ``tool_loop`` and ``quality_proxy`` (ML.md §3.2-§3.4).

Each evaluator is a pure function of ``AgentInputs`` returning a ``RuleOutcome``: a severity in
[0, 1], the value and threshold it compared, a one-line explanation and an evidence link. The
score multiplies severity by the tier cap (``score.py``); hysteresis uses ``severity > 0``.

R6-R8 are alert-only: their score contribution goes through ``quality_proxy`` (the max of the
three plus empty output) so output quality is never double counted (ML.md §10.4 item 2).
Leading rules (L1-L7) are lane P's and plug in through ``extensions.LeadingEvaluator``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from urllib.parse import quote
from uuid import UUID

from .config import EngineConfig, RuleSpec
from .features import AgentInputs

API_BASE = "/api/v1"
MAX_EXPLANATION = 300

FactorValue = float | str | bool


@dataclass(frozen=True)
class RuleOutcome:
    code: str
    kind: str
    evaluated: bool
    severity: float
    value: FactorValue | None = None
    threshold: FactorValue | None = None
    direction: str = "above"
    explanation: str = ""
    evidence: str = ""
    floor: str | None = None
    alert_only: bool = False
    score_only: bool = False
    hint: str | None = None  # dominant cause for recommended_action / failure mode


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def above(x: float, t: float, s: float) -> float:
    """Rates, shares, latency: 0 at the threshold, 1 at saturation ``s``."""
    if s <= t:
        return 1.0 if x > t else 0.0
    return clamp((x - t) / (s - t))


def below(x: float, t: float) -> float:
    """Headroom: 0 at the threshold, 1 at zero."""
    if t <= 0:
        return 0.0
    return clamp((t - x) / t)


def count_curve(n: int, t: int) -> float:
    """Consecutive failures: 1/t at the threshold, full at 2t - 1."""
    if t <= 0:
        return 0.0
    return clamp((n - t + 1) / t)


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"


@lru_cache(maxsize=64)
def _window(now: datetime, window_s: int) -> str:
    start = (now - timedelta(seconds=window_s)).isoformat().replace("+00:00", "Z")
    return f"from={quote(start)}&to={quote(now.isoformat().replace('+00:00', 'Z'))}"


def evidence(agent_id: UUID, now: datetime, window_s: int, **filters: str) -> str:
    """``GET /events`` link for the window (values are URL-safe: uuid, enum, RFC 3339)."""
    extra = "".join(f"&{k}={quote(v)}" for k, v in filters.items())
    return f"{API_BASE}/events?agent_id={agent_id}{extra}&{_window(now, window_s)}"


def _skip(rule: RuleSpec, why: str) -> RuleOutcome:
    return RuleOutcome(rule.code, rule.kind, False, 0.0, explanation=why[:MAX_EXPLANATION])


def _text(s: str) -> str:
    return s[:MAX_EXPLANATION]


# ----------------------------------------------------------------------- evaluators


def _error_rate(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    w = inp.w5
    t = rule.threshold(inp.tier)
    if t is None or w.request_count < rule.min_samples:
        return _skip(rule, f"{w.request_count} requests in 5 minutes; needs {rule.min_samples}")
    x = w.ratio("error_count") or 0.0
    s = cfg.curve("rate_saturation_multiple", 3) * t
    floor_at = float(cfg.section("floors").get("error_rate_failed", 0.5))
    share_5xx = w.ratio("server_error_count") or 0.0
    hint = "provider" if share_5xx >= x / 2 and x > 0 else None
    why = (
        f"Error rate {pct(x)} over the last 5 minutes (threshold {pct(t)}, saturates at "
        f"{pct(s)}); 5xx share {share_5xx:.2f}"
    )
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        above(x, t, s),
        round(x, 4),
        t,
        explanation=_text(why),
        evidence=evidence(inp.agent_id, now, 300, status="error"),
        floor="failed" if x >= floor_at else None,
        hint=hint,
    )


def _p95_latency(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    w = inp.w5
    p95 = w.p95_ms
    if p95 is None or w.request_count < rule.min_samples:
        return _skip(rule, f"{w.request_count} requests in 5 minutes; needs {rule.min_samples}")
    t = float(rule.threshold_by_model_class.get(inp.model_class, 20000))
    sev_abs = above(p95, t, cfg.curve("latency_saturation_multiple", 2) * t)
    base = inp.baselines.get("latency_p95_ms")
    sev_rel = 0.0
    if base and inp.baseline_ref.startswith("own/"):
        t_rel = cfg.curve("relative_threshold", 2)
        s_rel = cfg.curve("relative_saturation", 4)
        sev_rel = above(p95 / base, t_rel, s_rel)
    if base and sev_rel > sev_abs:
        why = f"p95 latency {p95:.0f} ms is {p95 / base:.1f}x the agent baseline {base:.0f} ms"
    else:
        why = f"p95 latency {p95:.0f} ms against {inp.model_class}-model threshold {t:.0f} ms"
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        max(sev_abs, sev_rel),
        p95,
        t,
        explanation=_text(why),
        evidence=evidence(inp.agent_id, now, 300, event_type="gen_ai.request"),
        hint="latency",
    )


def _consecutive(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    t = rule.threshold(inp.tier)
    if t is None:
        return _skip(rule, "no threshold for this tier")
    n = inp.consecutive_errors
    sev = count_curve(n, int(t))
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        sev,
        float(n),
        t,
        explanation=_text(f"{n} consecutive failed calls (threshold {int(t)})"),
        evidence=evidence(inp.agent_id, now, 60, status="error"),
        floor="failed" if sev >= 1 else None,
    )


def _provider_status(
    inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime
) -> RuleOutcome:
    status = inp.provider_status or "unknown"
    detected = status == "major_outage"
    sev = cfg.provider_status_ordinal(status) if detected else 0.0
    corroborated = False
    r1 = cfg.rules.get("error_rate")
    t_r1 = r1.threshold(inp.tier) if r1 else None
    if detected and t_r1 is not None and inp.provider_error_rate_fleet is not None:
        corroborated = inp.provider_error_rate_fleet > t_r1
    contradicted = detected and not corroborated and _own_traffic_clean(inp, r1, t_r1)
    why = f"Provider {inp.provider or '?'} reports {status}"
    if corroborated:
        why += f"; fleet error rate {pct(inp.provider_error_rate_fleet or 0)} corroborates"
    link = (
        f"{API_BASE}/providers/{inp.provider_id}/status"
        if inp.provider_id
        else evidence(inp.agent_id, now, 300)
    )
    if contradicted:
        # S-16 (ML §8.2): a status page contradicted by the agent's own clean traffic is
        # status-only evidence. It costs points at the leading facet's strongest ordinal
        # (ML §4.3, "agent not yet erroring") but is not a detected fact: as a leading outcome
        # it trips neither the failure floor nor the critical-rule degraded floor.
        why += f"; own traffic is clean ({inp.w5.request_count} calls in 5 minutes)"
        return RuleOutcome(
            rule.code,
            "leading",
            True,
            cfg.provider_status_ordinal("partial_outage"),
            status,
            "major_outage",
            direction="equals",
            explanation=_text(why),
            evidence=link,
            hint="provider_outage",
        )
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        sev,
        status,
        "major_outage",
        direction="equals",
        explanation=_text(why),
        evidence=link,
        floor="failed" if corroborated else None,
        hint="provider",
    )


def _own_traffic_clean(inp: AgentInputs, r1: RuleSpec | None, t_r1: float | None) -> bool:
    """The agent's own primary calls are failing below R1's threshold, now and with enough
    samples: R1's ``min_samples`` in 5 minutes, or, for a quiet agent, in the last hour.

    A call the inline fallback rescued or an open breaker refused failed on the primary, so a
    masked outage (B35) never reads as clean traffic. An agent with no call in 5 minutes says
    nothing about the provider now."""
    w = inp.w5
    if r1 is None or t_r1 is None or w.request_count < 1:
        return False
    failed = w.error_count + w.inline_fallback_count + w.breaker_open_count
    if failed / w.request_count >= t_r1:
        return False
    need = max(1, r1.min_samples)
    if w.request_count >= need:
        return True
    hour = inp.request_count_1h
    return hour >= need and inp.error_count_1h / hour < t_r1


def _budget(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    if inp.spend_ratio is None:
        return _skip(rule, "no monthly budget in the continuity plan")
    t = rule.threshold(inp.tier) or 1.0
    sev = 1.0 if inp.spend_ratio >= t else 0.0
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        sev,
        round(inp.spend_ratio, 4),
        t,
        explanation=_text(f"Month-to-date spend is {pct(inp.spend_ratio)} of the plan budget"),
        evidence=evidence(inp.agent_id, now, 3600, event_type="gen_ai.request"),
        hint="budget",
    )


def _share(
    code_metric: tuple[str, str],
    noun: str,
    filters: dict[str, str],
) -> Callable[[AgentInputs, RuleSpec, EngineConfig, datetime], RuleOutcome]:
    numerator, denominator = code_metric

    def run(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
        w = inp.w5
        t = rule.threshold(inp.tier)
        den = getattr(w, denominator)
        if t is None or den < rule.min_samples:
            return RuleOutcome(
                rule.code,
                rule.kind,
                False,
                0.0,
                alert_only=True,
                explanation=_text(f"{den} samples in 5 minutes; needs {rule.min_samples}"),
            )
        x = w.ratio(numerator, denominator) or 0.0
        s = cfg.curve("rate_saturation_multiple", 3) * t
        sev = above(x, t, s)
        why = f"{noun} {pct(x)} over 5 minutes (threshold {pct(t)})"
        vs = rule.params.get("vs_baseline")
        base = inp.baselines.get("finish_length_ratio") if vs else None
        if vs and base:
            if x / base <= float(vs):
                sev = 0.0
            why += f"; {x / base:.1f}x baseline (needs {float(vs):.0f}x)"
        return RuleOutcome(
            rule.code,
            rule.kind,
            True,
            sev,
            round(x, 4),
            t,
            explanation=_text(why),
            evidence=evidence(inp.agent_id, now, 300, **filters),
            alert_only=True,
            hint="quality",
        )

    return run


def _heartbeat(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    if not inp.cadence_s:
        return _skip(rule, "the continuity plan declares no traffic cadence")
    multiple = float(rule.params.get("silent_cadence_multiple", 2))
    limit = multiple * inp.cadence_s
    silent_s = (now - inp.last_request_at).total_seconds() if inp.last_request_at else None
    missing = silent_s is None or silent_s >= limit
    shown = "no traffic seen" if silent_s is None else f"silent for {silent_s:.0f} s"
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        1.0 if missing else 0.0,
        missing,
        True,
        direction="equals",
        explanation=_text(f"{shown}; declared cadence {inp.cadence_s} s x {multiple:g}"),
        evidence=evidence(inp.agent_id, now, int(limit)),
    )


def _tool_loop(inp: AgentInputs, rule: RuleSpec, cfg: EngineConfig, now: datetime) -> RuleOutcome:
    w = inp.w5
    min_calls = int(rule.params.get("tool_call_count_5m", 20))
    t = float(rule.params.get("tool_seq_repeat_ratio", 0.5))
    if w.tool_call_count <= min_calls:
        return RuleOutcome(
            rule.code,
            rule.kind,
            True,
            0.0,
            0.0,
            t,
            explanation=_text(f"{w.tool_call_count} tool calls in 5 minutes (needs > {min_calls})"),
            evidence=evidence(inp.agent_id, now, 300, event_type="tool.call"),
        )
    repeat = 1.0 - min(w.tool_seq_hash_distinct, w.tool_call_count) / w.tool_call_count
    return RuleOutcome(
        rule.code,
        rule.kind,
        True,
        above(repeat, t, 1.0),
        round(repeat, 4),
        t,
        explanation=_text(
            f"{w.tool_call_count} tool calls over {w.tool_seq_hash_distinct} distinct task/tool "
            f"pairs in 5 minutes: repeat ratio {pct(repeat)} (threshold {pct(t)})"
        ),
        evidence=evidence(inp.agent_id, now, 300, event_type="tool.call"),
        hint="tool_loop",
    )


QUALITY_COMPONENTS = ("refusal_share", "truncation_share", "schema_fail_share")


def _quality_proxy(
    inp: AgentInputs,
    rule: RuleSpec,
    cfg: EngineConfig,
    now: datetime,
    components: dict[str, RuleOutcome],
) -> RuleOutcome:
    w = inp.w5
    t_empty = float(rule.params.get("empty_output_ratio", 0.05))
    parts: list[tuple[float, str]] = [(o.severity, code) for code, o in components.items()]
    if w.request_count >= rule.min_samples:
        x = w.ratio("empty_output_count") or 0.0
        parts.append(
            (above(x, t_empty, cfg.curve("rate_saturation_multiple", 3) * t_empty), "empty_output")
        )
    evaluated = bool(parts) and (
        any(o.evaluated for o in components.values()) or w.request_count >= rule.min_samples
    )
    sev, dominant = max(parts, default=(0.0, "none"))
    return RuleOutcome(
        rule.code,
        rule.kind,
        evaluated,
        sev,
        round(sev, 4),
        0.0,
        explanation=_text(f"Output-quality proxy at {pct(sev)} severity, led by {dominant}"),
        evidence=evidence(inp.agent_id, now, 300, event_type="gen_ai.request"),
        score_only=True,
        hint="quality",
    )


Evaluator = Callable[[AgentInputs, RuleSpec, EngineConfig, datetime], RuleOutcome]

DETECTED: dict[str, Evaluator] = {
    "error_rate": _error_rate,
    "p95_latency": _p95_latency,
    "consecutive_failures": _consecutive,
    "provider_status": _provider_status,
    "budget_breach": _budget,
    "refusal_share": _share(("refusal_count", "request_count"), "Refusal share", {}),
    "truncation_share": _share(("finish_length_count", "request_count"), "Truncated responses", {}),
    "schema_fail_share": _share(
        ("tool_schema_invalid_count", "tool_call_count"),
        "Tool-call schema failures",
        {"event_type": "tool.call"},
    ),
    "heartbeat_missing": _heartbeat,
    "tool_loop": _tool_loop,
}


def evaluate_detected(inp: AgentInputs, cfg: EngineConfig, now: datetime) -> list[RuleOutcome]:
    """Every enabled detected rule for one agent, in a stable order."""
    out: dict[str, RuleOutcome] = {}
    for code, run in DETECTED.items():
        if cfg.has_rule(code):
            out[code] = run(inp, cfg.rule(code), cfg, now)
    if cfg.has_rule("quality_proxy"):
        comps = {c: out[c] for c in QUALITY_COMPONENTS if c in out}
        out["quality_proxy"] = _quality_proxy(inp, cfg.rule("quality_proxy"), cfg, now, comps)
    return list(out.values())


def iter_codes() -> Iterator[str]:
    yield from DETECTED
    yield "quality_proxy"
