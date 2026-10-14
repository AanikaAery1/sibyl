"""Behavioural features of one agent+provider+model (D51): freezing a baseline and comparing a
window against it. Pure functions over samples read by ``store``.

Per model call (``gen_ai.request``): output tokens, input tokens and latency (numeric, PSI over
the baseline's decile bins); refusal, truncation and tool-call shares among successful calls,
and the error-class mix over every call (categorical, Jensen-Shannon). Per agent tool call
(``tool.call``): schema-failure share and the tool-sequence bigram mix within a task. The rollup
derives the same flags the same way (``worker.rollup.pipeline``), so the drift numbers and the
health counters agree.

A frozen feature is a JSON document (stored in ``drift_baseline.features``):
``{"kind": "numeric", "statistic": "psi", "n": 812, "edges": [...], "probs": [...]}`` or
``{"kind": "categorical", "statistic": "js", "n": 812, "probs": {"no": 0.98, "yes": 0.02}}``.

Verdicts compare the statistic's **excess over its sampling noise floor** (the value two samples
of one distribution would show at these sizes, ``stats.psi_noise`` / ``stats.js_noise``) with
the watch / drift thresholds, so a small window never reads as drift by chance alone. Each
result keeps the raw value, the floor and the excess. A feature below its minimum sample size
on either side is ``insufficient_samples`` and never decides a verdict.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from itertools import pairwise
from typing import Any

from sibyl_schemas.values import DriftFeature, DriftStatistic, DriftVerdict

from . import stats
from .config import DriftConfig

F = DriftFeature
YES, NO = "yes", "no"
OK_CLASS = "ok"
SCHEMA_ERROR_TYPES = frozenset({"schema_validation", "invalid_arguments", "ValidationError"})
VERDICT_RANK = {DriftVerdict.NONE: 0, DriftVerdict.WATCH: 1, DriftVerdict.DRIFT: 2}


@dataclass(frozen=True)
class CallSample:
    """One ``gen_ai.request`` event, reduced to what drift reads."""

    tokens_out: int | None = None
    tokens_in: int | None = None
    latency_ms: float | None = None
    status: str | None = "ok"
    error_class: str | None = None
    refusal: bool = False
    truncated: bool = False
    tool_call: bool = False
    response_model: str | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class ToolSample:
    """One ``tool.call`` event in time order (within its task)."""

    task_id: str | None
    tool: str | None
    schema_fail: bool = False


@dataclass(frozen=True)
class Window:
    calls: tuple[CallSample, ...] = ()
    tools: tuple[ToolSample, ...] = ()


@dataclass(frozen=True)
class FeatureResult:
    feature: DriftFeature
    statistic: DriftStatistic
    status: str  # ok | insufficient_samples | invalid_baseline
    value: float | None
    watch: float
    drift: float
    verdict: DriftVerdict
    n_baseline: int
    n_window: int
    contributors: tuple[tuple[str, float, float], ...] = field(default=())
    noise_floor: float = 0.0

    @property
    def excess(self) -> float | None:
        """The statistic above what sampling alone produces (what the verdict compares)."""
        return None if self.value is None else max(0.0, self.value - self.noise_floor)

    def as_json(self) -> dict[str, Any]:
        excess = self.excess
        return {
            "feature": self.feature.value,
            "statistic": self.statistic.value,
            "status": self.status,
            "value": None if self.value is None else round(self.value, 6),
            "noise_floor": round(self.noise_floor, 6),
            "excess": None if excess is None else round(excess, 6),
            "watch": self.watch,
            "drift": self.drift,
            "verdict": self.verdict.value,
            "n_baseline": self.n_baseline,
            "n_window": self.n_window,
            "contributors": [
                {"label": label, "baseline": round(base, 6), "window": round(now, 6)}
                for label, base, now in self.contributors
            ],
        }


# --------------------------------------------------------------------------- extraction

NUMERIC: Mapping[DriftFeature, Callable[[CallSample], float | None]] = {
    F.OUTPUT_TOKENS: lambda c: None if c.tokens_out is None else float(c.tokens_out),
    F.INPUT_TOKENS: lambda c: None if c.tokens_in is None else float(c.tokens_in),
    F.LATENCY_MS: lambda c: None if c.latency_ms is None else float(c.latency_ms),
}
CALL_CATEGORICAL = (F.REFUSAL, F.TRUNCATION, F.TOOL_CALL, F.ERROR_CLASS)
TOOL_CATEGORICAL = (F.SCHEMA_FAIL, F.TOOL_BIGRAM)


def _flag(value: bool) -> str:
    return YES if value else NO


def bigrams(tools: Sequence[ToolSample]) -> list[str]:
    """``a>b`` for consecutive tool calls of the same task (calls without a task are skipped)."""
    by_task: dict[str, list[str]] = {}
    for t in tools:
        if t.task_id and t.tool:
            by_task.setdefault(t.task_id, []).append(t.tool)
    out: list[str] = []
    for seq in by_task.values():
        out.extend(f"{a}>{b}" for a, b in pairwise(seq))
    return out


def numeric_values(feature: DriftFeature, window: Window) -> list[float]:
    read = NUMERIC[feature]
    return [v for c in window.calls if (v := read(c)) is not None and v >= 0]


def categorical_values(feature: DriftFeature, window: Window) -> list[str]:
    ok = [c for c in window.calls if c.status == "ok"]
    if feature is F.REFUSAL:
        return [_flag(c.refusal) for c in ok]
    if feature is F.TRUNCATION:
        return [_flag(c.truncated) for c in ok]
    if feature is F.TOOL_CALL:
        return [_flag(c.tool_call) for c in ok]
    if feature is F.ERROR_CLASS:
        return [OK_CLASS if c.status == "ok" else (c.error_class or "other") for c in window.calls]
    if feature is F.SCHEMA_FAIL:
        return [_flag(t.schema_fail) for t in window.tools]
    if feature is F.TOOL_BIGRAM:
        return bigrams(window.tools)
    raise ValueError(f"{feature} is not categorical")


# ------------------------------------------------------------------------------- freezing


def freeze(window: Window, cfg: DriftConfig) -> dict[str, dict[str, Any]]:
    """The frozen distributions of every feature (JSON-ready, deterministic)."""
    out: dict[str, dict[str, Any]] = {}
    for feature in DriftFeature:
        if feature in NUMERIC:
            values = numeric_values(feature, window)
            edges = stats.quantile_edges(values, cfg.numeric_bins) if values else ()
            out[feature.value] = {
                "kind": "numeric",
                "statistic": DriftStatistic.PSI.value,
                "n": len(values),
                "edges": [round(e, 6) for e in edges],
                "probs": [round(p, 8) for p in stats.proportions(stats.bin_counts(values, edges))],
            }
            continue
        cats = categorical_values(feature, window)
        keep = stats.top_categories(cats, cfg.top_categories)
        out[feature.value] = {
            "kind": "categorical",
            "statistic": DriftStatistic.JS.value,
            "n": len(cats),
            "probs": {k: round(v, 8) for k, v in stats.categorical(cats, keep).items()},
        }
    return out


# ------------------------------------------------------------------------------- comparing


def _verdict(value: float, watch: float, drift: float) -> DriftVerdict:
    if value >= drift:
        return DriftVerdict.DRIFT
    if value >= watch:
        return DriftVerdict.WATCH
    return DriftVerdict.NONE


def _min_samples(feature: DriftFeature, cfg: DriftConfig) -> int:
    return cfg.tool_min_samples if feature in TOOL_CATEGORICAL else cfg.eval_min_samples


def compare_feature(
    feature: DriftFeature, frozen: Mapping[str, Any] | None, window: Window, cfg: DriftConfig
) -> FeatureResult:
    limits = cfg.threshold(feature)
    statistic = DriftStatistic.PSI if feature in NUMERIC else DriftStatistic.JS
    n_base = int((frozen or {}).get("n") or 0)
    if feature in NUMERIC:
        values = numeric_values(feature, window)
        n_now = len(values)
    else:
        cats = categorical_values(feature, window)
        n_now = len(cats)
    need = _min_samples(feature, cfg)

    def skipped(status: str) -> FeatureResult:
        return FeatureResult(
            feature,
            statistic,
            status,
            None,
            limits.watch,
            limits.drift,
            DriftVerdict.NONE,
            n_base,
            n_now,
        )

    if frozen is None or n_base < need or n_now < need:
        return skipped("insufficient_samples")
    if feature in NUMERIC:
        edges = [float(e) for e in frozen.get("edges") or []]
        expected = [float(p) for p in frozen.get("probs") or []]
        actual = stats.proportions(stats.bin_counts(values, edges))
        if len(expected) != len(actual):  # a malformed baseline never fakes a verdict
            return skipped("invalid_baseline")
        value = stats.psi(expected, actual)
        noise = stats.psi_noise(len(actual), n_base, n_now)
        labels = stats.bin_labels(edges)
        moved = stats.contributors(
            dict(zip(labels, expected, strict=True)), dict(zip(labels, actual, strict=True))
        )
    else:
        base_probs = {str(k): float(v) for k, v in (frozen.get("probs") or {}).items()}
        actual_probs = stats.categorical(cats, base_probs.keys())
        value = stats.js_divergence(base_probs, actual_probs)
        noise = stats.js_noise(len(set(base_probs) | set(actual_probs)), n_base, n_now)
        moved = stats.contributors(base_probs, actual_probs)
    excess = max(0.0, value - noise)
    return FeatureResult(
        feature,
        statistic,
        "ok",
        value,
        limits.watch,
        limits.drift,
        _verdict(excess, limits.watch, limits.drift),
        n_base,
        n_now,
        tuple(moved),
        noise,
    )


def compare(
    frozen: Mapping[str, Mapping[str, Any]], window: Window, cfg: DriftConfig
) -> list[FeatureResult]:
    """Every feature of ``window`` against the frozen baseline, in a stable order."""
    return [compare_feature(f, frozen.get(f.value), window, cfg) for f in DriftFeature]


def overall(results: Sequence[FeatureResult]) -> DriftVerdict:
    """The worst verdict over the features that had enough samples."""
    verdict = DriftVerdict.NONE
    for r in results:
        if r.status == "ok" and VERDICT_RANK[r.verdict] > VERDICT_RANK[verdict]:
            verdict = r.verdict
    return verdict


def evaluated(results: Sequence[FeatureResult]) -> bool:
    """At least one feature had enough samples on both sides."""
    return any(r.status == "ok" for r in results)


def drift_ratio(results: Sequence[FeatureResult]) -> float:
    """Largest ``excess / drift threshold`` over evaluated features (1.0 = at the threshold)."""
    ratios = [
        excess / r.drift for r in results if r.status == "ok" and (excess := r.excess) is not None
    ]
    return max(ratios, default=0.0)
