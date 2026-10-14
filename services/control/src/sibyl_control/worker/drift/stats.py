"""Pure distribution statistics for model drift (D51): no I/O, no randomness, no LLM.

* **PSI** (population stability index) for numeric features: the baseline's quantiles fix the
  bin edges once, at freeze; both sides are binned on those edges and
  ``PSI = sum((a_i - e_i) * ln(a_i / e_i))`` over the bin proportions, each proportion floored
  at ``EPS`` so an empty bin stays finite. ``0`` means identical; the usual reading is
  ``< 0.1`` stable, ``0.1-0.25`` moderate shift, ``> 0.25`` major shift.
* **Jensen-Shannon divergence** (base 2, so it lies in ``[0, 1]``) for categorical features:
  symmetric, finite even when a category appears on one side only.

Numeric bins are right-closed: a value ``v`` falls in bin ``i`` when
``edges[i-1] < v <= edges[i]`` (``-inf`` / ``+inf`` at the ends), so a baseline of ``k`` edges
has ``k + 1`` bins.
"""

from __future__ import annotations

import math
from bisect import bisect_left
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from itertools import pairwise

EPS = 1e-4
OTHER = "__other__"


def quantile_edges(values: Sequence[float], bins: int = 10) -> tuple[float, ...]:
    """Distinct interior cut points at the ``i / bins`` quantiles (nearest rank).

    At most ``bins - 1`` edges; fewer when the data has ties (a constant series has none, so
    everything lands in one bin and only a change of value can register).
    """
    if bins < 2:
        raise ValueError("bins must be at least 2")
    ordered = sorted(float(v) for v in values)
    if not ordered:
        return ()
    n = len(ordered)
    cuts: list[float] = []
    for i in range(1, bins):
        rank = max(0, math.ceil(i * n / bins) - 1)
        value = ordered[rank]
        if value < ordered[-1] and (not cuts or value > cuts[-1]):
            cuts.append(value)
    return tuple(cuts)


def bin_counts(values: Iterable[float], edges: Sequence[float]) -> list[int]:
    """Counts per right-closed bin defined by ``edges`` (``len(edges) + 1`` bins)."""
    counts = [0] * (len(edges) + 1)
    for v in values:
        counts[bisect_left(edges, float(v))] += 1
    return counts


def proportions(counts: Sequence[int]) -> list[float]:
    total = sum(counts)
    if total <= 0:
        return [0.0] * len(counts)
    return [c / total for c in counts]


def psi(expected: Sequence[float], actual: Sequence[float], eps: float = EPS) -> float:
    """Population stability index of ``actual`` against ``expected`` (same bins)."""
    if len(expected) != len(actual):
        raise ValueError("expected and actual need the same bins")
    total = 0.0
    for e, a in zip(expected, actual, strict=True):
        e_, a_ = max(float(e), eps), max(float(a), eps)
        total += (a_ - e_) * math.log(a_ / e_)
    return max(0.0, total)


def _normalised(p: Mapping[str, float]) -> dict[str, float]:
    total = sum(max(0.0, float(v)) for v in p.values())
    if total <= 0:
        return {}
    return {k: max(0.0, float(v)) / total for k, v in p.items()}


def js_divergence(p: Mapping[str, float], q: Mapping[str, float]) -> float:
    """Jensen-Shannon divergence (base 2) between two categorical distributions; each side is
    renormalised, an empty side counts as maximally different from a non-empty one."""
    pn, qn = _normalised(p), _normalised(q)
    if not pn and not qn:
        return 0.0
    if not pn or not qn:
        return 1.0
    total = 0.0
    for key in set(pn) | set(qn):
        a, b = pn.get(key, 0.0), qn.get(key, 0.0)
        m = (a + b) / 2
        if a > 0:
            total += 0.5 * a * math.log2(a / m)
        if b > 0:
            total += 0.5 * b * math.log2(b / m)
    return min(1.0, max(0.0, total))


def psi_noise(bins: int, n_expected: int, n_actual: int) -> float:
    """Expected PSI between two samples of the *same* distribution: ``(k - 1)(1/n1 + 1/n2)``
    (PSI is a symmetrised chi-square, so sampling alone gives about this much). Verdicts use
    the excess over it, so small windows do not read as drift."""
    if n_expected <= 0 or n_actual <= 0:
        return 0.0
    return max(0, bins - 1) * (1 / n_expected + 1 / n_actual)


def js_noise(categories: int, n_expected: int, n_actual: int) -> float:
    """Expected base-2 Jensen-Shannon divergence between two samples of the same distribution:
    ``(k - 1)(1/n1 + 1/n2) / (8 ln 2)`` (the chi-square approximation of JS)."""
    if n_expected <= 0 or n_actual <= 0:
        return 0.0
    return max(0, categories - 1) * (1 / n_expected + 1 / n_actual) / (8 * math.log(2))


def top_categories(values: Iterable[str], top_k: int) -> tuple[str, ...]:
    """The ``top_k`` most frequent categories (ties broken by name, so the result is stable)."""
    counts = Counter(values)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return tuple(k for k, _ in ranked[:top_k])


def categorical(values: Iterable[str], keep: Iterable[str]) -> dict[str, float]:
    """Proportions over ``keep``; anything else is pooled into ``OTHER`` (present only when
    non-zero, so a baseline without a long tail has no ``OTHER`` mass to compare against)."""
    kept = set(keep)
    counts: Counter[str] = Counter()
    for v in values:
        counts[v if v in kept else OTHER] += 1
    total = sum(counts.values())
    if total == 0:
        return {}
    return {k: c / total for k, c in sorted(counts.items())}


def contributors(
    expected: Mapping[str, float], actual: Mapping[str, float], limit: int = 3
) -> list[tuple[str, float, float]]:
    """The categories (or bins) whose share moved most: ``(label, expected, actual)``."""
    keys = set(expected) | set(actual)
    ranked = sorted(
        keys,
        key=lambda k: (-abs(actual.get(k, 0.0) - expected.get(k, 0.0)), k),
    )
    return [(k, expected.get(k, 0.0), actual.get(k, 0.0)) for k in ranked[:limit]]


def bin_labels(edges: Sequence[float]) -> list[str]:
    """Human labels of the right-closed bins: ``<= e1``, ``(e1, e2]`` … ``> ek``."""

    def fmt(x: float) -> str:
        return f"{x:g}"

    if not edges:
        return ["all"]
    labels = [f"<= {fmt(edges[0])}"]
    labels += [f"({fmt(a)}, {fmt(b)}]" for a, b in pairwise(edges)]
    labels.append(f"> {fmt(edges[-1])}")
    return labels
