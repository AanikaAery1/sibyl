"""Risk arithmetic (ML.md §4.2): noisy-OR over risk points, quantised to the frozen bands.

``r_i = severity_i x cap_i(tier) / 100`` (the same severity the health score uses, so the health
and risk pages cannot disagree); ``R_H = 1 - prod(1 - r_i)``; ``R_H`` is cut into the four
``ProbabilityBand`` strings. ``rules/v1`` never emits a numeric probability.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

PROBABILITY_BANDS: tuple[str, ...] = ("0.05", "0.25", "0.60", "0.90")
BAND_RANK: dict[str, int] = {b: i for i, b in enumerate(PROBABILITY_BANDS)}
CONFIDENCES: tuple[str, ...] = ("low", "medium", "high")
CONFIDENCE_RANK: dict[str, int] = {c: i for i, c in enumerate(CONFIDENCES)}
DEFAULT_CUTS: Mapping[str, float] = {"band_0_25": 0.15, "band_0_60": 0.45, "band_0_90": 0.8}


def clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def noisy_or(points: Iterable[float]) -> float:
    """``1 - prod(1 - r_i)``; each point is clamped to [0, 1] first."""
    keep = 1.0
    for r in points:
        keep *= 1.0 - clamp(r)
    return clamp(1.0 - keep)


def cuts_of(scoring: Mapping[str, Any]) -> Mapping[str, float]:
    raw = scoring.get("probability_band_cuts") or {}
    return {k: float(raw.get(k, v)) for k, v in DEFAULT_CUTS.items()}


def quantise(risk: float, cuts: Mapping[str, float] = DEFAULT_CUTS) -> str:
    """``< 0.15 -> "0.05"``, ``< 0.45 -> "0.25"``, ``< 0.80 -> "0.60"``, else ``"0.90"``."""
    if risk < cuts["band_0_25"]:
        return "0.05"
    if risk < cuts["band_0_60"]:
        return "0.25"
    if risk < cuts["band_0_90"]:
        return "0.60"
    return "0.90"


def band_at_least(band: str, floor: str) -> bool:
    return BAND_RANK[band] >= BAND_RANK[floor]


def confidence_at_least(confidence: str, floor: str) -> bool:
    return CONFIDENCE_RANK[confidence] >= CONFIDENCE_RANK[floor]
