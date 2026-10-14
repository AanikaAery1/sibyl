"""Noisy-OR and band quantisation (ML.md §4.2), with property tests on monotonicity."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sibyl_control.worker.predict.bands import (
    BAND_RANK,
    DEFAULT_CUTS,
    band_at_least,
    noisy_or,
    quantise,
)

risk = st.floats(min_value=0.0, max_value=1.0, allow_nan=False)
points = st.lists(risk, max_size=8)


@pytest.mark.parametrize(
    ("value", "band"),
    [
        (0.0, "0.05"),
        (0.1499, "0.05"),
        (0.15, "0.25"),
        (0.4499, "0.25"),
        (0.45, "0.60"),
        (0.7999, "0.60"),
        (0.8, "0.90"),
        (1.0, "0.90"),
    ],
)
def test_quantise_uses_the_frozen_cuts(value: float, band: str) -> None:
    assert quantise(value) == band


def test_noisy_or_of_nothing_is_zero_and_of_a_certainty_is_one() -> None:
    assert noisy_or([]) == 0
    assert noisy_or([0.2, 1.0]) == 1
    assert noisy_or([0.5, 0.5]) == pytest.approx(0.75)


@given(points, risk)
def test_adding_a_risk_point_never_lowers_the_risk_or_the_band(
    ps: list[float], extra: float
) -> None:
    before = noisy_or(ps)
    after = noisy_or([*ps, extra])
    assert after >= before - 1e-12
    assert BAND_RANK[quantise(after)] >= BAND_RANK[quantise(before)]


@given(points, st.integers(min_value=0, max_value=7), st.floats(min_value=0, max_value=1))
def test_raising_one_point_never_lowers_the_band(ps: list[float], i: int, bump: float) -> None:
    if not ps:
        return
    i %= len(ps)
    raised = list(ps)
    raised[i] = min(1.0, raised[i] + bump)
    assert BAND_RANK[quantise(noisy_or(raised))] >= BAND_RANK[quantise(noisy_or(ps))]


@given(risk, risk)
def test_quantise_is_monotone(a: float, b: float) -> None:
    lo, hi = sorted((a, b))
    assert BAND_RANK[quantise(lo)] <= BAND_RANK[quantise(hi)]


@given(points)
def test_noisy_or_stays_in_the_unit_interval_and_dominates_each_point(ps: list[float]) -> None:
    r = noisy_or(ps)
    assert 0 <= r <= 1
    assert all(r >= p - 1e-12 for p in ps)


def test_one_leading_rule_alone_cannot_reach_the_060_band() -> None:
    """Caps <= 30 bound a single leading rule's risk point at 0.30, below the 0.45 cut."""
    assert quantise(noisy_or([0.30])) == "0.25"
    assert DEFAULT_CUTS["band_0_60"] > 0.30


def test_band_at_least_orders_the_bands() -> None:
    assert band_at_least("0.90", "0.60")
    assert not band_at_least("0.25", "0.60")
