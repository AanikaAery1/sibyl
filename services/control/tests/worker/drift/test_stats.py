"""Property and example tests of the pure drift statistics (PSI, Jensen-Shannon, binning)."""

from __future__ import annotations

import math
from itertools import pairwise

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sibyl_control.worker.drift import stats

FLOATS = st.floats(min_value=-1e6, max_value=1e6, allow_nan=False, allow_infinity=False)
SAMPLES = st.lists(FLOATS, min_size=1, max_size=300)
CATS = st.sampled_from(["ok", "timeout", "rate_limit", "server_error", "a>b", "b>c"])


def _dist(draw_list: list[int]) -> list[float]:
    return stats.proportions(draw_list)


@given(SAMPLES, st.integers(min_value=2, max_value=20))
def test_edges_are_strictly_increasing_and_bounded(values: list[float], bins: int) -> None:
    edges = stats.quantile_edges(values, bins)
    assert len(edges) <= bins - 1
    assert all(a < b for a, b in pairwise(edges))
    assert all(min(values) <= e < max(values) for e in edges)


@given(SAMPLES, st.integers(min_value=2, max_value=20))
def test_binning_keeps_every_value(values: list[float], bins: int) -> None:
    edges = stats.quantile_edges(values, bins)
    counts = stats.bin_counts(values, edges)
    assert len(counts) == len(edges) + 1
    assert sum(counts) == len(values)
    assert counts[-1] > 0  # the maximum is never an edge, so the top bin is never empty


@given(st.lists(st.integers(min_value=0, max_value=1000), min_size=2, max_size=12))
def test_psi_of_a_distribution_against_itself_is_zero(counts: list[int]) -> None:
    p = _dist(counts)
    assert stats.psi(p, p) == pytest.approx(0.0, abs=1e-12)


@given(
    st.lists(st.integers(min_value=0, max_value=1000), min_size=2, max_size=12).flatmap(
        lambda a: st.tuples(
            st.just(a),
            st.lists(st.integers(min_value=0, max_value=1000), min_size=len(a), max_size=len(a)),
        )
    )
)
def test_psi_is_non_negative_finite_and_symmetric(pair: tuple[list[int], list[int]]) -> None:
    p, q = _dist(pair[0]), _dist(pair[1])
    forward, backward = stats.psi(p, q), stats.psi(q, p)
    assert forward >= 0 and math.isfinite(forward)
    assert forward == pytest.approx(backward, rel=1e-9, abs=1e-12)


def test_psi_known_value_and_bin_mismatch() -> None:
    expected = [0.25, 0.25, 0.25, 0.25]
    actual = [0.10, 0.20, 0.30, 0.40]
    manual = sum((a - e) * math.log(a / e) for e, a in zip(expected, actual, strict=True))
    assert stats.psi(expected, actual) == pytest.approx(manual)
    assert stats.psi(expected, actual) == pytest.approx(0.2282, abs=1e-3)
    with pytest.raises(ValueError):
        stats.psi([0.5, 0.5], [1.0])


def test_psi_empty_bin_stays_finite() -> None:
    assert math.isfinite(stats.psi([1.0, 0.0], [0.0, 1.0]))
    assert stats.psi([1.0, 0.0], [0.0, 1.0]) > 1.0


@given(st.dictionaries(CATS, st.floats(min_value=0, max_value=100), max_size=6))
def test_js_of_a_distribution_against_itself_is_zero(p: dict[str, float]) -> None:
    assert stats.js_divergence(p, p) == pytest.approx(0.0, abs=1e-12)


@given(
    st.dictionaries(CATS, st.floats(min_value=0, max_value=100), max_size=6),
    st.dictionaries(CATS, st.floats(min_value=0, max_value=100), max_size=6),
)
@settings(max_examples=200)
def test_js_is_bounded_and_symmetric(p: dict[str, float], q: dict[str, float]) -> None:
    forward = stats.js_divergence(p, q)
    assert 0.0 <= forward <= 1.0
    assert forward == pytest.approx(stats.js_divergence(q, p), abs=1e-12)


def test_js_known_values() -> None:
    assert stats.js_divergence({"a": 1.0}, {"b": 1.0}) == pytest.approx(1.0)
    assert stats.js_divergence({}, {}) == 0.0
    assert stats.js_divergence({"a": 1.0}, {}) == 1.0
    # refusal share 1 % -> 10 %: about 0.032 bits
    value = stats.js_divergence({"no": 0.99, "yes": 0.01}, {"no": 0.9, "yes": 0.1})
    assert value == pytest.approx(0.0323, abs=5e-4)


def test_top_categories_and_pooling() -> None:
    values = ["a"] * 5 + ["b"] * 3 + ["c"] * 3 + ["d"]
    assert stats.top_categories(values, 2) == ("a", "b")
    pooled = stats.categorical(values, ("a", "b"))
    assert pooled == {stats.OTHER: 4 / 12, "a": 5 / 12, "b": 3 / 12}
    assert stats.categorical([], ("a",)) == {}
    assert stats.categorical(["a", "a"], ("a",)) == {"a": 1.0}


def test_contributors_rank_by_movement() -> None:
    out = stats.contributors({"a": 0.5, "b": 0.5}, {"a": 0.1, "b": 0.6, "c": 0.3}, limit=2)
    assert out == [("a", 0.5, 0.1), ("c", 0.0, 0.3)]


def test_edge_cases() -> None:
    assert stats.quantile_edges([], 10) == ()
    assert stats.quantile_edges([3.0] * 50, 10) == ()
    with pytest.raises(ValueError):
        stats.quantile_edges([1.0], 1)
    assert stats.proportions([0, 0]) == [0.0, 0.0]
    assert stats.bin_labels(()) == ["all"]
    assert stats.bin_labels((10.0, 20.5)) == ["<= 10", "(10, 20.5]", "> 20.5"]
    assert stats.bin_counts([10.0, 10.5, 25.0, -1.0], (10.0, 20.5)) == [2, 1, 1]


def test_noise_floors() -> None:
    assert stats.psi_noise(10, 400, 200) == pytest.approx(9 * (1 / 400 + 1 / 200))
    assert stats.psi_noise(10, 0, 200) == 0.0
    assert stats.js_noise(2, 400, 200) == pytest.approx((1 / 400 + 1 / 200) / (8 * math.log(2)))
    assert stats.js_noise(1, 400, 200) == 0.0
    assert stats.js_noise(3, 400, 0) == 0.0


def test_noise_floor_tracks_sampling_of_one_distribution() -> None:
    """Two samples of one distribution: the mean PSI sits near the analytic floor."""
    import random

    rng = random.Random(5)  # noqa: S311 (reproducible test data)
    base = [rng.gauss(0, 1) for _ in range(2000)]
    edges = stats.quantile_edges(base, 10)
    expected = stats.proportions(stats.bin_counts(base, edges))
    values = []
    for _ in range(200):
        window = [rng.gauss(0, 1) for _ in range(200)]
        values.append(stats.psi(expected, stats.proportions(stats.bin_counts(window, edges))))
    mean = sum(values) / len(values)
    floor = stats.psi_noise(10, 2000, 200)
    assert 0.6 * floor < mean < 1.6 * floor
