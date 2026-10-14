"""Upstream rate-limit headers -> ``attrs.ratelimit`` (L3's headroom input, ML.md §1.2/§4.3)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sibyl_gateway.proxy.ratelimit import duration_ms, ratelimit_from_headers

NOW = datetime(2026, 10, 14, 12, 0, 0, tzinfo=UTC)


def test_openai_style_headers_map_to_the_six_fields() -> None:
    got = ratelimit_from_headers(
        {
            "x-ratelimit-limit-requests": "1000",
            "x-ratelimit-remaining-requests": "310",
            "x-ratelimit-reset-requests": "1s",
            "x-ratelimit-limit-tokens": "200000",
            "x-ratelimit-remaining-tokens": "62000",
            "x-ratelimit-reset-tokens": "6m0s",
        },
        now=NOW,
    )
    assert got == {
        "limit_requests": 1000,
        "remaining_requests": 310,
        "reset_requests_ms": 1000,
        "limit_tokens": 200000,
        "remaining_tokens": 62000,
        "reset_tokens_ms": 360000,
    }


def test_anthropic_headers_map_with_rfc3339_resets() -> None:
    got = ratelimit_from_headers(
        {
            "anthropic-ratelimit-requests-limit": "50",
            "anthropic-ratelimit-requests-remaining": "4",
            "anthropic-ratelimit-requests-reset": "2026-10-14T12:00:30Z",
            "anthropic-ratelimit-tokens-limit": "40000",
            "anthropic-ratelimit-tokens-remaining": "1000",
            "anthropic-ratelimit-tokens-reset": "2026-10-14T11:59:00Z",  # in the past: 0
        },
        now=NOW,
    )
    assert got == {
        "limit_requests": 50,
        "remaining_requests": 4,
        "reset_requests_ms": 30000,
        "limit_tokens": 40000,
        "remaining_tokens": 1000,
        "reset_tokens_ms": 0,
    }


def test_no_headers_is_none_and_garbage_is_dropped() -> None:
    assert ratelimit_from_headers({"content-type": "application/json"}, now=NOW) is None
    got = ratelimit_from_headers(
        {
            "x-ratelimit-limit-requests": "lots",
            "x-ratelimit-remaining-requests": "-3",
            "x-ratelimit-limit-tokens": "100",
            "x-ratelimit-remaining-tokens": "7",
            "x-ratelimit-reset-tokens": "soon",
        },
        now=NOW,
    )
    assert got == {"limit_tokens": 100, "remaining_tokens": 7}


@pytest.mark.parametrize(
    ("raw", "ms"),
    [("1s", 1000), ("20ms", 20), ("6m0s", 360000), ("1h2m3.5s", 3723500), ("0s", 0)],
)
def test_duration_ms_parses_go_style_durations(raw: str, ms: int) -> None:
    assert duration_ms(raw) == ms


@pytest.mark.parametrize("raw", ["", "abc", "1x", "s", "-1s"])
def test_duration_ms_rejects_garbage(raw: str) -> None:
    assert duration_ms(raw) is None
