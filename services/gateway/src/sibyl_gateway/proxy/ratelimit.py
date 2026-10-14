"""Upstream rate-limit headers -> the six ``attrs.ratelimit`` integers (sibyl-event/1).

L3 (``ratelimit_proximity``, ML.md §4.3) reads the headroom the control plane derives from these
(``min(remaining / limit)``), so the gateway mirrors whatever the provider reported on the last
upstream response, success or 429. Two families exist and never collide, so both are read
regardless of dialect:

* OpenAI-compatible: ``x-ratelimit-{limit,remaining,reset}-{requests,tokens}``; resets are Go
  durations (``1s``, ``6m0s``, ``20ms``).
* Anthropic: ``anthropic-ratelimit-{requests,tokens}-{limit,remaining,reset}``; resets are RFC 3339
  instants, stored as milliseconds from ``now`` (0 when already past).

Unparseable or negative values are dropped field by field; no header at all gives ``None``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

UNITS: Final = ("requests", "tokens")
_DURATION: Final = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")
_UNIT_MS: Final = {"h": 3_600_000, "m": 60_000, "s": 1000, "ms": 1}


def duration_ms(raw: str) -> int | None:
    """Milliseconds of a Go-style duration (``1h2m3.5s``, ``20ms``); ``None`` when malformed."""
    text = raw.strip()
    if not text:
        return None
    total, pos = 0.0, 0
    for match in _DURATION.finditer(text):
        if match.start() != pos:
            return None
        total += float(match.group(1)) * _UNIT_MS[match.group(2)]
        pos = match.end()
    if pos != len(text):
        return None
    return round(total)


def _instant_ms(raw: str, now: datetime) -> int | None:
    try:
        when = datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0, round((when - now).total_seconds() * 1000))


def _count(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw.strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def ratelimit_from_headers(
    headers: Mapping[str, str], *, now: datetime | None = None
) -> dict[str, int] | None:
    """The provider's rate-limit state from response ``headers`` (case-insensitive mapping
    expected, e.g. ``httpx.Headers``; plain dicts must use lower-case names)."""
    at = now or datetime.now(UTC)
    out: dict[str, int] = {}
    for unit in UNITS:
        fields = {
            "limit": _count(
                headers.get(f"x-ratelimit-limit-{unit}")
                or headers.get(f"anthropic-ratelimit-{unit}-limit")
            ),
            "remaining": _count(
                headers.get(f"x-ratelimit-remaining-{unit}")
                or headers.get(f"anthropic-ratelimit-{unit}-remaining")
            ),
        }
        reset: int | None = None
        if (raw := headers.get(f"x-ratelimit-reset-{unit}")) is not None:
            reset = duration_ms(raw)
        elif (raw := headers.get(f"anthropic-ratelimit-{unit}-reset")) is not None:
            reset = _instant_ms(raw, at)
        for name, value in fields.items():
            if value is not None:
                out[f"{name}_{unit}"] = value
        if reset is not None:
            out[f"reset_{unit}_ms"] = reset
    return out or None
