"""Typed attribute readers and envelope field builders shared by the span and log mappers."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.canonical import CanonicalizationError, parse_json_strict

from ..otlp.model import AnyBytes

CAPTURE_MODES = ("full", "redacted", "metadata")
POLICY_STATES = ("fresh", "stale", "expired", "unavailable", "not_applicable")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def rfc3339_ns(ns: int) -> str:
    seconds, rem = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, UTC)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{rem // 1000:06d}Z"


def rfc3339(dt: datetime) -> str:
    dt = dt.astimezone(UTC)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond:06d}Z"


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def as_uuid(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


NIL_UUID = "00000000-0000-0000-0000-000000000000"


def not_nil(value: str | None) -> str | None:
    """A nil-UUID identity claim means "resolve from the API key or X-Sibyl-Agent"."""
    return None if value is None or value.strip().lower() == NIL_UUID else value


def as_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def as_int(value: Any, *, minimum: int | None = None) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,18}", value):
        value = int(value)
    if not isinstance(value, int):
        return None
    if minimum is not None and value < minimum:
        return None
    return value


def as_float(
    value: Any, *, minimum: float | None = None, maximum: float | None = None
) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        return None
    if (minimum is not None and number < minimum) or (maximum is not None and number > maximum):
        return None
    return number


def as_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def as_str_list(value: Any) -> list[str] | None:
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    if isinstance(value, str):
        return [value]
    return None


def as_hash(value: Any) -> str | None:
    return value if isinstance(value, str) and _HEX64.match(value) else None


def json_value(value: Any) -> Any:
    """Content attributes are JSON strings in semconv 1.37; structured values pass through."""
    if isinstance(value, str):
        try:
            return parse_json_strict(value)
        except CanonicalizationError:
            return value
    if isinstance(value, AnyBytes):
        return value.data.decode("utf-8", errors="replace")
    return plain(value)


def plain(value: Any) -> Any:
    """AnyValue → JSON-compatible (bytes become text with replacement characters)."""
    if isinstance(value, AnyBytes):
        return value.data.decode("utf-8", errors="replace")
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    return value


def compact(obj: dict[str, Any]) -> dict[str, Any]:
    """Drop ``None`` members (and empty dicts) so optional keys stay absent, not null."""
    out: dict[str, Any] = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            value = compact(value)
            if not value:
                continue
        if value is not None:
            out[key] = value
    return out


def dumps(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
