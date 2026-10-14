"""Shared string formats so the JSON Schemas and the pydantic models agree exactly."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Final

RFC3339_PATTERN: Final = (
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$"
)
_RFC3339: Final = re.compile(RFC3339_PATTERN)
_FRACTION: Final = re.compile(r"\.([0-9]+)")

UUID_PATTERN: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
UUIDV7_PATTERN: Final = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
TRACE_ID_PATTERN: Final = r"^[0-9a-f]{32}$"
SPAN_ID_PATTERN: Final = r"^[0-9a-f]{16}$"
FEATURE_SNAPSHOT_REF_PATTERN: Final = r"^fs_[0-9a-f-]{36}$"


def is_rfc3339(value: object) -> bool:
    """True for an RFC 3339 `date-time` with an explicit offset and a real calendar date.

    Upper-case `T` and `Z` only (the wire convention, API §2.9); up to nanosecond
    fractions; leap seconds are rejected because PostgreSQL `timestamptz` rejects them.
    Non-strings return True so the JSON Schema `type` keyword reports them instead.
    """
    if not isinstance(value, str):
        return True
    if not _RFC3339.match(value):
        return False
    normalised = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), value, count=1)
    try:
        datetime.fromisoformat(normalised)
    except ValueError:
        return False
    return True
