"""Upper-bound estimate of ``pg_column_size(value::jsonb)`` (uncompressed, as CHECKs see it).

``events.attrs`` (≤ 4096), ``events.ingest`` (≤ 1024) and ``call_merge`` contributions
(≤ 16384) are bounded by ``pg_column_size`` of the binary jsonb, which can be 2-3x the JSON
text for number-heavy documents. The layout modelled: 4-byte varlena + container header,
4-byte JEntry per array element (8 per object pair: key + value), raw UTF-8 for keys and
strings, numerics as packed base-10000 digit groups with INTALIGN padding, nested containers
INTALIGN-padded. Every term is rounded up, so the estimate never undercounts (checked against
PostgreSQL in ``tests/ingest/test_jsonb_size.py``).
"""

from __future__ import annotations

import json
import math
from decimal import Decimal
from typing import Any

_PAD = 3  # worst-case INTALIGN padding before a numeric or nested container


def _numeric(value: int | float) -> int:
    text = format(Decimal(repr(value) if isinstance(value, float) else value), "f")
    whole, _, frac = text.lstrip("-").partition(".")
    groups = math.ceil(len(whole.lstrip("0") or "0") / 4) + math.ceil(len(frac) / 4)
    return _PAD + 4 + 4 + 2 * groups  # varlena + numeric header + digit groups


def _value(value: Any) -> int:
    if value is None or isinstance(value, bool):
        return 0
    if isinstance(value, int | float):
        return _numeric(value)
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="surrogatepass"))
    if isinstance(value, dict):
        body = sum(
            len(str(k).encode("utf-8", errors="surrogatepass")) + _value(v)
            for k, v in value.items()
        )
        return _PAD + 4 + 8 * len(value) + body
    if isinstance(value, list | tuple):
        return _PAD + 4 + 4 * len(value) + sum(_value(v) for v in value)
    return len(json.dumps(value))


def jsonb_size(value: Any) -> int:
    """Upper bound on ``pg_column_size(value::jsonb)``; scalars are wrapped like PostgreSQL does."""
    if isinstance(value, dict | list | tuple):
        return 4 + _value(value)
    return 4 + 4 + 4 + _value(value)
