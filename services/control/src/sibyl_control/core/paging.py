"""Cursor pagination (API.md §2.4): opaque keyset cursors bound to a filter hash.

A cursor is base64url(JSON ``{"v":2,"k":[typed parts],"b":<binding hash>,"f":<filter hash>}``).
``b`` binds the route, the sort and the key's type signature; ``f`` the filters. Replaying it with
different filters is 400 ``cursor_filter_mismatch``; anything else wrong (garbage, tampering,
another route or sort, bool-as-int, naive datetimes, oversize) is 400 ``invalid_cursor``, never a
500. Cursors are not secret and not signed: RLS bounds what any keyset can reach.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlencode
from uuid import UUID

from .problems import ProblemError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200
CURSOR_VERSION = 2
MAX_CURSOR_LENGTH = 2048  # characters of the opaque cursor
MAX_KEY_PARTS = 8
MAX_STRING_PART = 512
MAX_SAFE_INTEGER = 2**53 - 1
_NON_FILTER_PARAMS = frozenset({"limit", "cursor"})
_DOC_KEYS = frozenset({"v", "k", "b", "f"})

KeyPart = str | int | datetime | UUID


def validate_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if not 1 <= limit <= MAX_LIMIT:
        raise ProblemError("validation_failed", f"limit must be between 1 and {MAX_LIMIT}")
    return limit


def _filter_value(value: Any) -> Any:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple | set | frozenset):
        return sorted(_filter_value(v) for v in value)
    return str(value)


def filter_hash(filters: Mapping[str, Any]) -> str:
    """Hash of the filters a cursor was minted under; collections are order-insensitive."""
    material = {
        k: _filter_value(v)
        for k, v in filters.items()
        if k not in _NON_FILTER_PARAMS and v is not None
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _binding_hash(route: str, sort: str, signature: str) -> str:
    blob = json.dumps([route, sort, signature], separators=(",", ":")).encode()
    return hashlib.sha256(b"sibyl-cursor:" + blob).hexdigest()[:16]


def _encode_part(part: KeyPart) -> list[Any]:
    if isinstance(part, bool):
        raise TypeError("bool is not a keyset part")
    if isinstance(part, datetime):
        if part.tzinfo is None or part.utcoffset() is None:
            raise ValueError("keyset datetimes must carry a timezone")
        return ["t", part.isoformat()]
    if isinstance(part, UUID):
        return ["u", str(part)]
    if isinstance(part, int):
        if abs(part) > MAX_SAFE_INTEGER:
            raise ValueError("keyset integers must be IEEE-754 safe")
        return ["i", part]
    if isinstance(part, str):
        if len(part) > MAX_STRING_PART:
            raise ValueError("keyset string part is too long")
        return ["s", part]
    raise TypeError(f"unsupported keyset part {type(part).__name__}")


def _decode_part(raw: Any) -> tuple[str, KeyPart]:
    if not isinstance(raw, list) or len(raw) != 2:
        raise ValueError("part")
    tag, value = raw
    if tag == "t" and isinstance(value, str):
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("naive datetime")
        return tag, parsed
    if tag == "u" and isinstance(value, str):
        return tag, UUID(value)
    if tag == "i" and type(value) is int and abs(value) <= MAX_SAFE_INTEGER:
        return tag, value
    if tag == "s" and isinstance(value, str) and len(value) <= MAX_STRING_PART:
        return tag, value
    raise ValueError("part")


def encode_cursor(
    key: Sequence[KeyPart], filters: Mapping[str, Any], *, route: str, sort: str
) -> str:
    """Opaque cursor for ``key`` bound to ``route`` (e.g. ``GET /api/v1/agents``), ``sort`` and
    the key's type signature; replaying it elsewhere is 400 ``invalid_cursor``."""
    if not 1 <= len(key) <= MAX_KEY_PARTS:
        raise ValueError(f"a keyset has 1..{MAX_KEY_PARTS} parts")
    parts = [_encode_part(p) for p in key]
    signature = "".join(tag for tag, _ in parts)
    doc = {
        "v": CURSOR_VERSION,
        "k": parts,
        "b": _binding_hash(route, sort, signature),
        "f": filter_hash(filters),
    }
    raw = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()
    cursor = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    if len(cursor) > MAX_CURSOR_LENGTH:
        raise ValueError("cursor exceeds the maximum length")
    return cursor


def _parse(cursor: str) -> tuple[tuple[KeyPart, ...], str, str, str]:
    if not isinstance(cursor, str) or not 0 < len(cursor) <= MAX_CURSOR_LENGTH:
        raise ValueError("length")
    raw = base64.urlsafe_b64decode(cursor.encode("ascii") + b"=" * (-len(cursor) % 4))
    doc = json.loads(raw)
    if not isinstance(doc, dict) or set(doc) != _DOC_KEYS:
        raise ValueError("shape")
    if type(doc["v"]) is not int or doc["v"] != CURSOR_VERSION:
        raise ValueError("version")
    if not isinstance(doc["b"], str) or not isinstance(doc["f"], str):
        raise ValueError("hash")
    raw_parts = doc["k"]
    if not isinstance(raw_parts, list) or not 1 <= len(raw_parts) <= MAX_KEY_PARTS:
        raise ValueError("parts")
    decoded = [_decode_part(p) for p in raw_parts]
    signature = "".join(tag for tag, _ in decoded)
    return tuple(value for _, value in decoded), signature, doc["b"], doc["f"]


def decode_cursor(
    cursor: str,
    filters: Mapping[str, Any],
    *,
    route: str,
    sort: str,
    key_types: str | None = None,
) -> tuple[KeyPart, ...]:
    """Decode a client cursor. Anything malformed, or minted for another route, sort or key
    signature, is 400 ``invalid_cursor``; other filters are 400 ``cursor_filter_mismatch``.

    ``key_types`` (e.g. ``"tu"`` for ``(timestamp, uuid)``) pins the expected part types, so the
    values bound into SQL always have the types the handler expects.
    """
    try:
        parts, signature, binding, stored_filters = _parse(cursor)
    except Exception:  # every decode failure is the client's: never a 500 (code review M6)
        raise ProblemError("invalid_cursor") from None
    if binding != _binding_hash(route, sort, signature):
        raise ProblemError("invalid_cursor")
    if key_types is not None and signature != key_types:
        raise ProblemError("invalid_cursor")
    if stored_filters != filter_hash(filters):
        raise ProblemError("cursor_filter_mismatch")
    return parts


@dataclass(frozen=True)
class PageResult[T]:
    data: list[T]
    next_cursor: str | None
    has_more: bool

    def envelope(self, serialize: Callable[[T], Any]) -> dict[str, Any]:
        return {
            "data": [serialize(item) for item in self.data],
            "next_cursor": self.next_cursor,
            "has_more": self.has_more,
        }


def paginate[T](
    rows: Sequence[T],
    limit: int,
    key_of: Callable[[T], Sequence[KeyPart]],
    filters: Mapping[str, Any],
    *,
    route: str,
    sort: str,
) -> PageResult[T]:
    """``rows`` were fetched with ``LIMIT limit + 1`` in keyset order."""
    has_more = len(rows) > limit
    data = list(rows[:limit])
    cursor = (
        encode_cursor(key_of(data[-1]), filters, route=route, sort=sort)
        if has_more and data
        else None
    )
    return PageResult(data, cursor, has_more)


def link_header(base_url: str, query: Mapping[str, Any], next_cursor: str | None) -> str | None:
    if next_cursor is None:
        return None
    params = {k: v for k, v in query.items() if k != "cursor" and v is not None}
    params["cursor"] = next_cursor
    return f'<{base_url}?{urlencode(params, doseq=True)}>; rel="next"'
