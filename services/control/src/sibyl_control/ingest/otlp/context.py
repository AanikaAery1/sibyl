"""Decode-time limits and warnings shared by the protobuf and JSON decoders (API §4.2)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

MAX_ATTRIBUTES = 256
MAX_STRING_CHARS = 64 * 1024
MAX_ANY_DEPTH = 16


class OtlpDecodeError(ValueError):
    """The body is not a decodable OTLP export request (→ 422 ``validation_failed``)."""


class TooManyItems(OtlpDecodeError):
    """More spans / log records than one request may carry (→ 400 ``batch_too_large``)."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"more than {limit} items in one request")
        self.limit = limit


class DecodeContext:
    def __init__(self, max_items: int) -> None:
        self.max_items = max_items
        self.items = 0
        self.attrs_dropped = 0
        self.strings_truncated = 0

    def count_item(self) -> None:
        self.items += 1
        if self.items > self.max_items:
            raise TooManyItems(self.max_items)

    def string(self, value: str) -> str:
        if len(value) > MAX_STRING_CHARS:
            self.strings_truncated += 1
            return value[:MAX_STRING_CHARS]
        return value

    def check_depth(self, depth: int) -> None:
        if depth > MAX_ANY_DEPTH:
            raise OtlpDecodeError(f"attribute values nest deeper than {MAX_ANY_DEPTH} levels")

    def attributes(self, pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                continue
            if len(out) >= MAX_ATTRIBUTES:
                self.attrs_dropped += 1
                continue
            out[key] = value
        return out

    def warnings(self) -> tuple[str, ...]:
        found: list[str] = []
        if self.attrs_dropped:
            found.append(
                f"{self.attrs_dropped} attributes dropped beyond {MAX_ATTRIBUTES} per item"
            )
        if self.strings_truncated:
            found.append(f"{self.strings_truncated} attribute strings truncated at 64 KiB")
        return tuple(found)
