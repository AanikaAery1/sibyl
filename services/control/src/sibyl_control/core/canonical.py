"""RFC 8785 (JCS) canonical JSON: a thin wrapper over ``sibyl_schemas.canonical``.

Hash chains and signatures must use exactly ONE canonicaliser, the one W0-SCH owns in
``sibyl_schemas.canonical`` (shared test vectors, SDK and gateway use it too). This module only
adds the kernel's input rules (UUIDs as lowercase strings; floats and non-IEEE-safe integers
refused, W0-10) and delegates. The interim local fallback was removed at G0.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any
from uuid import UUID

from sibyl_schemas.canonical import canonicalize as _shared_canonicalize

MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value cannot be represented canonically (float, unsafe int, non-string key)."""


def _prepare(value: object) -> object:
    """Normalise to plain JSON types and enforce the float-free, safe-integer subset."""
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise CanonicalizationError(f"integer outside the IEEE-754 safe range: {value}")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are not allowed in canonical documents")
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        if not all(isinstance(k, str) for k in value):
            raise CanonicalizationError("object keys must be strings")
        return {k: _prepare(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return [_prepare(v) for v in value]
    raise CanonicalizationError(f"unsupported type {type(value).__name__}")


# Kept for callers that assert which implementation is active; always the shared one now.
USING_SHARED_CANONICALISER = True


def _check_bmp_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if any(ord(ch) > 0xFFFF for ch in str(key)):
                raise CanonicalizationError(
                    f"object key {key!r} has characters outside the Basic Multilingual Plane"
                )
            _check_bmp_keys(item)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        for item in value:
            _check_bmp_keys(item)


def freeze(value: object) -> object:
    """Deep read-only view of a JSON value: mappings become ``MappingProxyType``, lists tuples."""
    if isinstance(value, Mapping):
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze(v) for v in value)
    return value


def canonical_document(value: Mapping[str, Any]) -> tuple[bytes, Mapping[str, Any]]:
    """Canonicalise a chain/outbox document once: its JCS bytes and a frozen plain-JSON copy.

    Object keys must stay inside the BMP: for such keys RFC 8785's UTF-16 order equals the code
    point order the database's ``sibyl.jcs`` uses, so the audit chain cannot be poisoned by key
    order (code review M1, security M2). Values may hold any character.
    """
    _check_bmp_keys(value)
    canonical = canonicalize(value)
    frozen = freeze(json.loads(canonical))
    assert isinstance(frozen, Mapping)
    return canonical, frozen


def thaw(value: object) -> Any:
    """Plain ``dict``/``list`` copy of a frozen JSON value (what asyncpg's jsonb codec takes)."""
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [thaw(v) for v in value]
    return value


def canonicalize(value: object) -> bytes:
    """Return the JCS serialisation of ``value`` as UTF-8 bytes."""
    return _shared_canonicalize(_prepare(value), allow_floats=False)
