"""RFC 8785 JSON Canonicalization Scheme (JCS).

Used for the audit hash chain, the policy-snapshot signature and the redaction-profile
content hash. The output is UTF-8 bytes; both signer and verifier must call this module
(or a byte-identical implementation) so signatures agree byte for byte.

Rules implemented (RFC 8785 §3.2):
- I-JSON input only: no NaN/Infinity, no lone surrogates, no duplicate keys, and integers
  must be exactly representable as IEEE-754 doubles so no value is silently rounded.
- Object members sorted by the UTF-16 code units of their names.
- Strings escaped as ECMAScript `JSON.stringify` does (short escapes for \\b \\t \\n \\f \\r,
  lowercase `\\u00XX` for other controls, `\\"` and `\\\\`, everything else literal).
- Numbers serialised with the ECMAScript `Number.prototype.toString` algorithm.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Final

__all__ = [
    "DEFAULT_MAX_JSON_BYTES",
    "DEFAULT_MAX_JSON_DEPTH",
    "MAX_SAFE_INTEGER",
    "CanonicalizationError",
    "canonical_sha256",
    "canonicalize",
    "canonicalize_json_text",
    "parse_json_strict",
]

MAX_SAFE_INTEGER: Final = 2**53 - 1


class CanonicalizationError(ValueError):
    """The value is not representable as I-JSON and cannot be canonicalised."""


def canonicalize(value: Any, *, allow_floats: bool = True) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of a JSON-compatible value.

    `allow_floats=False` rejects every non-integral number; the audit `detail` contract
    forbids floats so chain hashes never depend on number formatting.
    """
    parts: list[str] = []
    _write(value, parts, allow_floats=allow_floats)
    return "".join(parts).encode("utf-8")


def canonical_sha256(value: Any, *, allow_floats: bool = True) -> str:
    """Lowercase hex SHA-256 of the canonical encoding."""
    return hashlib.sha256(canonicalize(value, allow_floats=allow_floats)).hexdigest()


DEFAULT_MAX_JSON_BYTES: Final = 4 * 1024 * 1024
"""Size cap for untrusted JSON text (UTF-8 bytes); B4 allows a 3 MiB raw snapshot."""

DEFAULT_MAX_JSON_DEPTH: Final = 64
"""Nesting cap for untrusted JSON text (arrays and objects both count)."""

_SURROGATE_ESCAPE: Final = re.compile(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")


def parse_json_strict(
    text: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_JSON_BYTES,
    max_depth: int = DEFAULT_MAX_JSON_DEPTH,
) -> Any:
    """Parse untrusted JSON text under I-JSON rules.

    Duplicate member names (at any depth), NaN/Infinity, lone surrogates and invalid UTF-8
    are rejected; integers beyond ±(2**53 - 1) become doubles. The text is refused before
    parsing when it exceeds `max_bytes` UTF-8 bytes, and after parsing when it nests deeper
    than `max_depth`. Every failure, including the parser's own `ValueError`,
    `OverflowError` and `RecursionError`, is raised as `CanonicalizationError`.
    """
    size = len(text) if isinstance(text, bytes) else _utf8_length(text)
    if size > max_bytes:
        raise CanonicalizationError(f"JSON text of {size} bytes exceeds the {max_bytes}-byte cap")

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise CanonicalizationError(f"duplicate member name {key!r}")
            result[key] = item
        return result

    def _no_constants(name: str) -> Any:
        raise CanonicalizationError(f"{name} is not valid I-JSON")

    try:
        decoded = text.decode("utf-8") if isinstance(text, bytes) else text
        value = json.loads(
            decoded,
            object_pairs_hook=_no_duplicates,
            parse_constant=_no_constants,
            parse_int=_parse_int,
        )
    except CanonicalizationError:
        raise
    except RecursionError as exc:
        raise CanonicalizationError(f"JSON nesting exceeds depth {max_depth}") from exc
    except (ValueError, OverflowError) as exc:  # JSONDecodeError and UnicodeDecodeError too
        raise CanonicalizationError(f"invalid JSON: {exc}") from exc
    _check_depth_and_strings(
        value, max_depth, check_strings=bool(_SURROGATE_ESCAPE.search(decoded))
    )
    return value


def _utf8_length(text: str) -> int:
    if text.isascii():
        return len(text)
    return len(text.encode("utf-8", errors="surrogatepass"))


def _check_depth_and_strings(value: Any, max_depth: int, *, check_strings: bool) -> None:
    """Iterative walk: nesting depth, and (only when the text escapes a surrogate) lone
    surrogates in names and strings."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: Any = node.values()
            if check_strings:
                for key in node:
                    _check_scalar_string(key)
        elif isinstance(node, list):
            children = node
        else:
            if check_strings and isinstance(node, str):
                _check_scalar_string(node)
            continue
        if depth + 1 > max_depth:
            raise CanonicalizationError(f"JSON nesting exceeds depth {max_depth}")
        stack.extend((child, depth + 1) for child in children)


def _check_scalar_string(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("lone surrogate in string is not I-JSON") from exc


def _parse_int(text: str) -> int | float:
    """JSON numbers are IEEE-754 doubles (RFC 8785 §3.2.2.3): integers beyond the safe
    range parse to the nearest double, exactly as an ECMAScript parser would. Integers
    beyond the double range are not I-JSON."""
    value = int(text)
    if abs(value) <= MAX_SAFE_INTEGER:
        return value
    try:
        return float(value)
    except OverflowError as exc:
        raise CanonicalizationError(f"integer of {len(text)} digits overflows a double") from exc


def canonicalize_json_text(text: str | bytes, *, allow_floats: bool = True) -> bytes:
    """Parse JSON text strictly and return its canonical encoding."""
    return canonicalize(parse_json_strict(text), allow_floats=allow_floats)


def _write(value: Any, out: list[str], *, allow_floats: bool) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_string(value))
    elif isinstance(value, int):
        out.append(_integer(value))
    elif isinstance(value, float):
        out.append(_float(value, allow_floats=allow_floats))
    elif isinstance(value, Mapping):
        _object(value, out, allow_floats=allow_floats)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _write(item, out, allow_floats=allow_floats)
        out.append("]")
    else:
        raise CanonicalizationError(f"type {type(value).__name__} is not JSON")


def _object(value: Mapping[Any, Any], out: list[str], *, allow_floats: bool) -> None:
    for key in value:
        if not isinstance(key, str):
            raise CanonicalizationError(f"object member name {key!r} is not a string")
    out.append("{")
    for index, key in enumerate(sorted(value, key=_utf16_key)):
        if index:
            out.append(",")
        out.append(_string(key))
        out.append(":")
        _write(value[key], out, allow_floats=allow_floats)
    out.append("}")


def _utf16_key(name: str) -> bytes:
    return name.encode("utf-16-be", errors="surrogatepass")


def _string(value: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("lone surrogate in string is not I-JSON") from exc
    return json.dumps(value, ensure_ascii=False)


def _integer(value: int) -> str:
    if abs(value) <= MAX_SAFE_INTEGER:
        return str(value)
    as_double = float(value) if abs(value) < 2**1024 else math.inf
    if math.isinf(as_double) or int(as_double) != value:
        raise CanonicalizationError(
            f"integer {value} is not exactly representable as an I-JSON number"
        )
    return format_es6_number(as_double)


def _float(value: float, *, allow_floats: bool) -> str:
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not I-JSON")
    if not allow_floats and not value.is_integer():
        raise CanonicalizationError(f"float {value!r} is forbidden in this document")
    return format_es6_number(value)


def format_es6_number(value: float) -> str:
    """ECMAScript Number::toString for a finite double (RFC 8785 §3.2.2.3)."""
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits, exponent = _shortest_digits(abs(value))
    k = len(digits)
    n = exponent
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = f"{digits[:n]}.{digits[n:]}"
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mantissa = digits if k == 1 else f"{digits[0]}.{digits[1:]}"
        body = f"{mantissa}e{'+' if e > 0 else '-'}{abs(e)}"
    return sign + body


def _shortest_digits(value: float) -> tuple[str, int]:
    """Shortest round-trip decimal digits `d` and exponent `n` with value = 0.d * 10**n."""
    mantissa, _, exp_text = repr(value).partition("e")
    exponent = int(exp_text) if exp_text else 0
    int_part, _, frac_part = mantissa.partition(".")
    raw = int_part + frac_part
    stripped = raw.lstrip("0")
    leading_zeros = len(raw) - len(stripped)
    digits = stripped.rstrip("0")
    return digits, len(int_part) + exponent - leading_zeros
