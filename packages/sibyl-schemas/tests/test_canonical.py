"""RFC 8785 JSON Canonicalization Scheme (used for hash chains and snapshot signing)."""

from __future__ import annotations

import hashlib
import json
import math
import struct
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sibyl_schemas.canonical import (
    DEFAULT_MAX_JSON_BYTES,
    DEFAULT_MAX_JSON_DEPTH,
    CanonicalizationError,
    canonical_sha256,
    canonicalize,
    canonicalize_json_text,
    parse_json_strict,
)

VECTORS = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "jcs" / "rfc8785.json").read_text("utf-8")
)


def _double(hex64: str) -> float:
    value: float = struct.unpack(">d", bytes.fromhex(hex64))[0]
    return value


@pytest.mark.parametrize(
    "vector", VECTORS["numbers"], ids=[v["ieee754"] for v in VECTORS["numbers"]]
)
def test_rfc8785_number_vectors(vector: dict[str, str]) -> None:
    assert canonicalize(_double(vector["ieee754"])) == vector["expected"].encode("ascii")


@pytest.mark.parametrize("hex64", VECTORS["number_errors"])
def test_rfc8785_nan_and_infinity_are_errors(hex64: str) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(_double(hex64))


@pytest.mark.parametrize("doc", VECTORS["documents"], ids=[d["name"] for d in VECTORS["documents"]])
def test_rfc8785_documents(doc: dict[str, str]) -> None:
    assert canonicalize_json_text(doc["input"]) == doc["expected"].encode("utf-8")


@pytest.mark.parametrize(
    "doc", VECTORS["document_errors"], ids=[d["name"] for d in VECTORS["document_errors"]]
)
def test_rfc8785_document_errors(doc: dict[str, str]) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_json_text(doc["input"])


def test_integers_are_exact_inside_safe_range() -> None:
    assert canonicalize(2**53 - 1) == b"9007199254740991"
    assert canonicalize(-(2**53 - 1)) == b"-9007199254740991"
    assert canonicalize(2**53) == b"9007199254740992"  # exactly representable
    with pytest.raises(CanonicalizationError, match="I-JSON"):
        canonicalize(2**53 + 1)
    with pytest.raises(CanonicalizationError, match="I-JSON"):
        canonicalize(10**400)


def test_booleans_are_not_numbers() -> None:
    assert canonicalize([True, False, None, 1]) == b"[true,false,null,1]"


def test_floats_can_be_forbidden_for_audit_detail() -> None:
    assert canonicalize({"n": 3}, allow_floats=False) == b'{"n":3}'
    with pytest.raises(CanonicalizationError, match="float"):
        canonicalize({"detail": {"ratio": 0.5}}, allow_floats=False)


def test_rejects_non_json_types_and_non_string_keys() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({1: "a"})
    with pytest.raises(CanonicalizationError):
        canonicalize({"a": {1, 2}})
    with pytest.raises(CanonicalizationError):
        canonicalize(b"bytes")


def test_tuples_serialise_as_arrays() -> None:
    assert canonicalize({"a": (1, "x")}) == b'{"a":[1,"x"]}'


def test_canonical_sha256_is_hex_of_canonical_bytes() -> None:
    doc = {"b": 1, "a": "é"}
    assert canonical_sha256(doc) == hashlib.sha256('{"a":"é","b":1}'.encode()).hexdigest()


def test_parse_json_strict_rejects_duplicates_and_constants() -> None:
    assert parse_json_strict('{"a": [1, 2.5]}') == {"a": [1, 2.5]}
    assert parse_json_strict("9007199254740993") == 9007199254740992.0
    with pytest.raises(CanonicalizationError, match="duplicate"):
        parse_json_strict('{"a": 1, "a": 1}')
    with pytest.raises(CanonicalizationError):
        parse_json_strict("[Infinity]")
    with pytest.raises(CanonicalizationError):
        parse_json_strict("{not json")


_json_leaf = (
    st.none()
    | st.booleans()
    | st.integers(min_value=-(2**53 - 1), max_value=2**53 - 1)
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(alphabet=st.characters(codec="utf-8"), max_size=20)
)
_json = st.recursive(
    _json_leaf,
    lambda children: (
        st.lists(children, max_size=5)
        | st.dictionaries(
            st.text(alphabet=st.characters(codec="utf-8"), max_size=8),
            children,
            max_size=5,
        )
    ),
    max_leaves=25,
)


@given(_json)
def test_canonical_form_is_a_fixed_point_and_round_trips(value: Any) -> None:
    once = canonicalize(value)
    reparsed = parse_json_strict(once)
    assert canonicalize(reparsed) == once
    assert _equal(reparsed, value)


def _equal(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        return math.isclose(float(a), float(b), rel_tol=0, abs_tol=0) or float(a) == float(b)
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b, strict=True))
    return bool(a == b)


# --- G0 fix pass: parse_json_strict on untrusted input (security M5, code review L3) -----


@pytest.mark.parametrize(
    "text",
    [
        '{"a": {"b": 1, "b": 2}}',
        '[{"x": 1}, {"y": {"z": [1, {"k": 0, "k": 0}]}}]',
        '{"kid": "k", "body": {"v": 1}, "body": {"v": 2}}',
    ],
    ids=["nested", "deep_in_array", "duplicate_body"],
)
def test_parse_json_strict_rejects_duplicate_names_at_any_depth(text: str) -> None:
    with pytest.raises(CanonicalizationError, match="duplicate member name"):
        parse_json_strict(text)


@pytest.mark.parametrize(
    "text",
    [
        "1" * 5000,  # int() digit limit: ValueError
        "1" + "0" * 400,  # beyond 2**1024: OverflowError converting to double
        "[" * 100_000 + "]" * 100_000,  # RecursionError in the C scanner
        '"\\ud800"',  # lone surrogate escape (valid JSON text, not I-JSON)
    ],
    ids=["too_many_digits", "int_overflows_double", "deep_nesting", "lone_surrogate"],
)
def test_parse_json_strict_wraps_every_parser_error(text: str) -> None:
    with pytest.raises(CanonicalizationError):
        parse_json_strict(text)


def test_parse_json_strict_caps_depth() -> None:
    ok = "[" * DEFAULT_MAX_JSON_DEPTH + "]" * DEFAULT_MAX_JSON_DEPTH
    parse_json_strict(ok)
    deeper = "[" * (DEFAULT_MAX_JSON_DEPTH + 1) + "]" * (DEFAULT_MAX_JSON_DEPTH + 1)
    with pytest.raises(CanonicalizationError, match="depth"):
        parse_json_strict(deeper)
    nested_objects = '{"a":' * 10 + "1" + "}" * 10
    with pytest.raises(CanonicalizationError, match="depth"):
        parse_json_strict(nested_objects, max_depth=9)
    assert parse_json_strict(nested_objects, max_depth=10)


def test_parse_json_strict_caps_size_in_bytes() -> None:
    assert DEFAULT_MAX_JSON_BYTES >= 3 * 1024 * 1024  # B4: 3 MiB raw snapshot must parse
    text = json.dumps({"k": "x" * 100})
    assert parse_json_strict(text, max_bytes=len(text))
    with pytest.raises(CanonicalizationError, match="exceeds"):
        parse_json_strict(text, max_bytes=len(text) - 1)
    with pytest.raises(CanonicalizationError, match="exceeds"):
        parse_json_strict(text.encode(), max_bytes=len(text) - 1)
    multibyte = json.dumps({"k": "é" * 10}, ensure_ascii=False)
    with pytest.raises(CanonicalizationError, match="exceeds"):
        parse_json_strict(multibyte, max_bytes=len(multibyte))  # counted as UTF-8 bytes


def test_parse_json_strict_rejects_invalid_utf8_bytes() -> None:
    with pytest.raises(CanonicalizationError):
        parse_json_strict(b'{"a": "\xff"}'.replace(b"\\xff", b"\xff"))


def test_utf16_key_order_vector_from_g0_tests_review() -> None:
    # RFC 8785 sorts by UTF-16 code units: U+1F600 is D83D DE00, so it precedes U+FF21.
    assert canonicalize({"\uff21": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"\uff21":1}'.encode()
    assert canonicalize({"\ue000": 1, "\U00010000": 2}).startswith('{"\U00010000"'.encode())
