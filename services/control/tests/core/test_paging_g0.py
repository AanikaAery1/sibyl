"""Code review M6: hostile cursors are always 400, never 500; cursors are bound to their route,
sort and key signature; filter hashes ignore collection order."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sibyl_control.core.paging import (
    MAX_CURSOR_LENGTH,
    decode_cursor,
    encode_cursor,
    filter_hash,
)
from sibyl_control.core.problems import ProblemError

ROUTE = "GET /api/v1/agents"
SORT = "created_at:desc"
TS = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
ID = UUID("01927000-0000-7000-8000-000000000001")


def enc(key, filters=None, *, route=ROUTE, sort=SORT) -> str:
    return encode_cursor(key, filters or {}, route=route, sort=sort)


def dec(cursor, filters=None, *, route=ROUTE, sort=SORT, key_types=None):
    return decode_cursor(cursor, filters or {}, route=route, sort=sort, key_types=key_types)


def raw_cursor(doc) -> str:
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def code_of(cursor: str, **kw) -> str:
    with pytest.raises(ProblemError) as err:
        dec(cursor, **kw)
    assert err.value.status == 400
    return err.value.code


def _valid_doc(parts) -> dict:
    good = json.loads(base64.urlsafe_b64decode(enc((1,)) + "=="))
    return {**good, "k": parts}


@pytest.mark.parametrize(
    "parts",
    [
        [["u", 5]],  # the review's AttributeError case
        [["i", True]],  # bool is not an int
        [["i", 1.5]],
        [["i", 2**60]],  # outside the IEEE-safe range
        [["t", "2026-10-10T09:00:00"]],  # naive datetime
        [["t", 5]],
        [["t", "not a date"]],
        [["u", "not-a-uuid"]],
        [["s", 7]],
        [["x", "unknown tag"]],
        [["s"]],
        [["s", "a", "b"]],
        ["s"],
        [None],
        [],
        [["i", 1]] * 9,  # too many parts
    ],
)
def test_malformed_key_parts_are_invalid_cursor(parts) -> None:
    assert code_of(raw_cursor(_valid_doc(parts))) == "invalid_cursor"


@pytest.mark.parametrize(
    "doc",
    [
        None,
        [],
        "x",
        1,
        {"v": 2},
        {"v": 99, "k": [["i", 1]], "b": "x", "f": "y"},
        {"v": True, "k": [["i", 1]], "b": "x", "f": "y"},
    ],
)
def test_malformed_documents_are_invalid_cursor(doc) -> None:
    assert code_of(raw_cursor(doc)) == "invalid_cursor"


def test_extra_fields_and_wrong_hash_types_are_invalid_cursor() -> None:
    good = _valid_doc([["i", 1]])
    assert code_of(raw_cursor({**good, "extra": 1})) == "invalid_cursor"
    assert code_of(raw_cursor({**good, "f": 5})) == "invalid_cursor"
    assert code_of(raw_cursor({**good, "b": ["x"]})) == "invalid_cursor"


def test_deep_nesting_and_garbage_are_invalid_cursor() -> None:
    deep = base64.urlsafe_b64encode(b"[" * 100_000).decode()
    assert code_of(deep[:MAX_CURSOR_LENGTH]) == "invalid_cursor"
    for bad in ("", "%%%", "a", "////", "\x00", "é", "a" * (MAX_CURSOR_LENGTH + 1)):
        assert code_of(bad) == "invalid_cursor"


def test_cursor_length_is_capped() -> None:
    assert len(enc(("x" * 100,))) <= MAX_CURSOR_LENGTH
    with pytest.raises(ValueError):
        enc(("x" * MAX_CURSOR_LENGTH,))


def test_cursor_is_bound_to_route_and_sort() -> None:
    cursor = enc((TS, ID))
    assert dec(cursor) == (TS, ID)
    assert code_of(cursor, route="GET /api/v1/incidents") == "invalid_cursor"
    assert code_of(cursor, sort="created_at:asc") == "invalid_cursor"


def test_cursor_is_bound_to_its_key_signature() -> None:
    cursor = enc((TS, ID))
    assert dec(cursor, key_types="tu") == (TS, ID)
    assert code_of(cursor, key_types="ti") == "invalid_cursor"
    doc = json.loads(base64.urlsafe_b64decode(cursor + "=="))
    swapped = {**doc, "k": [["s", "2026"], doc["k"][1]]}  # retyped part, stale binding
    assert code_of(raw_cursor(swapped)) == "invalid_cursor"


def test_filter_mismatch_keeps_its_own_code() -> None:
    cursor = enc((1,), {"state": "open"})
    assert code_of(cursor, filters={"state": "closed"}) == "cursor_filter_mismatch"


def test_filter_hash_ignores_collection_order_and_paging_params() -> None:
    assert filter_hash({"ids": ["b", "a"]}) == filter_hash({"ids": ("a", "b")})
    assert filter_hash({"ids": {"a", "b"}}) == filter_hash({"ids": ["b", "a"]})
    assert filter_hash({"a": 1, "limit": 5, "cursor": "x"}) == filter_hash({"a": 1})
    assert filter_hash({"a": True}) != filter_hash({"a": "True "})
    assert filter_hash({"a": None}) == filter_hash({})


def test_naive_datetimes_cannot_be_encoded() -> None:
    with pytest.raises(ValueError, match="timezone"):
        enc((datetime(2026, 1, 1),))
    with pytest.raises(TypeError):
        enc((True,))


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(st.text(max_size=MAX_CURSOR_LENGTH + 50))
def test_any_text_is_a_cursor_or_a_400(text: str) -> None:
    try:
        dec(text)
    except ProblemError as err:
        assert err.status == 400
        assert err.code in ("invalid_cursor", "cursor_filter_mismatch")


_json = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda inner: (
        st.lists(inner, max_size=4) | st.dictionaries(st.text(max_size=5), inner, max_size=4)
    ),
    max_leaves=12,
)


@settings(max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(
    st.fixed_dictionaries(
        {"v": _json | st.just(2), "k": _json, "b": _json, "f": _json},
        optional={"x": _json},
    )
)
def test_any_json_document_is_a_cursor_or_a_400(doc: dict) -> None:
    cursor = raw_cursor(doc)
    try:
        dec(cursor)
    except ProblemError as err:
        assert err.status == 400
        assert err.code in ("invalid_cursor", "cursor_filter_mismatch")


@given(
    st.lists(
        st.one_of(
            st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1),
            st.text(max_size=20),
            st.uuids(),
            st.datetimes(timezones=st.just(UTC)),
        ),
        min_size=1,
        max_size=4,
    )
)
def test_round_trip_for_every_valid_key(parts) -> None:
    assert dec(enc(tuple(parts))) == tuple(parts)
