from datetime import UTC, datetime
from uuid import UUID

import pytest
from sibyl_control.core.etag import (
    check_if_match,
    etag_for_row,
    etag_for_version,
    if_none_match_hit,
)
from sibyl_control.core.paging import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    decode_cursor,
    encode_cursor,
    link_header,
    paginate,
    validate_limit,
)
from sibyl_control.core.problems import ProblemError

ID = UUID("01927000-0000-7000-8000-000000000001")
TS = datetime(2026, 10, 10, 9, 0, 0, 123456, tzinfo=UTC)

R = "GET /api/v1/agents"


def test_etags_are_strong_and_quoted() -> None:
    assert etag_for_version(7) == '"7"'
    tag = etag_for_row(TS, ID)
    assert tag.startswith('"') and tag.endswith('"') and len(tag) == 18
    assert tag == etag_for_row(TS, ID)
    assert tag != etag_for_row(TS.replace(microsecond=1), ID)


def test_if_match_required_and_compared_strongly() -> None:
    with pytest.raises(ProblemError) as err:
        check_if_match(None, '"3"')
    assert (err.value.status, err.value.code) == (428, "precondition_required")
    check_if_match('"3"', '"3"')
    check_if_match('"2", "3"', '"3"')
    for header in ('"2"', 'W/"3"'):
        with pytest.raises(ProblemError) as err:
            check_if_match(header, '"3"', current_body={"v": 3})
        assert (err.value.status, err.value.code) == (412, "precondition_failed")
        assert err.value.extensions["current"] == {"v": 3}


def test_star_only_creates() -> None:
    check_if_match("*", None, allow_star_create=True)
    with pytest.raises(ProblemError):
        check_if_match("*", '"3"', allow_star_create=True)
    with pytest.raises(ProblemError):
        check_if_match("*", None, allow_star_create=False)
    with pytest.raises(ProblemError):
        check_if_match('"1"', None, allow_star_create=True)


def test_if_none_match_uses_weak_comparison() -> None:
    assert if_none_match_hit('W/"3"', '"3"')
    assert if_none_match_hit('"1", "3"', '"3"')
    assert if_none_match_hit("*", '"3"')
    assert not if_none_match_hit(None, '"3"')
    assert not if_none_match_hit('"4"', '"3"')


def test_limit_bounds() -> None:
    assert validate_limit(None) == DEFAULT_LIMIT == 50
    assert validate_limit(MAX_LIMIT) == 200
    for bad in (0, 201, -1):
        with pytest.raises(ProblemError) as err:
            validate_limit(bad)
        assert err.value.status == 422


def test_cursor_round_trip_with_typed_parts() -> None:
    filters = {"agent_id": str(ID), "state": "open", "limit": 10, "cursor": "ignored"}
    cursor = encode_cursor((TS, ID, 5, "x"), filters, route=R, sort="s")
    assert "=" not in cursor and "+" not in cursor and "/" not in cursor
    assert decode_cursor(cursor, {"agent_id": str(ID), "state": "open"}, route=R, sort="s") == (
        TS,
        ID,
        5,
        "x",
    )


def test_cursor_replayed_with_other_filters_is_400() -> None:
    cursor = encode_cursor((1,), {"state": "open"}, route=R, sort="s")
    with pytest.raises(ProblemError) as err:
        decode_cursor(cursor, {"state": "closed"}, route=R, sort="s")
    assert (err.value.status, err.value.code) == (400, "cursor_filter_mismatch")


def test_garbage_cursor_is_400() -> None:
    for bad in ("!!!", "eyJ4IjoxfQ", ""):
        with pytest.raises(ProblemError) as err:
            decode_cursor(bad, {}, route=R, sort="s")
        assert err.value.code == "invalid_cursor"


def test_paginate_uses_limit_plus_one_rows() -> None:
    rows = [{"id": i} for i in range(4)]
    page = paginate(rows, 3, lambda r: (r["id"],), {}, route=R, sort="s")
    assert [r["id"] for r in page.data] == [0, 1, 2]
    assert page.has_more
    assert decode_cursor(page.next_cursor, {}, route=R, sort="s") == (2,)
    last = paginate(rows[:2], 3, lambda r: (r["id"],), {}, route=R, sort="s")
    assert not last.has_more and last.next_cursor is None
    assert last.envelope(lambda r: r) == {"data": rows[:2], "next_cursor": None, "has_more": False}


def test_link_header() -> None:
    assert link_header("https://h/api/v1/agents", {"state": "open"}, None) is None
    link = link_header("https://h/api/v1/agents", {"state": "open", "cursor": "old"}, "abc")
    assert link == '<https://h/api/v1/agents?state=open&cursor=abc>; rel="next"'
