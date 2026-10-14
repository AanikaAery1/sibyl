from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.idempotency import (
    IDEMPOTENCY_TTL,
    MAX_STORED_BODY_BYTES,
    REPLAY_HEADER,
    ForeignKey,
    Fresh,
    IdempotencyClaimLost,
    InMemoryIdempotencyStore,
    Replay,
    ReplayUnavailable,
    StoredResponse,
    begin_or_raise,
    decode_body,
    encode_body,
    fingerprint,
    require_key,
)
from sibyl_control.core.problems import ProblemError

TENANT = UUID("01927000-0000-7000-8000-000000000001")
ROUTE = "POST /api/v1/agents"
NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)


def fp(body: bytes = b"{}", *, method: str = "POST", path: str = "/api/v1/agents", query=""):
    return fingerprint(body, method=method, path=path, query=query)


def test_require_key_validates_presence_and_length() -> None:
    assert require_key("abc") == "abc"
    with pytest.raises(ProblemError) as err:
        require_key(None)
    assert (err.value.status, err.value.code) == (428, "idempotency_key_required")
    with pytest.raises(ProblemError) as err:
        require_key("x" * 129)
    assert err.value.status == 422


def test_fingerprint_ignores_json_whitespace_and_key_order() -> None:
    assert fp(b'{"a": 1, "b": 2}') == fp(b'{"b":2,"a":1}')
    assert fp(b'{"a": 1}') != fp(b'{"a": 2}')
    assert fp(b"") == fp(b"")
    assert fp(b"not json") != fp(b"not json!")


def test_fingerprint_binds_method_path_and_query_string() -> None:
    """G0-8 / code review: ``?dry_run=true`` and the plain call must not share a key."""
    base = fp(b'{"a":1}')
    assert fp(b'{"a":1}', query="dry_run=true") != base
    assert fp(b'{"a":1}', method="PUT") != base
    assert fp(b'{"a":1}', path="/api/v1/agents/x") != base
    assert fp(b"{}", query="b=2&a=1") == fp(b"{}", query="a=1&b=2")
    assert fp(b"{}", method="post") == fp(b"{}", method="POST")
    # the separator cannot be smuggled through the path or the query
    assert fp(b"{}", path="/a", query="b") != fp(b"{}", path="/a?b", query="")


def test_fingerprint_requires_the_request_line() -> None:
    with pytest.raises(TypeError):
        fingerprint(b"{}")  # type: ignore[call-arg]


async def test_first_use_then_replay() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    principal = uuid4()
    outcome = await store.begin(TENANT, principal, ROUTE, "k1", fp(), principal_kind="user")
    assert isinstance(outcome, Fresh)
    assert isinstance(outcome.claim_id, UUID)
    stored = StoredResponse(201, {"etag": '"1"'}, b'{"id":1}')
    await store.complete(outcome.token, stored)
    replay = await store.begin(TENANT, principal, ROUTE, "k1", fp(), principal_kind="user")
    assert isinstance(replay, Replay)
    assert replay.response == stored
    assert REPLAY_HEADER == "Idempotency-Replayed"


async def test_principal_kind_is_required() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    with pytest.raises(TypeError):
        await store.begin(TENANT, uuid4(), ROUTE, "k", fp())  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="principal_kind"):
        await store.begin(TENANT, uuid4(), ROUTE, "k", fp(), principal_kind="robot")  # type: ignore[arg-type]


async def test_same_id_under_another_principal_kind_is_a_foreign_key() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    who = uuid4()
    await store.begin(TENANT, who, ROUTE, "k", fp(), principal_kind="user")
    other = await store.begin(TENANT, who, ROUTE, "k", fp(), principal_kind="api_key")
    assert isinstance(other, ForeignKey)


async def test_conflicts() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    principal = uuid4()
    body = fp(b'{"a":1}')
    outcome = await store.begin(TENANT, principal, ROUTE, "k1", body, principal_kind="user")
    with pytest.raises(ProblemError) as err:
        await begin_or_raise(store, TENANT, principal, ROUTE, "k1", body, principal_kind="user")
    assert (err.value.status, err.value.code) == (409, "idempotency_in_progress")
    await store.complete(outcome.token, StoredResponse(200, {}, b"{}"))
    with pytest.raises(ProblemError) as err:
        await begin_or_raise(
            store, TENANT, principal, ROUTE, "k1", fp(b'{"a":2}'), principal_kind="user"
        )
    assert (err.value.status, err.value.code) == (422, "idempotency_key_reuse")
    with pytest.raises(ProblemError) as err:
        await begin_or_raise(store, TENANT, uuid4(), ROUTE, "k1", body, principal_kind="user")
    assert err.value.status == 404


async def test_abandon_releases_the_key() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    principal = uuid4()
    outcome = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert await store.abandon(outcome.token) is True
    again = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(again, Fresh)


async def test_records_expire_after_24h() -> None:
    now = [NOW]
    store = InMemoryIdempotencyStore(clock=lambda: now[0])
    principal = uuid4()
    outcome = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    await store.complete(outcome.token, StoredResponse(200, {}, b"{}"))
    now[0] = NOW + IDEMPOTENCY_TTL + timedelta(seconds=1)
    again = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(again, Fresh)


async def test_crashed_in_progress_request_releases_its_key_after_5_minutes() -> None:
    now = [NOW]
    store = InMemoryIdempotencyStore(clock=lambda: now[0])
    principal = uuid4()
    await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    now[0] = NOW + timedelta(minutes=6)
    again = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(again, Fresh)


async def test_keys_are_scoped_by_route_and_tenant() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    principal = uuid4()
    await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    other_route = await store.begin(TENANT, principal, "POST /o", "k", fp(), principal_kind="user")
    assert isinstance(other_route, Fresh)
    other_tenant = await store.begin(uuid4(), principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(other_tenant, Fresh)


# --- M5: claim fencing --------------------------------------------------------------------------


async def test_a_late_complete_from_a_reclaimed_request_is_fenced() -> None:
    """A stalls past the stale window, B reclaims and finishes; A's late complete must not
    overwrite B's record (and must fail A's transaction)."""
    now = [NOW]
    store = InMemoryIdempotencyStore(clock=lambda: now[0])
    principal = uuid4()
    a = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    now[0] = NOW + timedelta(minutes=6)
    b = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(a, Fresh) and isinstance(b, Fresh)
    assert a.claim_id != b.claim_id
    await store.complete(b.token, StoredResponse(201, {}, b'{"by":"b"}'))
    with pytest.raises(IdempotencyClaimLost) as err:
        await store.complete(a.token, StoredResponse(201, {}, b'{"by":"a"}'))
    assert err.value.status == 409
    replay = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(replay, Replay) and replay.response.body == b'{"by":"b"}'


async def test_a_late_abandon_does_not_release_a_newer_claim() -> None:
    now = [NOW]
    store = InMemoryIdempotencyStore(clock=lambda: now[0])
    principal = uuid4()
    a = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    now[0] = NOW + timedelta(minutes=6)
    b = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert await store.abandon(a.token) is False
    with pytest.raises(ProblemError) as err:
        await begin_or_raise(store, TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert err.value.code == "idempotency_in_progress"
    await store.complete(b.token, StoredResponse(200, {}, b"{}"))


async def test_complete_twice_with_the_same_claim_is_fenced() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    a = await store.begin(TENANT, uuid4(), ROUTE, "k", fp(), principal_kind="api_key")
    await store.complete(a.token, StoredResponse(200, {}, b"{}"))
    with pytest.raises(IdempotencyClaimLost):
        await store.complete(a.token, StoredResponse(200, {}, b"{}"))


# --- G0-8: stored bodies are capped at 64 KB; replay of a larger one is 409 ---------------------


async def test_large_responses_store_a_hash_and_replay_is_unavailable() -> None:
    store = InMemoryIdempotencyStore(clock=lambda: NOW)
    principal = uuid4()
    big = b'{"blob":"' + b"x" * MAX_STORED_BODY_BYTES + b'"}'
    a = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    await store.complete(a.token, StoredResponse(201, {"etag": '"9"'}, big))
    outcome = await store.begin(TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert isinstance(outcome, ReplayUnavailable)
    assert outcome.status == 201 and outcome.headers == {"etag": '"9"'}
    assert len(outcome.body_sha256) == 32
    with pytest.raises(ProblemError) as err:
        await begin_or_raise(store, TENANT, principal, ROUTE, "k", fp(), principal_kind="user")
    assert (err.value.status, err.value.code) == (409, "idempotent_replay_unavailable")


def test_body_encoding_round_trips_and_caps() -> None:
    assert decode_body(encode_body(b"")) == b""
    assert decode_body(encode_body(b'{"a":[1,"x"]}')) == b'{"a":[1,"x"]}'
    assert decode_body(encode_body(b"\x00binary\xff")) == b"\x00binary\xff"
    exact = b"a" * MAX_STORED_BODY_BYTES
    assert decode_body(encode_body(exact)) == exact
    over = encode_body(exact + b"a")
    assert over is not None and over["omitted"] is True and "base64" not in over
    assert decode_body(over) is None


@pytest.mark.parametrize(
    "body",
    [b'{"name":"a\\u0000b"}', b'{"a\\u0000":1}', b'["\\u0000"]', b'"\\u0000"'],
)
def test_json_bodies_with_nul_are_stored_as_base64(body: bytes) -> None:
    """Postgres jsonb cannot hold U+0000 (22P05); such bodies must not fail the business tx."""
    stored = encode_body(body)
    assert stored is not None and "base64" in stored
    assert decode_body(stored) == body
