"""``sibyl_schemas.keyset``: the one key-set chain follower the gateway and the SDK share (CR-G1).

Runs the committed ``key_set_vectors.json`` (direct deliveries and ``?since=`` deliveries) and a
generated rotation chain through the follower, the staged catch-up and ``follow_chain``."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_schemas import keyset as ks
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.values import KeySetRejectCause

VECTORS: dict[str, Any] = load_fixture("snapshot", "key_set_vectors.json")
NOW = datetime.now(UTC)
T0 = NOW - timedelta(days=30)


def _now(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _raw(step: dict[str, Any]) -> str:
    return step["raw"] if "raw" in step else json.dumps(step["document"])


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


class _Key:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private = Ed25519PrivateKey.generate()
        self.public = _b64u(self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def entry(self, status: str | None = "active", not_after: str | None = None) -> dict[str, str]:
        out = {"kid": self.kid, "alg": "Ed25519", "public_key": self.public}
        if status:
            out["status"] = status
        if not_after:
            out["not_after"] = not_after
        return out

    def sign_set(
        self, sequence: int, keys: list[dict[str, str]], nxt: dict[str, str] | None, at: datetime
    ) -> bytes:
        body = {"sequence": sequence, "issued_at": _iso(at), "keys": keys, "next_key": nxt}
        sig = _b64u(self.private.sign(canonicalize(body)))
        return json.dumps({"kid": self.kid, "alg": "Ed25519", "sig": sig, "body": body}).encode()


def rotation_chain(rotations: int) -> tuple[list[_Key], list[bytes]]:
    """``keys[0]`` is the genesis pin; set n+1 is signed by keys[n-1] and rotates to keys[n]."""
    keys = [_Key(f"k{i + 1}") for i in range(rotations + 2)]
    sets = [keys[0].sign_set(1, [keys[0].entry()], keys[1].entry(None), T0)]
    for n in range(1, rotations + 1):
        nxt = keys[n + 1].entry(None) if n < rotations else None
        retiring = keys[n - 1].entry("retiring", "2099-01-01T00:00:00.000Z")
        sets.append(
            keys[n - 1].sign_set(n + 1, [keys[n].entry(), retiring], nxt, T0 + timedelta(days=n))
        )
    return keys, sets


def tamper(raw: bytes) -> bytes:
    doc = json.loads(raw)
    doc["body"]["issued_at"] = "2030" + doc["body"]["issued_at"][4:]
    return json.dumps(doc).encode()


def _pinned(keys: list[_Key]) -> ks.ChainFollower:
    return ks.ChainFollower(ks.ChainKey.from_entry(keys[0].entry()))


def _vector_follower() -> ks.ChainFollower:
    return ks.ChainFollower(ks.ChainKey.from_entry(VECTORS["pinned"]))


# ------------------------------------------------------------------ vectors


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_direct_vectors_hit_their_causes(case: dict[str, Any]) -> None:
    follower = _vector_follower()
    for step in case["steps"]:
        before = follower.chain_state
        try:
            follower.accept(_raw(step), now=_now(case["now"]))
            verdict = "ok"
        except ks.KeySetRejected as exc:
            verdict = exc.cause.value
            assert follower.chain_state is before  # a rejected set changes nothing
        assert verdict == step["expected"]


@pytest.mark.parametrize(
    "case", VECTORS["since_cases"], ids=[c["name"] for c in VECTORS["since_cases"]]
)
def test_since_vectors_hit_their_causes(case: dict[str, Any]) -> None:
    follower = _vector_follower()
    now = _now(case["now"])
    for held in case["held"]:
        follower.accept(json.dumps(held), now=now)
    stage = follower.stage()
    for index, step in enumerate(case["steps"]):
        if step["expected"] == "ok":
            stage.accept(_raw(step), now=now)
            continue
        with pytest.raises(ks.KeySetRejected) as info:
            stage.accept(_raw(step), now=now)
        assert info.value.cause.value == step["expected"] and info.value.index == index


def test_every_reject_cause_is_exercised_by_the_vectors() -> None:
    cases = [*VECTORS["cases"], *VECTORS["since_cases"]]
    seen = {s["expected"] for c in cases for s in c["steps"]}
    assert seen == {"ok"} | {c.value for c in KeySetRejectCause}


def test_rotation_moves_trust_and_keeps_the_retiring_key_in_the_overlap() -> None:
    case = next(c for c in VECTORS["cases"] if c["name"] == "valid_rotation")
    follower = _vector_follower()
    now = _now(case["now"])
    follower.accept(_raw(case["steps"][0]), now=now)
    follower.accept(_raw(case["steps"][1]), now=now)
    assert follower.trusted_kids() == {"snap-2026-11-v1"}
    assert {k.kid for k in follower.listed_keys(now)} == {"snap-2026-11-v1", "snap-2026-10-v1"}
    later = datetime(2027, 2, 1, tzinfo=UTC)
    assert {k.kid for k in follower.listed_keys(later)} == {"snap-2026-11-v1"}
    assert len(follower.chain_state.accepted) == 2


# ------------------------------------------------------------------ staged catch-up


def test_genesis_pin_catches_up_across_three_rotations() -> None:
    keys, sets = rotation_chain(3)
    follower = _pinned(keys)
    assert follower.accept_chain(sets, now=NOW) == 4
    assert follower.trusted_kids() == {"k4"}
    assert {k.kid for k in follower.listed_keys(NOW)} == {"k4", "k3"}


def test_tamper_in_the_middle_rejects_the_whole_chain() -> None:
    keys, sets = rotation_chain(3)
    follower = _pinned(keys)
    before = follower.chain_state
    with pytest.raises(ks.KeySetRejected) as info:
        follower.accept_chain([*sets[:2], tamper(sets[2]), sets[3]], now=NOW)
    assert info.value.cause is KeySetRejectCause.BAD_SIGNATURE and info.value.index == 2
    assert follower.chain_state is before


def test_a_sequence_gap_in_a_delivery_is_refused_but_a_direct_set_may_skip() -> None:
    keys, sets = rotation_chain(3)
    follower = _pinned(keys)
    follower.accept_chain(sets[:2], now=NOW)
    skipped = keys[1].sign_set(4, [keys[1].entry()], None, NOW)
    with pytest.raises(ks.KeySetRejected) as info:
        follower.accept_chain([skipped], now=NOW)
    assert info.value.cause is KeySetRejectCause.SEQUENCE_GAP and follower.sequence == 2
    follower.accept(skipped, now=NOW)  # a direct delivery is not a ?since= chain
    assert follower.sequence == 4


def test_a_stage_commits_only_against_the_state_it_started_from() -> None:
    keys, sets = rotation_chain(2)
    follower = _pinned(keys)
    stage = follower.stage()
    stage.accept(sets[0], now=NOW)
    assert follower.sequence == 0 and stage.sequence == 1 and stage.count == 1
    follower.commit(stage)
    with pytest.raises(ks.KeySetRejected) as info:
        follower.commit(stage)
    assert info.value.cause is KeySetRejectCause.NON_MONOTONIC


def test_from_state_restores_a_follower() -> None:
    keys, sets = rotation_chain(1)
    follower = _pinned(keys)
    follower.accept_chain(sets, now=NOW)
    restored = ks.ChainFollower.from_state(follower.pinned, follower.chain_state)
    assert restored.sequence == 2 and restored.trusted_kids() == {"k2"}


# ------------------------------------------------------------------ keys and helpers


@pytest.mark.parametrize(
    "entry",
    [
        [],
        {"kid": "k", "alg": "Ed25519", "public_key": "AA", "extra": 1},
        {"kid": "", "alg": "Ed25519", "public_key": _b64u(bytes(32))},
        {"kid": "k", "alg": "RS256", "public_key": _b64u(bytes(32))},
        {"kid": "k", "alg": "Ed25519", "public_key": _b64u(bytes(31))},
        {"kid": "k", "alg": "Ed25519", "public_key": _b64u(bytes(32)) + "="},
        {"kid": "k", "alg": "Ed25519", "public_key": _b64u(bytes(32)), "status": "revoked"},
        {"kid": "k", "alg": "Ed25519", "public_key": _b64u(bytes(32)), "not_after": "2026-01-01"},
    ],
)
def test_chain_key_from_entry_refuses_unusable_keys(entry: Any) -> None:
    with pytest.raises(ValueError):
        ks.ChainKey.from_entry(entry)


def test_chain_key_keeps_its_entry_and_usability() -> None:
    entry = {
        "kid": "k",
        "alg": "Ed25519",
        "public_key": _b64u(bytes(32)),
        "not_after": "2026-01-01T00:00:00Z",
    }
    key = ks.ChainKey.from_entry(entry)
    assert key.entry == entry and key.public_key == bytes(32)
    assert key.usable(datetime(2025, 12, 31, tzinfo=UTC))
    assert not key.usable(datetime(2026, 1, 2, tzinfo=UTC))


def test_helpers_are_strict() -> None:
    with pytest.raises(ValueError):
        ks.parse_ts(5)
    with pytest.raises(ValueError):
        ks.b64url_decode("a")
    with pytest.raises(ValueError):
        ks.b64url_decode(None)
    assert not ks.verify_ed25519(b"x", "AA", bytes(32))


def test_trust_on_first_use_pins_the_self_signed_first_set() -> None:
    _, sets = rotation_chain(1)
    follower = ks.ChainFollower.trust_on_first_use(sets[0], now=NOW)
    assert follower.sequence == 1 and follower.trusted_kids() == {"k1"}
    with pytest.raises(ks.KeySetRejected) as info:
        ks.ChainFollower.trust_on_first_use(b'{"keys": []}', now=NOW)
    assert info.value.cause is KeySetRejectCause.MALFORMED
    other = _Key("k9")
    foreign = json.loads(sets[0])
    foreign["kid"] = other.kid  # signer is not listed in its own set
    with pytest.raises(ks.KeySetRejected) as info:
        ks.ChainFollower.trust_on_first_use(json.dumps(foreign).encode(), now=NOW)
    assert info.value.cause is KeySetRejectCause.UNKNOWN_SIGNER


# ------------------------------------------------------------------ follow_chain


class ChainRoute:
    def __init__(self, sets: list[bytes], page: int = 1000) -> None:
        self.sets = sets
        self.page = page
        self.seen: list[int] = []
        self.data: list[bytes] | None = None

    def fetch(self, since: int) -> bytes:
        self.seen.append(since)
        docs = [json.loads(s) for s in self.sets]
        after = [d for d in docs if d["body"]["sequence"] > since][: self.page]
        if self.data is not None:
            after = [json.loads(s) for s in self.data]
        latest = max((d["body"]["sequence"] for d in docs), default=0)
        return json.dumps({"data": after, "latest_sequence": latest}).encode()


def _follow(
    route: ChainRoute, follower: ks.ChainFollower | None
) -> tuple[ks.ChainFollower | None, int]:
    return ks.follow_chain(route.fetch, follower, now=NOW, kind=ks.ChainFollower)


def test_follow_chain_pages_until_the_latest_sequence() -> None:
    keys, sets = rotation_chain(4)
    route = ChainRoute(sets, page=2)
    follower, adopted = _follow(route, _pinned(keys))
    assert follower is not None and follower.sequence == 5
    assert route.seen == [0, 2, 4] and adopted == 5


@pytest.mark.parametrize("page", [1, 1000])
def test_follow_chain_without_a_pin_trusts_the_genesis_on_first_use(page: int) -> None:
    _, sets = rotation_chain(3)
    route = ChainRoute(sets, page=page)
    follower, adopted = _follow(route, None)
    assert follower is not None and follower.sequence == 4 and adopted == 4
    assert follower.trusted_kids() == {"k4"}


def test_follow_chain_with_nothing_issued_returns_nothing() -> None:
    assert _follow(ChainRoute([]), None) == (None, 0)


def test_follow_chain_tofu_refuses_a_chain_that_does_not_start_at_genesis() -> None:
    keys, sets = rotation_chain(2)
    route = ChainRoute(sets)
    route.data = [keys[1].sign_set(2, [keys[1].entry()], None, NOW)]
    with pytest.raises(ks.KeySetRejected) as info:
        _follow(route, None)
    assert info.value.cause is KeySetRejectCause.CHAIN_BROKEN and info.value.index == 0


def test_follow_chain_tofu_reports_later_members_by_their_delivery_index() -> None:
    _, sets = rotation_chain(3)
    route = ChainRoute([*sets[:2], tamper(sets[2]), sets[3]])
    with pytest.raises(ks.KeySetRejected) as info:
        _follow(route, None)
    assert info.value.cause is KeySetRejectCause.BAD_SIGNATURE and info.value.index == 2


def test_follow_chain_tofu_with_a_malformed_genesis() -> None:
    with pytest.raises(ks.KeySetRejected) as info:
        ks.follow_chain(
            lambda since: b'{"data": [{"kid": "k1"}], "latest_sequence": 1}',
            None,
            now=NOW,
            kind=ks.ChainFollower,
        )
    assert info.value.cause is KeySetRejectCause.MALFORMED and info.value.index == 0


def test_follow_chain_rejects_a_tampered_later_page_atomically() -> None:
    keys, sets = rotation_chain(3)
    follower = _pinned(keys)
    route = ChainRoute([*sets[:2], tamper(sets[2]), sets[3]], page=2)
    with pytest.raises(ks.KeySetRejected) as info:
        _follow(route, follower)
    assert info.value.cause is KeySetRejectCause.BAD_SIGNATURE and follower.sequence == 0


def test_follow_chain_refuses_a_gap_in_the_delivery() -> None:
    keys, sets = rotation_chain(3)
    follower = _pinned(keys)
    follower.accept_chain(sets[:1], now=NOW)
    route = ChainRoute(sets)
    route.data = [keys[0].sign_set(3, [keys[0].entry()], None, NOW)]  # sequence 2 skipped
    with pytest.raises(ks.KeySetRejected) as info:
        _follow(route, follower)
    assert info.value.cause is KeySetRejectCause.SEQUENCE_GAP and follower.sequence == 1


def test_follow_chain_up_to_date_adopts_nothing() -> None:
    keys, sets = rotation_chain(2)
    follower = _pinned(keys)
    follower.accept_chain(sets, now=NOW)
    same, adopted = _follow(ChainRoute(sets), follower)
    assert same is follower and adopted == 0


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"data": []}',
        b'{"data": {}, "latest_sequence": 1}',
        b'{"data": [], "latest_sequence": true}',
        b'{"data": [], "latest_sequence": -1}',
        b"{,}",
    ],
)
def test_malformed_chain_envelope(payload: bytes) -> None:
    with pytest.raises(ks.KeySetRejected) as info:
        ks.parse_chain_page(payload)
    assert info.value.cause is KeySetRejectCause.MALFORMED


def test_chain_page_members_are_canonical_bytes() -> None:
    page = ks.parse_chain_page(b'{"latest_sequence": 3, "data": [{"b": 1, "a": 2}]}')
    assert page == ks.ChainPage((b'{"a":2,"b":1}',), 3)


def test_fetch_errors_propagate() -> None:
    def down(since: int) -> bytes:
        raise ks.ChainFetchError("down")

    keys, _ = rotation_chain(1)
    with pytest.raises(ks.ChainFetchError):
        ks.follow_chain(down, _pinned(keys), now=NOW, kind=ks.ChainFollower)
