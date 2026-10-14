"""B33: the SDK's `KeySetVerifier` follows the key-set chain through the one shared follower in
`sibyl_schemas.keyset`: every golden vector (direct and `?since=`) gets the same verdict, the
same failing member and the same snapshot keys as the shared follower, and the SDK raises the
shared exception types."""

from __future__ import annotations

import json
from datetime import datetime
from functools import partial
from typing import Any

import pytest
from sibyl import _keys, _keysync
from sibyl._keys import KeySetVerifier, parse_pin, trust_on_first_use
from sibyl_schemas import keyset as ks
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.values import KeySetRejectCause

VECTORS: dict[str, Any] = load_fixture("snapshot", "key_set_vectors.json")


def _now(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _raw(step: dict[str, Any]) -> str:
    return step["raw"] if "raw" in step else json.dumps(step["document"])


def _shared() -> ks.ChainFollower:
    return ks.ChainFollower(ks.ChainKey.from_entry(VECTORS["pinned"]))


def _verdict(accept: Any) -> tuple[str, int | None]:
    try:
        accept()
    except ks.KeySetRejected as exc:
        return exc.cause.value, exc.index
    return "ok", None


def _listed(verifier: KeySetVerifier, follower: ks.ChainFollower, now: datetime) -> None:
    for key in follower.chain_state.listed.values():
        expected = key.public_key if key.usable(now) else None
        assert verifier.public_key(key.kid, now=now) == expected


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_direct_vectors_match_the_shared_follower(case: dict[str, Any]) -> None:
    verifier, shared, now = KeySetVerifier(VECTORS["pinned"]), _shared(), _now(case["now"])
    for step in case["steps"]:
        raw = _raw(step)
        mine = _verdict(lambda raw=raw: verifier.accept(raw, now=now))
        theirs = _verdict(lambda raw=raw: shared.accept(raw, now=now))
        assert mine == theirs == (step["expected"], None), case["name"]
        assert verifier.sequence == shared.sequence
        assert verifier.trusted_kids() == shared.trusted_kids()
        _listed(verifier, shared, now)


@pytest.mark.parametrize(
    "case", VECTORS["since_cases"], ids=[c["name"] for c in VECTORS["since_cases"]]
)
def test_since_vectors_match_the_shared_follower(case: dict[str, Any]) -> None:
    verifier, shared, now = KeySetVerifier(VECTORS["pinned"]), _shared(), _now(case["now"])
    for held in case["held"]:
        verifier.accept(json.dumps(held), now=now)
        shared.accept(json.dumps(held), now=now)
    mine, theirs = verifier.stage(), shared.stage()
    for index, step in enumerate(case["steps"]):
        raw = _raw(step)
        got = _verdict(lambda raw=raw: mine.accept(raw, now=now))
        assert got == _verdict(lambda raw=raw: theirs.accept(raw, now=now))
        expected = ("ok", None) if step["expected"] == "ok" else (step["expected"], index)
        assert got == expected, case["name"]
        if got[0] != "ok":
            break


def test_every_shared_reject_cause_reaches_the_sdk() -> None:
    seen: set[str] = set()
    for case in VECTORS["cases"]:
        verifier, now = KeySetVerifier(VECTORS["pinned"]), _now(case["now"])
        for step in case["steps"]:
            raw = _raw(step)
            seen.add(_verdict(partial(verifier.accept, raw, now=now))[0])
    for case in VECTORS["since_cases"]:
        verifier, now = KeySetVerifier(VECTORS["pinned"]), _now(case["now"])
        for held in case["held"]:
            verifier.accept(json.dumps(held), now=now)
        steps = [_raw(s) for s in case["steps"]]
        seen.add(_verdict(partial(verifier.accept_chain, steps, now=now))[0])
    assert seen == {"ok"} | {c.value for c in KeySetRejectCause}


def test_trust_on_first_use_matches_the_shared_follower() -> None:
    first = json.dumps(VECTORS["cases"][0]["steps"][0]["document"]).encode()
    now = _now("2026-10-02T00:00:00Z")
    verifier = trust_on_first_use(first, now=now)
    shared = ks.ChainFollower.trust_on_first_use(first, now=now)
    assert verifier.sequence == shared.sequence and verifier.trusted_kids() == shared.trusted_kids()


def test_a_padded_bare_pin_is_still_accepted_and_stored_canonically() -> None:
    bare = "7bhBjgmAZPqpaPWOwzI4xLPD-LexVSwGNgNpKcE61xQ"
    pinned = parse_pin(bare + "=")
    assert pinned["public_key"] == bare
    verifier = KeySetVerifier(pinned)
    assert verifier.is_static and verifier.public_key("any", now=_now("2026-10-10T00:00:00Z"))


def test_unusable_stored_state_is_refused() -> None:
    with pytest.raises(IndexError):
        KeySetVerifier.from_state({"trusted": [], "sequence": 0})
    with pytest.raises(ValueError):
        KeySetVerifier.from_state({"trusted": [{"kid": "k"}], "sequence": 0})


def test_the_sdk_raises_the_shared_types() -> None:
    assert _keys.KeySetRejected is ks.KeySetRejected
    assert _keys.verify_ed25519 is ks.verify_ed25519
    assert _keysync.ChainFetchError is ks.ChainFetchError
    assert _keysync.parse_chain_page is ks.parse_chain_page
