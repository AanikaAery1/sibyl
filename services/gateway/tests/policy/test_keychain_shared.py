"""B33: the gateway's ``KeyChain`` follows the key-set chain through the one shared follower in
``sibyl_schemas.keyset``: every golden vector (direct and ``?since=``) gets the same verdict,
the same failing member and the same snapshot keys as the shared follower, and the gateway
raises (and catches) the shared exception types."""

from __future__ import annotations

import json
from datetime import datetime
from functools import partial
from typing import Any

import pytest
from sibyl_gateway.policy import keychain, keysync
from sibyl_gateway.policy.keychain import KeyChain
from sibyl_schemas import keyset as ks
from sibyl_schemas.values import KeySetRejectCause

from .vectors import key_set_vectors

VECTORS = key_set_vectors()


def _now(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _raw(step: dict[str, Any]) -> str:
    return step["raw"] if "raw" in step else json.dumps(step["document"])


def _gateway() -> KeyChain:
    return KeyChain.from_pin_json(json.dumps(VECTORS["pinned"]))


def _shared() -> ks.ChainFollower:
    return ks.ChainFollower(ks.ChainKey.from_entry(VECTORS["pinned"]))


def _verdict(accept: Any) -> tuple[str, int | None]:
    try:
        accept()
    except ks.KeySetRejected as exc:
        return exc.cause.value, exc.index
    return "ok", None


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_direct_vectors_match_the_shared_follower(case: dict[str, Any]) -> None:
    gateway, shared, now = _gateway(), _shared(), _now(case["now"])
    for step in case["steps"]:
        raw = _raw(step)
        mine = _verdict(lambda raw=raw: gateway.accept(raw, now=now, persist=False))
        theirs = _verdict(lambda raw=raw: shared.accept(raw, now=now))
        assert mine == theirs == (step["expected"], None), case["name"]
        assert gateway.sequence == shared.sequence
        listed = {k.kid for k in shared.listed_keys(now)} or {shared.pinned.kid}
        assert gateway.verification_keys(now).kids == listed


@pytest.mark.parametrize(
    "case", VECTORS["since_cases"], ids=[c["name"] for c in VECTORS["since_cases"]]
)
def test_since_vectors_match_the_shared_follower(case: dict[str, Any]) -> None:
    gateway, shared, now = _gateway(), _shared(), _now(case["now"])
    for held in case["held"]:
        gateway.accept(json.dumps(held), now=now, persist=False)
        shared.accept(json.dumps(held), now=now)
    mine, theirs = gateway.stage(), shared.stage()
    for index, step in enumerate(case["steps"]):
        raw = _raw(step)
        got = _verdict(lambda raw=raw: mine.accept(raw, now=now))
        assert got == _verdict(lambda raw=raw: theirs.accept(raw, now=now))
        expected = ("ok", None) if step["expected"] == "ok" else (step["expected"], index)
        assert got == expected, case["name"]
        if got[0] != "ok":
            break


def test_every_shared_reject_cause_reaches_the_gateway() -> None:
    seen: set[str] = set()
    for case in VECTORS["cases"]:
        gateway, now = _gateway(), _now(case["now"])
        for step in case["steps"]:
            raw = _raw(step)
            seen.add(_verdict(partial(gateway.accept, raw, now=now, persist=False))[0])
    for case in VECTORS["since_cases"]:
        gateway, now = _gateway(), _now(case["now"])
        for held in case["held"]:
            gateway.accept(json.dumps(held), now=now, persist=False)
        steps = [_raw(s) for s in case["steps"]]
        seen.add(_verdict(partial(gateway.accept_chain, steps, now=now))[0])
    assert seen == {"ok"} | {c.value for c in KeySetRejectCause}


def test_the_gateway_raises_and_catches_the_shared_types() -> None:
    assert keychain.KeySetRejected is ks.KeySetRejected
    assert keychain.ChainKey is ks.ChainKey
    assert keysync.ChainFetchError is ks.ChainFetchError
    assert keysync.parse_chain_page is ks.parse_chain_page
