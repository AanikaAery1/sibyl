"""Key-set catch-up (B9, B10, B18): a gateway pinned at genesis follows ``?since=<sequence>``,
verifying every set in order from the pin; the first failing set rejects the whole delivery
and the chain keeps the last set it had verified."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from sibyl_gateway.credentials.vault import CredentialVault
from sibyl_gateway.policy.fetcher import SnapshotFetcher
from sibyl_gateway.policy.keychain import KeyChain, KeySetRejected
from sibyl_gateway.policy.store import SnapshotStore

from ..support import GATEWAY_KEY, GATEWAY_PREFIX, TENANT, TestSigner, body, tenant_block
from .chainkit import ChainRoute, rotation_chain, tamper
from .test_keychain import _Key

NOW = datetime.now(UTC)


def _pinned(keys: list[_Key]) -> KeyChain:
    return KeyChain.from_pin_json(json.dumps(keys[0].entry()))


def test_genesis_pin_catches_up_across_three_rotations() -> None:
    keys, sets = rotation_chain(3)
    chain = _pinned(keys)
    assert chain.accept_chain(sets, now=NOW, persist=False) == 4
    assert chain.sequence == 4
    assert chain.verification_keys(NOW).kids == {"k4", "k3"}  # k3 retiring in the overlap


def test_tamper_in_the_middle_rejects_the_whole_chain() -> None:
    keys, sets = rotation_chain(3)
    chain = _pinned(keys)
    bad = [*sets[:2], tamper(sets[2]), sets[3]]
    with pytest.raises(KeySetRejected) as info:
        chain.accept_chain(bad, now=NOW, persist=False)
    assert info.value.cause == "bad_signature" and info.value.index == 2
    assert chain.sequence == 0 and chain.verification_keys(NOW).kids == {"k1"}


def test_a_sequence_gap_in_a_delivery_is_refused() -> None:
    keys, sets = rotation_chain(3)
    k2 = keys[1]
    chain = _pinned(keys)
    chain.accept_chain(sets[:2], now=NOW, persist=False)
    skipped = k2.sign_set(4, [k2.entry()], None, NOW)  # signer still trusted, sequence 3 missing
    with pytest.raises(KeySetRejected) as info:
        chain.accept_chain([skipped], now=NOW, persist=False)
    assert info.value.cause == "sequence_gap" and chain.sequence == 2  # CR-G1


def test_replay_of_an_older_set_is_refused() -> None:
    keys, sets = rotation_chain(3)
    chain = _pinned(keys)
    with pytest.raises(KeySetRejected) as info:
        chain.accept_chain([sets[0], sets[0]], now=NOW, persist=False)
    assert info.value.cause == "non_monotonic" and info.value.index == 1
    chain.accept_chain(sets, now=NOW, persist=False)
    with pytest.raises(KeySetRejected) as info:
        chain.accept_chain([sets[1]], now=NOW, persist=False)  # k1 no longer signs
    assert info.value.cause == "unknown_signer" and chain.sequence == 4


@pytest.mark.parametrize("raw", ["{}", "[]", "not json", '{"kid": "k1"}'])
def test_malformed_member_rejects(raw: str) -> None:
    keys, sets = rotation_chain(1)
    chain = _pinned(keys)
    with pytest.raises(KeySetRejected) as info:
        chain.accept_chain([sets[0], raw], now=NOW, persist=False)
    assert info.value.cause == "malformed" and chain.sequence == 0


def test_staged_pages_commit_atomically(tmp_path: Path) -> None:
    keys, sets = rotation_chain(3)
    chain = KeyChain.from_pin_json(json.dumps(keys[0].entry()), state_dir=tmp_path)
    stage = chain.stage()
    stage.accept(sets[0], now=NOW)
    stage.accept(sets[1], now=NOW)
    assert chain.sequence == 0 and stage.sequence == 2  # nothing adopted before commit
    chain.commit(stage)
    assert chain.sequence == 2
    again = KeyChain.from_pin_json(json.dumps(keys[0].entry()), state_dir=tmp_path)
    assert again.replay() == 2 and again.sequence == 2  # persisted, replayed from the pin
    with pytest.raises(KeySetRejected):
        chain.commit(stage)  # a stage is only good against the state it started from


# ------------------------------------------------------------------ fetcher over ?since=


def _fetcher(chain: KeyChain, route: ChainRoute, snap: TestSigner | None = None) -> SnapshotFetcher:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/policy/keys":
            return route.response(request)
        assert snap is not None
        raw, kid, sig = snap.deliver(body(5, tenants={str(TENANT): tenant_block()}))
        headers = {"x-sibyl-snapshot-kid": kid, "x-sibyl-snapshot-signature": sig}
        return httpx.Response(200, content=raw, headers=headers)

    return SnapshotFetcher(
        SnapshotStore(chain.verification_keys(NOW)),
        CredentialVault(),
        control_url="http://api",
        streams={GATEWAY_PREFIX: GATEWAY_KEY},
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        gateway_id="gw",
        keychain=chain,
    )


async def test_fetcher_catches_up_and_verifies_snapshots_by_the_latest_key() -> None:
    keys, sets = rotation_chain(3)
    chain = _pinned(keys)
    snap = TestSigner("k4")
    snap._key = keys[3].private
    fetcher = _fetcher(chain, route := ChainRoute(sets), snap)
    assert await fetcher.refresh_keys() == "installed"
    assert route.seen_since == [0] and chain.sequence == 4 and fetcher.stats.key_sets == 4
    assert await fetcher.refresh(GATEWAY_PREFIX) == "installed"
    fetcher._keys_at = None
    assert await fetcher.refresh_keys() == "not_modified"
    assert route.seen_since == [0, 4]


async def test_fetcher_pages_until_the_latest_sequence() -> None:
    keys, sets = rotation_chain(4)
    chain = _pinned(keys)
    route = ChainRoute(sets, page=2)
    fetcher = _fetcher(chain, route)
    assert await fetcher.refresh_keys() == "installed"
    assert route.seen_since == [0, 2, 4] and chain.sequence == 5


async def test_fetcher_rejects_a_tampered_page_and_keeps_the_last_verified_set() -> None:
    keys, sets = rotation_chain(3)
    chain = _pinned(keys)
    chain.accept_chain(sets[:1], now=NOW, persist=False)
    route = ChainRoute([*sets[:2], tamper(sets[2]), sets[3]], page=2)
    fetcher = _fetcher(chain, route)
    assert await fetcher.refresh_keys() == "rejected:bad_signature"
    assert chain.sequence == 1 and chain.verification_keys(NOW).kids == {"k1"}
    assert fetcher.stats.key_set_rejected == {"bad_signature": 1}
    assert fetcher._store._keys.kids == {"k1"}


async def test_fetcher_refuses_replayed_sets_and_gaps() -> None:
    keys, sets = rotation_chain(3)
    k1 = keys[0]
    chain = _pinned(keys)
    chain.accept_chain(sets[:1], now=NOW, persist=False)
    route = ChainRoute(sets, data=[sets[0]])  # the set already held, replayed after ?since=1
    fetcher = _fetcher(chain, route)
    assert await fetcher.refresh_keys() == "rejected:non_monotonic"
    route.data = [k1.sign_set(3, [k1.entry()], None, NOW)]  # sequence 2 skipped
    fetcher._keys_at = None
    assert await fetcher.refresh_keys() == "rejected:sequence_gap"
    assert chain.sequence == 1
    assert fetcher.stats.key_set_rejected == {"non_monotonic": 1, "sequence_gap": 1}


@pytest.mark.parametrize(
    "payload",
    [b"[]", b'{"data": []}', b'{"data": {}, "latest_sequence": 1}', b'{"latest_sequence": 1}'],
)
async def test_fetcher_rejects_a_malformed_chain_envelope(payload: bytes) -> None:
    keys, _ = rotation_chain(1)
    chain = _pinned(keys)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=payload)

    fetcher = SnapshotFetcher(
        SnapshotStore(chain.verification_keys(NOW)),
        CredentialVault(),
        control_url="http://api",
        streams={GATEWAY_PREFIX: GATEWAY_KEY},
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        gateway_id="gw",
        keychain=chain,
    )
    assert await fetcher.refresh_keys() == "rejected:malformed"
    assert chain.sequence == 0


async def test_a_lagging_replica_is_not_an_error() -> None:
    keys, sets = rotation_chain(2)
    chain = _pinned(keys)
    chain.accept_chain(sets, now=NOW, persist=False)
    route = ChainRoute(sets[:1])  # a replica that has only issued sequence 1
    fetcher = _fetcher(chain, route)
    assert await fetcher.refresh_keys() == "not_modified"
    assert chain.sequence == 3 and not fetcher.stats.key_set_rejected
