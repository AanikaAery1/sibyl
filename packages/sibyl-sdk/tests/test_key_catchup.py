"""Key-set catch-up (B10, B18): pinned at genesis (or trust on first use), the SDK follows
`GET /api/v1/policy/keys?since=<sequence>`, verifying every set in order; the first failing set
rejects the whole delivery and the verifier keeps the last set it had verified."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import sibyl
from sibyl._keys import KeySetRejected, KeySetVerifier, parse_pin
from sibyl._keysync import ChainFetchError, follow_chain, parse_chain_page
from sibyl.testing import TEST_KEY, Ingest, OffsetClock, SnapshotServer, SnapshotSigner, wait_for

NOW = datetime.now(UTC)
T0 = NOW - timedelta(days=30)


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def rotation_chain(rotations: int) -> tuple[list[SnapshotSigner], list[bytes]]:
    """`keys[0]` is the genesis pin; set n+1 is signed by keys[n-1] and rotates to keys[n]."""
    keys = [SnapshotSigner(n=i + 1, kid=f"k{i + 1}") for i in range(rotations + 2)]
    sets = [keys[0].key_set(1, [keys[0].key(status="active")], keys[1].key(), _iso(T0))]
    for n in range(1, rotations + 1):
        nxt = keys[n + 1].key() if n < rotations else None
        retiring = keys[n - 1].key(status="retiring", not_after="2099-01-01T00:00:00.000Z")
        issued = _iso(T0 + timedelta(days=n))
        sets.append(
            keys[n - 1].key_set(n + 1, [keys[n].key(status="active"), retiring], nxt, issued)
        )
    return keys, sets


def tamper(raw: bytes) -> bytes:
    doc = json.loads(raw)
    doc["body"]["issued_at"] = "2030" + doc["body"]["issued_at"][4:]
    return json.dumps(doc).encode()


def _pinned(keys: list[SnapshotSigner]) -> KeySetVerifier:
    return KeySetVerifier(parse_pin(keys[0].pin()))


# ------------------------------------------------------------------ verifier


def test_genesis_pin_catches_up_across_three_rotations() -> None:
    keys, sets = rotation_chain(3)
    verifier = _pinned(keys)
    assert verifier.accept_chain(sets, now=NOW) == 4
    assert verifier.trusted_kids() == {"k4"}
    assert verifier.public_key("k3", now=NOW) is not None  # retiring: still verifies (B10)
    assert verifier.public_key("k3", now=datetime(2100, 1, 1, tzinfo=UTC)) is None
    assert verifier.public_key("k1", now=NOW) is None
    restored = KeySetVerifier.from_state(json.loads(json.dumps(verifier.state())))
    assert restored.state() == verifier.state()
    assert restored.public_key("k3", now=NOW) is not None


def test_tamper_in_the_middle_rejects_the_whole_chain() -> None:
    keys, sets = rotation_chain(3)
    verifier = _pinned(keys)
    before = verifier.state()
    with pytest.raises(KeySetRejected) as info:
        verifier.accept_chain([*sets[:2], tamper(sets[2]), sets[3]], now=NOW)
    assert info.value.cause.value == "bad_signature" and info.value.index == 2
    assert verifier.state() == before


def test_a_sequence_gap_in_a_delivery_is_refused() -> None:
    keys, sets = rotation_chain(3)
    verifier = _pinned(keys)
    verifier.accept_chain(sets[:2], now=NOW)
    skipped = keys[1].key_set(4, [keys[1].key(status="active")], None, _iso(NOW))
    with pytest.raises(KeySetRejected) as info:
        verifier.accept_chain([skipped], now=NOW)
    assert info.value.cause.value == "sequence_gap" and verifier.sequence == 2  # CR-G1


def test_replay_of_an_older_set_is_refused() -> None:
    keys, sets = rotation_chain(3)
    verifier = _pinned(keys)
    with pytest.raises(KeySetRejected) as info:
        verifier.accept_chain([sets[0], sets[0]], now=NOW)
    assert info.value.cause.value == "non_monotonic" and info.value.index == 1
    verifier.accept_chain(sets, now=NOW)
    with pytest.raises(KeySetRejected) as info:
        verifier.accept_chain([sets[1]], now=NOW)
    assert info.value.cause.value == "unknown_signer" and verifier.sequence == 4


def test_a_stage_commits_only_against_the_state_it_started_from() -> None:
    keys, sets = rotation_chain(2)
    verifier = _pinned(keys)
    stage = verifier.stage()
    stage.accept(sets[0], now=NOW)
    assert verifier.sequence == 0 and stage.sequence == 1
    verifier.commit(stage)
    assert verifier.sequence == 1
    with pytest.raises(KeySetRejected):
        verifier.commit(stage)


# ------------------------------------------------------------------ follow_chain


class ChainRoute:
    def __init__(self, sets: list[bytes], page: int = 1000) -> None:
        self.sets = sets
        self.page = page
        self.seen: list[int] = []
        self.data: list[bytes] | None = None

    def body(self, since: int) -> bytes:
        self.seen.append(since)
        docs = [json.loads(s) for s in self.sets]
        after = [d for d in docs if d["body"]["sequence"] > since][: self.page]
        if self.data is not None:
            after = [json.loads(s) for s in self.data]
        latest = max((d["body"]["sequence"] for d in docs), default=0)
        return json.dumps({"data": after, "latest_sequence": latest}).encode()

    def fetch(self, since: int) -> bytes:
        return self.body(since)


def test_follow_chain_pages_until_the_latest_sequence() -> None:
    keys, sets = rotation_chain(4)
    route = ChainRoute(sets, page=2)
    verifier, adopted = follow_chain(route.fetch, _pinned(keys), now=NOW)
    assert verifier is not None and verifier.sequence == 5
    assert route.seen == [0, 2, 4] and adopted == 5


def test_follow_chain_without_a_pin_trusts_the_genesis_on_first_use() -> None:
    _, sets = rotation_chain(3)
    verifier, adopted = follow_chain(ChainRoute(sets).fetch, None, now=NOW)
    assert verifier is not None and verifier.sequence == 4 and adopted == 4
    assert verifier.trusted_kids() == {"k4"}


def test_follow_chain_tofu_refuses_a_chain_that_does_not_start_at_genesis() -> None:
    keys, sets = rotation_chain(2)
    route = ChainRoute(sets)
    route.data = [keys[1].key_set(2, [keys[1].key(status="active")], None, _iso(NOW))]
    with pytest.raises(KeySetRejected) as info:
        follow_chain(route.fetch, None, now=NOW)
    assert info.value.cause.value == "chain_broken"


def test_follow_chain_rejects_a_tampered_later_page_atomically() -> None:
    keys, sets = rotation_chain(3)
    verifier = _pinned(keys)
    route = ChainRoute([*sets[:2], tamper(sets[2]), sets[3]], page=2)
    with pytest.raises(KeySetRejected) as info:
        follow_chain(route.fetch, verifier, now=NOW)
    assert info.value.cause.value == "bad_signature" and verifier.sequence == 0


def test_follow_chain_up_to_date_adopts_nothing() -> None:
    keys, sets = rotation_chain(2)
    verifier = _pinned(keys)
    verifier.accept_chain(sets, now=NOW)
    same, adopted = follow_chain(ChainRoute(sets).fetch, verifier, now=NOW)
    assert same is verifier and adopted == 0


@pytest.mark.parametrize(
    "payload", [b"[]", b'{"data": []}', b'{"data": {}, "latest_sequence": 1}', b"{,}"]
)
def test_malformed_chain_envelope(payload: bytes) -> None:
    with pytest.raises(KeySetRejected) as info:
        parse_chain_page(payload)
    assert info.value.cause.value == "malformed"


def test_fetch_errors_propagate() -> None:
    def down(since: int) -> bytes:
        raise ChainFetchError("down")

    keys, _ = rotation_chain(1)
    with pytest.raises(ChainFetchError):
        follow_chain(down, _pinned(keys), now=NOW)


# ------------------------------------------------------------------ PolicyManager over HTTP


@pytest.fixture
def rotated(clock: OffsetClock, ingest: Ingest) -> tuple[list[SnapshotSigner], SnapshotServer]:
    keys, sets = rotation_chain(3)
    server = SnapshotServer(clock, signer=keys[3])
    server.key_sets = sets
    server.install(ingest)
    return keys, server


def _client(ingest: Ingest, tmp_path: Path, pin: str | None) -> sibyl.Client:
    return sibyl.init(
        TEST_KEY,
        endpoint="http://127.0.0.1:8445",
        agent_id="quote-assistant",
        policy=sibyl.PolicyConfig(
            cache_dir=str(tmp_path / "policy"), public_key=pin, poll_interval=timedelta(hours=1)
        ),
        transport=ingest.transport,
    )


@pytest.mark.parametrize("pinned", [True, False], ids=["genesis-pin", "tofu"])
def test_sdk_catches_up_and_verifies_snapshots_by_the_latest_key(
    rotated: tuple[list[SnapshotSigner], SnapshotServer],
    ingest: Ingest,
    tmp_path: Path,
    pinned: bool,
) -> None:
    keys, _ = rotated
    client = _client(ingest, tmp_path, keys[0].pin() if pinned else None)
    assert wait_for(lambda: client.snapshot is not None)
    key_requests = [r for r in ingest.requests if r.path == "/api/v1/policy/keys"]
    assert key_requests and "authorization" not in key_requests[0].headers
    assert client.policy._keys is not None and client.policy._keys.sequence == 4


def test_sdk_refuses_a_tampered_chain(
    rotated: tuple[list[SnapshotSigner], SnapshotServer], ingest: Ingest, tmp_path: Path
) -> None:
    keys, server = rotated
    server.key_sets = [*server.key_sets[:2], tamper(server.key_sets[2]), server.key_sets[3]]
    client = _client(ingest, tmp_path, keys[0].pin())
    deadline = time.monotonic() + 0.3
    while time.monotonic() < deadline and client.snapshot is None:
        time.sleep(0.02)
    assert client.snapshot is None
    assert client.policy._keys is not None and client.policy._keys.sequence == 0


def test_key_requests_ask_since_the_held_sequence(
    rotated: tuple[list[SnapshotSigner], SnapshotServer], ingest: Ingest, tmp_path: Path
) -> None:
    keys, server = rotated
    client = _client(ingest, tmp_path, keys[0].pin())
    assert wait_for(lambda: client.snapshot is not None)
    assert server.key_since[0] == 0
    client.policy._last_key_fetch = -1e18
    assert client.policy._refresh_keys() is False  # nothing newer than sequence 4
    assert server.key_since[-1] == 4
