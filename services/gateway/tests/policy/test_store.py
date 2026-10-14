"""SnapshotStore: verify, index, install; monotonic per stream; TTL/grace; persistence."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sibyl_gateway.policy.store import SnapshotStore
from sibyl_gateway.policy.verify import MALFORMED, PinnedKeySet, SnapshotRejected
from sibyl_gateway.policy.view import PolicyState

from ..support import BILLING, GATEWAY_PREFIX, TENANT, Clock, TestSigner, body, tenant_block


def make_store(signer: TestSigner, clock: Clock, tmp: Path | None = None) -> SnapshotStore:
    keys = PinnedKeySet.from_document(signer.key_set())
    return SnapshotStore(keys, snapshot_dir=tmp, clock=clock)


def offer(store: SnapshotStore, signer: TestSigner, version: int, clock: Clock, **kw):
    raw, kid, sig = signer.deliver(body(version, issued_at=clock.now, **kw))
    return store.offer("gw1", raw, kid=kid, signature=sig)


def test_install_indexes_tenant_keys_and_agents(signer: TestSigner) -> None:
    clock = Clock()
    store = make_store(signer, clock)
    assert not store.ever_loaded
    assert store.status().state is PolicyState.UNAVAILABLE
    doc = offer(store, signer, 10, clock)
    assert store.ever_loaded and doc.version == 10
    block, _doc = store.tenant(TENANT)  # type: ignore[misc]
    assert block.agents[BILLING].route.state == "failed_over"
    assert block.agent("billing-agent") is block.agents[BILLING]
    assert block.agent(str(BILLING)) is block.agents[BILLING]
    found = store.key(GATEWAY_PREFIX)
    assert found is not None and found[1].scopes == {"gateway:proxy", "routing:read"}
    assert block.killed_agents and not block.tenant_killed


def test_strictly_monotonic_and_rejection_keeps_the_held_snapshot(signer: TestSigner) -> None:
    clock = Clock()
    store = make_store(signer, clock)
    offer(store, signer, 10, clock)
    for version in (10, 9):
        with pytest.raises(SnapshotRejected) as err:
            offer(store, signer, version, clock)
        assert err.value.cause == "non_monotonic"
    assert store.held_version("gw1") == 10
    offer(store, signer, 11, clock)
    assert store.held_version("gw1") == 11


def test_signed_but_malformed_tenant_block_is_rejected(signer: TestSigner) -> None:
    clock = Clock()
    store = make_store(signer, clock)
    broken = tenant_block()
    del broken["kill_switches"]
    with pytest.raises(SnapshotRejected) as err:
        offer(store, signer, 5, clock, tenants={str(TENANT): broken})
    assert err.value.cause == MALFORMED
    assert not store.ever_loaded


def test_fresh_stale_expired_by_age(signer: TestSigner) -> None:
    clock = Clock(datetime(2026, 10, 10, 12, 0, tzinfo=UTC))
    store = make_store(signer, clock)
    offer(store, signer, 1, clock)
    assert store.status().state is PolicyState.FRESH
    clock.advance(60)
    assert store.status().state is PolicyState.FRESH
    clock.advance(1)
    assert store.status().state is PolicyState.STALE
    clock.advance(299)
    assert store.status().state is PolicyState.STALE
    clock.advance(1)
    status = store.status()
    assert status.state is PolicyState.EXPIRED and status.version == 1 and status.age_s == 361


def test_persisted_snapshot_survives_restart_and_keeps_the_floor(
    signer: TestSigner, tmp_path: Path
) -> None:
    clock = Clock()
    store = make_store(signer, clock, tmp_path)
    offer(store, signer, 42, clock)
    record = json.loads((tmp_path / "gw1.snapshot.json").read_text())
    assert (
        record["high_water"] == 42 and (tmp_path / "gw1.snapshot.json").stat().st_mode & 0o077 == 0
    )
    clock.advance(3600)  # restart long after expiry: still loaded, state expired
    again = make_store(signer, clock, tmp_path)
    assert again.load_persisted() == 1
    assert again.status().state is PolicyState.EXPIRED
    with pytest.raises(SnapshotRejected):
        offer(again, signer, 42, clock)  # replay of the persisted version


def test_tampered_persisted_snapshot_is_ignored(signer: TestSigner, tmp_path: Path) -> None:
    clock = Clock()
    offer(make_store(signer, clock, tmp_path), signer, 7, clock)
    path = tmp_path / "gw1.snapshot.json"
    record = json.loads(path.read_text())
    record["signature"] = TestSigner().sign(b"x")
    path.write_text(json.dumps(record))
    fresh = make_store(signer, clock, tmp_path)
    assert fresh.load_persisted() == 0 and not fresh.ever_loaded


def test_listeners_see_each_install_and_failures_do_not_break_install(signer: TestSigner) -> None:
    clock = Clock()
    store = make_store(signer, clock)
    seen: list[int] = []
    store.listeners.append(lambda stream, doc: seen.append(doc.version))
    store.listeners.append(lambda stream, doc: 1 / 0)  # type: ignore[arg-type,return-value]
    offer(store, signer, 3, clock)
    assert seen == [3] and store.held_version("gw1") == 3


def test_stream_names_are_restricted(signer: TestSigner) -> None:
    clock = Clock()
    raw, kid, sig = signer.deliver(body(1, issued_at=clock.now - timedelta(seconds=1)))
    with pytest.raises(ValueError):
        make_store(signer, clock).offer("../x", raw, kid=kid, signature=sig)
