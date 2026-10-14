"""Key-set rotation chain and snapshot verification against the `sibyl-schemas` vectors."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from typing import Any

import pytest
from sibyl._ids import parse_rfc3339
from sibyl._keys import KeySetRejected, KeySetVerifier, parse_pin, trust_on_first_use
from sibyl._snapshot import SnapshotRejected, agent_view, verify_snapshot
from sibyl.testing import SnapshotSigner
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import load_fixture

KEY_SETS: dict[str, Any] = load_fixture("snapshot", "key_set_vectors.json")
SNAPSHOTS: dict[str, Any] = load_fixture("snapshot", "vectors.json")
BOUND_PREFIX = "Bd3Fg5Hj7Kl9"


def _now(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


@pytest.mark.parametrize("case", KEY_SETS["cases"], ids=[c["name"] for c in KEY_SETS["cases"]])
def test_key_set_vectors_follow_the_rotation_chain(case: dict[str, Any]) -> None:
    verifier = KeySetVerifier(KEY_SETS["pinned"])
    for step in case["steps"]:
        raw = step.get("raw") or json.dumps(step["document"])
        before = verifier.state()
        if step["expected"] == "ok":
            verifier.accept(raw, now=_now(case["now"]))
        else:
            with pytest.raises(KeySetRejected) as info:
                verifier.accept(raw, now=_now(case["now"]))
            assert info.value.cause.value == step["expected"]
            assert verifier.state() == before  # a rejected set changes nothing


def test_rotation_moves_trust_to_the_successor() -> None:
    verifier = KeySetVerifier(KEY_SETS["pinned"])
    case = next(c for c in KEY_SETS["cases"] if c["name"] == "valid_rotation")
    for step in case["steps"]:
        verifier.accept(json.dumps(step["document"]), now=_now(case["now"]))
    assert verifier.trusted_kids() == {"snap-2026-11-v1"}
    assert verifier.public_key("snap-2026-10-v1", now=_now(case["now"])) is None
    restored = KeySetVerifier.from_state(json.loads(json.dumps(verifier.state())))
    assert restored.state() == verifier.state()


def test_trust_on_first_use_pins_the_self_signed_first_set() -> None:
    first = KEY_SETS["cases"][0]["steps"][0]["document"]
    verifier = trust_on_first_use(json.dumps(first).encode(), now=_now("2026-10-02T00:00:00Z"))
    assert verifier.sequence == 1 and verifier.trusted_kids() == {"snap-2026-10-v1"}
    with pytest.raises(KeySetRejected):
        trust_on_first_use(b'{"keys": []}', now=_now("2026-10-02T00:00:00Z"))


@pytest.mark.parametrize(
    "text",
    [
        "snap-2026-10-v1:7bhBjgmAZPqpaPWOwzI4xLPD-LexVSwGNgNpKcE61xQ",
        json.dumps(KEY_SETS["pinned"]),
        "7bhBjgmAZPqpaPWOwzI4xLPD-LexVSwGNgNpKcE61xQ",
    ],
)
def test_pin_forms(text: str) -> None:
    pinned = parse_pin(text)
    verifier = KeySetVerifier(pinned)
    assert verifier.public_key("snap-2026-10-v1", now=_now("2026-10-10T00:00:00Z")) is not None


def test_bad_pin_is_refused() -> None:
    with pytest.raises(ValueError):
        parse_pin("snap:short")


def _keys_for_vectors() -> KeySetVerifier:
    verifier = KeySetVerifier(KEY_SETS["pinned"])
    verifier.accept(json.dumps(SNAPSHOTS["key_set"]), now=_now("2026-10-10T12:00:00Z"))
    return verifier


def _snapshot_raw(case: dict[str, Any]) -> bytes:
    if "raw" in case:
        return str(case["raw"]).encode()
    return json.dumps(case["envelope"]).encode()


@pytest.mark.parametrize("case", SNAPSHOTS["cases"], ids=[c["name"] for c in SNAPSHOTS["cases"]])
def test_snapshot_vectors_envelope_form(case: dict[str, Any]) -> None:
    keys = _keys_for_vectors()
    now = parse_rfc3339(case["now"])
    raw = _snapshot_raw(case)
    if case["expected"] == "ok":
        verified = verify_snapshot(raw, {}, keys, held_version=case["held_version"], now=now)
        assert verified.version == case["envelope"]["body"]["version"]
    else:
        with pytest.raises(SnapshotRejected) as info:
            verify_snapshot(raw, {}, keys, held_version=case["held_version"], now=now)
        assert info.value.cause.value == case["expected"]


@pytest.mark.parametrize(
    "case",
    [c for c in SNAPSHOTS["cases"] if "envelope" in c],
    ids=[c["name"] for c in SNAPSHOTS["cases"] if "envelope" in c],
)
def test_snapshot_vectors_detached_form(case: dict[str, Any]) -> None:
    """Detached: body bytes = JCS(body), signature over those raw bytes (B4)."""
    envelope = case["envelope"]
    raw = canonicalize(envelope["body"])
    headers = {
        "X-Sibyl-Snapshot-Kid": envelope["kid"],
        "X-Sibyl-Snapshot-Signature": envelope["sig"],
    }
    now = parse_rfc3339(case["now"])
    keys = _keys_for_vectors()
    if case["expected"] == "ok":
        verify_snapshot(raw, headers, keys, held_version=case["held_version"], now=now)
    else:
        with pytest.raises(SnapshotRejected) as info:
            verify_snapshot(raw, headers, keys, held_version=case["held_version"], now=now)
        assert info.value.cause.value == case["expected"]


def test_detached_signature_covers_raw_bytes_not_a_reparse() -> None:
    signer = SnapshotSigner()
    body = copy.deepcopy(SNAPSHOTS["cases"][0]["envelope"]["body"])
    raw, headers = signer.detached(body)
    spaced = json.dumps(json.loads(raw), indent=2).encode()  # same JSON, different bytes
    keys = _keys_for_vectors()
    now = parse_rfc3339(SNAPSHOTS["cases"][0]["now"])
    verify_snapshot(raw, headers, keys, held_version=0, now=now)
    with pytest.raises(SnapshotRejected) as info:
        verify_snapshot(spaced, headers, keys, held_version=0, now=now)
    assert info.value.cause.value == "bad_signature"


def _view(body: dict[str, Any], agent_ref: str | None, prefix: str = BOUND_PREFIX) -> Any:
    signer = SnapshotSigner()
    raw, headers = signer.detached(body)
    verified = verify_snapshot(
        raw,
        headers,
        _keys_for_vectors(),
        held_version=0,
        now=parse_rfc3339(body["issued_at"]) + 1,
    )
    return agent_view(verified, agent_ref=agent_ref, key_prefix=prefix, max_stale_s=900)


def _body() -> dict[str, Any]:
    return copy.deepcopy(SNAPSHOTS["cases"][0]["envelope"]["body"])


def test_agent_view_by_uuid_slug_and_key_binding() -> None:
    body = _body()
    tenant = next(iter(body["tenants"].values()))
    agent_id, agent = next(
        (k, v) for k, v in tenant["agents"].items() if k == "0192767f-0000-7000-8000-00000000c011"
    )
    by_key = _view(body, None)
    assert str(by_key.agent_id) == agent_id
    assert by_key.slug == agent["slug"]
    assert _view(body, agent["slug"]).agent_id == by_key.agent_id
    assert _view(body, agent_id).state == agent["route"]["state"]
    assert set(by_key.key_scopes) == {"ingest:write", "routing:read", "handoff:write"}
    assert _view(body, "no-such-agent") is None


def test_agent_view_freshness_boundaries() -> None:
    view = _view(_body(), None)
    issued = view.issued_at.timestamp()
    assert view.freshness_at(issued + view.ttl_s) == "fresh"
    assert view.freshness_at(issued + view.ttl_s + 1) == "stale"
    assert view.freshness_at(issued + view.ttl_s + view.grace_s + 1) == "expired"
    assert view.freshness_at(issued + 901) == "unavailable"


@pytest.mark.parametrize("scope", ["tenant", "agent"])
def test_kill_switch_scopes_kill_the_agent(scope: str) -> None:
    body = _body()
    tenant = next(iter(body["tenants"].values()))
    agent_id = "0192767f-0000-7000-8000-00000000c011"
    tenant["kill_switches"] = [
        {
            "kill_switch_id": "0192f0d1-0000-7000-8000-000000000001",
            "scope_kind": scope,
            "scope_id": agent_id if scope == "agent" else None,
            "pulled_at": body["issued_at"],
        }
    ]
    view = _view(body, agent_id)
    assert view.state == "killed" and view.kill_reason


def test_provider_kill_switch_does_not_kill_the_agent() -> None:
    body = _body()
    tenant = next(iter(body["tenants"].values()))
    tenant["kill_switches"] = [
        {
            "kill_switch_id": "0192f0d1-0000-7000-8000-000000000001",
            "scope_kind": "provider",
            "scope_id": next(iter(tenant["providers"])),
            "pulled_at": body["issued_at"],
        }
    ]
    assert _view(body, None).state != "killed"
