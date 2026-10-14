"""Signed key sets (security M6, schema 1.1.0 ``$defs/key_set``): the kernel's builder and
verifier round-trip ``packages/sibyl-schemas/fixtures/snapshot/key_set_vectors.json``."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from sibyl_control.core.crypto.signing import (
    Ed25519Signer,
    KeySetRejected,
    KeySetVerifier,
    b64url,
    key_set_body,
    sign_key_set,
    signing_key,
)
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.values import KeySetRejectCause

VECTORS: dict[str, Any] = load_fixture("snapshot", "key_set_vectors.json")
KIDS = {1: "snap-2026-10-v1", 2: "snap-2026-11-v1", 3: "snap-2026-12-v1"}
K1_NOT_AFTER = datetime(2027, 1, 1, tzinfo=UTC)


def signer(n: int) -> Ed25519Signer:
    seed = VECTORS["test_signing_seed_sha256_input"].split(" (")[0].format(n=n)
    seed += " (TEST ONLY, never deploy)"
    return Ed25519Signer.from_seed(KIDS[n], hashlib.sha256(seed.encode()).digest())


def wire_key(n: int, status: str | None = None, not_after: datetime | None = None) -> dict:
    return signing_key(KIDS[n], signer(n).public_key_raw, status=status, not_after=not_after)


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _case(name: str) -> dict[str, Any]:
    return next(c for c in VECTORS["cases"] if c["name"] == name)


def test_the_test_seed_matches_the_pinned_key() -> None:
    assert b64url(signer(1).public_key_raw) == VECTORS["pinned"]["public_key"]


def test_the_builder_reproduces_the_valid_rotation_byte_for_byte() -> None:
    issued = {n: datetime(2026, 9 + n, 1, tzinfo=UTC) for n in (1, 2, 3)}
    built = [
        sign_key_set(
            signer(1),
            key_set_body(1, issued[1], [wire_key(1, "active", K1_NOT_AFTER)], wire_key(2)),
        ),
        sign_key_set(
            signer(1),
            key_set_body(
                2,
                issued[2],
                [wire_key(2, "active"), wire_key(1, "retiring", K1_NOT_AFTER)],
                wire_key(3),
            ),
        ),
        sign_key_set(signer(2), key_set_body(3, issued[3], [wire_key(2, "active")], wire_key(3))),
    ]
    expected = [step["document"] for step in _case("valid_rotation")["steps"]]
    assert built == expected


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_the_verifier_reproduces_every_vector(case: dict[str, Any]) -> None:
    verifier = KeySetVerifier(VECTORS["pinned"])
    now = _parse(case["now"])
    for index, step in enumerate(case["steps"]):
        raw = step.get("raw") or json.dumps(step["document"])
        try:
            accepted = verifier.accept(raw, now=now)
            outcome = "ok"
            assert accepted.body.sequence == verifier.sequence
        except KeySetRejected as rejected:
            outcome = rejected.cause.value
        assert outcome == step["expected"], (case["name"], index)


def test_a_rejected_set_leaves_the_trust_state_unchanged() -> None:
    verifier = KeySetVerifier(VECTORS["pinned"])
    steps = _case("broken_chain")["steps"]
    now = _parse(_case("broken_chain")["now"])
    verifier.accept(json.dumps(steps[0]["document"]), now=now)
    before = (verifier.sequence, verifier.trusted_kids(), verifier.announced_kid)
    with pytest.raises(KeySetRejected) as err:
        verifier.accept(json.dumps(steps[1]["document"]), now=now)
    assert err.value.cause is KeySetRejectCause.CHAIN_BROKEN
    assert (verifier.sequence, verifier.trusted_kids(), verifier.announced_kid) == before


def test_trusted_public_keys_follow_the_rotation_and_honour_not_after() -> None:
    verifier = KeySetVerifier(VECTORS["pinned"])
    case = _case("valid_rotation")
    now = _parse(case["now"])
    for step in case["steps"]:
        verifier.accept(json.dumps(step["document"]), now=now)
    assert verifier.trusted_kids() == {KIDS[2]}
    assert verifier.public_key(KIDS[2], now=now) == signer(2).public_key_raw
    assert verifier.public_key(KIDS[1], now=now) is None

    pinned_only = KeySetVerifier(VECTORS["pinned"])
    assert pinned_only.public_key(KIDS[1], now=now) == signer(1).public_key_raw
    assert pinned_only.public_key(KIDS[1], now=datetime(2027, 1, 2, tzinfo=UTC)) is None


def test_the_builder_refuses_bodies_the_schema_refuses() -> None:
    with pytest.raises(ValueError):
        key_set_body(0, datetime(2026, 1, 1, tzinfo=UTC), [wire_key(1, "active")], None)
    with pytest.raises(ValueError):
        key_set_body(1, datetime(2026, 1, 1, tzinfo=UTC), [], None)
    with pytest.raises(ValueError, match="timezone"):
        key_set_body(1, datetime(2026, 1, 1), [wire_key(1, "active")], None)
    with pytest.raises(ValueError):
        signing_key("bad kid!", signer(1).public_key_raw)


def test_a_signer_cannot_sign_with_a_mismatched_kid() -> None:
    body = key_set_body(1, datetime(2026, 1, 1, tzinfo=UTC), [wire_key(1, "active")], None)
    doc = sign_key_set(signer(2), body)
    verifier = KeySetVerifier(VECTORS["pinned"])
    with pytest.raises(KeySetRejected) as err:
        verifier.accept(json.dumps(doc), now=datetime(2026, 10, 1, tzinfo=UTC))
    assert err.value.cause is KeySetRejectCause.UNKNOWN_SIGNER


def test_the_legacy_unsigned_shape_is_not_built_anymore() -> None:
    from sibyl_control.core.crypto import signing

    assert not hasattr(signing, "keyset")


def test_snapshot_trust_covers_retiring_keys_until_not_after() -> None:
    """B10: snapshots verify under every key of the accepted set that is ``active`` or
    ``retiring`` and not past ``not_after`` (schemas reference, gateway and SDK behaviour), so a
    snapshot signed by the outgoing key during the rotation overlap still verifies. Signing the
    next key set stays restricted to the active keys."""
    case = _case("valid_rotation")
    verifier = KeySetVerifier(VECTORS["pinned"])
    now = _parse(case["now"])
    for step in case["steps"][:2]:  # genesis, then the rotation listing K1 as retiring
        verifier.accept(json.dumps(step["document"]), now=now)
    assert verifier.trusted_kids() == {KIDS[2]}  # signers of the next set
    assert verifier.public_key(KIDS[2], now=now) == signer(2).public_key_raw
    assert verifier.public_key(KIDS[1], now=now) == signer(1).public_key_raw
    assert verifier.public_key(KIDS[1], now=K1_NOT_AFTER) == signer(1).public_key_raw
    assert verifier.public_key(KIDS[1], now=datetime(2027, 1, 1, 0, 0, 1, tzinfo=UTC)) is None
    assert verifier.snapshot_kids(now=now) == {KIDS[1], KIDS[2]}
    verifier.accept(json.dumps(case["steps"][2]["document"]), now=now)  # K1 no longer listed
    assert verifier.public_key(KIDS[1], now=now) is None
    assert verifier.snapshot_kids(now=now) == {KIDS[2]}
