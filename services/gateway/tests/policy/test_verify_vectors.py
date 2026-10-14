"""Golden tests: the gateway verifier over ``sibyl-schemas`` ``fixtures/snapshot/vectors.json``.

Envelope cases are sent the way the api sends them (detached: the raw body bytes are
``canonicalize(body)``, kid and signature in headers); the verifier never re-canonicalises
(B4). Raw cases (1.1) are envelope texts and go through ``verify_envelope``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from sibyl_gateway.policy.verify import (
    MALFORMED,
    KeySetError,
    PinnedKeySet,
    SnapshotRejected,
    VerifiedSnapshot,
    verify_envelope,
    verify_snapshot,
)
from sibyl_schemas.canonical import canonical_sha256, canonicalize
from sibyl_schemas.values import SnapshotRejectCause

from ..support import TestSigner, body
from .vectors import snapshot_vectors, verification_keys

VECTORS = snapshot_vectors()
CASES = {case["name"]: case for case in VECTORS["cases"]}
KEYS = verification_keys(VECTORS)
_CASE = object()


def _now(case: dict[str, Any]) -> datetime:
    return datetime.fromisoformat(case["now"].replace("Z", "+00:00"))


def _run(case: dict[str, Any], *, raw: bytes | None = None, held: Any = _CASE) -> VerifiedSnapshot:
    held_version = case["held_version"] if held is _CASE else held
    if "raw" in case and raw is None:
        return verify_envelope(case["raw"], keys=KEYS, held_version=held_version, now=_now(case))
    envelope = case["envelope"]
    return verify_snapshot(
        canonicalize(envelope["body"]) if raw is None else raw,
        kid=envelope["kid"],
        signature=envelope["sig"],
        keys=KEYS,
        held_version=held_version,
        now=_now(case),
    )


def test_vectors_cover_every_cause_the_gateway_knows() -> None:
    expected = {c["expected"] for c in VECTORS["cases"]}
    known = {c.value for c in SnapshotRejectCause} | {MALFORMED, "ok"}
    assert expected <= known
    assert {
        "ok",
        "unknown_kid",
        "bad_signature",
        "non_monotonic",
        "future_issued",
        "bad_ttl",
    } <= expected


@pytest.mark.parametrize("name", list(CASES))
def test_vector_verdict_matches(name: str) -> None:
    case = CASES[name]
    if "envelope" in case and "body_jcs_sha256" in case:
        assert canonical_sha256(case["envelope"]["body"]) == case["body_jcs_sha256"]
    if case["expected"] == "ok":
        snap = _run(case)
        assert snap.version == case["envelope"]["body"]["version"]
        assert snap.kid == "snap-2026-10-v1"
        assert (snap.ttl_s, snap.grace_s) == (60, 300)
        assert list(snap.tenants) == ["0192767f-0000-7000-8000-00000000a001"]
        return
    with pytest.raises(SnapshotRejected) as err:
        _run(case)
    assert err.value.cause == case["expected"]


def test_signature_is_over_raw_bytes_not_a_reserialisation() -> None:
    case = CASES["valid"]
    pretty = json.dumps(case["envelope"]["body"], indent=2).encode()
    with pytest.raises(SnapshotRejected) as err:
        _run(case, raw=pretty)
    assert err.value.cause == SnapshotRejectCause.BAD_SIGNATURE.value


def test_malformed_comes_before_any_signature_work() -> None:
    case = CASES["unknown_kid"]
    for raw in (b"not even json", b'{"a":1,"a":2}'):
        with pytest.raises(SnapshotRejected) as err:
            _run(case, raw=raw, held=10**12)
        assert err.value.cause == MALFORMED


def test_order_unknown_kid_before_signature_and_monotonic() -> None:
    with pytest.raises(SnapshotRejected) as err:
        _run(CASES["unknown_kid"], held=10**12)
    assert err.value.cause == SnapshotRejectCause.UNKNOWN_KID.value


def test_order_bad_signature_before_monotonic() -> None:
    with pytest.raises(SnapshotRejected) as err:
        _run(CASES["bad_signature_unkill"], held=10**12)
    assert err.value.cause == SnapshotRejectCause.BAD_SIGNATURE.value


def test_first_load_has_no_monotonic_floor() -> None:
    assert _run(CASES["non_monotonic_replay"], held=None).version == 4182


@pytest.mark.parametrize("sig", ["!!" + "A" * 84, "A" * 85 + "=", "A" * 87, "A+" + "A" * 84])
def test_non_canonical_signature_encodings_are_bad_signature(sig: str) -> None:
    case = CASES["valid"]
    with pytest.raises(SnapshotRejected) as err:
        verify_snapshot(
            canonicalize(case["envelope"]["body"]),
            kid="snap-2026-10-v1",
            signature=sig,
            keys=KEYS,
            held_version=None,
            now=_now(case),
        )
    assert err.value.cause == SnapshotRejectCause.BAD_SIGNATURE.value


def test_signed_but_not_a_snapshot_is_malformed(signer: TestSigner) -> None:
    keys = PinnedKeySet.from_document(signer.key_set())
    raw = b'{"schema":"other"}'
    with pytest.raises(SnapshotRejected) as err:
        verify_snapshot(
            raw,
            kid=signer.kid,
            signature=signer.sign(raw),
            keys=keys,
            held_version=None,
            now=datetime.now(UTC),
        )
    assert err.value.cause == MALFORMED


def test_envelope_form_roundtrip_and_shape(signer: TestSigner) -> None:
    keys = PinnedKeySet.from_document(signer.key_set())
    raw, kid, sig = signer.deliver(body(3))
    envelope = json.dumps({"kid": kid, "alg": "Ed25519", "sig": sig, "body": json.loads(raw)})
    now = datetime.now(UTC)
    assert verify_envelope(envelope, keys=keys, held_version=None, now=now).version == 3
    for bad in ('{"kid":"x"}', envelope.replace('"alg": "Ed25519"', '"alg": "RS256"'), "[]"):
        with pytest.raises(SnapshotRejected) as err:
            verify_envelope(bad, keys=keys, held_version=None, now=now)
        assert err.value.cause == MALFORMED


def test_static_key_documents_accept_both_published_shapes(signer: TestSigner) -> None:
    jwks = {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": signer.public_key,
                "kid": signer.kid,
                "sibyl_purpose": "snapshot",
                "sibyl_state": "active",
            },
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": TestSigner().public_key,
                "kid": "a1",
                "sibyl_purpose": "audit_anchor",
            },
        ],
        "next_key": None,
    }
    assert PinnedKeySet.from_document(jwks).kids == {signer.kid}
    assert PinnedKeySet.from_document(signer.key_set()).kids == {signer.kid}


@pytest.mark.parametrize(
    "document",
    [
        {"keys": []},
        {"keys": [{"kid": "k", "public_key": "short"}]},
        {"keys": [{"kid": "k", "public_key": "A" * 43, "status": "compromised"}]},
        {"keys": [{"public_key": "A" * 43}]},
        {"keys": [{"kid": "k", "x": "A" * 43, "crv": "X25519"}]},
    ],
)
def test_unusable_key_sets_fail_fast(document: dict[str, Any]) -> None:
    with pytest.raises(KeySetError):
        PinnedKeySet.from_document(document)
