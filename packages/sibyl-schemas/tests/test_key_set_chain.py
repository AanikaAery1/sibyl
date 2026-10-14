"""Signed key-set rotation chain (security M6): schema, model and Ed25519 vectors.

The gateway and SDK pin the first signing key and follow rotations: each key set is signed
by an active key of the previously accepted set, and an active key must already be trusted
or have been announced as the previous set's `next_key`. The generator below is
deterministic (Ed25519 signatures are), so the committed vectors are regenerated and diffed.
Rewrite them with `uv run python packages/sibyl-schemas/tests/test_key_set_chain.py`.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.models import SigningKeySet
from sibyl_schemas.values import KeySetRejectCause

SEED_INPUT = "sibyl-test-vector-snapshot-key-{n} (TEST ONLY, never deploy)"
KIDS = {1: "snap-2026-10-v1", 2: "snap-2026-11-v1", 3: "snap-2026-12-v1", 4: "snap-rogue"}
K1_NOT_AFTER = "2027-01-01T00:00:00.000Z"
ISSUED_AT = {n: f"2026-{9 + n}-01T00:00:00.000Z" for n in (1, 2, 3)}
OUT = Path(__file__).resolve().parents[1] / "fixtures" / "snapshot" / "key_set_vectors.json"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_key(n: int) -> Ed25519PrivateKey:
    seed = hashlib.sha256(SEED_INPUT.format(n=n).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key(n: int) -> str:
    raw = (
        private_key(n)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    return _b64u(raw)


def key(n: int, status: str | None = None, not_after: str | None = None) -> dict[str, Any]:
    doc: dict[str, Any] = {"kid": KIDS[n], "alg": "Ed25519", "public_key": public_key(n)}
    if status is not None:
        doc["status"] = status
    if not_after is not None:
        doc["not_after"] = not_after
    return doc


def sign(signer: int, body: dict[str, Any]) -> dict[str, Any]:
    sig = private_key(signer).sign(canonicalize(body))
    return {"kid": KIDS[signer], "alg": "Ed25519", "sig": _b64u(sig), "body": body}


def body(
    sequence: int, keys: list[dict[str, Any]], next_key: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "issued_at": ISSUED_AT[sequence],
        "keys": keys,
        "next_key": next_key,
    }


def genesis() -> dict[str, Any]:
    """Sequence 1: self-signed by the pinned key K1, announces K2."""
    return sign(1, body(1, [key(1, "active", K1_NOT_AFTER)], key(2)))


def rotation() -> dict[str, Any]:
    """Sequence 2: signed by the previous active key K1; K2 (announced) becomes active."""
    return sign(1, body(2, [key(2, "active"), key(1, "retiring", K1_NOT_AFTER)], key(3)))


def after_rotation() -> dict[str, Any]:
    """Sequence 3: signed by K2, the active key since sequence 2."""
    return sign(2, body(3, [key(2, "active")], key(3)))


def build() -> dict[str, Any]:
    ks1, ks2, ks3 = genesis(), rotation(), after_rotation()
    broken = sign(1, body(2, [key(4, "active"), key(1, "retiring", K1_NOT_AFTER)], key(3)))
    swapped_next = json.loads(json.dumps(ks1))
    swapped_next["body"]["next_key"] = key(4)  # attacker-chosen successor, not re-signed
    retired_signer = sign(1, body(3, [key(1, "active", K1_NOT_AFTER)], key(3)))
    duplicate_body = (
        '{"kid":"snap-2026-10-v1","alg":"Ed25519","sig":"'
        + ks2["sig"]
        + '","body":'
        + canonicalize(ks2["body"]).decode()
        + ',"body":'
        + canonicalize(broken["body"]).decode()
        + "}"
    )
    legacy = {"keys": [key(1, "active")], "next_key": key(2)}
    skipped = sign(1, body(3, [key(1, "active", K1_NOT_AFTER)], key(2)))  # sequence 2 missing

    def step(expected: str, doc: Any = None, raw: str | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {"expected": expected}
        if raw is not None:
            out["raw"] = raw
        else:
            out["document"] = doc
        return out

    return {
        "description": (
            "Signed key-set rotation chain (sibyl.policy_snapshot/1 $defs/key_set). "
            "TEST-ONLY keys derived from public seeds; never deploy. A verifier pins the "
            "first key, then accepts a key set only if it parses strictly, is signed by a "
            "key the previous accepted set listed as active (not past not_after), carries a "
            "valid Ed25519 signature over JCS(body), has a higher sequence, and every active "
            "key it lists was already trusted or was the previous set's next_key. Check order: "
            "malformed, unknown_signer, signer_expired, bad_signature, non_monotonic, "
            "chain_broken. since_cases are ?since=<sequence> deliveries verified in order on top "
            "of the held sets: a sequence that is not exactly the held one + 1 is sequence_gap "
            "(checked after non_monotonic, before chain_broken)."
        ),
        "test_signing_seed_sha256_input": SEED_INPUT,
        "pinned": key(1, "active", K1_NOT_AFTER),
        "cases": [
            {
                "name": "valid_rotation",
                "now": "2026-12-01T00:00:10.000Z",
                "steps": [step("ok", ks1), step("ok", ks2), step("ok", ks3)],
            },
            {
                "name": "broken_chain",
                "now": "2026-11-01T00:00:10.000Z",
                "steps": [step("ok", ks1), step("chain_broken", broken)],
            },
            {
                "name": "unsigned_next_key",
                "now": "2026-10-01T00:00:10.000Z",
                "steps": [step("bad_signature", swapped_next)],
            },
            {
                "name": "retired_signer",
                "now": "2026-12-01T00:00:10.000Z",
                "steps": [step("ok", ks1), step("ok", ks2), step("unknown_signer", retired_signer)],
            },
            {
                "name": "replayed_sequence",
                "now": "2026-10-01T00:00:10.000Z",
                "steps": [step("ok", ks1), step("non_monotonic", ks1)],
            },
            {
                "name": "signer_expired",
                "now": "2027-01-02T00:00:00.000Z",
                "steps": [step("signer_expired", ks1)],
            },
            {
                "name": "unsigned_legacy_shape",
                "now": "2026-10-01T00:00:10.000Z",
                "steps": [step("malformed", legacy)],
            },
            {
                "name": "duplicate_body",
                "now": "2026-11-01T00:00:10.000Z",
                "steps": [step("ok", ks1), step("malformed", raw=duplicate_body)],
            },
        ],
        "since_cases": [
            {
                "name": "contiguous_catch_up",
                "now": "2026-12-01T00:00:10.000Z",
                "held": [ks1],
                "steps": [step("ok", ks2), step("ok", ks3)],
            },
            {
                "name": "sequence_gap",
                "now": "2026-11-01T00:00:10.000Z",
                "held": [ks1],
                "steps": [step("sequence_gap", skipped)],
            },
        ],
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


# --- reference chain verifier (test-only; pins the order the gateway and SDK implement) --


def _ts(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class ChainVerifier:
    def __init__(self, pinned: dict[str, Any]) -> None:
        self.trusted: dict[str, dict[str, Any]] = {pinned["kid"]: pinned}
        self.announced: dict[str, Any] | None = None
        self.sequence = 0

    def accept(self, step: dict[str, Any], now: str, *, contiguous: bool = False) -> str:
        try:
            if "raw" in step:
                document = parse_json_strict(step["raw"])
            else:
                document = parse_json_strict(json.dumps(step["document"]))
            SigningKeySet.model_validate(document)
        except (CanonicalizationError, ValueError):
            return KeySetRejectCause.MALFORMED.value
        signer = self.trusted.get(document["kid"])
        if signer is None:
            return KeySetRejectCause.UNKNOWN_SIGNER.value
        if "not_after" in signer and _ts(signer["not_after"]) < _ts(now):
            return KeySetRejectCause.SIGNER_EXPIRED.value
        public = Ed25519PublicKey.from_public_bytes(_b64d(signer["public_key"]))
        try:
            public.verify(_b64d(document["sig"]), canonicalize(document["body"]))
        except InvalidSignature:
            return KeySetRejectCause.BAD_SIGNATURE.value
        body = document["body"]
        if body["sequence"] <= self.sequence:
            return KeySetRejectCause.NON_MONOTONIC.value
        if contiguous and body["sequence"] != self.sequence + 1:
            return KeySetRejectCause.SEQUENCE_GAP.value
        active = [k for k in body["keys"] if k.get("status", "active") == "active"]
        for candidate in active:
            known = self.trusted.get(candidate["kid"])
            announced = self.announced is not None and self.announced["kid"] == candidate["kid"]
            pinned_same = known is not None and known["public_key"] == candidate["public_key"]
            if not pinned_same and not (
                announced and self.announced["public_key"] == candidate["public_key"]
            ):
                return KeySetRejectCause.CHAIN_BROKEN.value
        self.trusted = {k["kid"]: k for k in active}
        self.announced = body["next_key"]
        self.sequence = body["sequence"]
        return "ok"


VECTORS: dict[str, Any] = (
    load_fixture("snapshot", "key_set_vectors.json") if OUT.exists() else {"cases": []}
)
"""Empty only while bootstrapping; `test_committed_vectors_are_reproducible...` then fails."""


def test_committed_vectors_are_reproducible_from_the_test_seeds() -> None:
    assert OUT.read_text("utf-8") == render()


def test_vectors_cover_rotation_and_every_reject_cause() -> None:
    cases = [*VECTORS["cases"], *VECTORS["since_cases"]]
    expected = {s["expected"] for case in cases for s in case["steps"]}
    assert expected == {"ok"} | {cause.value for cause in KeySetRejectCause}
    names = {case["name"] for case in VECTORS["cases"]}
    assert {"valid_rotation", "broken_chain", "unsigned_next_key"} <= names


@pytest.mark.parametrize("case", VECTORS["cases"], ids=[c["name"] for c in VECTORS["cases"]])
def test_chain_vector_hits_its_cause(case: dict[str, Any]) -> None:
    verifier = ChainVerifier(VECTORS["pinned"])
    verdicts = [verifier.accept(step, case["now"]) for step in case["steps"]]
    assert verdicts == [step["expected"] for step in case["steps"]]


@pytest.mark.parametrize(
    "case", VECTORS.get("since_cases", []), ids=[c["name"] for c in VECTORS.get("since_cases", [])]
)
def test_since_vector_hits_its_cause(case: dict[str, Any]) -> None:
    verifier = ChainVerifier(VECTORS["pinned"])
    for held in case["held"]:
        assert verifier.accept({"document": held}, case["now"]) == "ok"
    verdicts = [verifier.accept(s, case["now"], contiguous=True) for s in case["steps"]]
    assert verdicts == [step["expected"] for step in case["steps"]]


def test_valid_rotation_moves_trust_to_the_announced_key() -> None:
    case = next(c for c in VECTORS["cases"] if c["name"] == "valid_rotation")
    verifier = ChainVerifier(VECTORS["pinned"])
    for step in case["steps"][:2]:
        assert verifier.accept(step, case["now"]) == "ok"
    assert set(verifier.trusted) == {KIDS[2]}
    assert verifier.announced is not None and verifier.announced["kid"] == KIDS[3]


def test_signed_documents_are_schema_valid_and_model_valid() -> None:
    for case in VECTORS["cases"]:
        for step in case["steps"]:
            if "document" not in step:
                continue
            valid = sj.is_valid(
                "sibyl.policy_snapshot/1", step["document"], pointer="/$defs/key_set"
            )
            assert valid is (step["expected"] != "malformed"), case["name"]


def test_key_set_next_key_is_inside_the_signed_body() -> None:
    schema = sj.load_schema("sibyl.policy_snapshot/1")["$defs"]
    assert set(schema["key_set"]["required"]) == {"kid", "alg", "sig", "body"}
    assert schema["key_set"]["additionalProperties"] is False
    assert "next_key" in schema["key_set_body"]["required"]
    assert "next_key" not in schema["key_set"]["properties"]


def test_key_set_model_parses_json_strictly() -> None:
    raw = next(s["raw"] for c in VECTORS["cases"] for s in c["steps"] if "raw" in s)
    with pytest.raises(ValueError, match="duplicate member name"):
        SigningKeySet.model_validate_json(raw)
    genesis_doc = VECTORS["cases"][0]["steps"][0]["document"]
    assert SigningKeySet.model_validate_json(json.dumps(genesis_doc)).body.sequence == 1


if __name__ == "__main__":
    OUT.write_text(render(), encoding="utf-8")
