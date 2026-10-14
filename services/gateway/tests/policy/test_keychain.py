"""Signed key-set rotation chain (security M6) over ``key_set_vectors.json`` and the
store/fetcher integration: pin one key, follow rotations, verify snapshots across the overlap."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_gateway.policy.keychain import KeyChain, KeySetRejected
from sibyl_gateway.policy.verify import KeySetError
from sibyl_schemas.canonical import canonicalize

from ..support import b64u, iso
from .vectors import key_set_vectors

CAUSES = {
    "malformed",
    "unknown_signer",
    "signer_expired",
    "bad_signature",
    "non_monotonic",
    "chain_broken",
}


def _now(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def _step_raw(step: dict[str, Any]) -> str:
    return step["raw"] if "raw" in step else json.dumps(step["document"])


def test_chain_vectors_hit_their_causes() -> None:
    vectors = key_set_vectors()
    seen: set[str] = set()
    for case in vectors["cases"]:
        chain = KeyChain.from_pin_json(json.dumps(vectors["pinned"]))
        for step in case["steps"]:
            try:
                chain.accept(_step_raw(step), now=_now(case["now"]), persist=False)
                verdict = "ok"
            except KeySetRejected as exc:
                verdict = exc.cause
            assert verdict == step["expected"], case["name"]
            seen.add(verdict)
    assert seen == CAUSES | {"ok"}


def test_rotation_moves_snapshot_trust_and_keeps_the_retiring_key_in_the_overlap() -> None:
    vectors = key_set_vectors()
    case = next(c for c in vectors["cases"] if c["name"] == "valid_rotation")
    chain = KeyChain.from_pin_json(json.dumps(vectors["pinned"]))
    now = _now(case["now"])
    chain.accept(_step_raw(case["steps"][0]), now=now, persist=False)
    assert chain.verification_keys(now).kids == {"snap-2026-10-v1"}
    chain.accept(_step_raw(case["steps"][1]), now=now, persist=False)
    assert chain.verification_keys(now).kids == {"snap-2026-11-v1", "snap-2026-10-v1"}
    assert chain.verification_keys(datetime(2027, 2, 1, tzinfo=UTC)).kids == {"snap-2026-11-v1"}
    chain.accept(_step_raw(case["steps"][2]), now=now, persist=False)
    assert chain.verification_keys(now).kids == {"snap-2026-11-v1"} and chain.sequence == 3


class _Key:
    def __init__(self, kid: str) -> None:
        self.kid = kid
        self.private = Ed25519PrivateKey.generate()
        self.public = b64u(self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def entry(self, status: str | None = "active") -> dict[str, str]:
        out = {"kid": self.kid, "alg": "Ed25519", "public_key": self.public}
        if status:
            out["status"] = status
        return out

    def sign_set(
        self,
        sequence: int,
        keys: list[dict[str, str]],
        nxt: dict[str, str] | None,
        issued: datetime,
    ) -> str:
        body = {"sequence": sequence, "issued_at": iso(issued), "keys": keys, "next_key": nxt}
        sig = b64u(self.private.sign(canonicalize(body)))
        return json.dumps({"kid": self.kid, "alg": "Ed25519", "sig": sig, "body": body})


def test_persisted_chain_is_replayed_from_the_pin(tmp_path: Path) -> None:
    k1, k2 = _Key("k1"), _Key("k2")
    t0 = datetime(2026, 10, 1, tzinfo=UTC)
    chain = KeyChain.from_pin_json(json.dumps(k1.entry()), state_dir=tmp_path)
    chain.accept(k1.sign_set(1, [k1.entry()], k2.entry(None), t0), now=t0)
    chain.accept(
        k1.sign_set(2, [k2.entry(), k1.entry("retiring")], None, t0 + timedelta(days=1)),
        now=t0 + timedelta(days=1),
    )
    assert (tmp_path / "keysets.json").stat().st_mode & 0o077 == 0
    again = KeyChain.from_pin_json(json.dumps(k1.entry()), state_dir=tmp_path)
    assert again.replay() == 2 and again.sequence == 2
    other_pin = KeyChain.from_pin_json(json.dumps(_Key("k1").entry()), state_dir=tmp_path)
    assert other_pin.replay() == 0 and other_pin.sequence == 0  # trust never read from disk


@pytest.mark.parametrize("pin", ["{}", "[]", '{"kid":"k","alg":"Ed25519","public_key":"AA"}'])
def test_bad_pins_fail_fast(pin: str) -> None:
    with pytest.raises(KeySetError):
        KeyChain.from_pin_json(pin)
