"""Snapshot verification keys: pin the first key, follow the signed rotation chain (R33, M6).

Every check, its order (`KeySetRejectCause`: malformed, unknown_signer, signer_expired,
bad_signature, non_monotonic, sequence_gap, chain_broken), the catch-up staging and the
snapshot key selection (every key the accepted set lists, active or retiring, until
`not_after`, B10) are the shared follower's in `sibyl_schemas.keyset` (B33), the one the
gateway uses too. This module adds only what is the SDK's own: the `public_key=` pin forms
(including the static wildcard pin), the JSON state the client persists, and the raw-key
lookup snapshot verification needs.

Catch-up (B10): `stage()` verifies a `?since=<sequence>` delivery in order and `commit()`
adopts it whole; `_keysync.follow_chain` drives it.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, Self

from sibyl_schemas.keyset import (
    ChainFollower,
    ChainKey,
    ChainStage,
    ChainState,
    KeySetRejected,
    verify_ed25519,
)
from sibyl_schemas.models import SigningKey, SigningKeySet

__all__ = [
    "WILDCARD_KID",
    "ChainStage",
    "KeySetRejected",
    "KeySetVerifier",
    "parse_pin",
    "trust_on_first_use",
    "verify_ed25519",
]

WILDCARD_KID = "*"


def _bare_key(text: str) -> str:
    """A bare `public_key=` value (padding and the standard alphabet tolerated, as before) as
    canonical unpadded base64url."""
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise ValueError("expected base64url") from None
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def parse_pin(text: str) -> dict[str, Any]:
    """`public_key=` forms: a SigningKey JSON object, `kid:base64url`, or bare base64url.

    A bare key pins statically for any kid (no rotation chain is followed)."""
    text = text.strip()
    if text.startswith("{"):
        pinned = dict(json.loads(text))
    elif ":" in text:
        kid, key = text.split(":", 1)
        pinned = {"kid": kid, "alg": "Ed25519", "public_key": key}
    else:
        pinned = {"kid": WILDCARD_KID, "alg": "Ed25519", "public_key": _bare_key(text)}
    if pinned["kid"] != WILDCARD_KID:
        SigningKey.model_validate(pinned)
    ChainKey.from_entry(pinned)  # 32-byte Ed25519 key, strict base64url
    return pinned


def _keys(entries: Any) -> dict[str, ChainKey]:
    return {key.kid: key for key in (ChainKey.from_entry(e) for e in entries)}


class KeySetVerifier:
    """The SDK's view of a `sibyl_schemas.keyset.ChainFollower` (not thread-safe)."""

    def __init__(self, pinned: Mapping[str, Any]) -> None:
        self._follower = ChainFollower(ChainKey.from_entry(pinned))

    @classmethod
    def _of(cls, follower: ChainFollower) -> Self:
        verifier = cls.__new__(cls)
        verifier._follower = follower
        return verifier

    @property
    def follower(self) -> ChainFollower:
        return self._follower

    # -------------------------------------------------------------- persistence

    def state(self) -> dict[str, Any]:
        state = self._follower.chain_state
        return {
            "trusted": [dict(k.entry) for k in state.trusted.values()],
            "listed": [dict(k.entry) for k in state.listed.values()],
            "announced": dict(state.announced.entry) if state.announced else None,
            "sequence": state.sequence,
        }

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> KeySetVerifier:
        """Raises `ValueError`, `KeyError`, `IndexError` or `TypeError` on unusable state."""
        trusted = _keys(state["trusted"])
        if not trusted:
            raise IndexError("no trusted key in the stored verifier state")
        pinned = next(iter(trusted.values()))
        announced = state.get("announced")
        restored = ChainState(
            trusted=trusted,
            listed=_keys(state.get("listed") or state["trusted"]),
            announced=ChainKey.from_entry(announced) if announced else None,
            sequence=int(state["sequence"]),
        )
        return cls._of(ChainFollower.from_state(pinned, restored))

    # -------------------------------------------------------------- queries

    @property
    def sequence(self) -> int:
        return self._follower.sequence

    @property
    def is_static(self) -> bool:
        return WILDCARD_KID in self._follower.trusted_kids()

    def trusted_kids(self) -> set[str]:
        """Kids that may sign the next key set (the active keys of the accepted set)."""
        return self._follower.trusted_kids()

    def public_key(self, kid: str, *, now: datetime) -> bytes | None:
        """Raw public key for a snapshot check: any key the accepted set lists, `active` or
        `retiring`, that is not past its `not_after` (B10 rotation overlap)."""
        listed = self._follower.chain_state.listed
        key = listed.get(kid) or listed.get(WILDCARD_KID)
        if key is None or not key.usable(now):
            return None
        return key.public_key

    # -------------------------------------------------------------- rotation

    def accept(self, raw: str | bytes, *, now: datetime) -> SigningKeySet:
        return self._follower.accept(raw, now=now)

    def stage(self) -> ChainStage:
        """Start verifying a `?since=<sequence>` delivery on top of the current state."""
        return self._follower.stage()

    def commit(self, stage: ChainStage) -> int:
        """Adopt a fully verified stage (refused if the verifier moved since it started)."""
        return self._follower.commit(stage)

    def accept_chain(self, documents: Sequence[str | bytes], *, now: datetime) -> int:
        """Verify `documents` in order from the current state, all or nothing (B10)."""
        return self._follower.accept_chain(documents, now=now)


def trust_on_first_use(raw: bytes, *, now: datetime) -> KeySetVerifier:
    """No pin configured: pin the signer of the first key set fetched over TLS (R33), then
    accept that set through the normal chain checks."""
    return KeySetVerifier._of(ChainFollower.trust_on_first_use(raw, now=now))
