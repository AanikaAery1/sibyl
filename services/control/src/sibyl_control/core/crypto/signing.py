"""Ed25519 signing over RFC 8785 canonical bytes (policy snapshots ADR-9, audit anchors ADR-12).

The signature is detached: ``X-Sibyl-Snapshot-Kid`` + ``X-Sibyl-Snapshot-Signature``
(base64url, unpadded) over ``canonicalize(body)``. Private keys never live in Postgres
(``signing_key.private_key_ref`` points outside).

Public keys are published at ``/api/v1/policy/keys`` and ``/.well-known/sibyl-keys.json`` as a
**signed key set** (security M6, ``sibyl.policy_snapshot/1`` ``$defs/key_set``):
``{kid, alg, sig, body: {sequence, issued_at, keys, next_key}}``. Each set is signed over
JCS(body) by an active key of the previously accepted set, so the pre-published successor
(``next_key``, R33) is inside the signature. ``sign_key_set`` builds one; ``KeySetVerifier``
pins the first key and follows the rotation chain with the ``KeySetRejectCause`` check order.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_schemas.canonical import parse_json_strict
from sibyl_schemas.models import SigningKey, SigningKeySet, SigningKeySetBody
from sibyl_schemas.values import KeySetRejectCause, SignatureAlgorithm

from ..canonical import canonicalize

ALG = SignatureAlgorithm.ED25519.value


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}")  # 64 bytes, unpadded


def b64url_decode(value: str) -> bytes:
    """Strict unpadded base64url: no padding, no foreign characters, canonical length."""
    if not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise ValueError("not canonical unpadded base64url")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


@dataclass(frozen=True)
class SignedDocument:
    kid: str
    body: bytes = field(repr=False)
    signature: str


class Ed25519Signer:
    def __init__(self, kid: str, private_key: Ed25519PrivateKey) -> None:
        self.kid = kid
        self._key = private_key

    def __repr__(self) -> str:
        return f"Ed25519Signer(kid={self.kid!r})"

    @classmethod
    def from_seed(cls, kid: str, seed: bytes) -> Ed25519Signer:
        if len(seed) != 32:
            raise ValueError("Ed25519 seeds are 32 bytes")
        return cls(kid, Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def generate(cls, kid: str) -> Ed25519Signer:
        return cls(kid, Ed25519PrivateKey.generate())

    @property
    def public_key_raw(self) -> bytes:
        return self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign_bytes(self, body: bytes) -> str:
        return b64url(self._key.sign(body))

    def sign_document(self, document: Mapping[str, Any]) -> SignedDocument:
        body = canonicalize(document)
        return SignedDocument(self.kid, body, self.sign_bytes(body))


def verify_document(body: bytes, signature: str, public_key_raw: bytes) -> bool:
    """Verify an Ed25519 signature over the raw ``body`` bytes (security L6: the signature must
    be exactly 86 base64url characters, so no alternative encoding of it is accepted)."""
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key_raw).verify(b64url_decode(signature), body)
    except (InvalidSignature, ValueError, binascii.Error):
        return False
    return True


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("key-set timestamps must carry a timezone")
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def signing_key(
    kid: str,
    public_key_raw: bytes,
    *,
    status: str | None = None,
    not_after: datetime | None = None,
) -> dict[str, str]:
    """One ``$defs/signing_key`` entry (validated)."""
    out = {"kid": kid, "alg": ALG, "public_key": b64url(public_key_raw)}
    if status is not None:
        out["status"] = status
    if not_after is not None:
        out["not_after"] = _timestamp(not_after)
    SigningKey.model_validate(out)
    return out


def key_set_body(
    sequence: int,
    issued_at: datetime,
    keys: Sequence[Mapping[str, str]],
    next_key: Mapping[str, str] | None,
) -> dict[str, Any]:
    """The signed content of a key set (validated against ``SigningKeySetBody``)."""
    body = {
        "sequence": sequence,
        "issued_at": _timestamp(issued_at),
        "keys": [dict(k) for k in keys],
        "next_key": dict(next_key) if next_key is not None else None,
    }
    SigningKeySetBody.model_validate(body)
    return body


def sign_key_set(signer: Ed25519Signer, body: Mapping[str, Any]) -> dict[str, Any]:
    """``{kid, alg, sig, body}`` signed over JCS(body) by ``signer``, which must be an active key
    of the previously published set (the pinned first key for sequence 1)."""
    document = {
        "kid": signer.kid,
        "alg": ALG,
        "sig": signer.sign_bytes(canonicalize(body)),
        "body": dict(body),
    }
    SigningKeySet.model_validate(document)
    return document


class KeySetRejected(ValueError):
    """A key set the verifier refuses; ``cause`` is the first failing check."""

    def __init__(self, cause: KeySetRejectCause) -> None:
        super().__init__(f"key set rejected: {cause.value}")
        self.cause = cause


def _at(text: str) -> datetime:
    return datetime.fromisoformat(text)


def _usable(key: Mapping[str, Any], now: datetime) -> bool:
    return key.get("status", "active") in ("active", "retiring") and (
        "not_after" not in key or _at(key["not_after"]) >= now
    )


class KeySetVerifier:
    """Pins the first key and follows the signed rotation chain (security M6).

    Check order: malformed, unknown_signer, signer_expired, bad_signature, non_monotonic,
    chain_broken. A rejected set changes nothing. After an accepted set, only its active keys
    may sign the next set and its ``next_key`` is the one successor that may appear next.

    Snapshot verification (B10) trusts every key the accepted set lists, ``active`` or
    ``retiring``, until its ``not_after``, so a snapshot signed by the outgoing key during the
    rotation overlap still verifies (schemas reference verifier, gateway ``KeyChain``, SDK).
    """

    def __init__(self, pinned: Mapping[str, Any]) -> None:
        SigningKey.model_validate(dict(pinned))
        self._trusted: dict[str, dict[str, Any]] = {pinned["kid"]: dict(pinned)}
        self._listed: dict[str, dict[str, Any]] = {pinned["kid"]: dict(pinned)}
        self._announced: dict[str, Any] | None = None
        self._sequence = 0

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def announced_kid(self) -> str | None:
        return self._announced["kid"] if self._announced else None

    def trusted_kids(self) -> set[str]:
        """Kids that may sign the next key set (the active keys of the accepted set)."""
        return set(self._trusted)

    def snapshot_kids(self, *, now: datetime) -> set[str]:
        """Kids a snapshot may be signed with at ``now`` (active or retiring, unexpired)."""
        return {kid for kid, key in self._listed.items() if _usable(key, now)}

    def public_key(self, kid: str, *, now: datetime) -> bytes | None:
        """The raw public key for a snapshot check: any key the accepted set lists (``active``
        or ``retiring``) that is not past its ``not_after``."""
        key = self._listed.get(kid)
        if key is None or not _usable(key, now):
            return None
        return b64url_decode(key["public_key"])

    def _chain_holds(self, keys: Sequence[Mapping[str, Any]]) -> bool:
        for candidate in keys:
            known = self._trusted.get(candidate["kid"])
            if known is not None and known["public_key"] == candidate["public_key"]:
                continue
            announced = self._announced
            if (
                announced is not None
                and announced["kid"] == candidate["kid"]
                and announced["public_key"] == candidate["public_key"]
            ):
                continue
            return False
        return True

    def accept(self, raw: str | bytes, *, now: datetime) -> SigningKeySet:
        """Verify an untrusted key-set document; raises ``KeySetRejected``."""
        try:
            document = parse_json_strict(raw)
            model = SigningKeySet.model_validate(document)
        except (ValueError, RecursionError):
            raise KeySetRejected(KeySetRejectCause.MALFORMED) from None
        signer = self._trusted.get(document["kid"])
        if signer is None:
            raise KeySetRejected(KeySetRejectCause.UNKNOWN_SIGNER)
        if not _usable(signer, now):
            raise KeySetRejected(KeySetRejectCause.SIGNER_EXPIRED)
        body = document["body"]
        public = b64url_decode(signer["public_key"])
        if not verify_document(canonicalize(body), document["sig"], public):
            raise KeySetRejected(KeySetRejectCause.BAD_SIGNATURE)
        if body["sequence"] <= self._sequence:
            raise KeySetRejected(KeySetRejectCause.NON_MONOTONIC)
        active = [k for k in body["keys"] if k.get("status", "active") == "active"]
        if not self._chain_holds(active):
            raise KeySetRejected(KeySetRejectCause.CHAIN_BROKEN)
        self._trusted = {k["kid"]: dict(k) for k in active}
        self._listed = {k["kid"]: dict(k) for k in body["keys"]}
        self._announced = dict(body["next_key"]) if body["next_key"] is not None else None
        self._sequence = body["sequence"]
        return model
