"""Snapshot verification (API.md §3.5, security-auditor §2.4, chair ruling B4).

The signature is checked over the **raw bytes received** (never re-canonicalised), in the fixed
order of ``sibyl_schemas.values.SnapshotRejectCause``; the first failing check names the cause.
Each failure leaves the held snapshot in place (the caller decides) and is reported as
``snapshot.rejected`` with the cause.

Pinned keys come from configuration, not from the network: a key set document in either the
OpenAPI JWKS shape (``/api/v1/policy/keys``: ``{kty, crv, x, kid, sibyl_state}``) or the
``sibyl.policy_snapshot/1`` ``$defs/key_set`` shape (``{kid, alg, public_key, status}``). The
pre-published ``next_key`` is pinned too, so a rotation never needs a gateway restart (R33).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict
from sibyl_schemas.keyset import b64url_decode, parse_ts
from sibyl_schemas.values import (
    SNAPSHOT_GRACE_BOUNDS_S,
    SNAPSHOT_MAX_FUTURE_SKEW_S,
    SNAPSHOT_TTL_BOUNDS_S,
    SnapshotRejectCause,
)

SNAPSHOT_SCHEMA = "sibyl.policy_snapshot/1"
MALFORMED = "malformed"  # SnapshotRejectCause.MALFORMED since sibyl-schemas 1.1.0
_UNUSABLE_STATES = frozenset({"retired", "compromised"})


__all__ = [
    "MALFORMED",
    "SNAPSHOT_SCHEMA",
    "KeySetError",
    "PinnedKey",
    "PinnedKeySet",
    "SnapshotRejected",
    "VerifiedSnapshot",
    "b64url_decode",
    "parse_ts",
    "verify_envelope",
    "verify_snapshot",
]


class SnapshotRejected(Exception):
    def __init__(self, cause: str, detail: str = "") -> None:
        super().__init__(f"snapshot rejected: {cause}{': ' + detail if detail else ''}")
        self.cause = cause


class KeySetError(ValueError):
    """The pinned key set document is unusable (fail fast at start)."""


@dataclass(frozen=True)
class PinnedKey:
    kid: str
    public_key: bytes = field(repr=False)
    state: str = "active"

    def verifier(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(self.public_key)


class PinnedKeySet:
    """kid -> Ed25519 public key; immutable after construction."""

    def __init__(self, keys: Iterable[PinnedKey]) -> None:
        self._keys: dict[str, PinnedKey] = {}
        self._verifiers: dict[str, Ed25519PublicKey] = {}
        for key in keys:
            if key.state in _UNUSABLE_STATES:
                continue
            self._keys[key.kid] = key
            self._verifiers[key.kid] = key.verifier()
        if not self._keys:
            raise KeySetError("no usable snapshot verification key pinned")

    def __contains__(self, kid: object) -> bool:
        return kid in self._keys

    @property
    def kids(self) -> frozenset[str]:
        return frozenset(self._keys)

    def verify(self, kid: str, signature: bytes, raw: bytes) -> bool:
        verifier = self._verifiers.get(kid)
        if verifier is None:
            return False
        try:
            verifier.verify(signature, raw)
        except InvalidSignature:
            return False
        return True

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> PinnedKeySet:
        entries = list(document.get("keys") or [])
        next_key = document.get("next_key")
        if isinstance(next_key, Mapping):
            entries.append({**next_key, "status": "next"})
        keys = [_parse_key(entry) for entry in entries]
        purposes = {entry.get("sibyl_purpose") for entry in entries if isinstance(entry, Mapping)}
        if "audit_anchor" in purposes:
            keys = [
                key
                for key, entry in zip(keys, entries, strict=True)
                if entry.get("sibyl_purpose", "snapshot") == "snapshot"
            ]
        return cls(keys)

    @classmethod
    def from_json(cls, text: str | bytes) -> PinnedKeySet:
        try:
            document = json.loads(text)
        except ValueError as exc:
            raise KeySetError(f"pinned key set is not JSON: {exc}") from None
        if not isinstance(document, Mapping):
            raise KeySetError("pinned key set must be an object")
        return cls.from_document(document)


def _parse_key(entry: Any) -> PinnedKey:
    if not isinstance(entry, Mapping) or not isinstance(entry.get("kid"), str):
        raise KeySetError("every pinned key needs a kid")
    encoded = entry.get("public_key", entry.get("x"))
    try:
        raw = b64url_decode(encoded)
    except ValueError:
        raise KeySetError(f"key {entry['kid']}: public key is not base64url") from None
    if len(raw) != 32:
        raise KeySetError(f"key {entry['kid']}: Ed25519 public keys are 32 bytes")
    if entry.get("crv", "Ed25519") != "Ed25519" or entry.get("alg", "Ed25519") not in (
        "Ed25519",
        "EdDSA",
    ):
        raise KeySetError(f"key {entry['kid']}: only Ed25519 is accepted")
    state = str(entry.get("status", entry.get("sibyl_state", "active")))
    return PinnedKey(entry["kid"], raw, state)


@dataclass(frozen=True)
class VerifiedSnapshot:
    raw: bytes = field(repr=False)
    kid: str
    signature: str = field(repr=False)
    body: Mapping[str, Any] = field(repr=False, compare=False)
    version: int
    issued_at: datetime
    expires_at: datetime
    ttl_s: int
    grace_s: int

    @property
    def tenants(self) -> Mapping[str, Any]:
        tenants: Mapping[str, Any] = self.body["tenants"]
        return tenants


def verify_snapshot(
    raw: bytes,
    *,
    kid: str,
    signature: str,
    keys: PinnedKeySet,
    held_version: int | None,
    now: datetime,
) -> VerifiedSnapshot:
    """Verify one delivery; raise ``SnapshotRejected(cause)`` at the first failing check.

    Order (sibyl-schemas 1.1.0): malformed (strict parse of the received bytes, before any
    signature work), unknown_kid (header kid pinned and equal to the body kid), bad_signature
    (Ed25519 over exactly ``raw``, B4), non_monotonic, future_issued, bad_ttl.
    """
    body = _parse_body(raw)
    if kid not in keys or body.get("kid") != kid:
        raise SnapshotRejected(SnapshotRejectCause.UNKNOWN_KID.value)
    try:
        sig = b64url_decode(signature)
    except ValueError:
        raise SnapshotRejected(
            SnapshotRejectCause.BAD_SIGNATURE.value, "signature encoding"
        ) from None
    if len(sig) != 64 or not keys.verify(kid, sig, raw):
        raise SnapshotRejected(SnapshotRejectCause.BAD_SIGNATURE.value)
    version = body.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise SnapshotRejected(MALFORMED, "version")
    if held_version is not None and version <= held_version:
        raise SnapshotRejected(SnapshotRejectCause.NON_MONOTONIC.value)
    try:
        issued_at = parse_ts(body.get("issued_at"))
        expires_at = parse_ts(body.get("expires_at"))
    except ValueError:
        raise SnapshotRejected(MALFORMED, "timestamps") from None
    if issued_at > now + timedelta(seconds=SNAPSHOT_MAX_FUTURE_SKEW_S):
        raise SnapshotRejected(SnapshotRejectCause.FUTURE_ISSUED.value)
    ttl_s, grace_s = body.get("ttl_s"), body.get("grace_s")
    if not _ttl_ok(issued_at, expires_at, ttl_s, grace_s):
        raise SnapshotRejected(SnapshotRejectCause.BAD_TTL.value)
    assert isinstance(ttl_s, int) and isinstance(grace_s, int)
    return VerifiedSnapshot(
        raw, kid, signature, body, version, issued_at, expires_at, ttl_s, grace_s
    )


def verify_envelope(
    raw_envelope: str | bytes,
    *,
    keys: PinnedKeySet,
    held_version: int | None,
    now: datetime,
) -> VerifiedSnapshot:
    """The ``$defs/envelope`` form ``{kid, alg, sig, body}`` (vectors, files): the envelope is
    parsed strictly (a duplicate ``body`` is ``malformed``) and the signature is checked over
    JCS(body), the bytes the api would have sent in the detached form."""
    try:
        envelope = parse_json_strict(raw_envelope)
    except (CanonicalizationError, ValueError, UnicodeDecodeError, RecursionError):
        raise SnapshotRejected(MALFORMED, "envelope is not I-JSON") from None
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"kid", "alg", "sig", "body"}
        or envelope["alg"] != "Ed25519"
        or not isinstance(envelope["kid"], str)
        or not isinstance(envelope["sig"], str)
    ):
        raise SnapshotRejected(MALFORMED, "envelope shape")
    try:
        raw = canonicalize(envelope["body"])
    except CanonicalizationError:
        raise SnapshotRejected(MALFORMED, "body") from None
    return verify_snapshot(
        raw,
        kid=envelope["kid"],
        signature=envelope["sig"],
        keys=keys,
        held_version=held_version,
        now=now,
    )


def _parse_body(raw: bytes) -> dict[str, Any]:
    try:
        body = parse_json_strict(raw)
    except (CanonicalizationError, ValueError, UnicodeDecodeError, RecursionError):
        raise SnapshotRejected(MALFORMED, "not I-JSON") from None
    if (
        not isinstance(body, dict)
        or body.get("schema") != SNAPSHOT_SCHEMA
        or not isinstance(body.get("tenants"), dict)
        or not body["tenants"]
    ):
        raise SnapshotRejected(MALFORMED, "not a sibyl.policy_snapshot/1 body")
    return body


def _ttl_ok(issued_at: datetime, expires_at: datetime, ttl_s: Any, grace_s: Any) -> bool:
    if not all(isinstance(v, int) and not isinstance(v, bool) for v in (ttl_s, grace_s)):
        return False
    lo, hi = SNAPSHOT_TTL_BOUNDS_S
    g_lo, g_hi = SNAPSHOT_GRACE_BOUNDS_S
    window = (expires_at - issued_at).total_seconds()
    return bool(lo <= ttl_s <= hi and window == ttl_s and g_lo <= grace_s <= g_hi)
