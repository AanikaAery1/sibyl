"""Signed key-set rotation chain follower (security M6, B9, B10, B18; CR-G1).

One implementation for every verifier outside the control plane (the gateway's ``KeyChain``,
the SDK's ``KeySetVerifier``); it imports only ``sibyl_schemas`` and ``cryptography`` (which
every consumer already depends on). A verifier pins ONE first key and follows the chain the api
publishes at ``/api/v1/policy/keys``: a set ``{kid, alg, sig, body: {sequence, issued_at, keys,
next_key}}`` is accepted only if (in this order, the first failure names the
``KeySetRejectCause``):

    malformed       strict I-JSON parse + the ``sibyl_schemas`` shape (no extra/duplicate members)
    unknown_signer  ``kid`` is an ACTIVE key of the previously accepted set (the pin at first)
    signer_expired  the signer is not past its ``not_after``
    bad_signature   Ed25519 over JCS(body) (``next_key`` is inside the signature)
    non_monotonic   ``sequence`` strictly greater than the last accepted one
    sequence_gap    (a ``?since=`` delivery only) ``sequence`` is exactly the held one + 1: every
                    set in between could have changed the trusted keys
    chain_broken    every active key was already trusted or is the previous ``next_key``

Snapshots then verify against every key the accepted set lists (active and retiring, B10
rotation overlap) that is not past ``not_after``. A rejected set changes nothing: states are
immutable and replaced whole.

Catch-up (B10): ``ChainFollower.stage()`` verifies a ``?since=<sequence>`` delivery in order on
top of the current state and ``commit()`` adopts it whole; the first failing member rejects the
delivery (``KeySetRejected.index`` names it). ``parse_chain_page`` reads one ``KeySetChain`` page
(``{data, latest_sequence}``) and ``follow_chain`` drives a synchronous fetch; asynchronous
callers loop over ``ChainStage.accept_page`` themselves.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sibyl_schemas.canonical import CanonicalizationError, canonicalize, parse_json_strict
from sibyl_schemas.models import SigningKeySet, parse_signing_key_set
from sibyl_schemas.values import KeySetRejectCause

KEYS_PATH: Final = "/api/v1/policy/keys"
MAX_CHAIN_PAGE: Final = 1000
MAX_PAGES: Final = 32  # bounds one refresh; anything left is fetched on the next one
MAX_SEQUENCE: Final = 9007199254740991
_CHAIN_FIELDS: Final = frozenset({"data", "latest_sequence"})
_KEY_FIELDS: Final = frozenset({"kid", "alg", "public_key", "status", "not_after"})
_STATUSES: Final = frozenset({"active", "retiring"})
_B64URL: Final = re.compile(r"[A-Za-z0-9_-]*")


class KeySetRejected(ValueError):
    """``cause`` is the first failing check; ``index`` the failing member of a delivered chain."""

    def __init__(self, cause: KeySetRejectCause, index: int | None = None) -> None:
        where = f" (chain member {index})" if index is not None else ""
        super().__init__(f"key set rejected: {cause.value}{where}")
        self.cause = cause
        self.index = index


class ChainFetchError(Exception):
    """Transport failure or a non-200 answer (nothing was verified or adopted)."""


def b64url_decode(text: Any) -> bytes:
    """Strict unpadded base64url (no padding, no foreign characters, canonical length)."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise ValueError("expected unpadded base64url")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except binascii.Error:
        raise ValueError("expected unpadded base64url") from None


def parse_ts(value: Any) -> datetime:
    """An RFC 3339 timestamp with an offset, as an aware UTC datetime."""
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp needs an offset")
    return parsed.astimezone(UTC)


def verify_ed25519(body: bytes, signature: str, public_raw: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(b64url_decode(signature), body)
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class ChainKey:
    """One signing key of a set (or the pin). ``entry`` is its JSON form, kept for persistence."""

    kid: str
    public_key: bytes
    status: str = "active"
    not_after: datetime | None = None
    entry: Mapping[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def usable(self, now: datetime) -> bool:
        return self.not_after is None or self.not_after >= now

    @classmethod
    def from_entry(cls, entry: Any) -> ChainKey:
        """A ``SigningKey`` object; ``ValueError`` when it is unusable."""
        if not isinstance(entry, Mapping) or not set(entry) <= _KEY_FIELDS:
            raise ValueError("signing key shape")
        kid, alg = entry.get("kid"), entry.get("alg")
        if not isinstance(kid, str) or not 1 <= len(kid) <= 64 or alg != "Ed25519":
            raise ValueError("signing key kid/alg")
        raw = b64url_decode(entry.get("public_key"))
        if len(raw) != 32:
            raise ValueError("Ed25519 public keys are 32 bytes")
        status = entry.get("status", "active")
        if status not in _STATUSES:
            raise ValueError("signing key status")
        not_after = parse_ts(entry["not_after"]) if "not_after" in entry else None
        return cls(kid, raw, status, not_after, dict(entry))


@dataclass(frozen=True)
class ChainState:
    """Everything one accepted set decides; replaced whole, never mutated.

    ``trusted``: the active keys (may sign the next set); ``listed``: active and retiring keys
    (may sign snapshots, B10); ``announced``: the pre-published successor; ``accepted``: the
    accepted documents in order (text), for callers that persist and replay the chain."""

    trusted: Mapping[str, ChainKey]
    listed: Mapping[str, ChainKey]
    announced: ChainKey | None
    sequence: int
    accepted: tuple[str, ...] = ()

    @classmethod
    def pinned(cls, key: ChainKey) -> ChainState:
        return cls({key.kid: key}, {key.kid: key}, None, 0, ())


def _parse(raw: str | bytes) -> tuple[SigningKeySet, dict[str, Any], list[ChainKey]]:
    try:
        model = parse_signing_key_set(raw)  # strict I-JSON + the sibyl_schemas shape
        document = parse_json_strict(raw)
        if not isinstance(document, dict):
            raise ValueError("key set envelope")
        body = document["body"]
        parse_ts(body["issued_at"])
        keys = [ChainKey.from_entry(k) for k in body["keys"]]
        if body["next_key"] is not None:
            ChainKey.from_entry(body["next_key"])
    except (CanonicalizationError, ValueError, KeyError, TypeError, RecursionError):
        raise KeySetRejected(KeySetRejectCause.MALFORMED) from None
    return model, document, keys


def _chain_holds(state: ChainState, active: Sequence[ChainKey]) -> bool:
    announced = state.announced
    for key in active:
        known = state.trusted.get(key.kid)
        if known is not None and known.public_key == key.public_key:
            continue
        if announced is not None and (announced.kid, announced.public_key) == (
            key.kid,
            key.public_key,
        ):
            continue
        return False
    return True


def step(
    state: ChainState, raw: str | bytes, *, now: datetime, contiguous: bool
) -> tuple[ChainState, SigningKeySet]:
    """Verify one set against ``state``: the successor state and the parsed set, or
    ``KeySetRejected``. ``contiguous`` (a ``?since=`` delivery) refuses a gap as
    ``sequence_gap``."""
    model, document, keys = _parse(raw)
    signer = state.trusted.get(document["kid"])
    if signer is None:
        raise KeySetRejected(KeySetRejectCause.UNKNOWN_SIGNER)
    if not signer.usable(now):
        raise KeySetRejected(KeySetRejectCause.SIGNER_EXPIRED)
    body = document["body"]
    if not verify_ed25519(canonicalize(body), document["sig"], signer.public_key):
        raise KeySetRejected(KeySetRejectCause.BAD_SIGNATURE)
    sequence = int(body["sequence"])
    if sequence <= state.sequence:
        raise KeySetRejected(KeySetRejectCause.NON_MONOTONIC)
    if contiguous and sequence != state.sequence + 1:
        raise KeySetRejected(KeySetRejectCause.SEQUENCE_GAP)
    active = [k for k in keys if k.status == "active"]
    if not _chain_holds(state, active):
        raise KeySetRejected(KeySetRejectCause.CHAIN_BROKEN)
    nxt = body["next_key"]
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    successor = ChainState(
        trusted={k.kid: k for k in active},
        listed={k.kid: k for k in keys},
        announced=None if nxt is None else ChainKey.from_entry(nxt),
        sequence=sequence,
        accepted=(*state.accepted, text),
    )
    return successor, model


# --- KeySetChain pages ----------------------------------------------------------------------


@dataclass(frozen=True)
class ChainPage:
    documents: tuple[bytes, ...]
    latest_sequence: int


def parse_chain_page(raw: bytes | str) -> ChainPage:
    """Strictly parse one ``KeySetChain`` page; members stay unverified (canonical bytes)."""
    try:
        doc = parse_json_strict(raw)
        if not isinstance(doc, dict) or set(doc) != _CHAIN_FIELDS:
            raise ValueError("key set chain envelope")
        data, latest = doc["data"], doc["latest_sequence"]
        if not isinstance(data, list) or len(data) > MAX_CHAIN_PAGE:
            raise ValueError("key set chain data")
        if not isinstance(latest, int) or isinstance(latest, bool):
            raise ValueError("latest_sequence")
        if not 0 <= latest <= MAX_SEQUENCE:
            raise ValueError("latest_sequence range")
        members = tuple(canonicalize(member) for member in data)
    except (CanonicalizationError, ValueError, TypeError, RecursionError):
        raise KeySetRejected(KeySetRejectCause.MALFORMED) from None
    return ChainPage(members, latest)


class ChainStage:
    """Sets verified in order on top of a follower state, adopted only by
    ``ChainFollower.commit``, so the first failing member of a ``?since=`` delivery rejects all
    of it and the follower keeps its last verified set (B10)."""

    def __init__(self, base: ChainState, *, offset: int = 0) -> None:
        self._base = base
        self._state = base
        self._count = 0
        self._offset = offset

    @property
    def base(self) -> ChainState:
        return self._base

    @property
    def state(self) -> ChainState:
        return self._state

    @property
    def sequence(self) -> int:
        return self._state.sequence

    @property
    def count(self) -> int:
        """Sets verified on this stage so far."""
        return self._count

    def accept(self, raw: str | bytes, *, now: datetime) -> int:
        try:
            self._state, _ = step(self._state, raw, now=now, contiguous=True)
        except KeySetRejected as exc:
            raise KeySetRejected(exc.cause, self._count + self._offset) from None
        self._count += 1
        return self._state.sequence

    def accept_page(self, page: ChainPage, *, now: datetime) -> bool:
        """Verify every member of one page; whether the chain says more pages remain."""
        for member in page.documents:
            self.accept(member, now=now)
        return bool(page.documents) and self.sequence < page.latest_sequence


class ChainFollower:
    """Pinned first key + the accepted rotation chain (not thread-safe; wrap it to share)."""

    def __init__(self, pinned: ChainKey) -> None:
        self._pinned = pinned
        self._state = ChainState.pinned(pinned)

    @classmethod
    def from_state(cls, pinned: ChainKey, state: ChainState) -> Self:
        follower = cls(pinned)
        follower._state = state
        return follower

    @classmethod
    def trust_on_first_use(cls, raw: str | bytes, *, now: datetime) -> Self:
        """No pin configured: pin the signer of the first key set fetched over TLS (R33), then
        accept that set through the normal chain checks."""
        try:
            document = parse_json_strict(raw)
            SigningKeySet.model_validate(document)
            entry = next(k for k in document["body"]["keys"] if k["kid"] == document["kid"])
        except StopIteration:
            raise KeySetRejected(KeySetRejectCause.UNKNOWN_SIGNER) from None
        except (CanonicalizationError, ValueError, KeyError, TypeError, RecursionError):
            raise KeySetRejected(KeySetRejectCause.MALFORMED) from None
        try:
            pinned = ChainKey.from_entry(entry)
        except ValueError:
            raise KeySetRejected(KeySetRejectCause.MALFORMED) from None
        follower = cls(pinned)
        follower.accept(raw, now=now)
        return follower

    @property
    def pinned(self) -> ChainKey:
        return self._pinned

    @property
    def chain_state(self) -> ChainState:
        return self._state

    @property
    def sequence(self) -> int:
        return self._state.sequence

    def trusted_kids(self) -> set[str]:
        """Kids that may sign the next key set (the active keys of the accepted set)."""
        return set(self._state.trusted)

    def listed_keys(self, now: datetime) -> list[ChainKey]:
        """Keys a snapshot may be signed by: listed (active or retiring), not past not_after."""
        return [k for k in self._state.listed.values() if k.usable(now)]

    def accept(self, raw: str | bytes, *, now: datetime) -> SigningKeySet:
        """Verify and adopt one key set (gaps allowed: a direct, not a ``?since=``, delivery)."""
        self._state, model = step(self._state, raw, now=now, contiguous=False)
        return model

    def stage(self, *, offset: int = 0) -> ChainStage:
        """Start verifying a ``?since=<sequence>`` delivery on top of the current state."""
        return ChainStage(self._state, offset=offset)

    def commit(self, stage: ChainStage) -> int:
        """Adopt a fully verified stage (refused if the follower moved since it started)."""
        if stage.base is not self._state:
            raise KeySetRejected(KeySetRejectCause.NON_MONOTONIC)
        self._state = stage.state
        return self._state.sequence

    def accept_chain(self, documents: Sequence[str | bytes], *, now: datetime) -> int:
        """Verify ``documents`` in order from the current state, all or nothing (B10)."""
        stage = self.stage()
        for raw in documents:
            stage.accept(raw, now=now)
        return self.commit(stage)


Fetch = Callable[[int], bytes]
"""``since`` -> the raw 200 body; raises ``ChainFetchError`` on transport failure or non-200."""


def _genesis[F: ChainFollower](kind: type[F], first: bytes, now: datetime) -> F:
    """Trust on first use: only the self-signed sequence-1 set may start a chain."""
    try:
        follower = kind.trust_on_first_use(first, now=now)
    except KeySetRejected as exc:
        raise KeySetRejected(exc.cause, 0) from None
    if follower.sequence != 1:
        raise KeySetRejected(KeySetRejectCause.CHAIN_BROKEN, 0)
    return follower


def follow_chain[F: ChainFollower](
    fetch: Fetch, follower: F | None, *, now: datetime, kind: type[F]
) -> tuple[F | None, int]:
    """Fetch, verify and adopt every set after the held sequence: (follower, sets adopted).

    Without a follower the genesis is trusted on first use (a ``kind``) and returned only if
    the whole delivery verifies. Raises ``KeySetRejected`` (nothing adopted) or
    ``ChainFetchError``."""
    page = parse_chain_page(fetch(follower.sequence if follower is not None else 0))
    members = page
    if follower is None:
        if not page.documents:
            return None, 0  # nothing issued yet
        target = _genesis(kind, page.documents[0], now)
        members = ChainPage(page.documents[1:], page.latest_sequence)
        stage, offset = target.stage(offset=1), 1
    else:
        target, offset = follower, 0
        stage = target.stage()
    for _ in range(MAX_PAGES):
        stage.accept_page(members, now=now)
        if not page.documents or stage.sequence >= page.latest_sequence:
            break
        page = members = parse_chain_page(fetch(stage.sequence))
    if stage.count == 0 and offset == 0:
        return target, 0
    target.commit(stage)
    return target, stage.count + offset
