"""Snapshot signing keys: private-key resolution and the signed key-set chain (security M6, B10).

``signing_key`` rows (purpose ``snapshot``) hold the public key and a ``private_key_ref`` that
points outside Postgres: ``env:VAR`` or ``file:/path``, each a 32-byte Ed25519 seed as hex or
unpadded base64url. A signer is used only if its derived public key equals the stored one.

Key sets are issued lazily and kept forever in ``signing_key_set`` (B10), so a freshly pinned
verifier can follow the whole chain (``/api/v1/policy/keys?since=<sequence>``). On each read the
desired content is derived from the rows: ``keys`` = the ``active`` key plus every ``retiring``
key until its ``retiring_until`` (published as ``not_after``), ``next_key`` = the pre-published
``next`` key (or ``null``). When it differs from the latest issued set, the next sequence is
signed by the latest set's active key (sequence 1 is self-signed: the pinned genesis). A rotation
to a key that the latest set did not announce first issues an announcement set (same keys,
``next_key`` = the new key) so the chain always holds for verifiers. If the signer the chain
needs has no usable private key, nothing is issued: the latest set keeps being served and the
gap is logged (a fabricated self-signed set would only be rejected by every verifier).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sibyl_schemas.canonical import canonicalize

from ...core.crypto.signing import Ed25519Signer, key_set_body, sign_key_set, signing_key

log = logging.getLogger("sibyl.api.snapshot")
SNAPSHOT_PURPOSE = "snapshot"
MAX_CHAIN_PAGE = 1000
_ISSUE_ATTEMPTS = 3


class SignerUnavailable(Exception):
    """No usable private key for a signing_key row (never says why to the caller)."""


@dataclass(frozen=True)
class SigningKeyRow:
    kid: str
    public_key: bytes
    private_key_ref: str
    state: str
    activated_at: datetime
    retiring_until: datetime | None


_ROWS_SQL = (
    "SELECT kid, public_key, private_key_ref, state, activated_at, retiring_until"
    " FROM sibyl.signing_key WHERE purpose = $1 ORDER BY activated_at, kid"
)


async def load_rows(conn: Any, purpose: str = SNAPSHOT_PURPOSE) -> list[SigningKeyRow]:
    return [
        SigningKeyRow(
            r["kid"],
            bytes(r["public_key"]),
            r["private_key_ref"],
            r["state"],
            r["activated_at"],
            r["retiring_until"],
        )
        for r in await conn.fetch(_ROWS_SQL, purpose)
    ]


def _seed(text: str) -> bytes:
    text = text.strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        try:
            raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            raise SignerUnavailable("seed encoding") from None
    if len(raw) != 32:
        raise SignerUnavailable("seed length")
    return raw


class SignerResolver:
    """Resolves and caches ``Ed25519Signer`` per kid from ``private_key_ref``."""

    def __init__(self, environ: Mapping[str, str] | None = None) -> None:
        self._environ = environ
        self._cache: dict[str, Ed25519Signer] = {}

    def resolve(self, row: SigningKeyRow) -> Ed25519Signer:
        cached = self._cache.get(row.kid)
        if cached is not None:
            return cached
        scheme, _, target = row.private_key_ref.partition(":")
        environ = os.environ if self._environ is None else self._environ
        if scheme == "env" and target in environ:
            seed = _seed(environ[target])
        elif scheme == "file" and target and Path(target).is_file():
            seed = _seed(Path(target).read_text("utf-8"))
        else:
            raise SignerUnavailable("private_key_ref not resolvable")
        signer = Ed25519Signer.from_seed(row.kid, seed)
        if signer.public_key_raw != row.public_key:
            raise SignerUnavailable("private key does not match the published public key")
        self._cache[row.kid] = signer
        return signer


def active_row(rows: Sequence[SigningKeyRow]) -> SigningKeyRow | None:
    return next((r for r in rows if r.state == "active"), None)


def next_row(rows: Sequence[SigningKeyRow]) -> SigningKeyRow | None:
    return next((r for r in rows if r.state == "next"), None)


@dataclass(frozen=True)
class IssuedKeySet:
    sequence: int
    signer_kid: str
    active_kid: str
    next_kid: str | None
    text: str = field(repr=False)

    @property
    def document(self) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(self.text)
        return value

    @property
    def body(self) -> dict[str, Any]:
        body: dict[str, Any] = self.document["body"]
        return body


_COLS = "sequence, signer_kid, active_kid, next_kid, document"
_LATEST_SQL = (
    f"SELECT {_COLS} FROM sibyl.signing_key_set WHERE purpose = $1"  # noqa: S608 (constant)
    " ORDER BY sequence DESC LIMIT 1"
)
_SINCE_SQL = (
    f"SELECT {_COLS} FROM sibyl.signing_key_set WHERE purpose = $1"  # noqa: S608 (constant)
    " AND sequence > $2 ORDER BY sequence LIMIT $3"
)
_INSERT_SQL = (
    "INSERT INTO sibyl.signing_key_set (purpose, sequence, signer_kid, active_kid, next_kid,"
    " document, body_sha256, issued_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    " ON CONFLICT (purpose, sequence) DO NOTHING RETURNING sequence"
)


def _issued(row: Any) -> IssuedKeySet:
    return IssuedKeySet(
        int(row["sequence"]), row["signer_kid"], row["active_kid"], row["next_kid"], row["document"]
    )


async def latest_set(conn: Any, purpose: str = SNAPSHOT_PURPOSE) -> IssuedKeySet | None:
    row = await conn.fetchrow(_LATEST_SQL, purpose)
    return None if row is None else _issued(row)


async def sets_since(
    conn: Any, since: int, purpose: str = SNAPSHOT_PURPOSE, limit: int = MAX_CHAIN_PAGE
) -> list[IssuedKeySet]:
    return [_issued(r) for r in await conn.fetch(_SINCE_SQL, purpose, since, limit)]


def _wire(
    row: SigningKeyRow, status: str | None = None, *, not_after: Any = None
) -> dict[str, str]:
    return signing_key(row.kid, row.public_key, status=status, not_after=not_after)


def desired_content(
    rows: Sequence[SigningKeyRow], *, now: datetime
) -> tuple[SigningKeyRow, list[dict[str, str]], dict[str, str] | None]:
    """(active row, ``keys``, ``next_key``) the published set should carry at ``now``."""
    active = active_row(rows)
    if active is None:
        raise SignerUnavailable("no active snapshot signing key")
    keys = [_wire(active, "active")]
    for row in rows:
        if row.state == "retiring" and row.retiring_until is not None and row.retiring_until > now:
            keys.append(_wire(row, "retiring", not_after=row.retiring_until))
    upcoming = next_row(rows)
    return active, keys, None if upcoming is None else _wire(upcoming)


def _same(body: Mapping[str, Any], keys: list[dict[str, str]], nxt: dict[str, str] | None) -> bool:
    return canonicalize(body["keys"]) == canonicalize(keys) and canonicalize(
        body["next_key"]
    ) == canonicalize(nxt)


@dataclass(frozen=True)
class _Planned:
    signer: SigningKeyRow
    active_kid: str
    keys: list[dict[str, str]]
    next_key: dict[str, str] | None


def plan(
    rows: Sequence[SigningKeyRow], latest: IssuedKeySet | None, *, now: datetime
) -> list[_Planned]:
    """The sets to append so the chain reaches the desired content (empty when current)."""
    active, keys, nxt = desired_content(rows, now=now)
    if latest is None:
        return [_Planned(active, active.kid, keys, nxt)]
    body = latest.body
    if _same(body, keys, nxt):
        return []
    by_kid = {r.kid: r for r in rows}
    signer = by_kid.get(latest.active_kid)
    if signer is None:
        raise SignerUnavailable("the latest set's active key is gone")
    if active.kid == latest.active_kid:
        return [_Planned(active, active.kid, keys, nxt)]
    announced = body["next_key"]
    out: list[_Planned] = []
    wire_active = _wire(active)
    if announced is None or canonicalize(announced) != canonicalize(wire_active):
        out.append(_Planned(signer, latest.active_kid, list(body["keys"]), wire_active))
    out.append(_Planned(signer, active.kid, keys, nxt))
    return out


def _ms(now: datetime) -> datetime:
    utc = now.astimezone(UTC)
    return utc.replace(microsecond=utc.microsecond // 1000 * 1000)


async def ensure_current(
    conn: Any, resolver: SignerResolver, *, now: datetime, purpose: str = SNAPSHOT_PURPOSE
) -> IssuedKeySet:
    """Issue whatever sets the chain needs (writable transaction) and return the latest."""
    for _ in range(_ISSUE_ATTEMPTS):
        rows = await load_rows(conn, purpose)
        latest = await latest_set(conn, purpose)
        try:
            planned = plan(rows, latest, now=now)
            signers = [resolver.resolve(p.signer) for p in planned]
        except SignerUnavailable as exc:
            if latest is None:
                raise
            log.error("key set chain cannot advance past %d: %s", latest.sequence, exc)
            return latest
        sequence = latest.sequence if latest is not None else 0
        raced = False
        for item, signer in zip(planned, signers, strict=True):
            sequence += 1
            body = key_set_body(sequence, _ms(now), item.keys, item.next_key)
            text = canonicalize(sign_key_set(signer, body)).decode("utf-8")
            next_kid = item.next_key["kid"] if item.next_key is not None else None
            stored = await conn.fetchval(
                _INSERT_SQL,
                purpose,
                sequence,
                signer.kid,
                item.active_kid,
                next_kid,
                text,
                hashlib.sha256(canonicalize(body)).digest(),
                _ms(now),
            )
            if stored is None:  # another replica issued this sequence first: re-plan
                raced = True
                break
        if not raced:
            current = await latest_set(conn, purpose)
            assert current is not None
            return current
    raise SignerUnavailable("key set issuance kept racing")


def chain_page(sets: Sequence[IssuedKeySet], latest: IssuedKeySet) -> dict[str, Any]:
    """``KeySetChain``: every set after ``since`` (ascending) and the latest sequence."""
    return {"data": [s.document for s in sets], "latest_sequence": latest.sequence}
