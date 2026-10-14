"""Idempotency-Key handling (API.md §2.6, T3, chair ruling G0-8).

Records live 24 h in ``sibyl.idempotency_record`` keyed ``(tenant_id, route, idempotency_key)``
with the owning ``principal_kind``/``principal_id`` stored: the same key from another principal
is a 404 (no cross-principal oracle), a different request is 422, a request still executing is
409. The request fingerprint binds method, path, query string and body.

Every claim carries a fresh ``claim_id``. ``complete``/``abandon`` only touch the record while it
still holds that claim: after a stale reclaim the late request's ``complete`` raises
``IdempotencyClaimLost`` (rolling back its handler transaction) and its ``abandon`` is a no-op
(code review M5). Stored bodies are capped at 64 KB; a larger response keeps status, headers and
the body's sha256, and replaying it is 409 ``idempotent_replay_unavailable``. Handlers that
transition routing also pass the key into ``routing_apply(p_idempotency_key)`` so a replay after
the TTL cannot double-transition.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol
from urllib.parse import parse_qsl, urlencode
from uuid import UUID, uuid4

from .problems import ProblemError

log = logging.getLogger("sibyl.idempotency")

IDEMPOTENCY_HEADER = "Idempotency-Key"
REPLAY_HEADER = "Idempotency-Replayed"
IDEMPOTENCY_TTL = timedelta(hours=24)
IN_PROGRESS_STALE_AFTER = timedelta(minutes=5)  # a crashed request no longer blocks its key
MAX_KEY_LENGTH = 128
MAX_STORED_BODY_BYTES = 64 * 1024  # G0-8
PRINCIPAL_KINDS: frozenset[str] = frozenset({"user", "api_key"})
PrincipalKindName = Literal["user", "api_key"]


def require_key(value: str | None) -> str:
    if not value:
        raise ProblemError("idempotency_key_required")
    if len(value) > MAX_KEY_LENGTH:
        raise ProblemError("validation_failed", "Idempotency-Key is at most 128 characters")
    return value


def _body_digest(body: bytes) -> bytes:
    try:
        normal = json.dumps(json.loads(body), sort_keys=True, separators=(",", ":"))
        payload = b"json:" + normal.encode()
    except (ValueError, UnicodeDecodeError, RecursionError):
        payload = b"raw:" + body
    return hashlib.sha256(payload).digest()


def fingerprint(body: bytes, *, method: str, path: str, query: str) -> bytes:
    """sha256 over the request line and body (G0-8).

    ``path`` is the concrete request path, ``query`` the raw query string (parameter order is
    normalised). JSON bodies are normalised so whitespace and key order do not matter. Each part
    is length-prefixed, so no part can be smuggled into another.
    """
    pairs = sorted(parse_qsl(query, keep_blank_values=True))
    parts = (method.upper().encode(), path.encode(), urlencode(pairs).encode(), _body_digest(body))
    material = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    return hashlib.sha256(b"sibyl-idem-v2:" + material).digest()


def _check_kind(principal_kind: str) -> None:
    if principal_kind not in PRINCIPAL_KINDS:
        raise ValueError(f"principal_kind must be one of {sorted(PRINCIPAL_KINDS)}")


@dataclass(frozen=True)
class StoredResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class RecordKey:
    """The claim token: the record's key plus the ``claim_id`` this request holds."""

    tenant_id: UUID
    route: str
    key: str
    claim_id: UUID


@dataclass(frozen=True)
class Fresh:
    """First use: execute, then ``complete(token, response)`` or ``abandon(token)``."""

    token: RecordKey

    @property
    def claim_id(self) -> UUID:
        return self.token.claim_id


@dataclass(frozen=True)
class Replay:
    response: StoredResponse


@dataclass(frozen=True)
class ReplayUnavailable:
    """The first response was over 64 KB: only its status, headers and body hash were kept."""

    status: int
    headers: Mapping[str, str]
    body_sha256: bytes


@dataclass(frozen=True)
class InProgress:
    pass


@dataclass(frozen=True)
class Mismatch:
    pass


@dataclass(frozen=True)
class ForeignKey:
    pass


BeginOutcome = Fresh | Replay | ReplayUnavailable | InProgress | Mismatch | ForeignKey


class IdempotencyClaimLost(ProblemError):
    """``complete`` found the record no longer held by this claim (a stale reclaim won).

    Raised inside the handler's transaction so its business writes roll back; the client sees
    409 ``idempotency_in_progress`` and may retry with the same key.
    """

    def __init__(self) -> None:
        super().__init__(
            "idempotency_in_progress", "the idempotency claim was taken over by a newer request"
        )


class IdempotencyStore(Protocol):
    async def begin(
        self,
        tenant_id: UUID,
        principal_id: UUID,
        route: str,
        key: str,
        request_sha256: bytes,
        *,
        principal_kind: PrincipalKindName,
    ) -> BeginOutcome: ...

    async def complete(self, token: RecordKey, response: StoredResponse) -> None: ...

    async def abandon(self, token: RecordKey) -> bool: ...


async def begin_or_raise(
    store: IdempotencyStore,
    tenant_id: UUID,
    principal_id: UUID,
    route: str,
    key: str,
    request_sha256: bytes,
    *,
    principal_kind: PrincipalKindName,
) -> Fresh | Replay:
    outcome = await store.begin(
        tenant_id, principal_id, route, key, request_sha256, principal_kind=principal_kind
    )
    if isinstance(outcome, Fresh | Replay):
        return outcome
    if isinstance(outcome, ReplayUnavailable):
        raise ProblemError("idempotent_replay_unavailable")
    if isinstance(outcome, InProgress):
        raise ProblemError("idempotency_in_progress")
    if isinstance(outcome, Mismatch):
        raise ProblemError("idempotency_key_reuse")
    raise ProblemError("not_found")


def encode_body(body: bytes) -> dict[str, Any] | None:
    """``response_body`` jsonb: the JSON document, base64 for anything else (including JSON that
    holds U+0000, which jsonb rejects), or only a hash when the body is over 64 KB (G0-8)."""
    if not body:
        return None
    if len(body) > MAX_STORED_BODY_BYTES:
        return {"omitted": True, "sha256": hashlib.sha256(body).hexdigest(), "length": len(body)}
    try:
        document = json.loads(body)
        if "\\u0000" not in json.dumps(document):
            return {"json": document}
    except (ValueError, UnicodeDecodeError, RecursionError):
        pass
    return {"base64": base64.b64encode(body).decode("ascii")}


def decode_body(stored: Mapping[str, Any] | None) -> bytes | None:
    """The replayable body, or ``None`` when only its hash was kept."""
    if not stored:
        return b""
    if stored.get("omitted"):
        return None
    if "base64" in stored:
        return base64.b64decode(stored["base64"])
    return json.dumps(stored["json"], separators=(",", ":"), ensure_ascii=False).encode()


def _outcome_for(response: StoredResponse) -> Replay | ReplayUnavailable:
    if len(response.body) > MAX_STORED_BODY_BYTES:
        digest = hashlib.sha256(response.body).digest()
        return ReplayUnavailable(response.status, dict(response.headers), digest)
    return Replay(response)


@dataclass(frozen=True)
class _Entry:
    principal_kind: str
    principal_id: UUID
    request_sha256: bytes
    expires_at: datetime
    claim_id: UUID
    outcome: Replay | ReplayUnavailable | None = None
    started_at: datetime | None = None


def _classify(
    entry: _Entry, principal_kind: str, principal_id: UUID, request_sha256: bytes
) -> Replay | ReplayUnavailable | InProgress | Mismatch | ForeignKey:
    if entry.principal_id != principal_id or entry.principal_kind != principal_kind:
        return ForeignKey()
    if entry.request_sha256 != request_sha256:
        return Mismatch()
    if entry.outcome is None:
        return InProgress()
    return entry.outcome


class InMemoryIdempotencyStore:
    """Process-local store for tests and single-replica dev."""

    def __init__(self, clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._clock = clock
        self._entries: dict[tuple[UUID, str, str], _Entry] = {}

    async def begin(
        self,
        tenant_id: UUID,
        principal_id: UUID,
        route: str,
        key: str,
        request_sha256: bytes,
        *,
        principal_kind: PrincipalKindName,
    ) -> BeginOutcome:
        _check_kind(principal_kind)
        now = self._clock()
        slot = (tenant_id, route, key)
        entry = self._entries.get(slot)
        stale = (
            entry is not None
            and entry.outcome is None
            and entry.started_at is not None
            and now - entry.started_at > IN_PROGRESS_STALE_AFTER
        )
        if entry is not None and entry.expires_at > now and not stale:
            return _classify(entry, principal_kind, principal_id, request_sha256)
        claim = uuid4()
        self._entries[slot] = _Entry(
            principal_kind, principal_id, request_sha256, now + IDEMPOTENCY_TTL, claim, None, now
        )
        return Fresh(RecordKey(tenant_id, route, key, claim))

    def _held(self, token: RecordKey) -> _Entry | None:
        entry = self._entries.get((token.tenant_id, token.route, token.key))
        if entry is None or entry.claim_id != token.claim_id or entry.outcome is not None:
            return None
        return entry

    async def complete(self, token: RecordKey, response: StoredResponse) -> None:
        entry = self._held(token)
        if entry is None:
            raise IdempotencyClaimLost()
        slot = (token.tenant_id, token.route, token.key)
        self._entries[slot] = _Entry(
            entry.principal_kind,
            entry.principal_id,
            entry.request_sha256,
            entry.expires_at,
            entry.claim_id,
            _outcome_for(response),
            entry.started_at,
        )

    async def abandon(self, token: RecordKey) -> bool:
        if self._held(token) is None:
            log.warning("idempotency abandon after the claim was lost (%s)", token.route)
            return False
        del self._entries[(token.tenant_id, token.route, token.key)]
        return True


class _TenantDatabase(Protocol):
    def tenant_tx(self, tenant_id: UUID) -> Any: ...


# The real table (0011_lifecycle, chair ruling G0-2): unique (tenant_id, route, idempotency_key),
# not partitioned; sibyl_app holds SELECT/INSERT/UPDATE but not DELETE (retention owns that).
# ``claim_id uuid NOT NULL`` fences complete/abandon (code review M5, FIX-DB migration).
_SELECT = """
SELECT principal_kind, principal_id, request_sha256, state, status_code, response_headers,
       response_body, claim_id,
       expires_at > now()
       AND NOT (state = 'in_progress' AND created_at < now() - $4::interval) AS live
  FROM sibyl.idempotency_record
 WHERE tenant_id = $1 AND route = $2 AND idempotency_key = $3
 FOR UPDATE
"""
# Claims the key unless a live record holds it (then RETURNING is empty): overwrites only an
# expired, abandoned or stale in-progress record, and always with a new claim_id.
_CLAIM = """
INSERT INTO sibyl.idempotency_record AS r
       (tenant_id, route, idempotency_key, principal_kind, principal_id, request_sha256, state,
        expires_at, claim_id)
VALUES ($1, $2, $3, $5, $6, $7, 'in_progress', clock_timestamp() + $8::interval, $9)
ON CONFLICT (tenant_id, route, idempotency_key) DO UPDATE
   SET principal_kind = EXCLUDED.principal_kind, principal_id = EXCLUDED.principal_id,
       request_sha256 = EXCLUDED.request_sha256, state = 'in_progress', status_code = NULL,
       response_headers = '{}', response_body = NULL, completed_at = NULL,
       created_at = clock_timestamp(), expires_at = EXCLUDED.expires_at,
       claim_id = EXCLUDED.claim_id
 WHERE r.expires_at <= now()
    OR (r.state = 'in_progress' AND r.created_at < now() - $4::interval)
RETURNING claim_id
"""
_COMPLETE = """
UPDATE sibyl.idempotency_record
   SET state = 'done', status_code = $5, response_headers = $6, response_body = $7,
       completed_at = clock_timestamp()
 WHERE tenant_id = $1 AND route = $2 AND idempotency_key = $3 AND claim_id = $4
   AND state = 'in_progress'
RETURNING id
"""
_ABANDON = """
UPDATE sibyl.idempotency_record
   SET expires_at = greatest(created_at + interval '1 microsecond', clock_timestamp())
 WHERE tenant_id = $1 AND route = $2 AND idempotency_key = $3 AND claim_id = $4
   AND state = 'in_progress'
RETURNING id
"""

_UNSTORED_HEADERS = frozenset({"content-length"})


def _row_entry(row: Any) -> _Entry:
    outcome: Replay | ReplayUnavailable | None = None
    if row["state"] == "done":
        headers = dict(row["response_headers"] or {})
        status = int(row["status_code"])
        stored = row["response_body"]
        body = decode_body(stored)
        if body is None:
            outcome = ReplayUnavailable(status, headers, bytes.fromhex(stored["sha256"]))
        else:
            outcome = Replay(StoredResponse(status, headers, body))
    return _Entry(
        row["principal_kind"],
        row["principal_id"],
        bytes(row["request_sha256"]),
        datetime.max.replace(tzinfo=UTC),
        row["claim_id"],
        outcome,
    )


class PgIdempotencyStore:
    """Postgres store over ``sibyl.idempotency_record``; each call is a short tenant transaction.

    A JSON response body is stored as the document (replayed in compact form, so key order and
    whitespace may differ from the first response, G0-8); any other body is stored base64, and a
    body over 64 KB as its hash only. The claim is an upsert that only overwrites an expired,
    abandoned or stale record, so two concurrent first uses of a key cannot both execute.
    """

    def __init__(self, database: _TenantDatabase) -> None:
        self._db = database

    async def begin(
        self,
        tenant_id: UUID,
        principal_id: UUID,
        route: str,
        key: str,
        request_sha256: bytes,
        *,
        principal_kind: PrincipalKindName,
    ) -> BeginOutcome:
        _check_kind(principal_kind)
        args = (tenant_id, route, key, IN_PROGRESS_STALE_AFTER)
        async with self._db.tenant_tx(tenant_id) as conn:
            row = await conn.fetchrow(_SELECT, *args)
            if row is not None and row["live"]:
                return _classify(_row_entry(row), principal_kind, principal_id, request_sha256)
            claimed = await conn.fetchval(
                _CLAIM,
                *args,
                principal_kind,
                principal_id,
                request_sha256,
                IDEMPOTENCY_TTL,
                uuid4(),
            )
            if claimed is None:  # a concurrent first use won the race
                row = await conn.fetchrow(_SELECT, *args)
                return _classify(_row_entry(row), principal_kind, principal_id, request_sha256)
        return Fresh(RecordKey(tenant_id, route, key, claimed))

    async def complete(self, token: RecordKey, response: StoredResponse) -> None:
        async with self._db.tenant_tx(token.tenant_id) as conn:
            await self.complete_in(conn, token, response)

    @staticmethod
    async def complete_in(conn: Any, token: RecordKey, response: StoredResponse) -> None:
        """Record the response inside the handler's own transaction (preferred: atomic).

        Raises ``IdempotencyClaimLost`` when this request no longer holds the claim, which rolls
        the handler's transaction back.
        """
        headers = {k: v for k, v in response.headers.items() if k.lower() not in _UNSTORED_HEADERS}
        updated = await conn.fetchval(
            _COMPLETE,
            token.tenant_id,
            token.route,
            token.key,
            token.claim_id,
            response.status,
            headers,
            encode_body(response.body),
        )
        if updated is None:
            raise IdempotencyClaimLost()

    async def abandon(self, token: RecordKey) -> bool:
        """Release a key whose request failed: expire the in-progress record (no DELETE grant).

        Returns False (and changes nothing) when the claim was already lost to a newer request.
        """
        async with self._db.tenant_tx(token.tenant_id) as conn:
            released = await conn.fetchval(
                _ABANDON, token.tenant_id, token.route, token.key, token.claim_id
            )
        if released is None:
            log.warning("idempotency abandon after the claim was lost (%s)", token.route)
            return False
        return True
