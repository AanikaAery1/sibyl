"""Audit interface: one ``sibyl.audit_append()`` call per state-changing handler, same transaction.

The api never computes the chain; Postgres does (DATAMODEL §5). The api canonicalises ``detail``
(JCS, float-free) and passes both the JSON and its canonical bytes; ``audit_append`` checks they
agree. ``X-Sibyl-Audit-Receipt: <tenant>:<seq>:<hash>`` goes on every 2xx that wrote a row.

The audit taxonomy (action → allowed actor types, required detail keys) is imported from
``sibyl_schemas.values.AUDIT_ACTIONS``; ``tests/db`` diffs it against the seeded ``audit_action``
rows. ``audit_actor()`` is the one place a principal becomes an audit actor: a break-glass key is
recorded as ``api_key`` with its key id, never as ``system``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from sibyl_schemas import values as sv

from .authz import Principal, PrincipalKind
from .canonical import canonical_document, thaw

RECEIPT_HEADER = "X-Sibyl-Audit-Receipt"
MAX_DETAIL_BYTES = 8 * 1024
FORBIDDEN_DETAIL_KEYS: frozenset[str] = frozenset(key.lower() for key in sv.AUDIT_CONTENT_KEYS)
"""Content keys refused anywhere in audit detail and outbox payloads, case-insensitively and at
any depth (T2). The list is ``sibyl_schemas.values.AUDIT_CONTENT_KEYS``, the same one the
database's ``audit_append`` / telemetry checks are generated against (code review M4). A
``content_hashes`` map of SHA-256 digests is exempt (``sv.is_hash_only_subtree``), as in the DB."""
ACTOR_TYPES: frozenset[str] = frozenset(actor.value for actor in sv.ActorType)
AUDIT_ACTIONS: frozenset[str] = sv.AUDIT_ACTION_NAMES
"""The taxonomy is ``sibyl_schemas.values.AUDIT_ACTIONS`` (G0 single source)."""


def _check_keys(value: object, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if sv.is_hash_only_subtree(key, item):
                continue  # content_hashes: digests of content, never content (INT-1)
            if str(key).lower() in FORBIDDEN_DETAIL_KEYS:
                raise ValueError(f"content key {key!r} is not allowed in audit detail ({path})")
            _check_keys(item, f"{path}/{key}")
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _check_keys(item, f"{path}/{index}")


def checked_detail(detail: Mapping[str, Any]) -> tuple[bytes, Mapping[str, Any]]:
    """JCS bytes and a frozen copy of ``detail``; refuses content keys (T2), floats, astral
    object keys and anything over 8 KB canonical."""
    _check_keys(detail, "")
    canonical, frozen = canonical_document(detail)
    if len(canonical) > MAX_DETAIL_BYTES:
        raise ValueError("audit detail exceeds 8 KB")
    return canonical, frozen


def canonical_detail(detail: Mapping[str, Any]) -> bytes:
    """JCS bytes of ``detail`` (see ``checked_detail``)."""
    return checked_detail(detail)[0]


@dataclass(frozen=True)
class AuditRecord:
    action: str
    actor_type: str
    resource_type: str
    actor_id: UUID | None = None
    actor_key_id: UUID | None = None
    actor_session_id: UUID | None = None
    resource_id: UUID | None = None
    resource_ref: str | None = None
    reason: str | None = None
    detail: Mapping[str, Any] = field(default_factory=dict)
    occurred_at: datetime | None = None
    request_id: UUID | None = None
    canonical: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate once; ``detail`` is then a frozen plain-JSON copy (UUIDs as strings) and
        ``canonical`` its JCS bytes, so the writer never re-serialises (code review M3)."""
        canonical, frozen = checked_detail(self.detail)
        object.__setattr__(self, "canonical", canonical)
        object.__setattr__(self, "detail", frozen)
        spec = sv.AUDIT_ACTIONS.get(self.action)
        if spec is None:
            raise ValueError(f"undeclared audit action {self.action!r}")
        if self.actor_type not in ACTOR_TYPES:
            raise ValueError(f"unknown actor_type {self.actor_type!r}")
        if self.actor_type not in spec.actor_types:
            raise ValueError(f"actor_type {self.actor_type!r} is not allowed for {self.action}")


@dataclass(frozen=True)
class AuditActor:
    """The actor columns of one audit row."""

    actor_type: str
    actor_id: UUID | None
    actor_key_id: UUID | None
    actor_session_id: UUID | None

    def fields(self) -> dict[str, Any]:
        return {
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "actor_key_id": self.actor_key_id,
            "actor_session_id": self.actor_session_id,
        }


def audit_actor(principal: Principal) -> AuditActor:
    """Who a principal's own actions are attributed to.

    Humans are ``human`` with their user and session ids. Every API-key principal (agent-bound,
    hosted gateway, break-glass) acts in its own name as ``api_key`` with ``actor_key_id``
    (chair rulings G0-4, G0-6); ``system`` is reserved for the worker.
    """
    if principal.kind is not PrincipalKind.API_KEY:
        return AuditActor(sv.ActorType.HUMAN.value, principal.id, None, principal.session_id)
    return AuditActor(sv.ActorType.API_KEY.value, None, principal.id, None)


@dataclass(frozen=True)
class AuditReceipt:
    tenant_id: UUID
    seq: int
    hash: bytes

    def header_value(self) -> str:
        return f"{self.tenant_id}:{self.seq}:{self.hash.hex()}"

    @classmethod
    def parse(cls, value: str) -> AuditReceipt:
        tenant, seq, digest = value.rsplit(":", 2)
        return cls(UUID(tenant), int(seq), bytes.fromhex(digest))


class AuditWriter(Protocol):
    async def append(self, conn: Any, tenant_id: UUID, record: AuditRecord) -> AuditReceipt: ...


_APPEND_SQL = (
    "SELECT seq, hash, recorded_at FROM sibyl.audit_append("
    "$1::uuid, $2::text, $3::uuid, $4::uuid, $5::uuid, $6::text, $7::text, $8::uuid, $9::text,"
    " $10::text, $11::jsonb, $12::bytea, $13::timestamptz, $14::uuid)"
)


class PgAuditWriter:
    """Calls ``sibyl.audit_append`` (signature per DATAMODEL §5) on the handler's connection."""

    async def append(self, conn: Any, tenant_id: UUID, record: AuditRecord) -> AuditReceipt:
        row = await conn.fetchrow(
            _APPEND_SQL,
            tenant_id,
            record.actor_type,
            record.actor_id,
            record.actor_key_id,
            record.actor_session_id,
            record.action,
            record.resource_type,
            record.resource_id,
            record.resource_ref,
            record.reason,
            thaw(record.detail),
            record.canonical,
            record.occurred_at,
            record.request_id,
        )
        return AuditReceipt(tenant_id, int(row["seq"]), bytes(row["hash"]))


class InMemoryAuditWriter:
    """Test double with a per-tenant sha256 chain; records every appended row."""

    def __init__(self) -> None:
        self._rows: dict[UUID, list[tuple[AuditRecord, AuditReceipt]]] = {}

    async def append(self, conn: Any, tenant_id: UUID, record: AuditRecord) -> AuditReceipt:
        rows = self._rows.setdefault(tenant_id, [])
        prev = rows[-1][1].hash if rows else bytes(32)
        digest = hashlib.sha256(prev + record.canonical).digest()
        receipt = AuditReceipt(tenant_id, len(rows) + 1, digest)
        rows.append((record, receipt))
        return receipt

    def records(self, tenant_id: UUID) -> list[AuditRecord]:
        return [record for record, _ in self._rows.get(tenant_id, [])]

    def actions(self, tenant_id: UUID) -> list[str]:
        return [record.action for record in self.records(tenant_id)]

    def all_actions(self) -> list[str]:
        return [r.action for rows in self._rows.values() for r, _ in rows]


def access_denied(
    *,
    permission: str,
    resource_type: str,
    resource_id: UUID | None,
    actor_type: str,
    actor_id: UUID | None,
    actor_key_id: UUID | None = None,
    actor_session_id: UUID | None = None,
    request_id: UUID | None = None,
) -> AuditRecord:
    """The ``access.denied`` row written when ``authorize`` refuses (taxonomy: actor S)."""
    return AuditRecord(
        action="access.denied",
        actor_type="system",
        resource_type=resource_type,
        resource_id=resource_id,
        actor_id=actor_id,
        actor_key_id=actor_key_id,
        actor_session_id=actor_session_id,
        detail={
            "permission": permission,
            "resource_type": resource_type,
            "resource_id": str(resource_id) if resource_id else None,
            "principal_type": actor_type,
        },
        request_id=request_id,
    )
