"""Transactional outbox writer (ADR-4, R58 X1/X2).

~12 coarse topics carry fine ``event_type`` values; the DB trigger NOTIFYs on exactly two
channels, ``sibyl_policy`` (policy, killswitch) and ``sibyl_outbox`` (everything else), with a
constant payload. Payloads are refs and versions only (≤ 8 KB, no content keys); SSE consumers
re-fetch through authorised GETs. Nothing is visible before the writing transaction commits.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol
from uuid import UUID, uuid4

from sibyl_schemas import values as sv

from .audit import FORBIDDEN_DETAIL_KEYS
from .canonical import canonical_document, thaw

# Topics, channels and the event_type -> topic map are ``sibyl_schemas.values`` (R58 X1/X2).
TOPICS: tuple[str, ...] = tuple(topic.value for topic in sv.OutboxTopic)
POLICY_CHANNEL: str = sv.NotifyChannel.POLICY.value
OUTBOX_CHANNEL: str = sv.NotifyChannel.OUTBOX.value
_POLICY_TOPICS = frozenset(
    topic.value for topic, channel in sv.TOPIC_CHANNEL.items() if channel is sv.NotifyChannel.POLICY
)
MAX_PAYLOAD_BYTES = 8 * 1024
_EVENT_TYPE_RE = re.compile(r"^[a-z_]+(\.[a-z_]+)?$")

# SSE ``event:`` name (API.md §7) plus the worker-only event types -> outbox topic. ``reset`` is a
# control frame with no row.
EVENT_TOPICS: Mapping[str, str] = MappingProxyType(
    {event: topic.value for event, topic in sv.OUTBOX_EVENT_TOPIC.items()}
)


def channel_for(topic: str) -> str:
    if topic not in TOPICS:
        raise ValueError(f"unknown outbox topic {topic!r}")
    return POLICY_CHANNEL if topic in _POLICY_TOPICS else OUTBOX_CHANNEL


def _check_refs_only(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_DETAIL_KEYS:
                raise ValueError(f"content key {key!r} is not allowed in an outbox payload")
            _check_refs_only(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _check_refs_only(item)


@dataclass(frozen=True)
class OutboxMessage:
    """One outbox row. Validated once at construction, then immutable.

    ``topic`` must be the topic that owns ``event_type`` in ``EVENT_TOPICS`` (a mismatch would
    NOTIFY the wrong channel, code review H3); ``for_event`` derives it. ``payload`` becomes a
    frozen plain-JSON copy (UUIDs as strings) and ``canonical`` its JCS bytes, which is what is
    size-checked and written (code review M3). ``idempotency_key`` is stored for tracing only:
    the table's unique key includes ``created_at``, so it does not de-duplicate (code review L1).
    """

    topic: str
    event_type: str
    aggregate_kind: str
    aggregate_id: UUID
    payload: Mapping[str, Any] = field(default_factory=dict)
    idempotency_key: str | None = None
    canonical: bytes = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.topic not in TOPICS:
            raise ValueError(f"unknown outbox topic {self.topic!r}")
        if not _EVENT_TYPE_RE.fullmatch(self.event_type):
            raise ValueError(f"bad event_type {self.event_type!r}")
        owner = EVENT_TOPICS.get(self.event_type)
        if owner is None:
            raise ValueError(f"undeclared outbox event_type {self.event_type!r}")
        if owner != self.topic:
            raise ValueError(
                f"event_type {self.event_type!r} belongs to topic {owner!r}, not {self.topic!r}"
            )
        _check_refs_only(self.payload)
        canonical, frozen = canonical_document(self.payload)
        if len(canonical) > MAX_PAYLOAD_BYTES:
            raise ValueError("outbox payload exceeds 8 KB")
        if self.aggregate_id is None:
            raise ValueError("outbox rows name their aggregate (aggregate_id is NOT NULL)")
        object.__setattr__(self, "canonical", canonical)
        object.__setattr__(self, "payload", frozen)

    @classmethod
    def for_event(
        cls,
        event_type: str,
        aggregate_kind: str,
        aggregate_id: UUID,
        payload: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> OutboxMessage:
        """Build a message whose topic is the one ``EVENT_TOPICS`` assigns to ``event_type``."""
        topic = EVENT_TOPICS.get(event_type)
        if topic is None:
            raise ValueError(f"undeclared outbox event_type {event_type!r}")
        return cls(topic, event_type, aggregate_kind, aggregate_id, payload or {}, idempotency_key)


class OutboxWriter(Protocol):
    async def emit(self, conn: Any, tenant_id: UUID, message: OutboxMessage) -> None: ...


_INSERT_SQL = (
    "INSERT INTO sibyl.outbox"
    " (tenant_id, topic, event_type, aggregate_kind, aggregate_id, payload, idempotency_key)"
    " VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)"
)


class PgOutboxWriter:
    """Inserts on the caller's connection, inside the caller's tenant transaction.

    ``id``, ``created_at`` and ``xid`` (R60) are column defaults of ``sibyl.outbox``. The table's
    ``idempotency_key`` is NOT NULL; a message without one gets a unique ``outbox:<uuid>`` key
    (no de-duplication is requested, so none is implied).
    """

    async def emit(self, conn: Any, tenant_id: UUID, message: OutboxMessage) -> None:
        await conn.execute(
            _INSERT_SQL,
            tenant_id,
            message.topic,
            message.event_type,
            message.aggregate_kind,
            message.aggregate_id,
            thaw(message.payload),
            message.idempotency_key or f"outbox:{uuid4()}",
        )


class InMemoryOutboxWriter:
    def __init__(self) -> None:
        self._messages: dict[UUID, list[OutboxMessage]] = {}

    async def emit(self, conn: Any, tenant_id: UUID, message: OutboxMessage) -> None:
        self._messages.setdefault(tenant_id, []).append(message)

    def messages(self, tenant_id: UUID) -> list[OutboxMessage]:
        return list(self._messages.get(tenant_id, []))
