"""Async jobs, the enqueue side (chair ruling B14).

The api never does slow or network-bound work inline: a handler enqueues a ``sibyl.job`` row
(state ``queued``) and an outbox ``job.requested`` (topic ``job``, the ``sibyl_outbox`` channel
wakes the worker's ``jobs`` loop) in its own tenant transaction, then answers 202 with the job id.
At most one job per ``(kind, subject)`` is open at a time: a second request returns the job
already in flight. ``GET /api/v1/jobs/{id}`` shows it to its requester only (``job_owner``).
The worker side (claim with SKIP LOCKED, lease, retry with back-off) is ``worker/jobs``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sibyl_schemas.values import JobKind, JobState

from .authz import Principal, PrincipalKind
from .outbox import OutboxMessage, OutboxWriter

DEFAULT_MAX_ATTEMPTS = 5
JOB_REQUESTED = "job.requested"


@dataclass(frozen=True)
class Requester:
    """Who asked: ``human`` (user id), ``api_key`` (key id) or the worker (``system``)."""

    kind: str
    id: UUID | None

    @classmethod
    def of(cls, principal: Principal) -> Requester:
        if principal.kind is PrincipalKind.API_KEY:
            return cls("api_key", principal.id)
        return cls("human", principal.id)

    @classmethod
    def system(cls) -> Requester:
        return cls("system", None)


@dataclass(frozen=True)
class Enqueued:
    id: UUID
    created: bool  # False: an open job for the same subject already existed


_INSERT_SQL = """
INSERT INTO sibyl.job (tenant_id, kind, params, max_attempts, requested_by, requested_by_kind,
                       subject_kind, subject_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, kind, subject_kind, subject_id)
   WHERE state IN ('queued', 'running') AND subject_id IS NOT NULL
DO NOTHING
RETURNING id
"""
_OPEN_SQL = """
SELECT id FROM sibyl.job
 WHERE tenant_id = $1 AND kind = $2 AND subject_kind = $3 AND subject_id = $4
   AND state IN ('queued', 'running')
"""


async def enqueue_job(
    conn: Any,
    outbox: OutboxWriter,
    tenant_id: UUID,
    *,
    kind: JobKind,
    requester: Requester,
    params: Mapping[str, Any] | None = None,
    subject: tuple[str, UUID] | None = None,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> Enqueued:
    """Enqueue on the caller's tenant transaction (``job`` row + ``job.requested``)."""
    subject_kind, subject_id = subject if subject is not None else (None, None)
    job_id = await conn.fetchval(
        _INSERT_SQL,
        tenant_id,
        JobKind(kind).value,
        plain_json(params or {}),
        max_attempts,
        requester.id,
        requester.kind,
        subject_kind,
        subject_id,
    )
    if job_id is None:
        existing = await conn.fetchval(_OPEN_SQL, tenant_id, kind, subject_kind, subject_id)
        if existing is not None:
            return Enqueued(existing, False)
        raise RuntimeError("job conflict without an open job")  # pragma: no cover (race)
    await outbox.emit(
        conn,
        tenant_id,
        OutboxMessage.for_event(
            JOB_REQUESTED,
            "job",
            job_id,
            {"job_id": job_id, "kind": JobKind(kind).value},
            idempotency_key=f"job:{job_id}",
        ),
    )
    return Enqueued(job_id, True)


def plain_json(value: Mapping[str, Any]) -> dict[str, Any]:
    """A JSON-safe copy (UUIDs and datetimes as strings) for a jsonb column."""
    out: dict[str, Any] = json.loads(json.dumps(dict(value), default=str))
    return out


def _ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def job_view(row: Mapping[str, Any]) -> dict[str, Any]:
    """The ``Job`` resource (OpenAPI ``components.schemas.Job``); params are never echoed."""
    return {
        "id": str(row["id"]),
        "kind": row["kind"],
        "state": JobState(row["state"]).value,
        "result": _json(row["result"]),
        "error": row["error"],
        "attempts": row["attempts"],
        "requested_by": str(row["requested_by"]) if row["requested_by"] else None,
        "created_at": _ts(row["created_at"]),
        "updated_at": _ts(row["updated_at"]),
        "started_at": _ts(row["started_at"]),
        "finished_at": _ts(row["finished_at"]),
    }
