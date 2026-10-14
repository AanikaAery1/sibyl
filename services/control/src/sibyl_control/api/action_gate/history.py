"""The decision trail of a held action (lane AG-LIVE): ``held_action.history``, one entry per
event, returned on single-object reads (``HeldActionHistoryEntry``).

Kinds: ``requested`` / ``blocked`` (created pending / denied by the control plane's own block),
``approval`` (a four-eyes first approval), ``refused`` (an attempt refused 409 with ``code``:
``self_approval`` or ``duplicate_approver``), ``approved``, ``denied``, ``expired`` (the worker).
Entries are appended in the transaction that makes the change, except a refused attempt: its
request transaction rolls back, so it is appended afterwards in its own transaction, at most
until the trail holds ``REFUSALS_UNTIL`` entries (the row allows 64, so the decision and the
expiry always fit; every refusal is audited ``access.denied`` regardless).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any
from uuid import UUID

from ..deps import AuthContext
from ..registry._kit import require_db, services_of

log = logging.getLogger("sibyl.api.action_gate")
REFUSALS_UNTIL = 49
RECORDED_REFUSALS = frozenset({"self_approval", "duplicate_approver"})
REASON_MAX = 500
EXPIRY_REASON = "hold timeout; default deny"


def stamp(at: datetime) -> str:
    return at.isoformat().replace("+00:00", "Z")


def entry(
    kind: str,
    at: datetime,
    *,
    user_id: UUID | None = None,
    key_id: UUID | None = None,
    reason: str | None = None,
    step_up: bool = False,
    code: str | None = None,
    approvals: int | None = None,
) -> dict[str, Any]:
    """One ``HeldActionHistoryEntry``; every member is always present."""
    return {
        "at": stamp(at),
        "kind": kind,
        "user_id": None if user_id is None else str(user_id),
        "key_id": None if key_id is None else str(key_id),
        "reason": None if reason is None else reason[:REASON_MAX],
        "step_up": step_up,
        "code": code,
        "approvals": approvals,
    }


async def record_refusal(ctx: AuthContext, held_action_id: UUID, reason: str, code: str) -> None:
    """Append a ``refused`` entry to a still-pending hold. Never masks the refusal: a failure
    here is logged and the 409 stands."""
    principal = ctx.principal
    if principal is None:  # pragma: no cover - the route always has a principal
        return

    async def work(conn: Any) -> None:
        now = await conn.fetchval("SELECT now()")
        refused = entry("refused", now, user_id=principal.id, reason=reason.strip(), code=code)
        await conn.execute(
            "UPDATE sibyl.held_action SET history = history || $3::jsonb"
            " WHERE tenant_id = $1 AND id = $2 AND state = 'pending'"
            " AND jsonb_array_length(history) < $4",
            ctx.tenant_id,
            held_action_id,
            [refused],
            REFUSALS_UNTIL,
        )

    try:
        await require_db(services_of(ctx)).run_in_tenant_tx(ctx.tenant_id, work)
    except Exception:
        log.warning("refused attempt on held action %s not recorded", held_action_id, exc_info=True)
