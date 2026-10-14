"""The failover saga steps (API.md §6.2): validate → check_viability → write_routing →
create_handoff_tasks → mark_alert_actioned → done.

``advance`` runs exactly one step on a row the caller has locked, inside a savepoint, and
persists the result (``step``, ``step_results``, ``state``) in the caller's transaction. Every
step is idempotent: results are keyed by step name, ``write_routing`` passes a deterministic
idempotency key to ``routing_apply`` and handoff tasks are unique per ``(failover, task)``, so a
crash between steps resumes at the recorded step without double effects.

* The worker calls ``advance`` once per transaction (resumable after a crash).
* The api calls ``drive`` inline in the request transaction; a step it may not do
  (``create_handoff_tasks`` with tasks to build, which needs the worker role) yields: the row
  stays ``running`` with an expired claim so the worker resumes it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from datetime import timedelta
from typing import Any
from uuid import UUID

from . import routing
from .model import CLAIM_LOCK, RETRY_BASE_S, RETRY_MAX_S, SYSTEM, Env, SagaError

# The steps and row plumbing live in ``rows`` / ``steps_prepare`` / ``steps_commit``; every name
# stays importable from here (callers and tests address the saga through ``engine``).
from .rows import FAILOVER_FROM as FAILOVER_FROM
from .rows import OPERATOR_FROM as OPERATOR_FROM
from .rows import Progress as Progress
from .rows import Row as Row
from .rows import _agent as _agent
from .rows import _alerts as _alerts
from .rows import _audit as _audit
from .rows import _uuid as _uuid
from .rows import allowed_from as allowed_from
from .rows import cancel_approval as cancel_approval
from .rows import finish as finish
from .rows import load as load
from .rows import opened as opened
from .rows import results as results
from .rows import saga_actor as saga_actor
from .rows import save as save
from .rows import with_result as with_result
from .steps_commit import RoutingPlan as RoutingPlan
from .steps_commit import _recheck_viability as _recheck_viability
from .steps_commit import _routing_plan as _routing_plan
from .steps_commit import _rto as _rto
from .steps_commit import step_create_handoff_tasks as step_create_handoff_tasks
from .steps_commit import step_mark_alert_actioned as step_mark_alert_actioned
from .steps_commit import step_write_routing as step_write_routing
from .steps_prepare import _prediction_persisted as _prediction_persisted
from .steps_prepare import _revert_degrade as _revert_degrade
from .steps_prepare import breaker_open as breaker_open
from .steps_prepare import failure_mode_of as failure_mode_of
from .steps_prepare import request_approval as request_approval
from .steps_prepare import step_check_viability as step_check_viability
from .steps_prepare import step_validate as step_validate
from .steps_prepare import suppress_for_hold as suppress_for_hold

log = logging.getLogger("sibyl.saga")


StepFn = Callable[[Any, Env, UUID, Row], Awaitable[tuple[Row, Progress]]]
STEP_FUNCTIONS: Mapping[str, StepFn] = {
    "validate": step_validate,
    "check_viability": step_check_viability,
    "write_routing": step_write_routing,
    "create_handoff_tasks": step_create_handoff_tasks,
    "mark_alert_actioned": step_mark_alert_actioned,
}


def backoff(attempt: int) -> timedelta:
    return timedelta(seconds=min(RETRY_MAX_S, RETRY_BASE_S * 2 ** max(0, attempt - 1)))


async def advance(conn: Any, env: Env, tenant: UUID, row: Row) -> tuple[Row, Progress]:
    """One step on a locked, runnable row. Refusals fail (or retry) the saga; never raise."""
    step = row["step"]
    fn = STEP_FUNCTIONS.get(step)
    if fn is None or row["state"] in ("done", "failed", "cancelled", "waiting_approval"):
        return row, Progress("done" if row["state"] == "done" else row["state"], step)
    try:
        try:
            async with conn.transaction():
                return await fn(conn, env, tenant, row)
        except SagaError:
            raise
        except Exception as unexpected:
            # A poison step must not block the tenant: the savepoint is rolled back and the
            # saga takes the retry path, failing after max_attempts.
            log.exception("saga %s step %s failed unexpectedly", row["id"], step)
            raise SagaError("internal_error", type(unexpected).__name__, retryable=True) from None
    except SagaError as exc:
        fresh = await load(conn, tenant, row["id"]) or row
        attempt = int(fresh["attempt"]) + 1
        if exc.retryable and attempt < int(fresh["max_attempts"]):
            delay = backoff(attempt)
            fresh = await save(
                conn,
                env,
                tenant,
                fresh,
                attempt=attempt,
                error=exc.code,
                claim_lock_until=None,
                next_action_at=await conn.fetchval("SELECT now() + $1::interval", delay),
            )
            return fresh, Progress("retry", step, exc.code)
        fresh = await save(
            conn,
            env,
            tenant,
            fresh,
            attempt=min(attempt, int(fresh["max_attempts"])),
            step_results=with_result(
                fresh, "error", {"step": step, "code": exc.code, **exc.extensions}
            ),
        )
        fresh = await finish(conn, env, tenant, fresh, "failed", exc.code)
        await release_awaiting(conn, env, tenant, fresh)
        return fresh, Progress("failed", step, exc.code)


async def release_awaiting(conn: Any, env: Env, tenant: UUID, row: Row) -> None:
    """A failed saga never strands its agent in ``awaiting_approval``: back to ``degraded``."""
    state = await routing.state_of(conn, tenant, row["agent_id"])
    if state is None or state["state"] != "awaiting_approval":
        return
    if row.get("approval_id") is None or state["approval_id"] != row["approval_id"]:
        return
    try:
        await routing.apply(
            conn,
            tenant,
            row["agent_id"],
            expected_from="awaiting_approval",
            to_state="degraded",
            trigger="approval_timeout",
            actor=SYSTEM,
            idempotency_key=f"failover:{row['id']}:released_after_failure",
            audit_action="route.changed",
            failover_id=row["id"],
            approval_id=row["approval_id"],
            reason=f"saga failed ({row.get('error')}); approval no longer pending",
        )
    except SagaError:
        log.warning("could not release agent %s from awaiting_approval", row["agent_id"])


async def drive(
    conn: Any, env: Env, tenant: UUID, failover_id: UUID, *, max_steps: int = 8
) -> tuple[Row, Progress]:
    """Run steps inline until the saga waits, yields to the worker or ends (the api path).

    A step refusal raises ``SagaError`` so the request transaction rolls back (409)."""
    row = await load(conn, tenant, failover_id)
    if row is None:
        raise SagaError("not_found")
    runnable = row["state"] in ("pending", "running")
    progress = Progress("continue" if runnable else row["state"], row["step"])
    for _ in range(max_steps):
        fn = STEP_FUNCTIONS.get(row["step"])
        if fn is None or row["state"] not in ("pending", "running"):
            break
        row, progress = await fn(conn, env, tenant, row)
        if progress.status != "continue":
            break
    return row, progress


async def claim_lock(conn: Any) -> Any:
    return await conn.fetchval("SELECT now() + $1::interval", CLAIM_LOCK)
