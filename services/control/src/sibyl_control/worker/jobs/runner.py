"""The jobs worker loop (chair ruling B14): claim, run outside any transaction, finish fenced.

Per tenant and tick:

1. **expire**: a ``running`` job whose lease ran out with no attempts left is failed
   (``lease_expired``), with the handler's exhaustion audits;
2. **claim**: up to ``batch`` runnable jobs of a kind this worker has a handler for (``queued``
   and due, or ``running`` with an expired lease and attempts left) are taken with
   ``FOR UPDATE SKIP LOCKED``, so concurrent workers never claim the same row; each claim bumps
   ``attempts`` and sets a lease;
3. **run** each job outside any transaction (network work never holds a row lock) under a
   deadline shorter than the lease;
4. **finish** in its own tenant transaction, ``audit_lock`` first, fenced by
   ``state = 'running' AND attempts = <claimed attempts>``: a worker that lost its lease writes
   nothing, so a job's outcome and audits are recorded exactly once (idempotent). A retryable
   outcome goes back to ``queued`` with exponential back-off and jitter until ``max_attempts``,
   then fails with the handler's exhaustion audits.

Handlers are resolved lazily from ``HANDLERS`` (like ``worker.loops``): a kind whose module is
not written yet is simply never claimed, so its jobs wait in ``queued``.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import random
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol
from uuid import UUID

from sibyl_schemas.values import JobKind

from ...core.audit import AuditRecord, AuditWriter, PgAuditWriter
from ...core.jobs import plain_json

log = logging.getLogger("sibyl.worker.jobs")

LEASE_S = 60.0
JOB_TIMEOUT_S = 30.0
CLAIM_BATCH = 5
BASE_BACKOFF_S = 2.0
MAX_BACKOFF_S = 300.0

HANDLERS: Mapping[str, str] = {
    JobKind.CREDENTIAL_PROBE.value: "sibyl_control.worker.jobs.probe:CredentialProbe",
    JobKind.AUDIT_VERIFY.value: "sibyl_control.worker.jobs.audit:AuditVerify",
    JobKind.AUDIT_EXPORT.value: "sibyl_control.worker.jobs.audit:AuditExport",
    # agent_bom: cut to Phase 1.5 (Tier A1); data_export: lane U, not written yet.
}
"""kind -> ``module:factory``; the factory takes a ``JobEnv`` and returns a ``JobHandler``."""


@dataclass(frozen=True)
class ClaimedJob:
    tenant_id: UUID
    id: UUID
    kind: str
    params: Mapping[str, Any]
    attempts: int
    max_attempts: int
    requested_by: UUID | None
    requested_by_kind: str
    subject_kind: str | None
    subject_id: UUID | None

    @classmethod
    def of(cls, row: Mapping[str, Any]) -> ClaimedJob:
        params = row["params"]
        return cls(
            row["tenant_id"],
            row["id"],
            row["kind"],
            dict(params) if isinstance(params, Mapping) else {},
            int(row["attempts"]),
            int(row["max_attempts"]),
            row["requested_by"],
            row["requested_by_kind"],
            row["subject_kind"],
            row["subject_id"],
        )


Apply = Callable[[Any], Awaitable[None]]


@dataclass(frozen=True)
class JobOutcome:
    """What a run produced. ``apply`` runs in the finish transaction (side effects such as
    ``last_verified_at``); ``audits`` are appended there too, after ``audit_lock``."""

    state: Literal["done", "failed", "retry"]
    result: Mapping[str, Any] | None = None
    error: str | None = None
    audits: tuple[AuditRecord, ...] = ()
    apply: Apply | None = field(default=None, compare=False)

    @classmethod
    def done(
        cls, result: Mapping[str, Any], *audits: AuditRecord, apply: Apply | None = None
    ) -> JobOutcome:
        return cls("done", result, None, audits, apply)

    @classmethod
    def failed(
        cls, error: str, result: Mapping[str, Any] | None = None, *audits: AuditRecord
    ) -> JobOutcome:
        return cls("failed", result, error, audits)

    @classmethod
    def retry(cls, error: str, result: Mapping[str, Any] | None = None) -> JobOutcome:
        return cls("retry", result, error)


@dataclass
class JobEnv:
    db: Any
    settings: Any
    audit: AuditWriter = field(default_factory=PgAuditWriter)
    log: logging.Logger = log
    extras: dict[str, Any] = field(default_factory=dict)  # test seams (transport, resolver …)


class JobHandler(Protocol):
    async def run(self, job: ClaimedJob) -> JobOutcome: ...

    def exhausted(self, job: ClaimedJob, last: JobOutcome | None) -> tuple[AuditRecord, ...]: ...


def resolve_handler(kind: str, env: JobEnv) -> JobHandler | None:
    target = HANDLERS.get(kind)
    if target is None:
        return None
    module_name, _, attr = target.partition(":")
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name and module_name.startswith(exc.name):
            return None
        raise
    factory = getattr(module, attr, None)
    if factory is None:
        return None
    handler: JobHandler | None = factory(env)
    return handler


def backoff_s(attempts: int, rand: Callable[[], float] = random.random) -> float:
    """Delay before attempt ``attempts + 1``: doubling from 2 s, capped at 5 min, jittered
    to 50-100 % of the step."""
    step = min(MAX_BACKOFF_S, BASE_BACKOFF_S * 2.0 ** max(0, attempts - 1))
    return float(step * (0.5 + rand() / 2))


_TENANTS_SQL = "SELECT id FROM sibyl.tenant WHERE status <> 'erased' ORDER BY id"
_CLAIM_SQL = """
WITH picked AS (
  SELECT id FROM sibyl.job
   WHERE tenant_id = $1 AND kind = ANY($2::text[]) AND attempts < max_attempts
     AND ((state = 'queued' AND run_after <= now()) OR (state = 'running' AND lease_until < now()))
   ORDER BY run_after, id
   LIMIT $3
   FOR UPDATE SKIP LOCKED)
UPDATE sibyl.job j
   SET state = 'running', attempts = j.attempts + 1, started_at = coalesce(j.started_at, now()),
       lease_until = now() + make_interval(secs => $4)
  FROM picked
 WHERE j.tenant_id = $1 AND j.id = picked.id
RETURNING j.*
"""
_EXPIRE_SQL = """
UPDATE sibyl.job
   SET state = 'failed', error = 'lease_expired', lease_until = NULL, finished_at = now()
 WHERE tenant_id = $1 AND state = 'running' AND lease_until < now() AND attempts >= max_attempts
   AND kind = ANY($2::text[])
RETURNING *
"""
_FINISH_SQL = """
UPDATE sibyl.job
   SET state = $3, result = $4, error = $5, lease_until = NULL,
       finished_at = CASE WHEN $3 IN ('done', 'failed') THEN now() END,
       run_after = coalesce(now() + make_interval(secs => $6::double precision), run_after)
 WHERE tenant_id = $1 AND id = $2 AND state = 'running' AND attempts = $7
RETURNING id
"""


class JobRunner:
    def __init__(
        self,
        env: JobEnv,
        *,
        kinds: Sequence[str] | None = None,
        batch: int = CLAIM_BATCH,
        lease_s: float = LEASE_S,
        job_timeout_s: float = JOB_TIMEOUT_S,
        rand: Callable[[], float] = random.random,
    ) -> None:
        if job_timeout_s >= lease_s:
            raise ValueError("a job's deadline must be shorter than its lease")
        self.env = env
        self.batch = batch
        self.lease_s = lease_s
        self.job_timeout_s = job_timeout_s
        self.rand = rand
        self.handlers: dict[str, JobHandler] = {}
        for kind in kinds if kinds is not None else HANDLERS:
            handler = resolve_handler(kind, env)
            if handler is not None:
                self.handlers[kind] = handler

    async def tenants(self) -> list[UUID]:
        async with self.env.db.pre_tenant() as conn:
            return [row["id"] for row in await conn.fetch(_TENANTS_SQL)]

    async def run_once(self) -> int:
        """One tick over every tenant; returns the number of jobs finished or expired."""
        if not self.handlers:
            return 0
        total = 0
        for tenant in await self.tenants():
            total += await self.run_tenant(tenant)
        return total

    async def run_tenant(self, tenant: UUID) -> int:
        kinds = sorted(self.handlers)
        expired = await self._expire(tenant, kinds)
        async with self.env.db.tenant_tx(tenant) as conn:
            rows = await conn.fetch(_CLAIM_SQL, tenant, kinds, self.batch, self.lease_s)
        jobs = [ClaimedJob.of(r) for r in rows]
        if not jobs:
            return expired
        outcomes = await asyncio.gather(*(self._run(job) for job in jobs))
        for job, outcome in zip(jobs, outcomes, strict=True):
            await self._finish(job, outcome)
        return expired + len(jobs)

    async def _expire(self, tenant: UUID, kinds: list[str]) -> int:
        async def body(conn: Any) -> int:
            await conn.execute("SELECT sibyl.audit_lock($1)", tenant)
            rows = await conn.fetch(_EXPIRE_SQL, tenant, kinds)
            for row in rows:
                job = ClaimedJob.of(row)
                for record in self.handlers[job.kind].exhausted(job, None):
                    await self.env.audit.append(conn, tenant, record)
            return len(rows)

        result: int = await self.env.db.run_in_tenant_tx(tenant, body)
        return result

    async def _run(self, job: ClaimedJob) -> JobOutcome:
        try:
            return await asyncio.wait_for(
                self.handlers[job.kind].run(job), timeout=self.job_timeout_s
            )
        except TimeoutError:
            return JobOutcome.retry("job_timeout")
        except Exception:
            log.exception("job %s (%s) crashed", job.id, job.kind)
            return JobOutcome.retry("job_crashed")

    async def _finish(self, job: ClaimedJob, outcome: JobOutcome) -> None:
        state: str = outcome.state
        audits = outcome.audits
        delay: float | None = None
        if state == "retry":
            if job.attempts >= job.max_attempts:
                state = "failed"
                audits = audits + self.handlers[job.kind].exhausted(job, outcome)
            else:
                state = "queued"
                delay = backoff_s(job.attempts, self.rand)
        result = plain_json(outcome.result) if outcome.result is not None else None
        error = outcome.error if state != "done" else None

        async def body(conn: Any) -> bool:
            await conn.execute("SELECT sibyl.audit_lock($1)", job.tenant_id)
            fenced = await conn.fetchval(
                _FINISH_SQL, job.tenant_id, job.id, state, result, error, delay, job.attempts
            )
            if fenced is None:
                return False
            if state in ("done", "failed") and outcome.apply is not None:
                await outcome.apply(conn)
            for record in audits:
                await self.env.audit.append(conn, job.tenant_id, record)
            return True

        if not await self.env.db.run_in_tenant_tx(job.tenant_id, body):
            log.warning("job %s lost its lease before finishing; outcome dropped", job.id)


_RUNNERS: dict[int, JobRunner] = {}


async def tick(ctx: Any) -> None:
    """``worker.loops`` entry (``jobs``, every 2 s and on ``sibyl_outbox``)."""
    key = id(ctx)
    runner = _RUNNERS.get(key)
    if runner is None:
        runner = JobRunner(JobEnv(ctx.db, ctx.settings, log=ctx.log))
        _RUNNERS[key] = runner
    finished = await runner.run_once()
    if finished:
        ctx.log.info("jobs: %d finished", finished)
