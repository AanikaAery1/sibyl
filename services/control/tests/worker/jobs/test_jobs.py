"""Jobs infrastructure end to end on PG17 (B14): enqueue, claim, probe, finish, audit, getJob.

The credential probe goes through the real runner and handler; only the provider is faked
(``httpx.MockTransport``), except in the SSRF case where the real ``GuardedTransport`` refuses a
host that resolves to a private address before any connection is made.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID, uuid4

import httpx
from sibyl_control.core.jobs import Requester, enqueue_job
from sibyl_control.core.outbox import PgOutboxWriter
from sibyl_control.worker.jobs import runner as runner_module
from sibyl_control.worker.jobs.net import GuardedBackend, GuardedTransport
from sibyl_control.worker.jobs.runner import JobRunner, tick
from sibyl_control.worker.loops import LoopContext
from sibyl_schemas.values import JobKind

from .conftest import BASE_URL, SECRET, Rig, Worker, add_credential


async def _enqueue(
    w: Worker, credential: UUID | None = None, *, tenant: UUID | None = None, **kw: Any
) -> UUID:
    tenant = tenant or w.rig.a.id
    credential = credential or (w.rig.a.credential if tenant == w.rig.a.id else w.rig.b.credential)
    async with w.app_db.tenant_tx(tenant) as conn:
        job = await enqueue_job(
            conn,
            PgOutboxWriter(),
            tenant,
            kind=JobKind.CREDENTIAL_PROBE,
            requester=Requester("human", w.rig.a.owner if tenant == w.rig.a.id else w.rig.b.owner),
            params={"credential_id": credential},
            subject=("provider_credential", credential),
            **kw,
        )
    return job.id


async def _job(rig: Rig, job: UUID) -> Any:
    async with rig.admin() as conn:
        return await conn.fetchrow("SELECT * FROM sibyl.job WHERE id = $1", job)


async def _audits(rig: Rig, credential: UUID) -> list[Any]:
    async with rig.admin() as conn:
        return await conn.fetch(
            "SELECT action, actor_type, detail FROM sibyl.audit_events"
            " WHERE resource_id = $1 ORDER BY seq",
            credential,
        )


async def _due(rig: Rig, job: UUID) -> None:
    async with rig.admin() as conn:
        await conn.execute("UPDATE sibyl.job SET run_after = now() WHERE id = $1", job)


async def _fresh_credential(w: Worker, **kw: Any) -> UUID:
    async with w.rig.admin(w.rig.a.id) as conn:
        return await add_credential(conn, w.rig.a.id, w.rig.a.provider, w.rig.a.owner, **kw)


async def test_enqueue_writes_the_job_and_one_outbox_event_and_dedupes_open_jobs(
    worker: Worker,
) -> None:
    credential = await _fresh_credential(worker)
    first = await _enqueue(worker, credential)
    second = await _enqueue(worker, credential)
    assert first == second
    async with worker.rig.admin() as conn:
        events = await conn.fetch(
            "SELECT topic, event_type, payload FROM sibyl.outbox WHERE aggregate_id = $1", first
        )
    assert [(e["topic"], e["event_type"]) for e in events] == [("job", "job.requested")]
    assert events[0]["payload"]["kind"] == "credential_probe"
    row = await _job(worker.rig, first)
    assert (row["state"], row["attempts"], row["requested_by_kind"]) == ("queued", 0, "human")


async def test_a_verified_credential_is_audited_and_stamped(worker: Worker) -> None:
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential)
    assert await worker.runner().run_once() >= 1
    row = await _job(worker.rig, job)
    assert row["state"] == "done" and row["attempts"] == 1 and row["error"] is None
    assert row["result"]["outcome"] == "verified" and row["result"]["http_status"] == 200
    sent = worker.upstream.requests[-1]
    assert str(sent.url) == BASE_URL + "/models"
    assert sent.headers["authorization"] == f"Bearer {SECRET}"
    audits = await _audits(worker.rig, credential)
    assert [(a["action"], a["actor_type"]) for a in audits] == [("credential.verified", "system")]
    async with worker.rig.admin() as conn:
        stamped = await conn.fetchval(
            "SELECT last_verified_at FROM sibyl.provider_credential WHERE id = $1", credential
        )
        dump = json.dumps(
            [dict(r) for r in await conn.fetch("SELECT * FROM sibyl.job")], default=str
        )
        audit_dump = await conn.fetchval(
            "SELECT string_agg(detail::text, ' ') FROM sibyl.audit_events"
        )
    assert stamped is not None
    assert SECRET not in dump and SECRET not in (audit_dump or "")


async def test_a_rejected_credential_finishes_with_probe_failed(worker: Worker) -> None:
    worker.upstream.status = 401
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential)
    await worker.runner().run_once()
    row = await _job(worker.rig, job)
    assert row["state"] == "done" and row["result"]["outcome"] == "rejected"
    audits = await _audits(worker.rig, credential)
    assert [a["action"] for a in audits] == ["credential.probe_failed"]
    assert audits[0]["detail"]["http_status"] == 401


async def test_transient_failures_retry_with_backoff_then_fail(worker: Worker) -> None:
    worker.upstream.status = 503
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential, max_attempts=2)
    runner = worker.runner()
    await runner.run_once()
    row = await _job(worker.rig, job)
    assert (row["state"], row["attempts"], row["error"]) == ("queued", 1, "upstream_unavailable")
    assert row["run_after"] > row["updated_at"] and row["finished_at"] is None
    assert await _audits(worker.rig, credential) == []
    await runner.run_once()  # not due yet: untouched
    assert (await _job(worker.rig, job))["attempts"] == 1
    await _due(worker.rig, job)
    await runner.run_once()
    row = await _job(worker.rig, job)
    assert (row["state"], row["attempts"], row["error"]) == ("failed", 2, "upstream_unavailable")
    audits = await _audits(worker.rig, credential)
    assert [a["action"] for a in audits] == ["credential.probe_failed"]
    assert audits[0]["detail"]["http_status"] == 503


async def test_a_network_error_is_retried(worker: Worker) -> None:
    worker.upstream.error = httpx.ConnectError("refused")
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential)
    await worker.runner().run_once()
    row = await _job(worker.rig, job)
    assert (row["state"], row["error"]) == ("queued", "probe_unreachable")


async def test_ssrf_guard_refuses_a_private_resolution_before_connecting(worker: Worker) -> None:
    credential = await _fresh_credential(
        worker, base_url="https://llm.corp.example/v1", basis="resolver_checked"
    )
    resolved: list[str] = []

    async def resolver(host: str, port: int) -> list[str]:
        resolved.append(host)
        return ["93.184.216.34", "10.1.2.3"]  # one private address is enough to refuse

    def guarded(dev_hosts: Any) -> httpx.AsyncBaseTransport:
        return GuardedTransport(GuardedBackend(dev_hosts or (), resolver=resolver))

    worker.env.extras["probe_transport"] = guarded
    job = await _enqueue(worker, credential)
    await worker.runner().run_once()
    row = await _job(worker.rig, job)
    assert (row["state"], row["error"]) == ("failed", "base_url_refused")
    assert resolved == ["llm.corp.example"]
    audits = await _audits(worker.rig, credential)
    assert [(a["action"], a["detail"]["http_status"]) for a in audits] == [
        ("credential.probe_failed", 0)
    ]


async def test_a_revoked_credential_is_not_probed(worker: Worker) -> None:
    credential = await _fresh_credential(worker)
    async with worker.rig.admin(worker.rig.a.id) as conn:
        await conn.execute(
            "UPDATE sibyl.provider_credential SET status = 'revoked', ciphertext = NULL,"
            " nonce = NULL, revoked_at = now(), revoke_reason = 'drill' WHERE id = $1",
            credential,
        )
    before = len(worker.upstream.requests)
    job = await _enqueue(worker, credential)
    await worker.runner().run_once()
    assert (await _job(worker.rig, job))["error"] == "credential_unavailable"
    assert len(worker.upstream.requests) == before


async def test_a_lost_lease_writes_nothing(worker: Worker) -> None:
    """Fencing: the finish is keyed on the claimed attempt; a re-claimed job is not touched."""
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential)
    gate = asyncio.Event()
    handler = worker.upstream.handler

    def slow(request: httpx.Request) -> httpx.Response:
        return handler(request)

    runner = worker.runner()
    original = runner._run

    async def run_then_lose_lease(claimed: Any) -> Any:
        outcome = await original(claimed)
        async with worker.rig.admin() as conn:  # another worker re-claimed after expiry
            await conn.execute("UPDATE sibyl.job SET attempts = attempts + 1 WHERE id = $1", job)
        gate.set()
        return outcome

    runner._run = run_then_lose_lease  # type: ignore[method-assign]
    worker.upstream.handler = slow  # type: ignore[method-assign]
    await runner.run_tenant(worker.rig.a.id)
    assert gate.is_set()
    row = await _job(worker.rig, job)
    assert (row["state"], row["attempts"]) == ("running", 2)
    assert await _audits(worker.rig, credential) == []


async def test_an_expired_lease_without_attempts_left_fails_the_job(worker: Worker) -> None:
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential, max_attempts=1)
    async with worker.rig.admin() as conn:
        await conn.execute(
            "UPDATE sibyl.job SET state = 'running', attempts = 1, started_at = now(),"
            " lease_until = now() - interval '1 second' WHERE id = $1",
            job,
        )
    await worker.runner().run_tenant(worker.rig.a.id)
    row = await _job(worker.rig, job)
    assert (row["state"], row["error"]) == ("failed", "lease_expired")
    assert [a["action"] for a in await _audits(worker.rig, credential)] == [
        "credential.probe_failed"
    ]


async def test_concurrent_workers_never_run_a_job_twice(worker: Worker) -> None:
    credentials = [await _fresh_credential(worker) for _ in range(6)]
    jobs = [await _enqueue(worker, c) for c in credentials]
    runners = [worker.runner(batch=2) for _ in range(3)]
    await asyncio.gather(*(r.run_tenant(worker.rig.a.id) for r in runners))
    await asyncio.gather(*(r.run_tenant(worker.rig.a.id) for r in runners))
    for job, credential in zip(jobs, credentials, strict=True):
        row = await _job(worker.rig, job)
        assert (row["state"], row["attempts"]) == ("done", 1)
        assert len(await _audits(worker.rig, credential)) == 1


async def test_kinds_without_a_handler_stay_queued(worker: Worker) -> None:
    async with worker.app_db.tenant_tx(worker.rig.a.id) as conn:
        job = await enqueue_job(
            conn,
            PgOutboxWriter(),
            worker.rig.a.id,
            kind=JobKind.AGENT_BOM,
            requester=Requester.system(),
            params={"agent_version_id": str(uuid4())},
        )
    await worker.runner().run_once()
    assert (await _job(worker.rig, job.id))["state"] == "queued"


async def test_tenants_are_isolated(worker: Worker) -> None:
    job_b = await _enqueue(worker, tenant=worker.rig.b.id)
    async with worker.db.tenant_tx(worker.rig.a.id) as conn:
        assert await conn.fetchval("SELECT count(*) FROM sibyl.job WHERE id = $1", job_b) == 0
    await worker.runner().run_tenant(worker.rig.a.id)
    assert (await _job(worker.rig, job_b))["state"] == "queued"
    await worker.runner().run_tenant(worker.rig.b.id)
    assert (await _job(worker.rig, job_b))["state"] == "done"


async def test_the_loop_tick_runs_the_jobs(worker: Worker, monkeypatch: Any) -> None:
    credential = await _fresh_credential(worker)
    job = await _enqueue(worker, credential)
    monkeypatch.setattr(runner_module, "_RUNNERS", {})
    ctx = LoopContext("jobs", worker.db, worker.env.settings, runner_module.log)
    runner_module._RUNNERS[id(ctx)] = JobRunner(worker.env)
    await tick(ctx)
    assert (await _job(worker.rig, job))["state"] == "done"
