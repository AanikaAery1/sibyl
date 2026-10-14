# ruff: noqa: S106, S107 -- bearer tokens here are test principal names, not secrets
"""``verifyProviderCredential`` enqueues (202 + job id, never probes inline) and ``getJob`` shows
the job to its requester only (``job_owner``); the worker then finishes it."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient
from sibyl_control.worker.jobs.runner import JobEnv, JobRunner

from .conftest import SETTINGS, Rig, Upstream, Worker


def _verify(
    api: TestClient, rig: Rig, credential: Any, token: str = "owner-a", key: str = ""
) -> Any:
    return api.post(
        f"/api/v1/provider-credentials/{credential}/verify",
        headers={"Authorization": f"Bearer {token}", "Idempotency-Key": key or str(uuid4())},
    )


def _get(api: TestClient, job: str, token: str = "owner-a") -> Any:
    return api.get(f"/api/v1/jobs/{job}", headers={"Authorization": f"Bearer {token}"})


def test_verify_answers_202_with_a_job_and_replays_by_key(api: TestClient, rig: Rig) -> None:
    resp = _verify(api, rig, rig.a.credential, key="verify-replay-1")
    assert resp.status_code == 202, resp.text
    job = resp.json()["job_id"]
    assert resp.headers["location"] == f"/api/v1/jobs/{job}"
    replay = _verify(api, rig, rig.a.credential, key="verify-replay-1")
    assert replay.status_code == 202 and replay.json()["job_id"] == job
    again = _verify(api, rig, rig.a.credential)  # new key, same open job
    assert again.json()["job_id"] == job

    shown = _get(api, job)
    assert shown.status_code == 200, shown.text
    body = shown.json()
    assert body["kind"] == "credential_probe" and body["state"] == "queued"
    assert body["attempts"] == 0 and body["requested_by"] == str(rig.a.owner)
    assert "params" not in body


def test_jobs_are_visible_to_their_requester_only(api: TestClient, rig: Rig) -> None:
    job = _verify(api, rig, rig.a.credential).json()["job_id"]
    assert _get(api, job, "other-a").status_code == 404  # same tenant, not the requester
    assert _get(api, job, "owner-b").status_code == 404  # another tenant
    assert _get(api, str(uuid4())).status_code == 404


def test_verify_of_an_unknown_or_foreign_credential_is_404(api: TestClient, rig: Rig) -> None:
    assert _verify(api, rig, uuid4()).status_code == 404
    assert _verify(api, rig, rig.b.credential).status_code == 404


async def test_the_worker_finishes_an_api_requested_probe(
    api: TestClient, rig: Rig, worker: Worker
) -> None:
    job = _verify(api, rig, rig.b.credential, token="owner-b").json()["job_id"]
    upstream = Upstream(status=200)
    env = JobEnv(worker.db, SETTINGS, extras={"probe_transport": upstream.factory()})
    await JobRunner(env).run_tenant(rig.b.id)
    body = _get(api, job, "owner-b").json()
    assert body["state"] == "done" and body["result"]["outcome"] == "verified"
    assert body["finished_at"] is not None and body["error"] is None
    assert isinstance(upstream.requests[0], httpx.Request)
