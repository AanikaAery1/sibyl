"""Audit exports and large verifications run as jobs (B14, CR U-6, ruling G0-12), end to end
on PG17: the governance route enqueues, the real ``worker.jobs.audit`` handler runs lane U's
``verification.verify_chain`` / ``exports.run_export`` through ``JobRunner``, and the outcome is
audited exactly once (``audit.export_completed`` / ``audit.verified``, actor ``system``)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_lane_u_helpers as h
from sibyl.cli import EXIT_OK
from sibyl.cli import main as sibyl_cli
from sibyl_control.api.governance import audit as audit_routes
from sibyl_control.core.crypto.sealed import open_payload
from sibyl_control.core.outbox import OutboxMessage, PgOutboxWriter
from sibyl_control.worker.housekeeping import anchors, exports
from sibyl_control.worker.housekeeping.common import dek_provider


def _job(world: Any, job_id: UUID | str) -> Any:
    return world.fetchrow(
        "SELECT * FROM sibyl.job WHERE tenant_id = $1 AND id = $2", world.a.id, UUID(str(job_id))
    )


def _audits(world: Any, action: str, since: int) -> list[Any]:
    return world.fetch(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = $2 AND seq > $3"
        " ORDER BY seq",
        world.a.id,
        action,
        since,
    )


def _export_job(world: Any, export_id: str) -> Any:
    return world.fetchrow(
        "SELECT * FROM sibyl.job WHERE tenant_id = $1 AND kind = 'audit_export'"
        " AND subject_kind = 'audit_export' AND subject_id = $2",
        world.a.id,
        UUID(export_id),
    )


def _bytes(world: Any, ref_id: str) -> bytes:
    uri = world.fetchval(
        "SELECT uri FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(ref_id),
    )
    deks = dek_provider(world.worker_db, world.settings)
    body: bytes = world.run(open_payload(world.blob, deks, world.a.id, uri, UUID(ref_id)))
    return body


@pytest.fixture(scope="module")
def finished_export(world: Any) -> dict[str, Any]:
    h.append_rows(world, world.a.id, 5)
    to_seq = world.head(world.a.id)
    since = to_seq
    resp = world.post(
        "owner", "/audit/exports", {"from_seq": 0, "to_seq": to_seq, "format": "jsonl"}
    )
    assert resp.status_code == 202, resp.text
    created = resp.json()
    job = _export_job(world, created["id"])
    assert job is not None and job["state"] == "queued"
    assert resp.headers["Location"] == f"/api/v1/jobs/{job['id']}"
    assert job["requested_by_kind"] == "human"
    assert job["params"] == {
        "export_id": created["id"],
        "from_seq": 0,
        "to_seq": to_seq,
        "format": "jsonl",
    }
    assert world.get("owner", f"/audit/exports/{created['id']}").json()["state"] == "queued"
    assert world.run_jobs("audit_export") == 1
    got = world.get("owner", f"/audit/exports/{created['id']}")
    assert got.status_code == 200, got.text
    return {"export": got.json(), "job": _job(world, job["id"]), "since": since}


def test_the_export_request_is_audited_at_request_time_without_a_digest(
    world: Any, finished_export: dict[str, Any]
) -> None:
    export = finished_export["export"]
    rows = world.fetch(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = 'audit.exported'"
        " AND resource_ref = $2",
        world.a.id,
        f"audit_export:{export['id']}",
    )
    assert len(rows) == 1
    assert rows[0]["actor_type"] == "human"
    assert rows[0]["detail"]["export_sha256"] is None
    assert rows[0]["detail"]["export_id"] == export["id"]
    assert rows[0]["seq"] <= finished_export["since"] + 1  # written before the job ran


def test_the_export_job_completes_and_is_audited_once_as_system(
    world: Any, finished_export: dict[str, Any]
) -> None:
    export, job = finished_export["export"], finished_export["job"]
    assert export["state"] == "done" and job["state"] == "done"
    assert job["result"]["export_sha256"] == export["export_sha256"]
    assert job["result"]["anchor_id"] == export["anchor_id"]
    assert job["result"]["payload_ref_id"] == export["payload_ref_id"]
    completed = _audits(world, "audit.export_completed", finished_export["since"])
    assert len(completed) == 1
    row = completed[0]
    assert row["actor_type"] == "system"
    assert row["detail"]["export_sha256"] == export["export_sha256"]
    assert row["detail"]["anchor_id"] == export["anchor_id"]
    assert row["detail"]["job_id"] == str(job["id"])
    body = _bytes(world, export["payload_ref_id"])
    assert hashlib.sha256(body).hexdigest() == export["export_sha256"]
    anchor = world.fetchrow(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(export["anchor_id"]),
    )
    assert anchor["kind"] == "export" and anchor["seq_to"] == export["to_seq"]


def test_the_job_made_export_anchor_is_published_off_database(
    world: Any, finished_export: dict[str, Any]
) -> None:
    """B21: a job-made export anchor gets an off-database copy, like a loop-made one."""
    export = finished_export["export"]
    anchor = world.fetchrow(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(export["anchor_id"]),
    )
    assert anchor["external_ref"] is not None
    stored = json.loads(world.run(world.blob.get(anchor["external_ref"])))
    assert stored["id"] == export["anchor_id"] and stored["kind"] == "export"
    assert stored["seq_to"] == export["to_seq"]


def test_the_job_export_verifies_offline(
    world: Any,
    finished_export: dict[str, Any],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    export = finished_export["export"]
    path = tmp_path / "export.jsonl"
    path.write_bytes(_bytes(world, export["payload_ref_id"]))
    keys = tmp_path / "keys.json"
    keys.write_text(world.get("auditor", "/audit/signing-keys").text)
    assert sibyl_cli(["audit", "verify", str(path), "--public-key", str(keys)]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["to_seq"] == export["to_seq"]


def test_a_finished_export_is_not_redone_and_not_reaudited(
    world: Any, finished_export: dict[str, Any]
) -> None:
    since = world.head(world.a.id)
    assert world.run_jobs("audit_export") == 0  # a done job is never claimed again
    world.settle_outbox()
    world.tick(anchors)  # the anchors loop has no export path any more
    assert _audits(world, "audit.export_completed", since) == []
    export = finished_export["export"]
    request = exports.ExportRequest.from_payload(
        {
            "export_id": export["id"],
            "from_seq": export["from_seq"],
            "to_seq": export["to_seq"],
            "format": "jsonl",
        }
    )

    async def again() -> Any:
        async with world.worker_db.tenant_tx(world.a.id) as conn:
            return await exports.run_export(conn, world.a.id, request, signer=None, sealer=None)

    redo = world.run(again())  # idempotent by export_id: the stored result, no new object
    assert str(redo.payload_ref_id) == export["payload_ref_id"]
    assert str(redo.anchor_id) == export["anchor_id"]
    assert redo.sha256 == export["export_sha256"]
    assert redo.rows == export["to_seq"] - export["from_seq"] + 1


def test_a_failing_export_job_surfaces_as_failed(world: Any, monkeypatch: Any) -> None:
    resp = world.post("owner", "/audit/exports", {"from_seq": 0, "to_seq": 1, "format": "csv"})
    assert resp.status_code == 202, resp.text
    export_id = resp.json()["id"]
    job = _export_job(world, export_id)
    world.admin.execute(
        "UPDATE sibyl.job SET max_attempts = 1 WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        job["id"],
    )

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("blob store down")

    monkeypatch.setattr(exports, "run_export", boom)
    since = world.head(world.a.id)
    world.run_jobs("audit_export")
    got = world.get("owner", f"/audit/exports/{export_id}").json()
    assert got["state"] == "failed"
    assert got["export_sha256"] is None and got["payload_ref_id"] is None
    assert _audits(world, "audit.export_completed", since) == []


def test_a_large_verification_is_a_job_audited_once_as_system(world: Any, monkeypatch: Any) -> None:
    monkeypatch.setattr(audit_routes, "SYNC_ROW_LIMIT", 3)
    resp = world.post("security_admin", "/audit/verifications", {"from_seq": 0})
    assert resp.status_code == 202, resp.text
    job_id = resp.json()["job_id"]
    assert set(resp.json()) == {"job_id"}
    job = _job(world, job_id)
    assert job["kind"] == "audit_verify" and job["state"] == "queued"
    assert job["params"] == {"from_seq": 0, "to_seq": None}
    since = world.head(world.a.id)
    assert world.run_jobs("audit_verify") == 1
    done = _job(world, job_id)
    assert done["state"] == "done" and done["result"]["ok"] is True
    verified = _audits(world, "audit.verified", since)
    assert len(verified) == 1
    assert verified[0]["actor_type"] == "system"
    assert verified[0]["detail"]["job_id"] == job_id
    assert verified[0]["detail"]["to_seq"] == done["result"]["to_seq"]
    polled = world.get("security_admin", f"/jobs/{job_id}")
    assert polled.status_code == 200 and polled.json()["state"] == "done"


def test_legacy_export_and_verify_requests_are_ignored_by_the_anchors_loop(world: Any) -> None:
    async def emit(payload: dict[str, Any]) -> None:
        async with world.worker_db.tenant_tx(world.a.id) as conn:
            message = OutboxMessage.for_event("audit.anchor_now", "audit", uuid4(), payload)
            await PgOutboxWriter().emit(conn, world.a.id, message)

    world.run(emit({"reason": "verify", "job_id": str(uuid4()), "from_seq": 0}))
    world.run(
        emit(
            {
                "reason": "export",
                "export_id": str(uuid4()),
                "from_seq": 0,
                "to_seq": 1,
                "format": "jsonl",
            }
        )
    )
    since = world.head(world.a.id)
    requested_kinds = (
        "SELECT count(*) FROM sibyl.audit_anchors WHERE tenant_id = $1"
        " AND kind IN ('export', 'break_glass')"
    )
    before = world.fetchval(requested_kinds, world.a.id)
    world.settle_outbox()
    world.tick(anchors)
    assert world.fetchval(requested_kinds, world.a.id) == before  # no anchor for either
    assert _audits(world, "audit.verified", since) == []
    assert _audits(world, "audit.export_completed", since) == []
