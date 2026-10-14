"""End to end on PG17: audit export → export job (anchor + object) → offline ``sibyl audit verify``.

The export object is downloaded through ``GET /payloads/{ref_id}`` (the payload route serves
and audits downloads); the bytes are then verified with the Apache-2 SDK CLI using only the
public key set from ``GET /audit/signing-keys``, and a one-row tamper is reported at its seq.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
import sibyl_lane_u_helpers as h
from sibyl.cli import EXIT_BREAK, EXIT_OK
from sibyl.cli import main as sibyl_cli
from sibyl_control.core.crypto.sealed import open_payload
from sibyl_control.worker.housekeeping import exports as export_worker
from sibyl_control.worker.housekeeping.common import dek_provider

RECEIPT = "X-Sibyl-Audit-Receipt"


def _request(world: Any, token: str, body: dict[str, Any]) -> dict[str, Any]:
    resp = world.post(token, "/audit/exports", body)
    assert resp.status_code == 202, resp.text
    assert resp.headers[RECEIPT].startswith(f"{world.a.id}:")
    return resp.json()


def _export_bytes(world: Any, ref_id: str) -> bytes:
    row = world.fetchrow(
        "SELECT uri FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(ref_id),
    )
    deks = dek_provider(world.worker_db, world.settings)
    return world.run(open_payload(world.blob, deks, world.a.id, row["uri"], UUID(ref_id)))


def _keys_file(world: Any, tmp: Path) -> Path:
    path = tmp / "audit-keys.json"
    path.write_text(world.get("auditor", "/audit/signing-keys").text)
    return path


@pytest.fixture(scope="module")
def done_export(world: Any) -> dict[str, Any]:
    h.append_rows(world, world.a.id, 6)
    to_seq = world.head(world.a.id)
    created = _request(world, "owner", {"from_seq": 0, "to_seq": to_seq, "format": "jsonl"})
    assert created["state"] == "queued"
    row = world.fetchrow(
        "SELECT * FROM sibyl.audit_events WHERE tenant_id = $1 AND action = 'audit.exported'"
        " AND resource_ref = $2",
        world.a.id,
        f"audit_export:{created['id']}",
    )
    assert row["actor_type"] == "human" and row["detail"]["to_seq"] == to_seq
    pending = world.get("owner", f"/audit/exports/{created['id']}")
    assert pending.status_code == 200 and pending.json()["state"] == "queued"
    assert world.run_jobs("audit_export") == 1
    got = world.get("owner", f"/audit/exports/{created['id']}")
    assert got.status_code == 200
    return got.json()


def test_export_is_anchored_first_and_completes(world: Any, done_export: dict[str, Any]) -> None:
    assert done_export["state"] == "done"
    assert done_export["download_url"].endswith(f"/api/v1/payloads/{done_export['payload_ref_id']}")
    anchor = world.fetchrow(
        "SELECT * FROM sibyl.audit_anchors WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(done_export["anchor_id"]),
    )
    assert anchor["kind"] == "export" and anchor["seq_to"] == done_export["to_seq"]
    ref = world.fetchrow(
        "SELECT * FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        UUID(done_export["payload_ref_id"]),
    )
    assert ref["kind"] == "anchor_export" and ref["source_kind"] == "export"
    assert ref["created_at"] >= anchor["anchored_at"]  # anchor first, then the object
    body = _export_bytes(world, done_export["payload_ref_id"])
    import hashlib

    assert hashlib.sha256(body).hexdigest() == done_export["export_sha256"]


def test_export_verifies_offline_and_a_tamper_is_reported_at_its_seq(
    world: Any, done_export: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _export_bytes(world, done_export["payload_ref_id"])
    keys = _keys_file(world, tmp_path)
    export_path = tmp_path / "export.jsonl"
    export_path.write_bytes(body)
    assert sibyl_cli(["audit", "verify", str(export_path), "--public-key", str(keys)]) == EXIT_OK
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] and report["to_seq"] == done_export["to_seq"]
    assert report["anchors_checked"] >= 1

    # the anchor can also come from the anchors API instead of the export itself
    anchor_file = tmp_path / "anchor.json"
    anchor_file.write_text(
        world.get("auditor", "/audit/anchors", params={"kind": "export", "limit": 200}).text
    )
    lines = [json.loads(ln) for ln in body.decode().splitlines()]
    events_only = tmp_path / "events.jsonl"
    events_only.write_text("".join(json.dumps(ln) + "\n" for ln in lines if ln["type"] != "anchor"))
    args = [
        "audit",
        "verify",
        str(events_only),
        "--anchor",
        str(anchor_file),
        "--public-key",
        str(keys),
    ]
    assert sibyl_cli(args) == EXIT_OK
    capsys.readouterr()

    victim = next(ln for ln in lines if ln["type"] == "event" and ln["seq"] == 3)
    victim["detail"] = {**victim["detail"], "to_seq": 999}
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("".join(json.dumps(ln) + "\n" for ln in lines))
    assert sibyl_cli(["audit", "verify", str(tampered), "--public-key", str(keys)]) == EXIT_BREAK
    report = json.loads(capsys.readouterr().out)
    assert (report["first_break_seq"], report["kind"]) == (3, "content_mismatch")


def test_download_through_the_payload_route(world: Any, done_export: dict[str, Any]) -> None:
    resp = world.get("owner", f"/payloads/{done_export['payload_ref_id']}")
    assert resp.status_code == 200
    assert resp.content == _export_bytes(world, done_export["payload_ref_id"])


def test_csv_export(world: Any) -> None:
    created = _request(world, "security_admin", {"from_seq": 0, "to_seq": 2, "format": "csv"})
    assert world.run_jobs("audit_export") == 1
    got = world.get("security_admin", f"/audit/exports/{created['id']}").json()
    assert got["state"] == "done" and got["format"] == "csv"
    text = _export_bytes(world, got["payload_ref_id"]).decode()
    header, *rows = text.strip().splitlines()
    assert header.startswith("seq,recorded_at") and len(rows) == 3


def test_export_validation_and_isolation(world: Any) -> None:
    beyond = world.head(world.a.id) + 100
    assert (
        world.post(
            "owner", "/audit/exports", {"from_seq": 0, "to_seq": beyond, "format": "jsonl"}
        ).status_code
        == 422
    )
    assert (
        world.post(
            "owner", "/audit/exports", {"from_seq": 5, "to_seq": 1, "format": "jsonl"}
        ).status_code
        == 422
    )
    assert (
        world.post(
            "owner", "/audit/exports", {"from_seq": 0, "to_seq": 1, "format": "xml"}
        ).status_code
        == 422
    )
    assert (
        world.post(
            "viewer", "/audit/exports", {"from_seq": 0, "to_seq": 1, "format": "jsonl"}
        ).status_code
        == 403
    )
    created = _request(world, "owner", {"from_seq": 0, "to_seq": 1, "format": "jsonl"})
    assert world.get("owner-b", f"/audit/exports/{created['id']}").status_code == 404
    assert world.get("owner", "/audit/exports/not-a-uuid").status_code == 404
    # an auditor's audited export grant still exports (the export itself is the audit row)
    assert (
        world.post(
            "auditor", "/audit/exports", {"from_seq": 0, "to_seq": 1, "format": "jsonl"}
        ).status_code
        == 202
    )


def test_failed_export_surfaces_as_failed(world: Any, monkeypatch: Any) -> None:
    created = _request(world, "owner", {"from_seq": 0, "to_seq": 1, "format": "jsonl"})

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("blob store down")

    world.admin.execute(
        "UPDATE sibyl.job SET max_attempts = 1 WHERE tenant_id = $1 AND subject_id = $2",
        world.a.id,
        UUID(created["id"]),
    )
    monkeypatch.setattr(export_worker, "run_export", boom)
    world.run_jobs("audit_export")
    got = world.get("owner", f"/audit/exports/{created['id']}").json()
    assert got["state"] == "failed"
    assert export_worker.MAX_EXPORT_ROWS > 0


def test_data_export_is_cut_to_phase_1_5(world: Any) -> None:
    resp = world.post("owner", "/exports", {"kind": "events", "filter": {}})
    assert resp.status_code == 501
    assert world.post("viewer", "/exports", {"kind": "events", "filter": {}}).status_code == 403
