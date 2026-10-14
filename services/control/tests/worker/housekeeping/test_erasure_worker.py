"""erasure_exec and erasure_ledger edge cases on PG17 (lane U)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_lane_u_helpers as h
from sibyl_control.core.blob.base import BlobExists
from sibyl_control.migrate import ledger as ledger_mod
from sibyl_control.worker.housekeeping import erasure_exec, erasure_ledger, ledger_store
from sibyl_schemas.canonical import canonicalize

NOW = datetime.now(UTC)


def _approved_request(world: Any, agent: UUID) -> UUID:
    tenant = world.a
    rid = world.in_tenant(
        tenant.id,
        "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, scope_ref, legal_basis,"
        " requested_by, execution_log) VALUES ($1, 'agent', $2, 'other', $3,"
        ' \'[{"step": "requested"}]\') RETURNING id',
        tenant.id,
        str(agent),
        tenant.users["owner"],
    )[0]["id"]
    world.in_tenant(
        tenant.id,
        "UPDATE sibyl.erasure_request SET state = 'approved', approved_by = $3, approved_at = now()"
        " WHERE tenant_id = $1 AND id = $2",
        tenant.id,
        rid,
        tenant.users["approver"],
    )
    return rid


def _row(world: Any, rid: UUID) -> Any:
    return world.fetchrow("SELECT * FROM sibyl.erasure_request WHERE id = $1", rid)


def test_a_hold_placed_mid_execution_stops_the_phase_and_is_recorded(world: Any) -> None:
    agent = world.add_agent(world.a, "mid-hold")
    h.add_payload(world, world.a.id, agent=agent)
    rid = _approved_request(world, agent)
    hold = world.in_tenant(
        world.a.id,
        "INSERT INTO sibyl.legal_hold (tenant_id, scope_kind, scope_ref, agent_ids, window_from,"
        " reason, expires_at) VALUES ($1, 'agent', $2, $3, $4, 'late hold for test', $5)"
        " RETURNING id",
        world.a.id,
        str(agent),
        [agent],
        NOW - timedelta(days=1),
        NOW + timedelta(days=1),
    )[0]["id"]
    world.tick(erasure_exec)
    row = _row(world, rid)
    assert row["state"] == "executing"
    assert row["error"] and "legal_hold_active" in row["error"]
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE agent_id = $1", agent) == 1
    world.in_tenant(
        world.a.id,
        "UPDATE sibyl.legal_hold SET state = 'released', released_at = now(),"
        " release_reason = 'test release' WHERE tenant_id = $1 AND id = $2",
        world.a.id,
        hold,
    )
    world.tick(erasure_exec)
    row = _row(world, rid)
    assert row["state"] == "completed" and row["error"] is None
    assert world.fetchval("SELECT count(*) FROM sibyl.payload_refs WHERE agent_id = $1", agent) == 0


def test_unapproved_or_closed_requests_are_never_executed(world: Any) -> None:
    agent = world.add_agent(world.a, "not-approved")
    rid = world.in_tenant(
        world.a.id,
        "INSERT INTO sibyl.erasure_request (tenant_id, scope_kind, scope_ref, legal_basis,"
        " requested_by) VALUES ($1, 'agent', $2, 'other', $3) RETURNING id",
        world.a.id,
        str(agent),
        world.a.users["owner"],
    )[0]["id"]
    world.tick(erasure_exec)
    assert _row(world, rid)["state"] == "requested"
    assert world.fetchval("SELECT count(*) FROM sibyl.agent WHERE id = $1", agent) == 1


def test_residue_blocks_verification(world: Any, monkeypatch: Any) -> None:
    agent = world.add_agent(world.a, "residue")
    rid = _approved_request(world, agent)

    async def leftover(conn: Any, row: Any, rt: Any) -> dict[str, int]:
        return {"events": 2}

    monkeypatch.setattr(erasure_exec, "residue", leftover)
    world.tick(erasure_exec)
    row = _row(world, rid)
    assert row["state"] == "derived_purged" and "events=2" in row["error"]
    monkeypatch.undo()
    world.tick(erasure_exec)
    assert _row(world, rid)["state"] == "completed"


def test_completion_waits_for_the_ledger_key(world: Any, monkeypatch: Any) -> None:
    agent = world.add_agent(world.a, "no-ledger-key")
    rid = _approved_request(world, agent)
    monkeypatch.setattr(world.settings, "ledger_signing_key_file", None)
    world.tick(erasure_exec)
    row = _row(world, rid)
    assert row["state"] == "verified" and "LEDGER" in row["error"]
    monkeypatch.undo()
    world.tick(erasure_exec)
    assert _row(world, rid)["state"] == "completed"


def test_ledger_append_is_idempotent_and_survives_a_racing_writer(
    world: Any, monkeypatch: Any
) -> None:
    key = ledger_store.signing_key_from_settings(world.settings)
    fields = {
        "tenant_id": str(world.b.id),
        "scope_kind": "agent",
        "scope_ref": str(uuid4()),
        "key_ids": [],
        "completed_at": "2026-10-11T00:00:00.000000Z",
        "subject_set": None,
    }
    first = world.run(
        ledger_store.append(world.blob, key, erasure_request_id=str(uuid4()), **fields)
    )
    again = world.run(
        ledger_store.append(
            world.blob, key, erasure_request_id=first["erasure_request_id"], **fields
        )
    )
    assert again == first
    real_put = world.blob.put
    calls = {"n": 0}
    racer_id = str(uuid4())

    async def racing_put(k: str, data: bytes, **kw: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:  # another worker commits its entry at this seq first
            entries = await ledger_store.load(world.blob)
            theirs = ledger_mod.append(
                entries, signing_key=key, erasure_request_id=racer_id, **fields
            )[-1]
            await real_put(
                k, canonicalize(dict(theirs)), content_type="application/json", if_absent=True
            )
            raise BlobExists(k)
        return await real_put(k, data, **kw)

    monkeypatch.setattr(world.blob, "put", racing_put)
    mine = world.run(
        ledger_store.append(world.blob, key, erasure_request_id=str(uuid4()), **fields)
    )
    monkeypatch.undo()
    entries = world.run(ledger_store.load(world.blob))
    racer = ledger_store.find(entries, racer_id)
    assert racer is not None and mine["seq"] == racer["seq"] + 1
    ledger_mod.verify(ledger_mod.to_jsonl(entries), key.public_key())


def test_ledger_tick_refuses_a_tampered_ledger(world: Any) -> None:
    world.tick(erasure_ledger)
    names = sorted(world.run(world.blob.list_prefix(ledger_store.ENTRIES)))
    assert names
    original = world.run(world.blob.get(names[0]))
    entry = json.loads(original)
    entry["scope_ref"] = "tampered"
    world.run(
        world.blob.put(
            names[0], json.dumps(entry).encode(), content_type="application/json", if_absent=False
        )
    )
    head_before = world.run(world.blob.get(ledger_store.HEAD_KEY))
    with pytest.raises(ledger_mod.LedgerError):
        world.tick(erasure_ledger)
    assert world.run(world.blob.get(ledger_store.HEAD_KEY)) == head_before  # never rewritten over
    world.run(world.blob.put(names[0], original, content_type="application/json", if_absent=False))
    world.tick(erasure_ledger)
