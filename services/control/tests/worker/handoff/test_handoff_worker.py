"""Handoff loop on PG17: SDK packets become tasks, deadlines expire, lapsed claims requeue."""

from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID, uuid4

from sibyl_control.core.audit import PgAuditWriter
from sibyl_control.core.outbox import PgOutboxWriter
from sibyl_control.core.settings import Settings
from sibyl_control.worker.handoff import tasks
from sibyl_control.worker.loops import LOOPS, LoopContext, resolve_tick
from sibyl_lane_s_world import SWorld


def _event(s: SWorld, agent: UUID, task: UUID, event_type: str, **cols: Any) -> UUID:
    eid = uuid4()
    s.admin.execute(
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, task_id,"
        " emitter_id, seq, policy_state, capture_mode, redaction_profile_hash, normaliser_version,"
        " payload_ref_id, payload_sha256, attrs)"
        " VALUES ($1, $2, now(), $3, 'sdk', $4, $5, 'sdk-1', 1, 'fresh', 'full', $6,"
        " 'normaliser/1.0',"
        " $7, $8, $9::jsonb)",
        s.a.id,
        eid,
        event_type,
        agent,
        task,
        b"\x00" * 32,
        cols.get("payload_ref_id"),
        cols.get("payload_sha256"),
        json.dumps(cols.get("attrs", {})),
    )
    return eid


def _with_db(s: SWorld, fn: Any) -> Any:
    async def go() -> Any:
        async with s.worker_db.tenant_tx(s.a.id) as conn:
            await conn.execute("SELECT sibyl.audit_lock($1)", s.a.id)
            return await fn(conn)

    return s.run(go())


def _task(s: SWorld, agent: UUID, *, deadline_s: int = 900) -> UUID:
    return s.val(
        "INSERT INTO sibyl.handoff_task (tenant_id, agent_id, task_id, packet_id, packet,"
        " packet_sha256, fidelity, failure_mode, trigger_kind, assembled_by, priority, deadline_at,"
        " next_action, summary) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, 'request_only',"
        " 'tool_failure', 'operator', 'control_plane', 2, now() + make_interval(secs => $6),"
        " 'do it', 'test task') RETURNING id",
        s.a.id,
        agent,
        uuid4(),
        uuid4(),
        b"\x01" * 32,
        deadline_s,
    )


def test_sdk_handoff_event_becomes_a_task_once(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent(tier=1)
    s.plan(agent)
    task = uuid4()
    ref = uuid4()
    _event(
        s,
        agent,
        task,
        "handoff.requested",
        payload_ref_id=ref,
        payload_sha256=b"\x07" * 32,
        attrs={
            "sibyl.handoff.fidelity": "checkpoint",
            "sibyl.handoff.failure_mode": "tool_failure",
        },
    )
    audit, outbox = PgAuditWriter(), PgOutboxWriter()
    n = _with_db(s, lambda c: tasks.build_sdk_tasks(c, s.a.id, audit=audit, outbox=outbox))
    assert n == 1
    row = s.one(
        "SELECT * FROM sibyl.handoff_task WHERE tenant_id = $1 AND task_id = $2", s.a.id, task
    )
    assert row["packet_ref_id"] == ref and row["packet"] is None
    assert row["assembled_by"] == "sdk" and row["fidelity"] == "checkpoint"
    assert row["deadline_at"] > row["created_at"]
    assert _with_db(s, lambda c: tasks.build_sdk_tasks(c, s.a.id, audit=audit, outbox=outbox)) == 0


def test_in_flight_tasks_come_from_events_and_checkpoints(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    t1, t2, t3 = uuid4(), uuid4(), uuid4()
    _event(s, agent, t1, "gen_ai.request")
    s.checkpoint(agent, t2)
    _event(s, agent, t3, "gen_ai.request")
    _event(s, agent, t3, "task.outcome")
    found = _with_db(s, lambda c: tasks.in_flight(c, s.a.id, agent))
    by_id = {t.task_id: t for t in found}
    assert set(by_id) == {t1, t2}
    assert by_id[t2].checkpoint_id is not None and by_id[t1].checkpoint_id is None


def test_expiry_and_lapsed_claims(sworld: SWorld) -> None:
    s = sworld
    agent = s.agent()
    late = _task(s, agent, deadline_s=-1)
    claimed = _task(s, agent)
    s.admin.execute(
        "UPDATE sibyl.handoff_task SET state = 'claimed', claimed_by_user_id = $2, claimed_at ="
        " now(),"
        " claim_lock_until = now() - interval '1 s' WHERE id = $1",
        claimed,
        s.a.users["operator"],
    )
    head = s.head(s.a)
    tick = resolve_tick(next(x for x in LOOPS if x.name == "handoff"))
    assert tick is not None
    s.run(tick(LoopContext("handoff", s.worker_db, Settings(), logging.getLogger("t"))))
    assert (
        s.one("SELECT state, outcome FROM sibyl.handoff_task WHERE id = $1", late)["state"]
        == "expired"
    )
    row = s.one("SELECT state, claimed_by_user_id FROM sibyl.handoff_task WHERE id = $1", claimed)
    assert row["state"] == "queued" and row["claimed_by_user_id"] is None
    actions = s.audit_actions(s.a, head)
    assert "handoff.expired" in actions and "handoff.claim_released" in actions
