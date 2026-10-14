"""Operator queue on PG17: claim / extend / release / complete / return / reassign, the summary
counter, packets (auditor reveal, shredded refs)."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_lane_s_world import SWorld


def _type(resp: Any) -> str:
    return str(resp.json().get("type", "")).rsplit("/", 1)[-1]


def _task(s: SWorld, *, priority: int = 2, deadline_s: int = 3600, ref: UUID | None = None) -> str:
    agent = s.agent()
    return str(
        s.val(
            "INSERT INTO sibyl.handoff_task (tenant_id, agent_id, task_id, packet_id, packet,"
            " packet_ref_id, packet_sha256, fidelity, failure_mode, trigger_kind, assembled_by,"
            " priority, deadline_at, next_action, summary) VALUES ($1, $2, $3, $4,"
            ' CASE WHEN $5::uuid IS NULL THEN \'{"schema": "sibyl-handoff/1", "goal":'
            ' "g"}\'::jsonb END,'
            " $5, $6, 'request_only', 'tool_failure', 'operator', 'control_plane', $7,"
            " now() + make_interval(secs => $8), 'do it by hand', 'queue test task') RETURNING id",
            s.a.id,
            agent,
            uuid4(),
            uuid4(),
            ref,
            b"\x02" * 32,
            priority,
            deadline_s,
        )
    )


def _do(s: SWorld, task: str, action: str, who: str = "operator", **extra: Any) -> Any:
    return s.post(who, f"/handoff-tasks/{task}/actions", {"action": action, **extra})


def test_claim_complete_counts_as_completed_despite_failure(sworld: SWorld) -> None:
    s = sworld
    before = s.get("operator", "/queue").json()["summary"]["completed_despite_failure"]
    task = _task(s)
    claimed = _do(s, task, "claim")
    assert claimed.status_code == 200, claimed.text
    body = claimed.json()
    assert body["state"] == "claimed" and body["claimed_by"] == str(s.users["operator"])
    assert body["lock_expires_at"] is not None
    assert _do(s, task, "complete").status_code == 422  # outcome required
    done = _do(s, task, "complete", outcome="resolved", outcome_note="done by hand", rating=4)
    assert done.status_code == 200 and done.json()["outcome"] == "resolved"
    assert done.json()["rating"] == 4
    assert s.val("SELECT rating FROM sibyl.handoff_task WHERE id = $1", UUID(task)) == 4
    assert s.get("operator", f"/handoff-tasks/{task}").json()["rating"] == 4
    summary = s.get("operator", "/queue").json()["summary"]
    assert summary["completed_despite_failure"] == before + 1
    label = s.val(
        "SELECT value->>'rating' FROM sibyl.label WHERE tenant_id = $1 AND kind = 'handoff_outcome'"
        " AND value->>'handoff_task_id' = $2",
        s.a.id,
        task,
    )
    assert label == "4"
    actions = s.audit_actions(s.a)
    assert "handoff.claimed" in actions and "handoff.completed" in actions


def test_claimed_by_other_lock_lapsed_extend_and_release(sworld: SWorld) -> None:
    s = sworld
    task = _task(s)
    s.human("operator2", s.a, ("operator",))
    assert _do(s, task, "claim").status_code == 200
    other = _do(s, task, "claim", who="operator2")
    assert other.status_code == 409 and _type(other) == "claimed_by_other"
    assert (
        _type(_do(s, task, "complete", who="operator2", outcome="resolved")) == "claimed_by_other"
    )
    assert _do(s, task, "extend_lock").status_code == 200
    s.admin.execute(
        "UPDATE sibyl.handoff_task SET claim_lock_until = now() - interval '1 s' WHERE id = $1",
        UUID(task),
    )
    lapsed = _do(s, task, "complete", outcome="resolved")
    assert lapsed.status_code == 409 and _type(lapsed) == "lock_lapsed"
    taken = _do(s, task, "claim", who="operator2")  # a lapsed claim can be taken over
    assert taken.status_code == 200 and taken.json()["reclaim_count"] == 1
    released = _do(s, task, "release_claim", who="operator2")
    assert released.status_code == 200 and released.json()["state"] == "queued"
    assert "handoff.claim_released" in s.audit_actions(s.a)


def test_return_only_from_queued_and_reassign(sworld: SWorld) -> None:
    s = sworld
    task = _task(s)
    reassigned = _do(s, task, "reassign", who="admin", accountable_user_id=str(s.users["operator"]))
    assert reassigned.status_code == 200 and reassigned.json()["accountable_user_id"] == str(
        s.users["operator"]
    )
    assert (
        _do(
            s, task, "reassign", who="operator", accountable_user_id=str(s.users["operator"])
        ).status_code
        == 403
    )
    assert (
        _do(s, task, "reassign", who="admin", accountable_user_id=str(uuid4())).status_code == 422
    )
    _do(s, task, "claim")
    assert _type(_do(s, task, "return")) == "invalid_transition"
    _do(s, task, "release_claim")
    returned = _do(s, task, "return")
    assert returned.status_code == 200 and returned.json()["outcome"] == "returned_to_agent"
    assert _type(_do(s, task, "claim")) == "invalid_transition"


def test_expired_tasks_can_still_be_claimed(sworld: SWorld) -> None:
    s = sworld
    task = _task(s)
    s.admin.execute(
        "UPDATE sibyl.handoff_task SET state = 'expired', outcome = 'expired_unclaimed' WHERE id"
        " = $1",
        UUID(task),
    )
    resp = _do(s, task, "claim")
    assert resp.status_code == 200 and resp.json()["state"] == "claimed"


def test_queue_order_filters_and_mine(sworld: SWorld) -> None:
    s = sworld
    late = _task(s, priority=3, deadline_s=100)
    urgent = _task(s, priority=1, deadline_s=5000)
    data = s.get("operator", "/queue", limit=200).json()["data"]
    ids = [t["id"] for t in data]
    assert ids.index(urgent) < ids.index(late)
    assert all("packet" not in t for t in data)
    _do(s, urgent, "claim")
    mine = s.get("operator", "/queue", mine=True, limit=200).json()["data"]
    assert urgent in {t["id"] for t in mine} and late not in {t["id"] for t in mine}
    assert {t["claimed_by"] for t in mine} == {str(s.users["operator"])}
    assert s.get("viewer", "/queue").status_code == 200  # agents:read sees summaries
    assert s.get("operator", "/queue", priority=3, state="queued").json()["data"]
    page = s.get("operator", "/queue", limit=1).json()
    nxt = s.get("operator", "/queue", limit=1, cursor=page["next_cursor"]).json()
    assert page["data"][0]["id"] != nxt["data"][0]["id"]


def test_task_and_packet_reads(sworld: SWorld) -> None:
    s = sworld
    task = _task(s)
    meta = s.get("viewer", f"/handoff-tasks/{task}")
    assert meta.status_code == 200 and "packet" not in meta.json()
    assert s.get("viewer", f"/handoff-tasks/{task}/packet").status_code == 403
    packet = s.get("operator", f"/handoff-tasks/{task}/packet")
    assert packet.status_code == 200 and packet.json()["schema"] == "sibyl-handoff/1"
    assert packet.headers["etag"] == '"' + "02" * 32 + '"'
    head = s.head(s.a)
    audited = s.get("auditor", f"/handoff-tasks/{task}/packet")
    assert audited.status_code == 200
    assert s.audit_actions(s.a, head) == ["data.revealed"]
    assert audited.headers.get("X-Sibyl-Audit-Receipt", "").startswith(str(s.a.id))
    assert s.get("owner", f"/handoff-tasks/{uuid4()}").status_code == 404


def test_packet_by_ref_that_was_shredded_is_404(sworld: SWorld) -> None:
    s = sworld
    task = _task(s, ref=uuid4())
    resp = s.get("operator", f"/handoff-tasks/{task}/packet")
    assert resp.status_code == 404 and _type(resp) == "packet_shredded"


@pytest.mark.parametrize("action", ["claim", "complete"])
def test_queue_actions_need_queue_scope(sworld: SWorld, action: str) -> None:
    s = sworld
    task = _task(s)
    assert _do(s, task, action, who="viewer").status_code == 403
