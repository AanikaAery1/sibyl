"""Findings routes on PG17 (D53): submission (shape, subjects, idempotency, per-monitor rate,
alert request, held-action advice), the unified list across Sentinel and external sources, and
feedback on both. A finding never touches an enforcement table."""

from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.ratelimit import InMemoryRateLimiter

from .conftest import get, new_monitor, post

PROMPT_SHA = b"\x07" * 32


def _finding(agent: UUID, **changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "anomaly",
        "subject_kind": "agent",
        "subject_id": str(agent),
        "severity": "warning",
        "summary": "Tool-call rate tripled in the last hour.",
        "body": {"tool_calls_per_run": {"before": 3, "after": 9}},
        "recommendation": "Check the new prompt version.",
        "confidence": "medium",
        "provider": "openai",
        "model": "gpt-5.4",
    }
    body.update(changes)
    return body


def _held(world: Any, agent: UUID) -> UUID:
    held = uuid4()
    world.admin.execute(
        "INSERT INTO sibyl.held_action (tenant_id, id, agent_id, call_id, tool, source,"
        " args_sha256, args_bytes, server_effect, reason, requested_by_key_id, hold_timeout_s,"
        " expires_at) VALUES ($1, $2, $3, $4, 'payments.transfer', 'sdk', $5, 20, 'escalate',"
        " 'needs a human', $6, 900, now() + interval '15 minutes')",
        world.a.id,
        held,
        agent,
        f"findings-{held.hex[:12]}",
        b"\x05" * 32,
        uuid4(),
    )
    return held


def failed_run(world: Any, agent: UUID) -> UUID:
    """A finished root run that failed: one ``agent.invoke`` end event (run id = task id)."""
    run = uuid4()
    world.admin.in_tenant(
        world.a.id,
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, task_id,"
        " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
        " normaliser_version, status, error_type, attrs) VALUES ($1, $2, now() - interval"
        " '5 seconds', 'agent.invoke', 'sdk', $3, $4, $5, 'sdk', 1, 'fresh', 'full', $6,"
        " 'normaliser/1.0', 'error', 'timeout',"
        """ '{"phase": "end", "agent_name": "monitored", "status": "error"}')""",
        world.a.id,
        uuid4(),
        agent,
        run,
        uuid4(),
        b"\x07" * 32,
    )
    return run


def _sentinel_finding(world: Any, agent: UUID) -> UUID:
    fid = uuid4()
    with world.admin.tx(world.a.id):
        world.admin.execute(
            "INSERT INTO sibyl.sentinel_finding (tenant_id, id, kind, subject_kind, subject_id,"
            " agent_id, severity, summary, body, provider, model, prompt_sha256, trigger)"
            " VALUES ($1, $2, 'semantic_drift', 'agent', $3, $3, 'info', 'on purpose',"
            " '{\"output\": {\"confidence\": \"high\"}}', 'anthropic', 'claude-fable-5-1', $4,"
            " 'scheduled')",
            world.a.id,
            fid,
            agent,
            PROMPT_SHA,
        )
    return fid


def test_submit_shape_and_idempotency(mw: Any) -> None:
    agent = mw.a.agents["in_g1"]
    headers = mw.idem("monitor")
    first = mw.client.post("/api/v1/findings", json=_finding(agent), headers=headers)
    assert first.status_code == 201, first.text
    view = first.json()
    assert view["source"] == "external" and view["monitor_id"] == str(mw.monitor_ids["monitor"])
    assert view["monitor_name"] == "contract-monitor" and view["agent_id"] == str(agent)
    assert view["body"] == {"tool_calls_per_run": {"before": 3, "after": 9}}
    assert view["trigger"] == "external" and view["cost_usd"] is None
    assert first.headers["Location"].endswith(view["id"])
    again = mw.client.post("/api/v1/findings", json=_finding(agent), headers=headers)
    assert again.status_code == 201 and again.json()["id"] == view["id"]
    assert again.headers["Idempotency-Replayed"] == "true"


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "incident_explanation"},  # kind fixes the subject (incident)
        {"subject_kind": "fleet"},  # a fleet finding has no subject_id
        {"subject_id": None},
        {"advice": "approve"},  # advice is for held_action_review only
        {"severity": "info", "raise_alert": True},
        {"summary": ""},
        {"summary": "bell\x07"},
        {"body": {"blob": "x" * 40_000}},
        {"provider": "Not A Provider"},
        {"unexpected": 1},
    ],
)
def test_submit_rejects_bad_bodies(mw: Any, changes: dict[str, Any]) -> None:
    resp = post(mw, "/findings", _finding(mw.a.agents["in_g1"], **changes), who="monitor")
    assert resp.status_code == 422, (changes, resp.text)


def test_humans_and_plain_keys_cannot_submit(mw: Any) -> None:
    body = _finding(mw.a.agents["in_g1"])
    assert post(mw, "/findings", body, who="owner").status_code == 403
    assert post(mw, "/findings", body, who="keys").status_code == 403


def test_every_subject_kind_resolves_its_agent(mw: Any) -> None:
    agent = mw.a.agents["in_g2"]
    held = _held(mw, agent)
    review = {
        "kind": "held_action_review",
        "subject_kind": "held_action",
        "subject_id": str(held),
        "severity": "warning",
        "summary": "The transfer exceeds the customer's usual amount.",
        "advice": "deny",
        "recommendation": "Deny and ask the customer to confirm by phone.",
    }
    resp = post(mw, "/findings", review, who="monitor")
    assert resp.status_code == 201, resp.text
    assert resp.json()["agent_id"] == str(agent) and resp.json()["advice"] == "deny"
    status = mw.admin.fetchval("SELECT state FROM sibyl.held_action WHERE id = $1", held)
    assert status == "pending"  # advisory: the hold is untouched
    by_hold = get(mw, "/findings", subject_kind="held_action", subject_id=str(held)).json()
    assert [f["id"] for f in by_hold["data"]] == [resp.json()["id"]]
    run = failed_run(mw, agent)
    on_run = post(
        mw, "/findings", _finding(agent, subject_kind="run", subject_id=str(run)), who="monitor"
    )
    assert on_run.status_code == 201, on_run.text
    assert on_run.json()["agent_id"] == str(agent)
    unknown = post(
        mw,
        "/findings",
        _finding(agent, subject_kind="incident", subject_id=str(uuid4())),
        who="monitor",
    )
    assert unknown.status_code == 404


def test_alerts_are_requested_only_when_warranted(mw: Any) -> None:
    agent = mw.a.agents["in_g1"]
    cases = [
        ({"severity": "critical"}, True),
        ({"severity": "critical", "raise_alert": False}, False),
        ({"severity": "warning"}, False),
        ({"severity": "warning", "raise_alert": True}, True),
        ({"severity": "info"}, False),
    ]
    for changes, wanted in cases:
        resp = post(mw, "/findings", _finding(agent, **changes), who="monitor")
        assert resp.status_code == 201, resp.text
        flag = mw.admin.fetchval(
            "SELECT alert_requested FROM sibyl.external_finding WHERE id = $1",
            UUID(resp.json()["id"]),
        )
        assert flag is wanted, changes


def test_the_rate_limit_is_per_monitor(mw: Any) -> None:
    created = new_monitor(mw, rate_limit_per_min=2)
    services = mw.lane.services
    previous = services.rate_limiter
    services.rate_limiter = InMemoryRateLimiter()
    try:
        body = _finding(mw.a.agents["in_g1"])
        codes = [post(mw, "/findings", body, who=created["id"]).status_code for _ in range(3)]
        assert codes == [201, 201, 429]
        limited = post(mw, "/findings", body, who=created["id"])
        assert int(limited.headers["Retry-After"]) >= 1
        assert post(mw, "/findings", body, who="monitor").status_code == 201  # other monitor
    finally:
        services.rate_limiter = previous


def test_list_get_and_feedback_across_sources(mw: Any) -> None:
    agent = mw.a.agents["other"]
    sentinel = _sentinel_finding(mw, agent)
    external = post(mw, "/findings", _finding(agent), who="monitor").json()["id"]
    both = get(mw, "/findings", "auditor", agent_id=str(agent)).json()["data"]
    assert {f["id"] for f in both} >= {str(sentinel), external}
    only = get(mw, "/findings", source="sentinel", agent_id=str(agent)).json()["data"]
    assert [f["id"] for f in only] == [str(sentinel)]
    assert only[0]["confidence"] == "high" and only[0]["monitor_id"] is None
    mine = get(mw, "/findings", monitor_id=str(mw.monitor_ids["monitor"]), limit=200).json()
    assert external in {f["id"] for f in mine["data"]}
    page = get(mw, "/findings", limit=1).json()
    assert page["has_more"] and page["next_cursor"]
    nxt = get(mw, "/findings", limit=1, cursor=page["next_cursor"]).json()
    assert nxt["data"][0]["id"] != page["data"][0]["id"]
    assert get(mw, f"/findings/{sentinel}").json()["source"] == "sentinel"
    assert get(mw, f"/findings/{uuid4()}").status_code == 404
    assert get(mw, "/findings", "viewer").status_code == 403
    head = mw.audit_head(mw.a.id)
    rated = post(mw, f"/findings/{external}/feedback", {"feedback": "wrong"}, who="operator")
    assert rated.status_code == 200 and rated.json()["feedback"] == "wrong"
    rated = post(mw, f"/findings/{sentinel}/feedback", {"feedback": "useful"}, who="operator")
    assert rated.status_code == 200 and rated.json()["feedback"] == "useful"
    actions = [a for a in mw.audit_since(mw.a.id, head) if a != "access.denied"]
    assert actions == ["finding.feedback_recorded", "sentinel.feedback_recorded"]
    missing = post(mw, f"/findings/{uuid4()}/feedback", {"feedback": "useful"})
    assert missing.status_code == 404
    assert post(mw, f"/findings/{external}/feedback", {"feedback": "x"}).status_code == 422
