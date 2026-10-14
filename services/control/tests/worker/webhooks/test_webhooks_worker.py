"""The webhooks loop on PG17 as ``sibyl_worker`` (D53): outbox and failed runs become deliveries
for the right webhooks only, deliveries are signed and sent through the transport, retried with
backoff and dead-lettered (audited), paused monitors wait, revoked ones are dropped, external
findings raise watch-only alerts, and settled deliveries are purged after 14 days."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.worker.loops import LOOPS, resolve_tick
from sibyl_control.worker.webhooks.deliver import MAX_ATTEMPTS
from sibyl_schemas.webhook_signature import verify

from .conftest import WWorld


def _alert(agent: UUID | None, rule: str = "error_rate") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "alert_id": str(uuid4()),
        "rule": rule,
        "severity": "warning",
        "scope": "agent" if agent else "provider",
        "state": "open",
    }
    if agent is not None:
        payload["agent_id"] = str(agent)
    return payload


def _failed_run(ww: WWorld, agent: UUID) -> UUID:
    run = uuid4()
    ww.w.admin.in_tenant(
        ww.tenant,
        "INSERT INTO sibyl.events (tenant_id, event_id, ts, event_type, source, agent_id, task_id,"
        " trace_id, emitter_id, seq, policy_state, capture_mode, redaction_profile_hash,"
        " normaliser_version, status, error_type, received_at, attrs) VALUES ($1, $2,"
        " now() - interval '2 seconds', 'agent.invoke', 'sdk', $3, $4, $5, 'sdk', 1, 'fresh',"
        " 'full', $6, 'normaliser/1.0', 'error', 'timeout', now(),"
        ' \'{"phase": "end", "status": "error"}\')',
        ww.tenant,
        uuid4(),
        agent,
        run,
        uuid4(),
        b"\x07" * 32,
    )
    return run


def test_the_loop_is_registered() -> None:
    spec = next(s for s in LOOPS if s.name == "webhooks")
    assert spec.owner == "EXTMON" and spec.channel == "sibyl_outbox"
    assert resolve_tick(spec) is not None


def test_outbox_events_reach_subscribed_webhooks_signed(ww: WWorld) -> None:
    ww.tick()  # first scan only places the cursor at the horizon: no backlog
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired", "drift.detected", "action.held"])
    ww.tick()
    agent = ww.w.a.agents["in_g1"]
    ww.outbox("alert.fired", "alert", _alert(agent, "silent_drift"))
    ww.outbox(
        "action.held",
        "held_action",
        {
            "held_action_id": str(uuid4()),
            "agent_id": str(agent),
            "tool": "payments.transfer",
            "state": "pending",
            "decision": None,
        },
    )
    ww.outbox("incident.updated", "failover", {"failover_id": str(uuid4()), "agent_id": str(agent)})
    report = ww.tick()
    rows = ww.deliveries(hook["id"])
    assert sorted(r["event_type"] for r in rows) == ["action.held", "alert.fired", "drift.detected"]
    assert report.outcomes == {"delivered": 3}
    assert {r["status"] for r in ww.deliveries(hook["id"])} == {"delivered"}
    assert len(ww.receiver.requests) == 3
    for request in ww.receiver.requests:
        verify(hook["secret"], request.headers["Sibyl-Signature"], request.content)
        event = json.loads(request.content)
        assert event["monitor_id"] == m["id"] and event["advisory"] is True
        assert request.headers["Sibyl-Event-Id"] == event["id"]
        assert hook["secret"] not in request.content.decode()
    again = ww.tick()  # nothing new: no duplicate deliveries
    assert again.enqueued == 0 and len(ww.deliveries(hook["id"])) == 3
    view = ww.api("GET", f"/monitors/{m['id']}")["webhooks"][0]
    assert view["last_delivery_status"] == "delivered" and view["last_response_code"] == 204


def test_watched_groups_and_tenant_level_events(ww: WWorld) -> None:
    everything = ww.monitor()
    narrow = ww.monitor(all_groups=False, group_ids=[str(ww.w.a.groups["g1"])])
    wide_hook = ww.webhook(everything["id"], ["alert.fired"])
    narrow_hook = ww.webhook(narrow["id"], ["alert.fired"])
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g2"]))  # g2 is under g1
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["other"]))
    ww.outbox("alert.fired", "alert", _alert(None))  # a provider-level alert
    ww.tick()
    assert len(ww.deliveries(wide_hook["id"])) == 3
    narrow_rows = ww.deliveries(narrow_hook["id"])
    assert [r["agent_id"] for r in narrow_rows] == [ww.w.a.agents["in_g2"]]


def test_failed_runs_are_delivered_once(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["run.failed"])
    ww.tick()
    run = _failed_run(ww, ww.w.a.agents["in_g1"])
    later = datetime.now(UTC) + timedelta(seconds=10)  # past the settle delay
    ww.tick(clock=lambda: later)
    rows = ww.deliveries(hook["id"])
    assert [r["event_key"] for r in rows] == [f"run:{run}"]
    data = rows[0]["payload"]["data"]
    assert data["run_id"] == str(run) and data["status"] == "error"
    assert data["error_type"] == "timeout"
    ww.tick(clock=lambda: later)  # the re-scan overlap sees it again; the event key absorbs it
    assert len(ww.deliveries(hook["id"])) == 1


def test_retries_back_off_then_dead_letter_with_audit(ww: WWorld, caplog: Any) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    ww.receiver.status = 503
    caplog.set_level(logging.DEBUG)
    report = ww.tick()
    assert report.outcomes == {"retrying": 1}
    row = ww.deliveries(hook["id"])[0]
    assert (row["status"], row["attempts"], row["response_code"]) == ("retrying", 1, 503)
    assert row["next_attempt_at"] > row["last_attempt_at"]
    head = ww.w.audit_head(ww.tenant)
    for _ in range(MAX_ATTEMPTS - 1):
        ww.due_now(hook["id"])
        ww.tick()
    row = ww.deliveries(hook["id"])[0]
    assert (row["status"], row["attempts"], row["error"]) == ("dead", MAX_ATTEMPTS, "http_error")
    assert len(ww.receiver.requests) == MAX_ATTEMPTS
    audit = ww.w.admin.fetchrow(
        "SELECT action, actor_type, detail FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND seq > $2 AND action = 'webhook.delivery_failed'",
        ww.tenant,
        head,
    )
    assert audit["actor_type"] == "system" and audit["detail"]["attempts"] == MAX_ATTEMPTS
    assert hook["secret"] not in caplog.text
    view = ww.api("GET", f"/monitors/{m['id']}")["webhooks"][0]
    assert view["consecutive_failures"] == 1 and view["last_delivery_status"] == "dead"


def test_paused_monitors_wait_and_revoked_ones_drop(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    ww.receiver.status = 500
    ww.tick()  # one failed attempt: retrying
    resp = ww.w.client.patch(
        f"/api/v1/monitors/{m['id']}",
        json={"state": "paused"},
        headers=ww.w.headers("owner", **{"If-Match": '"1"'}),
    )
    assert resp.status_code == 200, resp.text
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    ww.due_now(hook["id"])
    report = ww.tick()
    assert report.outcomes == {"waiting": 1} and report.enqueued == 0
    ww.api("POST", f"/monitors/{m['id']}/revoke", {"reason": "the monitor is being replaced"})
    ww.due_now(hook["id"])
    sent = len(ww.receiver.requests)
    report = ww.tick()
    assert report.outcomes == {"dead": 1} and len(ww.receiver.requests) == sent
    assert ww.deliveries(hook["id"])[0]["error"] == "webhook_disabled"


def test_external_findings_raise_watch_only_alerts(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired", "alert.updated"])
    ww.tick()
    agent = ww.w.a.agents["in_g1"]
    body = {
        "kind": "safety",
        "subject_kind": "agent",
        "subject_id": str(agent),
        "severity": "critical",
        "summary": "Prompt-injection-like trajectory in three runs.",
    }
    first = ww.api("POST", "/findings", body, who=m["id"])
    second = ww.api("POST", "/findings", body, who=m["id"])
    quiet = ww.api("POST", "/findings", {**body, "severity": "info"}, who=m["id"])
    report = ww.tick()
    assert report.alerts == 2
    alerts = ww.w.admin.fetch(
        "SELECT a.id, a.state, a.fired_count, r.code, r.kind FROM sibyl.alert a"
        " JOIN sibyl.alert_rule r ON r.tenant_id = a.tenant_id AND r.id = a.rule_id"
        " WHERE a.tenant_id = $1 AND a.agent_id = $2 AND r.code = 'external_finding'",
        ww.tenant,
        agent,
    )
    assert len(alerts) == 1 and alerts[0]["kind"] == "leading" and alerts[0]["fired_count"] >= 1
    linked = ww.w.admin.fetch(
        "SELECT id, alert_id, alert_checked_at FROM sibyl.external_finding WHERE id = ANY($1)",
        [UUID(first["id"]), UUID(second["id"]), UUID(quiet["id"])],
    )
    by_id = {str(r["id"]): r for r in linked}
    assert by_id[first["id"]]["alert_id"] == alerts[0]["id"]
    assert by_id[second["id"]]["alert_id"] == alerts[0]["id"]
    assert by_id[quiet["id"]]["alert_checked_at"] is None  # never asked for an alert
    seen = ww.api("GET", f"/findings/{first['id']}")
    assert seen["alert_id"] == str(alerts[0]["id"])
    ww.tick()  # the alert's own outbox rows reach the webhook
    types = sorted(r["event_type"] for r in ww.deliveries(hook["id"]))
    assert types == ["alert.fired", "alert.updated"]
    failovers = ww.w.admin.fetchval(
        "SELECT count(*) FROM sibyl.failover WHERE tenant_id = $1 AND agent_id = $2",
        ww.tenant,
        agent,
    )
    assert failovers == 0  # advisory: no automation started


def test_without_a_kek_deliveries_wait(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    report = ww.tick(kek=None)
    assert report.enqueued == 1 and report.outcomes == {}
    assert ww.deliveries(hook["id"])[0]["status"] == "pending"


def test_settled_deliveries_are_purged_after_14_days(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    ww.tick()
    ww.w.admin.in_tenant(
        ww.tenant,
        "UPDATE sibyl.webhook_delivery SET settled_at = now() - interval '15 days'"
        " WHERE webhook_id = $1",
        UUID(hook["id"]),
    )
    report = ww.tick()
    assert report.purged >= 1 and ww.deliveries(hook["id"]) == []


def test_a_webhook_that_keeps_dying_is_disabled(ww: WWorld) -> None:
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.w.admin.in_tenant(
        ww.tenant,
        "UPDATE sibyl.monitor_webhook SET consecutive_failures = 49 WHERE id = $1",
        UUID(hook["id"]),
    )
    ww.tick()
    ww.outbox("alert.fired", "alert", _alert(ww.w.a.agents["in_g1"]))
    ww.receiver.status = 410
    ww.tick()
    ww.w.admin.in_tenant(
        ww.tenant,
        "UPDATE sibyl.webhook_delivery SET attempts = $2 WHERE webhook_id = $1",
        UUID(hook["id"]),
        MAX_ATTEMPTS - 1,
    )
    ww.due_now(hook["id"])
    ww.tick()
    view = ww.api("GET", f"/monitors/{m['id']}")["webhooks"][0]
    assert view["state"] == "disabled" and view["disabled_reason"] == "deliveries kept failing"


@pytest.mark.parametrize("who", ["sibyl_worker"])
def test_the_worker_cannot_read_the_sealed_secret(ww: WWorld, who: str) -> None:
    async def probe() -> Any:
        async with ww.db.tenant_tx(ww.tenant, readonly=True) as conn:
            return await conn.fetch("SELECT ciphertext FROM sibyl.monitor_webhook LIMIT 1")

    with pytest.raises(Exception, match="permission denied"):
        ww.run(probe())


def test_an_oversized_event_is_trimmed_and_never_stalls_the_loop(ww: WWorld) -> None:
    """Security review (EXTMON): an outbox payload within the outbox's 8 KB canonical limit can
    exceed the delivery's 8 KB ``payload::text`` CHECK once wrapped (jsonb text adds spaces and
    the envelope adds ~250 bytes). That insert used to abort the tenant's whole webhooks
    transaction every tick (no deliveries, no external_finding alerts, cursor stuck). It is
    now delivered with references only."""
    m = ww.monitor()
    hook = ww.webhook(m["id"], ["alert.fired"])
    ww.tick()
    agent = ww.w.a.agents["in_g1"]
    big = _alert(agent) | {f"k{i:03d}": 1 for i in range(880)}
    ww.outbox("alert.fired", "alert", big)
    ww.outbox("alert.fired", "alert", _alert(agent))
    ww.tick()
    rows = ww.deliveries(hook["id"])
    assert len(rows) == 2
    payloads = [
        json.loads(r["payload"]) if isinstance(r["payload"], str) else r["payload"] for r in rows
    ]
    trimmed = [p for p in payloads if p["data"].get("truncated")]
    assert len(trimmed) == 1
    assert trimmed[0]["data"]["agent_id"] == str(agent)
    assert not any(k.startswith("k0") for k in trimmed[0]["data"])
