"""Alert routes on PG17: lists and the D33 queue, one alert with its fire-time snapshot, ack /
silence / close-with-verdict (D24) with labels, audit, outbox and idempotency, provider-scope
verdict propagation, provider incidents, and the role and group rules."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_lane_a_kit as kit  # loaded by conftest
from sibyl_control.core.audit import RECEIPT_HEADER

API = "/api/v1"
NOW = datetime.now(UTC)


# ---- seeds ---------------------------------------------------------------------------------------


def provider(db: Any, w: Any, slug: str = "prov-a") -> UUID:
    pid = uuid4()
    with db.admin.tx(w.tenant):
        db.admin.execute(
            "INSERT INTO sibyl.provider (tenant_id, id, slug, name, provider_kind, dialect,"
            " base_url)"
            " VALUES ($1, $2, $3, $3, 'openai', 'openai_compatible', $4)",
            w.tenant,
            pid,
            slug,
            f"https://api.{slug}.example/v1",
        )
    return pid


def snapshot(db: Any, w: Any, agent: UUID, at: datetime) -> UUID:
    with db.admin.tx(w.tenant):
        config = db.admin.fetchval(
            "SELECT id FROM sibyl.scoring_config WHERE tenant_id = $1 LIMIT 1", w.tenant
        )
        return db.admin.fetchval(  # type: ignore[no-any-return]
            "INSERT INTO sibyl.health_snapshot (tenant_id, evaluated_at, agent_id, score, band,"
            " provisional, events_seen, observation_coverage, factors, horizons, scoring_config_id,"
            " policy_version, routing_state_at, window_start, window_end, grain_s)"
            " VALUES ($1, $2::timestamptz, $3, 42, 'failed', false, 300, 1, $4::jsonb, '{}', $5,"
            " 1, 'active', $2::timestamptz - interval '5 minutes', $2::timestamptz, 300)"
            " RETURNING id",
            w.tenant,
            at,
            agent,
            [
                {
                    "rule": "error_rate",
                    "penalty": 40,
                    "weight": 0.4,
                    "value": 0.6,
                    "threshold": 0.1,
                    "direction": "above",
                    "explanation": "errors",
                    "kind": "detected",
                }
            ],
            config,
        )


def alert(
    db: Any,
    w: Any,
    *,
    agent: UUID | None = None,
    provider_id: UUID | None = None,
    code: str = "error_rate",
    state: str = "open",
    severity: str = "warning",
    fired: datetime | None = None,
    resolved: datetime | None = None,
    verdict_wanted: bool = False,
    suppressed: bool = False,
    incident: UUID | None = None,
    with_snapshot: bool = False,
) -> UUID:
    fired = fired or NOW - timedelta(minutes=10)
    scope = "agent" if agent is not None else "provider"
    snap = snapshot(db, w, agent, fired) if with_snapshot and agent else None
    with db.admin.tx(w.tenant):
        rule = db.admin.fetchval(
            "SELECT id FROM sibyl.alert_rule WHERE tenant_id = $1 AND code = $2", w.tenant, code
        )
        return db.admin.fetchval(  # type: ignore[no-any-return]
            "INSERT INTO sibyl.alert (tenant_id, rule_id, scope, agent_id, provider_id, severity,"
            " state, dedupe_key, first_fired_at, last_evaluated_at, resolved_at, what_to_do,"
            " evidence, health_snapshot_id, verdict_wanted, suppressed_by_incident,"
            " provider_incident_id, outcome_observed, summary)"
            " VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9, $10, 'Check the provider.',"
            " '{\"rule\": \"error_rate\"}', $11, $12, $13, $14, $15, 'Error rate 60%')"
            " RETURNING id",
            w.tenant,
            rule,
            scope,
            agent,
            provider_id,
            severity,
            state,
            f"{code}:{scope}:{agent or provider_id}:{uuid4()}",
            fired,
            resolved,
            snap,
            verdict_wanted,
            suppressed,
            incident,
            "recovered" if state == "resolved" else None,
        )


def incident(db: Any, w: Any, pid: UUID, agents: list[UUID]) -> UUID:
    with db.admin.tx(w.tenant):
        return db.admin.fetchval(  # type: ignore[no-any-return]
            "INSERT INTO sibyl.provider_incident (tenant_id, provider_id, severity, rule_codes,"
            " affected_agent_ids, summary) VALUES ($1, $2, 'critical', '{error_rate}', $3,"
            " 'Provider prov-a: 2 agents') RETURNING id",
            w.tenant,
            pid,
            agents,
        )


def tok(lane: Any, w: Any, role: str) -> str:
    return kit.add_session(lane.db, w.tenant, w.users[role])  # type: ignore[no-any-return]


def get(lane: Any, token: str, path: str, **params: Any) -> Any:
    return lane.client.get(f"{API}{path}", params=params, headers=lane.bearer(token))


def act(lane: Any, token: str, alert_id: UUID, body: dict[str, Any], key: str | None = None) -> Any:
    headers = lane.bearer(token, **{"Idempotency-Key": key or str(uuid4())})
    return lane.client.post(f"{API}/alerts/{alert_id}/actions", json=body, headers=headers)


def db_row(lane: Any, w: Any, sql: str, *args: Any) -> Any:
    with lane.db.admin.tx(w.tenant):
        return lane.db.admin.fetchrow(sql, *args)


def outbox_types(lane: Any, w: Any) -> list[str]:
    return [r["event_type"] for r in kit.outbox_events(lane.db, w.tenant)]


# ---- lists ---------------------------------------------------------------------------------------


def test_list_filters_groups_and_suppression(lane: Any, world: Any) -> None:
    w = world
    pid = provider(lane.db, w)
    a1 = alert(lane.db, w, agent=w.agents["in_g1"], severity="critical")
    a2 = alert(lane.db, w, agent=w.agents["in_g2"], code="p95_latency")
    other = alert(lane.db, w, agent=w.agents["other"])
    prov = alert(lane.db, w, provider_id=pid, code="provider_status")
    hidden = alert(
        lane.db, w, agent=w.agents["in_g1"], code="consecutive_failures", suppressed=True
    )
    owner = tok(lane, w, "owner")

    ids = lambda resp: {d["id"] for d in resp.json()["data"]}  # noqa: E731
    resp = get(lane, owner, "/alerts")
    assert resp.status_code == 200
    assert ids(resp) == {str(x) for x in (a1, a2, other, prov)}
    assert str(hidden) in ids(get(lane, owner, "/alerts", include_suppressed="true"))
    assert ids(get(lane, owner, "/alerts", severity="critical")) == {str(a1)}
    assert ids(get(lane, owner, "/alerts", rule_code="p95_latency")) == {str(a2)}
    assert ids(get(lane, owner, "/alerts", agent_id=str(w.agents["other"]))) == {str(other)}
    assert ids(get(lane, owner, "/alerts", provider_id=str(pid))) == {str(prov)}
    one = get(lane, owner, "/alerts", rule_code="p95_latency").json()["data"][0]
    assert one["rule_code"] == "p95_latency" and one["fired_at"] and one["verdict"] is None
    # agents:read is tenant-wide for every role (API.md §2.2): the group-scoped engineer reads
    # every alert, and only alerts:act is group-limited (see the action tests)
    eng = tok(lane, w, "engineer")
    assert ids(get(lane, eng, "/alerts")) == {str(a1), str(a2), str(other), str(prov)}
    assert get(lane, owner, "/alerts", state="bogus").status_code == 422


def test_list_pages_with_a_cursor(lane: Any, world: Any) -> None:
    w = world
    made = [
        alert(lane.db, w, agent=w.agents["in_g1"], fired=NOW - timedelta(minutes=i + 1))
        for i in range(3)
    ]
    owner = tok(lane, w, "owner")
    first = get(lane, owner, "/alerts", limit=2).json()
    assert first["has_more"] and len(first["data"]) == 2
    second = get(lane, owner, "/alerts", limit=2, cursor=first["next_cursor"]).json()
    assert not second["has_more"]
    assert [d["id"] for d in first["data"] + second["data"]] == [str(x) for x in made]
    stale = get(lane, owner, "/alerts", limit=2, cursor=first["next_cursor"], severity="critical")
    assert stale.status_code == 400


def test_unverdicted_queue_puts_verdict_wanted_first_with_the_backlog_sli(
    lane: Any, world: Any
) -> None:
    w = world
    g1 = w.agents["in_g1"]
    old = alert(
        lane.db,
        w,
        agent=g1,
        state="resolved",
        resolved=NOW - timedelta(days=8),
        fired=NOW - timedelta(days=8, minutes=5),
    )
    wanted = alert(
        lane.db,
        w,
        agent=g1,
        code="p95_latency",
        state="resolved",
        resolved=NOW - timedelta(days=1),
        verdict_wanted=True,
    )
    recent = alert(
        lane.db,
        w,
        agent=g1,
        code="consecutive_failures",
        state="resolved",
        resolved=NOW - timedelta(hours=1),
    )
    alert(lane.db, w, agent=g1, code="tool_loop")  # open: not in the queue
    body = get(lane, tok(lane, w, "operator"), "/alerts", unverdicted="true").json()
    assert [d["id"] for d in body["data"]] == [str(wanted), str(recent), str(old)]
    assert body["backlog"]["unverdicted"] == 3
    assert body["backlog"]["unverdicted_older_than_7d"] == 1
    assert body["backlog"]["ratio"] == pytest.approx(1 / 3, abs=1e-4)
    assert body["backlog"]["banner"] is True


# ---- one alert -----------------------------------------------------------------------------------


def test_get_alert_embeds_the_fire_time_snapshot_and_honours_etags(lane: Any, world: Any) -> None:
    w = world
    pid = provider(lane.db, w)
    inc = incident(lane.db, w, pid, [w.agents["in_g1"]])
    aid = alert(lane.db, w, agent=w.agents["in_g1"], with_snapshot=True, incident=inc)
    owner = tok(lane, w, "owner")
    resp = get(lane, owner, f"/alerts/{aid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["health_snapshot"]["schema"] == "sibyl-health/1"
    assert body["health_snapshot"]["score"] == 42
    assert body["provider_incident"]["id"] == str(inc)
    assert body["what_to_do"] == "Check the provider."
    etag = resp.headers["ETag"]
    cached = lane.client.get(
        f"{API}/alerts/{aid}", headers=lane.bearer(owner, **{"If-None-Match": etag})
    )
    assert cached.status_code == 304


def test_get_alert_unknown_ids_and_tenant_wide_reads(lane: Any, world: Any) -> None:
    w = world
    other = alert(lane.db, w, agent=w.agents["other"])
    prov = alert(lane.db, w, provider_id=provider(lane.db, w), code="provider_status")
    eng = tok(lane, w, "engineer")
    assert get(lane, eng, f"/alerts/{other}").status_code == 200
    assert get(lane, eng, f"/alerts/{prov}").status_code == 200
    assert get(lane, eng, f"/alerts/{uuid4()}").status_code == 404
    assert get(lane, eng, "/alerts/not-a-uuid").status_code == 404
    assert get(lane, tok(lane, w, "viewer"), f"/alerts/{other}").status_code == 200


# ---- actions -------------------------------------------------------------------------------------


def test_ack_then_ack_again_and_idempotent_replay(lane: Any, world: Any) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    op = tok(lane, w, "operator")
    head = kit.audit_head(lane.db, w.tenant)
    key = str(uuid4())
    resp = act(lane, op, aid, {"action": "ack", "reason": "looking"}, key)
    assert resp.status_code == 200, resp.text
    assert resp.json()["state"] == "acked" and resp.json()["acked_at"]
    assert resp.headers[RECEIPT_HEADER].startswith(f"{w.tenant}:")
    assert kit.audit_actions(lane.db, w.tenant, head) == ["alert.acked"]
    assert outbox_types(lane, w)[-1] == "alert.updated"
    replay = act(lane, op, aid, {"action": "ack", "reason": "looking"}, key)
    assert replay.status_code == 200 and replay.headers.get("Idempotency-Replayed") == "true"
    again = act(lane, op, aid, {"action": "ack"})
    assert again.status_code == 409 and again.json()["type"].endswith("/invalid_transition")
    assert kit.audit_actions(lane.db, w.tenant, head) == ["alert.acked"]


def test_actions_need_an_idempotency_key(lane: Any, world: Any) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    resp = lane.client.post(
        f"{API}/alerts/{aid}/actions",
        json={"action": "ack"},
        headers=lane.bearer(tok(lane, w, "owner")),
    )
    assert resp.status_code == 428


def test_silence_validates_until_and_acks(lane: Any, world: Any) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    op = tok(lane, w, "operator")
    assert act(lane, op, aid, {"action": "silence"}).status_code == 422
    past = (NOW - timedelta(minutes=1)).isoformat()
    assert act(lane, op, aid, {"action": "silence", "until": past}).status_code == 422
    far = (NOW + timedelta(days=45)).isoformat()
    assert act(lane, op, aid, {"action": "silence", "until": far}).status_code == 422
    until = (datetime.now(UTC) + timedelta(hours=2)).replace(microsecond=0)
    head = kit.audit_head(lane.db, w.tenant)
    resp = act(lane, op, aid, {"action": "silence", "until": until.isoformat()})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["state"] == "acked"
    assert datetime.fromisoformat(body["silenced_until"].replace("Z", "+00:00")) == until
    rows = kit.audit_rows(lane.db, w.tenant, "alert.silenced")
    assert kit.audit_actions(lane.db, w.tenant, head) == ["alert.silenced"]
    assert rows[-1]["detail"]["alert_id"] == str(aid)


def test_close_requires_a_verdict_and_writes_one_label(lane: Any, world: Any) -> None:
    w = world
    agent = w.agents["in_g1"]
    aid = alert(lane.db, w, agent=agent, with_snapshot=True)
    op = tok(lane, w, "operator")
    head = kit.audit_head(lane.db, w.tenant)
    missing = act(lane, op, aid, {"action": "close"})
    assert missing.status_code == 422 and missing.json()["type"].endswith("/verdict_required")
    assert act(lane, op, aid, {"action": "close", "verdict": "maybe"}).status_code == 422
    resp = act(lane, op, aid, {"action": "close", "verdict": "tp", "verdict_note": "real outage"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert (body["state"], body["verdict"], body["verdict_note"]) == (
        "resolved",
        "tp",
        "real outage",
    )
    label = db_row(
        lane,
        w,
        "SELECT l.* FROM sibyl.label l JOIN sibyl.alert a ON a.verdict_label_id = l.id"
        " AND a.tenant_id = l.tenant_id WHERE a.id = $1",
        aid,
    )
    assert (label["kind"], label["label_strength"], label["labeller_kind"]) == (
        "alert_verdict",
        "verdict",
        "operator",
    )
    assert (label["judges_kind"], label["judges_id"], label["agent_id"]) == (
        "alert",
        str(aid),
        agent,
    )
    assert label["value"]["verdict"] == "tp" and label["labeller_ref"] == str(w.users["operator"])
    assert kit.audit_actions(lane.db, w.tenant, head) == ["alert.labelled"]
    assert outbox_types(lane, w)[-1] == "alert.resolved"
    again = act(lane, op, aid, {"action": "close", "verdict": "fp"})
    assert again.status_code == 409 and again.json()["type"].endswith("/already_resolved")
    assert act(lane, op, aid, {"action": "ack"}).status_code == 409


def test_auto_resolved_alert_takes_exactly_one_verdict(lane: Any, world: Any) -> None:
    """D33/R29: hysteresis resolves with ``verdict=null``; a one-time close adds the verdict."""
    w = world
    aid = alert(
        lane.db,
        w,
        agent=w.agents["in_g1"],
        state="resolved",
        resolved=NOW - timedelta(minutes=1),
        verdict_wanted=True,
    )
    op = tok(lane, w, "operator")
    assert (
        act(
            lane, op, aid, {"action": "silence", "until": (NOW + timedelta(hours=1)).isoformat()}
        ).status_code
        == 409
    )
    resp = act(lane, op, aid, {"action": "close", "verdict": "fp"})
    assert resp.status_code == 200
    assert resp.json()["state"] == "resolved" and resp.json()["verdict"] == "fp"
    assert resp.json()["outcome_observed"] == "recovered"
    assert outbox_types(lane, w)[-1] == "alert.updated"
    assert act(lane, op, aid, {"action": "close", "verdict": "tp"}).status_code == 409


def test_provider_verdict_propagates_to_resolved_member_alerts(lane: Any, world: Any) -> None:
    w = world
    pid = provider(lane.db, w)
    g1, g2 = w.agents["in_g1"], w.agents["in_g2"]
    inc = incident(lane.db, w, pid, [g1, g2])
    anchor = alert(lane.db, w, provider_id=pid, code="provider_status", incident=inc)
    m1 = alert(lane.db, w, agent=g1, state="resolved", resolved=NOW, incident=inc, suppressed=True)
    m2 = alert(lane.db, w, agent=g2, state="open", incident=inc, suppressed=True)
    resp = act(lane, tok(lane, w, "owner"), anchor, {"action": "close", "verdict": "tp"})
    assert resp.status_code == 200, resp.text
    with lane.db.admin.tx(w.tenant):
        labels = lane.db.admin.fetch(
            "SELECT agent_id, labeller_kind, labeller_ref FROM sibyl.label WHERE tenant_id = $1"
            " AND judges_id = ANY($2::text[]) ORDER BY labeller_kind, agent_id",
            w.tenant,
            [str(anchor), str(m1)],
        )
        member = lane.db.admin.fetchrow("SELECT verdict FROM sibyl.alert WHERE id = $1", m1)
        still = lane.db.admin.fetchrow("SELECT verdict, state FROM sibyl.alert WHERE id = $1", m2)
    assert sorted(r["labeller_kind"] for r in labels) == ["operator", "operator", "worker"]
    assert {r["agent_id"] for r in labels if r["labeller_kind"] == "operator"} == {g1, g2}
    assert member["verdict"] == "tp"
    assert (still["verdict"], still["state"]) == (None, "open"), (
        "open members keep their own verdict"
    )
    detail = kit.audit_rows(lane.db, w.tenant, "alert.labelled")[-1]["detail"]
    assert detail["propagated_to"] == [str(m1)]


@pytest.mark.parametrize(
    ("role", "status"),
    [
        ("owner", 200),
        ("security_admin", 200),
        ("operator", 200),
        ("engineer", 200),
        ("admin", 403),
        ("auditor", 403),
        ("viewer", 403),
        ("nobody", 403),
    ],
)
def test_who_may_act_on_an_in_group_alert(lane: Any, world: Any, role: str, status: int) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    head = kit.audit_head(lane.db, w.tenant)
    resp = act(lane, tok(lane, w, role), aid, {"action": "ack"})
    assert resp.status_code == status, resp.text
    if status == 403:
        assert kit.audit_actions(lane.db, w.tenant, head) == ["access.denied"]


def test_engineer_cannot_reach_out_of_group_or_provider_alerts(lane: Any, world: Any) -> None:
    w = world
    other = alert(lane.db, w, agent=w.agents["other"])
    prov = alert(lane.db, w, provider_id=provider(lane.db, w), code="provider_status")
    eng = tok(lane, w, "engineer")
    head = kit.audit_head(lane.db, w.tenant)
    assert act(lane, eng, other, {"action": "ack"}).status_code == 404
    assert act(lane, eng, prov, {"action": "ack"}).status_code == 404
    assert "alert.acked" not in kit.audit_actions(lane.db, w.tenant, head)


def test_foreign_tenant_ids_are_404(lane: Any, lane_db: Any) -> None:
    a, b = kit.world(lane_db), kit.world(lane_db)
    aid = alert(lane_db, a, agent=a.agents["in_g1"])
    inc = incident(lane_db, a, provider(lane_db, a), [a.agents["in_g1"]])
    owner_b = tok(lane, b, "owner")
    assert get(lane, owner_b, f"/alerts/{aid}").status_code == 404
    assert act(lane, owner_b, aid, {"action": "ack"}).status_code == 404
    assert get(lane, owner_b, f"/provider-incidents/{inc}").status_code == 404
    assert get(lane, owner_b, "/alerts").json()["data"] == []


def test_reads_write_no_audit_rows(lane: Any, world: Any) -> None:
    w = world
    aid = alert(lane.db, w, agent=w.agents["in_g1"])
    inc = incident(lane.db, w, provider(lane.db, w), [w.agents["in_g1"]])
    owner = tok(lane, w, "owner")
    head = kit.audit_head(lane.db, w.tenant)
    for path in ("/alerts", f"/alerts/{aid}", "/provider-incidents", f"/provider-incidents/{inc}"):
        resp = get(lane, owner, path)
        assert resp.status_code == 200 and RECEIPT_HEADER not in resp.headers
    assert kit.audit_actions(lane.db, w.tenant, head) == []


# ---- provider incidents --------------------------------------------------------------------------


def test_provider_incidents_list_and_members(lane: Any, world: Any) -> None:
    w = world
    lane.db.admin.execute("UPDATE sibyl.tenant SET hold_on_incident = true WHERE id = $1", w.tenant)
    pid = provider(lane.db, w)
    inc = incident(lane.db, w, pid, [w.agents["in_g1"], w.agents["in_g2"]])
    m = alert(lane.db, w, agent=w.agents["in_g1"], incident=inc, suppressed=True)
    owner = tok(lane, w, "owner")
    listed = get(lane, owner, "/provider-incidents", state="open").json()["data"]
    assert [i["id"] for i in listed] == [str(inc)]
    assert listed[0]["legal_hold_id"], "the tenant's hold_on_incident placed an incident hold"
    assert get(lane, owner, "/provider-incidents", provider_id=str(uuid4())).json()["data"] == []
    one = get(lane, owner, f"/provider-incidents/{inc}").json()
    assert [a["id"] for a in one["alerts"]] == [str(m)]
    assert set(one["affected_agent_ids"]) == {str(w.agents["in_g1"]), str(w.agents["in_g2"])}
    assert get(lane, owner, "/provider-incidents", state="nope").status_code == 422
