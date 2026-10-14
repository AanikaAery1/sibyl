"""The drift api on PG17 against reports the real drift tick wrote: the fleet view and its
summary, one agent's drift, one report, and the audited reset (supersede, re-collect, resolve
the open drift alerts). Every role reads; only Owner, Admin and Security admin reset."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_drift_kit import NORMAL, Profile, Traffic, make_traffic
from sibyl_lane_s_world import SWorld

H = timedelta(hours=1)
REASON = "the provider upgraded the model on purpose"


@pytest.fixture(scope="module")
def traffic(sworld: SWorld) -> Traffic:
    return make_traffic(sworld)


@pytest.fixture(scope="module")
def drifted(traffic: Traffic) -> UUID:
    """An agent whose behaviour and served model drifted twice in a row (both alerts open)."""
    t = traffic
    agent = t.agent()
    now = t.now()
    t0 = now - 3 * H
    t.period(agent, t0 - H, t0, 400, seed=31, tasks=60)
    bad = Profile(out_mu=800, served="gpt-4o-mini-2024-07-18")
    t.period(agent, t0, t0 + H, 200, bad, seed=32)
    t.period(agent, t0 + H, t0 + 2 * H, 200, bad, seed=33)
    for step in range(3):
        t.run(t0 + step * H)
    assert {a["code"] for a in t.alerts(agent) if a["state"] == "open"} == {
        "silent_drift",
        "model_change",
    }
    return agent


def _get(s: SWorld, who: str, path: str, **params: Any) -> Any:
    return s.get(who, path, **params)


def test_fleet_view_lists_current_baselines_with_their_latest_verdict(
    sworld: SWorld, drifted: UUID
) -> None:
    resp = _get(sworld, "viewer", "/drift", agent_id=str(drifted))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    [row] = body["data"]
    assert row["agent_id"] == str(drifted) and row["state"] == "frozen"
    assert row["verdict"] == "drift" and row["identity_changed"] is True
    assert "output_tokens" in row["drifting_features"]
    assert row["provider"] == "openai" and row["model"] == "gpt-4o"
    summary = body["summary"]
    assert summary["drift"] >= 1 and summary["open_alerts"] >= 2 and summary["frozen"] >= 1
    only_drift = _get(sworld, "auditor", "/drift", verdict="drift").json()["data"]
    assert str(drifted) in {r["agent_id"] for r in only_drift}
    none = _get(sworld, "owner", "/drift", verdict="none", agent_id=str(drifted)).json()
    assert none["data"] == []
    assert _get(sworld, "owner", "/drift", verdict="bogus").status_code == 422


def test_agent_drift_and_one_report(sworld: SWorld, drifted: UUID) -> None:
    resp = _get(sworld, "engineer", f"/agents/{drifted}/drift")
    assert resp.status_code == 200, resp.text
    doc = resp.json()
    [baseline] = doc["baselines"]
    assert baseline["features"]["output_tokens"]["statistic"] == "psi"
    assert baseline["served_models"] == ["gpt-4o-2024-08-06"]
    [latest] = doc["latest"]
    assert latest["verdict"] == "drift"
    psi = next(f for f in latest["features"] if f["feature"] == "output_tokens")
    assert psi["value"] > psi["drift"] and psi["contributors"]
    assert {i["kind"] for i in latest["identity"]} == {"served_model_mismatch"}
    assert len(doc["history"]) == 2
    assert {a["rule"] for a in doc["open_alerts"]} == {"silent_drift", "model_change"}
    one = _get(sworld, "operator", f"/drift/reports/{latest['id']}")
    assert one.status_code == 200 and one.json() == latest
    assert one.headers["etag"] == f'"{latest["id"]}"'
    assert _get(sworld, "owner", f"/drift/reports/{uuid4()}").status_code == 404
    assert _get(sworld, "owner", f"/agents/{uuid4()}/drift").status_code == 404


def test_agent_drift_history_is_bounded_by_since_and_limit(sworld: SWorld, drifted: UUID) -> None:
    path = f"/agents/{drifted}/drift"
    full = _get(sworld, "viewer", path).json()["history"]
    assert len(full) == 2 and full[0]["evaluated_at"] >= full[1]["evaluated_at"]
    [newest] = _get(sworld, "viewer", path, limit=1).json()["history"]
    assert newest == full[0]
    since = full[0]["evaluated_at"]
    assert _get(sworld, "viewer", path, since=since).json()["history"] == [full[0]]
    future = "2999-01-01T00:00:00Z"
    later = _get(sworld, "viewer", path, since=future).json()
    assert later["history"] == [] and later["baselines"]  # since bounds history only
    for bad in ({"limit": 0}, {"limit": 501}, {"since": "yesterday"}):
        assert _get(sworld, "viewer", path, **bad).status_code == 422, bad
    assert _get(sworld, "viewer", path, limit=500).status_code == 200


def test_reset_supersedes_recollects_resolves_and_audits(
    sworld: SWorld, traffic: Traffic, drifted: UUID
) -> None:
    head = sworld.head(sworld.a)
    denied = sworld.post("operator", f"/agents/{drifted}/drift/baseline", {"reason": REASON})
    assert denied.status_code == 403
    since = (traffic.now() - 3 * H).isoformat()
    resp = sworld.post(
        "admin", f"/agents/{drifted}/drift/baseline", {"reason": REASON, "since": since}
    )
    assert resp.status_code == 201, resp.text
    assert resp.headers.get("x-sibyl-audit-receipt")
    body = resp.json()
    [new] = body["baselines"]
    [old] = body["superseded"]
    assert new["state"] == "collecting" and new["supersedes"] == old
    assert new["reset_reason"] == REASON
    rows = {r["id"]: r for r in traffic.baselines(drifted)}
    assert rows[UUID(old)]["state"] == "superseded"
    assert rows[UUID(old)]["superseded_by"] == UUID(new["id"])
    assert all(a["state"] == "resolved" for a in traffic.alerts(drifted))
    actions = sworld.audit_actions(sworld.a, head)
    assert actions.count("drift.baseline_reset") == 1 and "access.denied" in actions
    detail = sworld.one(
        "SELECT detail, reason FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'drift.baseline_reset' ORDER BY seq DESC LIMIT 1",
        sworld.a.id,
    )
    assert detail["reason"] == REASON
    # the next tick re-freezes on the recent (drifted) traffic: the new normal
    traffic.run(traffic.now())
    current = [r for r in traffic.baselines(drifted) if r["state"] != "superseded"]
    assert [r["state"] for r in current] == ["frozen"]
    assert list(current[0]["served_models"]) == ["gpt-4o-mini-2024-07-18"]
    again = _get(sworld, "owner", f"/agents/{drifted}/drift").json()
    assert again["open_alerts"] == [] and again["baselines"][0]["state"] == "frozen"


def test_reset_validation(sworld: SWorld, traffic: Traffic) -> None:
    agent = traffic.agent()
    now = traffic.now()
    traffic.period(agent, now - H, now, 50, NORMAL, seed=41, tasks=0)
    traffic.run(now)
    path = f"/agents/{agent}/drift/baseline"
    future = (now + H).isoformat()
    assert sworld.post("owner", path, {"reason": REASON, "since": future}).status_code == 422
    ancient = (now - timedelta(days=8)).isoformat()
    assert sworld.post("owner", path, {"reason": REASON, "since": ancient}).status_code == 422
    assert sworld.post("owner", path, {"reason": "short"}).status_code == 422
    assert sworld.post("owner", path, {"reason": REASON, "extra": 1}).status_code == 422
    naive = {"reason": REASON, "since": "2026-10-12T10:00:00"}
    assert sworld.post("owner", path, naive).status_code == 422
    nothing = {"reason": REASON, "provider": "anthropic"}
    assert sworld.post("owner", path, nothing).status_code == 404
    ok = sworld.post("security_admin", path, {"reason": REASON, "model": "gpt-4o"})
    assert ok.status_code == 201, ok.text
    assert sworld.post("engineer", path, {"reason": REASON}).status_code == 403
    assert (
        sworld.post("owner", f"/agents/{uuid4()}/drift/baseline", {"reason": REASON}).status_code
        == 404
    )


def test_the_other_tenant_sees_nothing(sworld: SWorld, drifted: UUID) -> None:
    assert _get(sworld, "owner-b", f"/agents/{drifted}/drift").status_code == 404
    rows = _get(sworld, "owner-b", "/drift").json()
    assert rows["data"] == [] and rows["summary"]["baselines"] == 0
