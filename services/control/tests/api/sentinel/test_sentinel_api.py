"""Sentinel API on PG17 with a fake LLM: config (write-only vaulted key, step-up, base URL
vetting), connectivity test, on-demand explain (budget, failures, idempotency, advisory only),
findings list/get/feedback, and authorization."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import pytest
import sibyl_sentinel_kit as kit
from sibyl_control.api.auth.common import LANE_STATE
from sibyl_control.api.credentials.vault import open_secret
from sibyl_control.core.crypto.envelope import EncryptedBlob
from sibyl_lane_s_world import SWorld

KEY = "sk-ant-api-test-abcdef123456"
BODY: dict[str, Any] = {
    "enabled": True,
    "provider": "anthropic",
    "api_key": KEY,
    "daily_budget_usd": "5",
    "sampling_rate": 0.25,
    "tasks": ["incident_explanation", "held_action_review"],
    "reason": "turning Sentinel on for the payments team",
}


async def _no_sleep(_: float) -> None:
    return None


@pytest.fixture
def llm(sworld: SWorld) -> Any:
    fake = kit.fake()
    state = getattr(sworld.client.app.state, LANE_STATE, None)
    if state is None:
        state = {}
        setattr(sworld.client.app.state, LANE_STATE, state)
    state["sentinel_transport"] = lambda policy: fake.transport()
    state["sentinel_client_kw"] = {"sleep": _no_sleep, "max_retries": 0}
    kit.reset(sworld.w, sworld.a)
    kit.capture_policy(sworld, "metadata")
    return fake


def _etag(sw: SWorld) -> str:
    return sw.get("owner", "/sentinel/config").headers.get("etag") or "*"


def _put(sw: SWorld, body: dict[str, Any], who: str = "owner", if_match: str | None = None) -> Any:
    headers = sw.w.headers(who, **{"If-Match": if_match or _etag(sw)})
    return sw.client.put("/api/v1/sentinel/config", json=body, headers=headers)


def _configured(sw: SWorld, **changes: Any) -> None:
    resp = _put(sw, {**BODY, **changes})
    assert resp.status_code == 200, resp.text


def test_config_lifecycle_keeps_the_key_write_only(sworld: SWorld, llm: Any) -> None:
    sworld.admin.execute("DELETE FROM sibyl.sentinel_config WHERE tenant_id = $1", sworld.a.id)
    empty_resp = sworld.get("owner", "/sentinel/config")
    assert empty_resp.headers["etag"] == '"0"'  # uniform If-Match before the first save
    empty = empty_resp.json()
    assert (empty["configured"], empty["enabled"], empty["advisory"]) == (False, False, True)
    no_key = _put(sworld, {**BODY, "api_key": None})
    assert no_key.status_code == 422 and no_key.json()["type"].endswith("/validation_failed")
    assert _put(sworld, BODY, if_match='"3"').status_code == 412
    head = sworld.head(sworld.a)
    resp = _put(sworld, BODY, if_match='"0"')
    assert resp.status_code == 200, resp.text
    view = resp.json()
    assert view["has_key"] and view["key_hint"] == "3456" and view["model"] == "claude-fable-5-1"
    assert view["daily_budget_usd"] == "5.0000" and view["tasks"] == BODY["tasks"]
    assert KEY not in resp.text and "X-Sibyl-Audit-Receipt" in resp.headers
    assert sworld.audit_actions(sworld.a, head) == ["sentinel.config_changed"]
    audit = sworld.one(
        "SELECT detail, reason FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2",
        sworld.a.id,
        head,
    )
    assert KEY not in json.dumps(audit["detail"]) and audit["reason"] == BODY["reason"]
    row = sworld.one("SELECT * FROM sibyl.sentinel_config WHERE tenant_id = $1", sworld.a.id)
    blob = EncryptedBlob(row["key_version"], bytes(row["nonce"]), bytes(row["ciphertext"]))
    opened = sworld.run(
        open_secret(sworld.admin.raw, kit.R.kek(), sworld.a.id, row["credential_id"], blob)
    )
    assert opened.decode() == KEY and KEY.encode() not in bytes(row["ciphertext"])
    rule = sworld.one(
        "SELECT kind, enabled FROM sibyl.alert_rule WHERE tenant_id = $1 AND code ="
        " 'sentinel_finding'",
        sworld.a.id,
    )
    assert (rule["kind"], rule["enabled"]) == ("leading", True)
    assert resp.headers["etag"] == '"1"'
    stale = _put(sworld, BODY, if_match='"7"')
    assert stale.status_code == 412 and stale.json()["current"]["version"] == 1
    assert _put(sworld, BODY, if_match="*").status_code == 412
    raw = sworld.client.put("/api/v1/sentinel/config", json=BODY, headers=sworld.w.headers("owner"))
    assert raw.status_code == 428
    # a later change without a key keeps the vaulted one
    again = _put(sworld, {**{k: v for k, v in BODY.items() if k != "api_key"}, "enabled": False})
    assert again.status_code == 200 and again.json()["has_key"] and again.json()["version"] == 2
    kept = sworld.one(
        "SELECT credential_id FROM sibyl.sentinel_config WHERE tenant_id = $1", sworld.a.id
    )
    assert kept["credential_id"] == row["credential_id"]
    read = sworld.get("operator", "/sentinel/config")
    assert read.status_code == 200 and "api_key" not in read.json()


@pytest.mark.parametrize(
    "change,pointer",
    [
        ({"provider": "openai"}, "model"),
        ({"daily_budget_usd": "20000"}, "budget"),
        ({"sampling_rate": 1.5}, "rate"),
        ({"tasks": ["fleet_summary", "fleet_summary"]}, "tasks"),
        ({"api_key": "short"}, "key"),
        ({"model": "../../evil"}, "model"),
        ({"price_in_usd_per_mtok": "1"}, "price"),
        ({"unknown": 1}, "extra"),
    ],
)
def test_config_validation(sworld: SWorld, llm: Any, change: dict[str, Any], pointer: str) -> None:
    resp = _put(sworld, {**BODY, **change})
    assert resp.status_code == 422, (pointer, resp.text)


def test_base_url_is_vetted_like_a_provider_credential(sworld: SWorld, llm: Any) -> None:
    bad = _put(
        sworld, {**BODY, "provider": "openai", "model": "gpt-x", "base_url": "https://10.0.0.1/v1"}
    )
    assert bad.status_code == 422 and bad.json()["type"].endswith("/base_url_not_allowlisted")
    creds = _put(sworld, {**BODY, "base_url": "https://u:p@api.anthropic.com"})
    assert creds.status_code == 422
    ok = _put(sworld, {**BODY, "base_url": "https://api.anthropic.com"})
    assert ok.status_code == 200 and ok.json()["base_url"] == "https://api.anthropic.com"
    _configured(sworld)


def test_config_write_needs_admin_and_a_fresh_step_up(sworld: SWorld, llm: Any) -> None:
    stale = _put(sworld, BODY, "owner-stale")
    assert stale.status_code == 403 and stale.json()["type"].endswith("/step_up_required")
    for who in ("operator", "auditor", "engineer", "viewer"):
        assert _put(sworld, BODY, who).status_code == 403, who
    for who in ("engineer", "viewer"):
        assert sworld.get(who, "/sentinel/config").status_code == 403, who
        assert sworld.get(who, "/sentinel/findings").status_code == 403, who
    assert _put(sworld, BODY, "security_admin").status_code == 200


def test_connectivity_check(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    head = sworld.head(sworld.a)
    resp = sworld.post("owner", "/sentinel/config/test")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["ok"] and body["provider"] == "anthropic" and body["http_status"] == 200
    assert body["cost_usd"] == "0.003200"
    assert sworld.audit_actions(sworld.a, head) == ["sentinel.config_tested"]
    assert kit.usage(sworld)["calls"] == 1
    llm.push(kit.fk.Scripted(status=401, body={"error": {"type": "authentication_error"}}))
    failed = sworld.post("owner", "/sentinel/config/test").json()
    assert (failed["ok"], failed["http_status"], failed["error"]) == (False, 401, "http_error")
    assert kit.usage(sworld)["failures"] == 1
    sworld.admin.execute("DELETE FROM sibyl.sentinel_config WHERE tenant_id = $1", sworld.b.id)
    other = sworld.post("owner-b", "/sentinel/config/test")
    assert other.status_code == 409 and other.json()["type"].endswith("/not_active")
    assert sworld.post("operator", "/sentinel/config/test").status_code == 403


def test_explain_a_held_action_is_advisory_and_idempotent(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    agent = sworld.agent()
    held = kit.hold(sworld, agent)
    head = sworld.head(sworld.a)
    headers = sworld.idem("owner")
    body = {"subject_kind": "held_action", "subject_id": str(held)}
    resp = sworld.client.post("/api/v1/sentinel/explain", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    finding = resp.json()
    assert finding["kind"] == "held_action_review" and finding["subject_id"] == str(held)
    assert finding["trigger"] == "on_demand" and finding["advisory"] is True
    assert finding["requested_by_user_id"] == str(sworld.users["owner"])
    assert finding["recommendation"].startswith("Advisory: approve")
    assert resp.headers["location"].endswith(finding["id"])
    assert sworld.audit_actions(sworld.a, head) == ["sentinel.finding_created"]
    actor = sworld.one(
        "SELECT actor_type, actor_id FROM sibyl.audit_events WHERE tenant_id = $1 AND seq > $2",
        sworld.a.id,
        head,
    )
    assert (actor["actor_type"], actor["actor_id"]) == ("human", sworld.users["owner"])
    held_row = sworld.one("SELECT state, decision FROM sibyl.held_action WHERE id = $1", held)
    assert (held_row["state"], held_row["decision"]) == ("pending", None)
    replay = sworld.client.post("/api/v1/sentinel/explain", json=body, headers=headers)
    assert replay.status_code == 201 and replay.json()["id"] == finding["id"]
    assert replay.headers.get("idempotency-replayed") == "true"
    assert len(llm.requests) == 1


def test_explain_an_incident(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    incident = kit.incident(sworld, sworld.agent())
    resp = sworld.post(
        "security_admin",
        "/sentinel/explain",
        {"subject_kind": "incident", "subject_id": str(incident)},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["kind"] == "incident_explanation"
    assert resp.json()["body"]["output"]["what_to_check"]


def test_explain_refusals(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    missing = sworld.post(
        "owner", "/sentinel/explain", {"subject_kind": "incident", "subject_id": str(uuid4())}
    )
    assert missing.status_code == 404
    held = kit.hold(sworld, sworld.agent())
    body = {"subject_kind": "held_action", "subject_id": str(held)}
    llm.push(kit.fk.Scripted(status=500))
    failed = sworld.post("owner", "/sentinel/explain", body)
    assert failed.status_code == 503
    used = kit.usage(sworld)
    assert used["failures"] == 1 and used["spent_usd"] == 0
    assert kit.findings(sworld) == []
    _configured(sworld, daily_budget_usd="0.0001")
    head = sworld.head(sworld.a)
    spent = sworld.post("owner", "/sentinel/explain", body)
    assert spent.status_code == 409 and spent.json()["type"].endswith("/conflict")
    assert sworld.audit_actions(sworld.a, head) == ["sentinel.budget_exhausted"]
    _configured(sworld, enabled=False)
    off = sworld.post("owner", "/sentinel/explain", body)
    assert off.status_code == 409 and off.json()["type"].endswith("/not_active")
    assert sworld.post("operator", "/sentinel/explain", body).status_code == 403
    bad = sworld.post(
        "owner", "/sentinel/explain", {"subject_kind": "agent", "subject_id": str(held)}
    )
    assert bad.status_code == 422
    _configured(sworld)


def test_findings_list_get_and_feedback(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    agent = sworld.agent()
    ids = []
    for _ in range(3):
        held = kit.hold(sworld, agent)
        resp = sworld.post(
            "owner", "/sentinel/explain", {"subject_kind": "held_action", "subject_id": str(held)}
        )
        ids.append(resp.json()["id"])
    page = sworld.get("operator", "/sentinel/findings", limit=2, kind="held_action_review")
    assert page.status_code == 200
    first = page.json()
    assert [f["id"] for f in first["data"]] == ids[::-1][:2] and first["has_more"]
    rest = sworld.get(
        "operator",
        "/sentinel/findings",
        limit=2,
        kind="held_action_review",
        cursor=first["next_cursor"],
    ).json()
    assert [f["id"] for f in rest["data"]] == [ids[0]]
    by_agent = sworld.get("auditor", "/sentinel/findings", agent_id=str(agent)).json()["data"]
    assert len(by_agent) == 3
    assert sworld.get("owner", "/sentinel/findings", severity="critical").json()["data"] == []
    assert sworld.get("owner", "/sentinel/findings", kind="bogus").status_code == 422
    one = sworld.get("operator", f"/sentinel/findings/{ids[0]}")
    assert one.status_code == 200 and one.json()["prompt_sha256"]
    assert sworld.get("owner-b", f"/sentinel/findings/{ids[0]}").status_code == 404
    head = sworld.head(sworld.a)
    rated = sworld.post("operator", f"/sentinel/findings/{ids[0]}/feedback", {"feedback": "wrong"})
    assert rated.status_code == 200, rated.text
    assert rated.json()["feedback"] == "wrong"
    assert rated.json()["feedback_by_user_id"] == str(sworld.users["operator"])
    assert sworld.audit_actions(sworld.a, head) == ["sentinel.feedback_recorded"]
    again = sworld.post("owner", f"/sentinel/findings/{ids[0]}/feedback", {"feedback": "useful"})
    assert again.json()["feedback"] == "useful"
    assert (
        sworld.post(
            "owner", f"/sentinel/findings/{ids[0]}/feedback", {"feedback": "meh"}
        ).status_code
        == 422
    )
    assert (
        sworld.post(
            "owner", f"/sentinel/findings/{uuid4()}/feedback", {"feedback": "useful"}
        ).status_code
        == 404
    )
    assert (
        sworld.post(
            "owner-b", f"/sentinel/findings/{ids[0]}/feedback", {"feedback": "useful"}
        ).status_code
        == 404
    )


def test_findings_are_tenant_isolated(sworld: SWorld, llm: Any) -> None:
    _configured(sworld)
    held = kit.hold(sworld, sworld.agent())
    sworld.post(
        "owner", "/sentinel/explain", {"subject_kind": "held_action", "subject_id": str(held)}
    )
    assert sworld.get("owner-b", "/sentinel/findings").json()["data"] == []
    ids = [UUID(f["id"]) for f in sworld.get("owner", "/sentinel/findings").json()["data"]]
    assert ids
