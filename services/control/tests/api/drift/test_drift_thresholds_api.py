"""``GET`` / ``PUT /drift/thresholds`` on PG17 (wave 4 HARDEN item 7): every role reads the
effective thresholds (each value with its source: tenant override or deployment default);
Owner, Admin and Security admin replace the override set with If-Match (ETag ``"<version>"``,
``"0"`` before the first save), a reason, validated ranges and ``watch < drift`` on the effective
pair; null or omitted fields fall back to the defaults (a body with only a reason resets); every
change is audited ``drift.thresholds_updated`` with the before and after overrides."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from sibyl_lane_s_world import SWorld
from sibyl_schemas.models.drift import THRESHOLD_BOUNDS

PATH = "/drift/thresholds"
REASON = "our agents are chatty; widen the PSI band"
DEFAULTS = {
    "psi_watch": 0.10,
    "psi_drift": 0.25,
    "js_two_category_watch": 0.005,
    "js_two_category_drift": 0.02,
    "js_many_category_watch": 0.05,
    "js_many_category_drift": 0.10,
    "min_samples_calls": 200,
    "min_samples_tools": 50,
}


@pytest.fixture
def clean(sworld: SWorld) -> Iterator[None]:
    for tenant in (sworld.a, sworld.b):
        sworld.admin.execute("DELETE FROM sibyl.drift_thresholds WHERE tenant_id = $1", tenant.id)
    yield
    for tenant in (sworld.a, sworld.b):
        sworld.admin.execute("DELETE FROM sibyl.drift_thresholds WHERE tenant_id = $1", tenant.id)


def _get(s: SWorld, who: str) -> Any:
    return s.get(who, PATH)


def _put(s: SWorld, who: str, body: Any, if_match: str | None = "auto") -> Any:
    headers = s.w.headers(who)
    if if_match == "auto":
        if_match = _get(s, "owner" if not who.endswith("-b") else "owner-b").headers["etag"]
    if if_match is not None:
        headers["If-Match"] = if_match
    return s.client.put("/api/v1" + PATH, json=body, headers=headers)


def test_every_role_reads_the_deployment_defaults(sworld: SWorld, clean: None) -> None:
    for who in ("viewer", "auditor", "operator", "engineer", "security_admin", "admin", "owner"):
        resp = _get(sworld, who)
        assert resp.status_code == 200, (who, resp.text)
    assert resp.headers["etag"] == '"0"'
    doc = resp.json()
    assert doc["version"] == 0 and doc["updated_at"] is None and doc["watch_only"] is True
    assert set(doc["values"]) == set(DEFAULTS) == set(THRESHOLD_BOUNDS)
    for name, value in DEFAULTS.items():
        item = doc["values"][name]
        assert item == {
            "value": value,
            "default": value,
            "source": "default",
            "minimum": THRESHOLD_BOUNDS[name][0],
            "maximum": THRESHOLD_BOUNDS[name][1],
        }, name


def test_writers_override_audit_and_reset(sworld: SWorld, clean: None) -> None:
    head = sworld.head(sworld.a)
    for who in ("operator", "engineer", "viewer", "auditor"):
        body = {"psi_drift": 0.4, "reason": REASON}
        assert _put(sworld, who, body).status_code == 403, who
    assert _put(sworld, "admin", {"psi_drift": 0.4, "reason": REASON}, None).status_code == 428

    body = {"psi_watch": 0.15, "psi_drift": 0.4, "min_samples_calls": 300, "reason": REASON}
    resp = _put(sworld, "admin", body, '"0"')
    assert resp.status_code == 200, resp.text
    assert resp.headers["etag"] == '"1"' and resp.headers.get("x-sibyl-audit-receipt")
    doc = resp.json()
    assert doc["version"] == 1 and doc["updated_by_user_id"] == str(sworld.a.users["admin"])
    values = doc["values"]
    assert values["psi_watch"]["value"] == 0.15 and values["psi_watch"]["source"] == "tenant"
    assert values["psi_drift"]["value"] == 0.4 and values["psi_drift"]["default"] == 0.25
    assert values["min_samples_calls"] == {**values["min_samples_calls"], "value": 300}
    assert values["min_samples_calls"]["source"] == "tenant"
    assert values["js_two_category_watch"]["source"] == "default"
    assert _get(sworld, "viewer").json() == doc

    # a stale ETag is refused with the current representation
    stale = _put(sworld, "security_admin", {"psi_drift": 0.5, "reason": REASON}, '"0"')
    assert stale.status_code == 412, stale.text
    # PUT replaces the override set: psi_watch / min_samples_calls fall back to the defaults
    resp = _put(sworld, "security_admin", {"psi_drift": 0.5, "reason": REASON}, '"1"')
    assert resp.status_code == 200, resp.text
    values = resp.json()["values"]
    assert values["psi_watch"] == {**values["psi_watch"], "value": 0.10, "source": "default"}
    assert values["psi_drift"]["value"] == 0.5 and values["psi_drift"]["source"] == "tenant"
    # reset: only a reason (every field null or omitted)
    resp = _put(sworld, "owner", {"psi_drift": None, "reason": REASON}, '"2"')
    assert resp.status_code == 200, resp.text
    assert resp.headers["etag"] == '"3"'
    assert {v["source"] for v in resp.json()["values"].values()} == {"default"}

    actions = sworld.audit_actions(sworld.a, head)
    assert actions.count("drift.thresholds_updated") == 3
    assert "access.denied" in actions
    rows = sworld.rows(
        "SELECT detail, reason, resource_type FROM sibyl.audit_events WHERE tenant_id = $1"
        " AND action = 'drift.thresholds_updated' AND seq > $2 ORDER BY seq",
        sworld.a.id,
        head,
    )
    first = json.loads(rows[0]["detail"])
    assert rows[0]["reason"] == REASON and rows[0]["resource_type"] == "drift_thresholds"
    assert first["before"] == {name: None for name in DEFAULTS}
    assert first["after"] == {  # canonical audit JSON: thresholds as decimal strings
        **{name: None for name in DEFAULTS},
        "psi_watch": "0.15",
        "psi_drift": "0.4",
        "min_samples_calls": 300,
    }
    last = json.loads(rows[2]["detail"])
    assert last["before"]["psi_drift"] == "0.5" and last["after"] == {n: None for n in DEFAULTS}


def test_tenants_are_isolated(sworld: SWorld, clean: None) -> None:
    resp = _put(sworld, "owner", {"js_many_category_drift": 0.3, "reason": REASON})
    assert resp.status_code == 200, resp.text
    other = _get(sworld, "owner-b")
    assert other.status_code == 200 and other.headers["etag"] == '"0"'
    assert other.json()["values"]["js_many_category_drift"]["source"] == "default"


@pytest.mark.parametrize(
    ("body", "pointer"),
    [
        ({"psi_watch": 0.005}, "/psi_watch"),
        ({"psi_drift": 2.5}, "/psi_drift"),
        ({"js_two_category_watch": 0.0001}, "/js_two_category_watch"),
        ({"js_two_category_drift": 0.6}, "/js_two_category_drift"),
        ({"js_many_category_watch": 0.001}, "/js_many_category_watch"),
        ({"js_many_category_drift": 1.5}, "/js_many_category_drift"),
        ({"min_samples_calls": 49}, "/min_samples_calls"),
        ({"min_samples_calls": 5001}, "/min_samples_calls"),
        ({"min_samples_tools": 9}, "/min_samples_tools"),
        ({"min_samples_tools": 20001}, "/min_samples_tools"),
        ({"min_samples_calls": 300.5}, "/min_samples_calls"),
        ({"psi_watch": 0.2, "psi_drift": 0.2}, "/psi_watch"),
        ({"psi_watch": 0.3}, "/psi_watch"),  # above the default drift 0.25
        ({"js_two_category_drift": 0.004}, "/js_two_category_drift"),  # below default watch
        ({"psi_watch": "0.1"}, "/psi_watch"),
        ({"bogus": 1}, "/bogus"),
    ],
)
def test_out_of_range_and_inconsistent_values_are_refused(
    sworld: SWorld, clean: None, body: dict[str, Any], pointer: str
) -> None:
    resp = _put(sworld, "admin", {**body, "reason": REASON})
    assert resp.status_code == 422, resp.text
    problem = resp.json()
    assert problem["type"].endswith("/validation_failed")
    assert pointer in {e["pointer"] for e in problem.get("errors", [])}, problem
    assert _get(sworld, "owner").headers["etag"] == '"0"'  # nothing saved


def test_a_reason_is_required(sworld: SWorld, clean: None) -> None:
    for body in ({"psi_drift": 0.4}, {"psi_drift": 0.4, "reason": "short"}):
        resp = _put(sworld, "admin", body)
        assert resp.status_code == 422, resp.text
