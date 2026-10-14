"""D53 external monitor value sets, request bodies and the webhook signature scheme."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sibyl_schemas import values as v
from sibyl_schemas.models.monitor import (
    FindingSubmit,
    MonitorCreate,
    MonitorKeyCreate,
    MonitorPatch,
    MonitorRevoke,
    WebhookCreate,
)
from sibyl_schemas.models.sentinel import SUBJECT_OF_KIND
from sibyl_schemas.webhook_signature import (
    SignatureError,
    parse_header,
    sign,
    signature_header,
    verify,
)

SECRET = "whsec_test-secret-0123456789"  # noqa: S105 (a test fixture)
BODY = b'{"id":"1","type":"ping"}'


def test_value_sets_line_up_with_the_bus_and_sentinel() -> None:
    assert set(v.OUTBOX_WEBHOOK_EVENTS) <= {e.value for e in v.SseEventType}
    assert v.WebhookEventType.PING not in v.SUBSCRIBABLE_EVENTS
    assert len(v.SUBSCRIBABLE_EVENTS) == len(v.WebhookEventType) - 1
    for kind, subject in v.FIXED_SUBJECT_OF_KIND.items():
        assert SUBJECT_OF_KIND[v.SentinelTask(kind.value)].value == subject.value
    assert {s.value for s in v.MONITOR_KEY_SCOPES} == {"monitor:read", "findings:write"}
    assert v.MONITOR_KEY_SCOPES <= v.MACHINE_ONLY_SCOPES <= v.MACHINE_SCOPES
    assert v.DRIFT_ALERT_RULES == {"silent_drift", "model_change"}
    assert v.EXTERNAL_FINDING_ALERT_RULE == "external_finding"


def test_monitor_scopes_need_a_monitor_bound_key() -> None:
    read = [v.Scope.MONITOR_READ]
    assert v.api_key_scope_errors(read, agent_bound=False, env="live")
    assert v.api_key_scope_errors(read, agent_bound=False, env="live", monitor_bound=True) == []
    mixed = [v.Scope.MONITOR_READ, v.Scope.AGENTS_READ]
    assert v.api_key_scope_errors(mixed, agent_bound=False, env="live", monitor_bound=True)
    assert v.api_key_scope_errors(read, agent_bound=True, env="live", monitor_bound=True)
    for role in v.Role:
        assert v.Scope.MONITOR_READ not in v.ROLE_SCOPES[role]
    assert v.Scope.MONITORS_ADMIN in v.ROLE_SCOPES[v.Role.OWNER]
    assert v.Scope.MONITORS_ADMIN not in v.ROLE_SCOPES[v.Role.ENGINEER]


def test_audit_actions_are_declared() -> None:
    submitted = v.AUDIT_ACTIONS["finding.submitted"]
    assert submitted.actor_types == {v.ActorType.API_KEY}
    assert v.AUDIT_ACTIONS["webhook.delivery_failed"].actor_types == {v.ActorType.SYSTEM}
    assert v.AUDIT_ACTIONS["monitor.revoked"].reason_required


# --- signatures ---------------------------------------------------------------------------------


def test_sign_and_verify_round_trip() -> None:
    header = signature_header(SECRET, BODY, timestamp=1_800_000_000)
    assert header == f"t=1800000000,v1={sign(SECRET, 1_800_000_000, BODY)}"
    assert verify(SECRET, header, BODY, now=1_800_000_100) == 1_800_000_000
    assert verify(SECRET.encode(), header, BODY, now=1_800_000_000) == 1_800_000_000


@pytest.mark.parametrize(
    ("header", "body", "now"),
    [
        (None, BODY, 1_800_000_000),
        ("", BODY, 1_800_000_000),
        ("t=1800000000", BODY, 1_800_000_000),
        ("v1=" + "0" * 64, BODY, 1_800_000_000),
        ("t=abc,v1=" + "0" * 64, BODY, 1_800_000_000),
        ("garbage", BODY, 1_800_000_000),
        ("t=1800000000,v1=é" + "0" * 63, BODY, 1_800_000_000),
        ("x" * 3000, BODY, 1_800_000_000),
    ],
)
def test_malformed_headers_are_refused(header: str | None, body: bytes, now: int) -> None:
    with pytest.raises(SignatureError):
        verify(SECRET, header, body, now=now)


def test_tampering_staleness_and_rotation() -> None:
    header = signature_header(SECRET, BODY, timestamp=1_800_000_000)
    with pytest.raises(SignatureError, match="does not match"):
        verify(SECRET, header, BODY + b" ", now=1_800_000_000)
    with pytest.raises(SignatureError, match="does not match"):
        verify("whsec_other", header, BODY, now=1_800_000_000)
    with pytest.raises(SignatureError, match="tolerance"):
        verify(SECRET, header, BODY, now=1_800_000_301)
    assert verify(SECRET, header, BODY, now=1_900_000_000, tolerance_s=-1) == 1_800_000_000
    assert verify(["whsec_old", SECRET], header, BODY, now=1_800_000_000) == 1_800_000_000
    two = header + ",v1=" + sign("whsec_next", 1_800_000_000, BODY)
    assert parse_header(two).signatures[1] == sign("whsec_next", 1_800_000_000, BODY)
    assert verify("whsec_next", two, BODY, now=1_800_000_000) == 1_800_000_000
    with pytest.raises(SignatureError):
        sign("", 1, BODY)
    with pytest.raises(SignatureError) as caught:
        verify(SECRET, header, b"x", now=1_800_000_000)
    assert SECRET not in str(caught.value)


# --- bodies -------------------------------------------------------------------------------------


def _finding(**changes: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "kind": "anomaly",
        "subject_kind": "agent",
        "subject_id": str(uuid4()),
        "severity": "warning",
        "summary": "Odd.",
    }
    body.update(changes)
    return body


def test_finding_bodies() -> None:
    ok = FindingSubmit.model_validate(_finding())
    assert not ok.wants_alert()
    assert FindingSubmit.model_validate(_finding(severity="critical")).wants_alert()
    assert not FindingSubmit.model_validate(
        _finding(severity="critical", raise_alert=False)
    ).wants_alert()
    assert FindingSubmit.model_validate(_finding(raise_alert=True)).wants_alert()
    review = _finding(kind="held_action_review", subject_kind="held_action", advice="deny")
    assert FindingSubmit.model_validate(review).advice is v.HeldActionAdvice.DENY
    fleet = FindingSubmit.model_validate(
        _finding(kind="fleet_summary", subject_kind="fleet", subject_id=None)
    )
    assert fleet.subject_id is None
    for bad in (
        _finding(kind="semantic_drift", subject_kind="run"),
        _finding(subject_kind="fleet"),
        _finding(subject_id=None),
        _finding(advice="approve"),
        _finding(severity="info", raise_alert=True),
        _finding(body={"x": float("nan")}),
        _finding(body={"x": "y" * 40_000}),
        _finding(recommendation="tab\x00"),
        _finding(model="bad model"),
        _finding(extra=True),
    ):
        with pytest.raises(ValidationError):
            FindingSubmit.model_validate(bad)


def test_monitor_bodies() -> None:
    created = MonitorCreate.model_validate({"name": "Claude", "kind": "mcp"})
    assert created.all_groups and created.issue_key and created.rate_limit_per_min == 60
    group = str(uuid4())
    narrow = MonitorCreate.model_validate(
        {"name": "n", "kind": "api", "all_groups": False, "group_ids": [group]}
    )
    assert [str(g) for g in narrow.group_ids] == [group]
    for bad in (
        {"name": "x", "kind": "api", "group_ids": [group]},
        {"name": "x", "kind": "api", "all_groups": False},
        {"name": "x", "kind": "api", "all_groups": False, "group_ids": [group, group]},
        {"name": "x\n", "kind": "api"},
        {"name": "x", "kind": "api", "rate_limit_per_min": 0},
    ):
        with pytest.raises(ValidationError):
            MonitorCreate.model_validate(bad)
    assert MonitorPatch.model_validate({"state": "paused"}).state == "paused"
    for bad in (
        {},
        {"reason": "only a reason here"},
        {"state": "revoked"},
        {"all_groups": True},
        {"all_groups": False, "group_ids": []},
    ):
        with pytest.raises(ValidationError):
            MonitorPatch.model_validate(bad)
    with pytest.raises(ValidationError):
        MonitorRevoke.model_validate({"reason": "short"})
    assert MonitorKeyCreate.model_validate({}).env is None
    hook = WebhookCreate.model_validate(
        {"url": "https://h.example.com/x", "event_types": ["run.failed"]}
    )
    assert hook.event_types == [v.WebhookEventType.RUN_FAILED]
    for bad in (
        {"url": "https://h.example.com/x", "event_types": ["ping"]},
        {"url": "https://h.example.com/x", "event_types": ["run.failed", "run.failed"]},
        {"url": "https://h.example.com/x y", "event_types": ["run.failed"]},
        {"url": "https://h.example.com/x", "event_types": []},
    ):
        with pytest.raises(ValidationError):
            WebhookCreate.model_validate(bad)
