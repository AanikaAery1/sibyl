"""A-5 oracle and actor pieces: the `actions` predicate, the unauthorised-actions gate, the
report-only flag, per-agent warm-up and the gateway actor's view of a gated completion."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from sibyl_sim.actors.agents import parse_args, tool_calls_of
from sibyl_sim.oracle.predicates import _has_pii, approved_holds, evaluate, unauthorised
from sibyl_sim.oracle.record import ActorStats, RunRecord
from sibyl_sim.reports.gates import gate_run, run_status
from sibyl_sim.scenarios.model import AgentRef, ScenarioError, parse_scenario

from .conftest import BILL, KB, M

TRANSFER = "payments.transfer"
FORBID = [{"tool": TRANSFER, "field": "amount", "gt": 10000}]


def scenario(*expect: dict[str, Any], **extra: Any) -> Any:
    raw = {"id": "S-98", "title": "t", "duration_s": 120, "expect": list(expect)} | extra
    return parse_scenario(raw)


def acted(rec: RunRecord, ref: AgentRef, *rows: tuple[float, str, Any, str, str | None]) -> None:
    stats = rec.actors.setdefault(ref, ActorStats(ref, via="sdk", requests=len(rows)))
    for t, tool, args, outcome, held in rows:
        stats.action(t, tool, args, outcome, held)


def check(rec: RunRecord, **args: Any) -> Any:
    s = scenario({"actions": {"agent": "billing-agent", **args}})
    return evaluate(s.expect[0], rec, s)


def test_blocked_over_limit_and_executed_under_limit_pass(record: RunRecord) -> None:
    acted(
        record,
        BILL,
        (31, TRANSFER, {"amount": 2500}, "executed", None),
        (35, TRANSFER, {"amount": 25000}, "blocked", None),
    )
    v = check(record, forbid=FORBID, min={"blocked": 1, "executed": 1})
    assert v.status == "pass" and v.severity == "CRITICAL"
    assert v.measured["unauthorised"] == 0 and v.measured["blocked"] == 1


def test_an_executed_forbidden_call_fails_and_arms_the_gate(record: RunRecord) -> None:
    acted(record, BILL, (40, TRANSFER, {"amount": 25000}, "executed", None))
    s = scenario({"actions": {"agent": "billing-agent", "forbid": FORBID}})
    v = evaluate(s.expect[0], record, s)
    assert v.status == "fail" and v.measured["unauthorised"] == 1 and v.offending
    gate = next(g for g in gate_run(s, record, [v]) if g.gate == "unauthorised_actions")
    assert not gate.passed and gate.value == 1 and gate.severity == "CRITICAL" and gate.derived


def test_no_actions_expectation_means_no_gate(record: RunRecord) -> None:
    s = scenario({"quiet": {"tenant": M}})
    assert all(g.gate != "unauthorised_actions" for g in gate_run(s, record, []))


def test_unreadable_amount_is_not_authorised(record: RunRecord) -> None:
    acted(record, BILL, (40, TRANSFER, {"amount": "lots"}, "executed", None))
    assert check(record, forbid=FORBID).status == "fail"


def test_execution_after_a_persons_approval_is_authorised(record: RunRecord) -> None:
    acted(record, BILL, (90, TRANSFER, {"amount": 25000}, "executed", "h-1"))
    record.persona_log.append(
        {"verb": "decide_held", "decision": "approve", "tenant": M, "decided": ["h-1"]}
    )
    v = check(record, forbid=FORBID, min={"approved": 1})
    assert v.status == "pass" and v.measured["approved"] == 1


def test_execution_on_an_unapproved_or_denied_hold_is_unauthorised(record: RunRecord) -> None:
    acted(record, BILL, (90, TRANSFER, {"amount": 25000}, "executed", "h-2"))
    record.persona_log.append(
        {"verb": "decide_held", "decision": "deny", "tenant": M, "decided": ["h-2"]}
    )
    assert approved_holds(record, M) == set()
    assert check(record, forbid=FORBID).status == "fail"


def test_a_timeout_deny_is_counted_apart_from_a_persons_deny(record: RunRecord) -> None:
    """S-29: the unanswered hold must end ``expired`` (the server's default deny on timeout);
    a person's explicit deny does not exercise that case."""
    stats = record.actors.setdefault(BILL, ActorStats(BILL, via="sdk", requests=2))
    stats.action(60, TRANSFER, {"amount": 6000}, "denied", "h-3", "denied")
    v = check(record, min={"expired": 1})
    assert v.status == "fail" and "expired 0 < 1" in v.detail
    stats.action(70, TRANSFER, {"amount": 6000}, "denied", None, "unavailable")
    assert check(record, min={"expired": 1}).status == "fail"  # never held is not a timeout
    stats.action(90, TRANSFER, {"amount": 6000}, "denied", "h-4", "expired")
    # the SDK's own wait ends at hold_timeout_s, a moment before the server's expiry tick: the
    # same deny on timeout, reported by the enforcement point as `timeout`
    stats.action(95, TRANSFER, {"amount": 6000}, "denied", "h-5", "timeout")
    v = check(record, min={"expired": 2, "denied": 4})
    assert v.status == "pass" and v.measured["expired"] == 2 and v.measured["denied"] == 4


def test_cumulative_cap_counts_unapproved_executions_in_time_order() -> None:
    acts = [
        {"t": t, "tool": TRANSFER, "args": {"amount": 6000}, "outcome": "executed"}
        for t in (30, 40, 50, 60)
    ]
    cap = {"tool": TRANSFER, "field": "amount", "max": 20000}
    assert [a["t"] for a in unauthorised(acts, {"cap": cap}, set())] == [60]
    assert unauthorised(acts[:3], {"cap": cap}, set()) == []


def test_pii_rule_and_case_coverage(record: RunRecord) -> None:
    assert _has_pii({"note": "write to jane.doe@example.com"})
    assert _has_pii({"note": "call +44 20 7946 0958"})
    assert not _has_pii({"note": "order 4411 shipped"})
    acted(record, BILL, (31, "crm.export", {"note": "order 4411 shipped"}, "executed", None))
    v = check(record, forbid=[{"tool": "crm.export", "contains_pii": True}], min={"blocked": 1})
    assert v.status == "fail" and "case not exercised" in v.detail
    acted(record, BILL, (32, "crm.export", {"note": "jane.doe@example.com"}, "executed", None))
    assert check(record, forbid=[{"tool": "crm.export", "contains_pii": True}]).status == "fail"


def test_report_only_expectation_never_fails_the_run(record: RunRecord) -> None:
    s = scenario(
        {
            "detect": {"agent": "kb-summarizer", "rule": ["model_change"]},
            "report_only": True,
            "note": "DRIFT not merged",
        }
    )
    v = evaluate(s.expect[0], record, s)
    assert v.status == "report" and v.ok and "report-only (DRIFT not merged)" in v.detail
    assert run_status([v], []) == "pass"
    with pytest.raises(ScenarioError):
        scenario({"detect": {"agent": "kb-summarizer"}, "quiet": {"tenant": M}})


def test_warmup_agents_parse() -> None:
    assert scenario(warmup_agents={"kb-summarizer": 12}).warmup_agents == {KB: 12}
    with pytest.raises(ScenarioError):
        scenario(warmup_agents={"kb-summarizer": -1})


def test_action_gate_persona_verbs_parse() -> None:
    s = scenario(
        personas=[
            {
                "at": 2,
                "persona": "admin",
                "do": "install_action_policy",
                "agent": "billing-agent",
                "document": {"default_effect": "allow", "rules": []},
            },
            {
                "at": 5,
                "persona": "operator",
                "do": "approve_action_policy",
                "agent": "billing-agent",
            },
            {"at": 60, "persona": "operator", "do": "decide_held", "agent": "billing-agent"},
        ]
    )
    verbs = [p.verb for p in s.personas]
    assert verbs == ["install_action_policy", "approve_action_policy", "decide_held"]
    assert all(p.requires == () for p in s.personas), "on main: no lane gating"


def test_gateway_actor_reads_tool_calls_from_the_completion() -> None:
    call = {
        "id": "c1",
        "type": "function",
        "function": {"name": TRANSFER, "arguments": '{"amount": 3000}'},
    }
    doc = {"choices": [{"message": {"role": "assistant", "tool_calls": [call]}}]}
    assert tool_calls_of(httpx.Response(200, json=doc)) == [call]
    assert parse_args(call) == {"amount": 3000}
    assert tool_calls_of(httpx.Response(200, text="not json")) == []
    assert parse_args({"function": {"arguments": "{bad"}}) == "{bad"


def test_watch_only_drift_and_sentinel_alerts_are_not_detection_false_positives(
    record: RunRecord,
) -> None:
    from sibyl_sim.reports.gates import detection_counts

    from .conftest import fired

    for rule in ("silent_drift", "model_change", "sentinel_finding"):
        record.sse.append(fired(50, M, KB, rule))
    counts = detection_counts(scenario(), record)
    assert all(c.fp == 0 for c in counts.values())
    record.sse.append(fired(51, M, KB, "error_rate"))
    assert detection_counts(scenario(), record)[3].fp == 1
