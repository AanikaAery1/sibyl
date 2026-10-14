"""Frozen value sets: DATAMODEL §4.0, API §2.3/§6.3/§7, ML §3.3, R25, R58."""

from __future__ import annotations

import enum
import re

import pytest
from sibyl_schemas import values as v


def _value_sets() -> list[type[enum.Enum]]:
    return [
        obj
        for obj in vars(v).values()
        if isinstance(obj, type)
        and issubclass(obj, enum.Enum)
        and obj.__module__.startswith("sibyl_schemas.")
    ]


def test_event_types_are_the_fourteen_frozen_types() -> None:
    assert [e.value for e in v.EventType] == [
        "gen_ai.request",
        "tool.call",
        "agent.invoke",
        "checkpoint",
        "handoff.requested",
        "handoff.completed",
        "handoff.returned",
        "feedback",
        "task.outcome",
        "agent.discovered",
        "policy.decision",
        "observation.gap",
        "provider.status",
        "health.transition",
    ]


def test_only_platform_events_may_omit_agent_id() -> None:
    assert frozenset({v.EventType.PROVIDER_STATUS, v.EventType.OBSERVATION_GAP}) == (
        v.AGENT_OPTIONAL_EVENT_TYPES
    )


def test_routing_states_match_state_machine() -> None:
    assert {s.value for s in v.RoutingState} == {
        "active",
        "degraded",
        "awaiting_approval",
        "failed_over",
        "failing_back",
        "quarantined",
        "killed",
    }


def test_incident_actions_are_r25_backend_vocabulary() -> None:
    assert {a.value for a in v.IncidentAction} == {
        "failover",
        "degrade",
        "recover",
        "handoff",
        "quarantine",
        "kill",
        "approve",
        "deny",
        "undo",
        "clear_hold",
        "release",
        "fail_back",
        "cancel",
    }
    assert v.INCIDENT_CREATE_ACTIONS | v.INCIDENT_TRANSITION_ACTIONS == frozenset(v.IncidentAction)
    assert not v.INCIDENT_CREATE_ACTIONS & v.INCIDENT_TRANSITION_ACTIONS


def test_capture_mode_order_and_most_restrictive() -> None:
    assert v.CaptureMode.most_restrictive(v.CaptureMode.FULL, v.CaptureMode.METADATA) is (
        v.CaptureMode.METADATA
    )
    assert v.CaptureMode.most_restrictive(v.CaptureMode.FULL, v.CaptureMode.REDACTED) is (
        v.CaptureMode.REDACTED
    )
    assert v.CaptureMode.most_restrictive(v.CaptureMode.FULL) is v.CaptureMode.FULL
    with pytest.raises(ValueError, match="at least one"):
        v.CaptureMode.most_restrictive()


def test_fallback_kind_rank_is_positional() -> None:
    assert [k.rank for k in v.FallbackKind] == [0, 1, 2, 3, 4, 5]
    assert v.FallbackKind.HUMAN_QUEUE.rank == 5


def test_tiers_and_rto_defaults() -> None:
    assert [int(t) for t in v.Tier] == [1, 2, 3]
    assert v.TIER_RTO_S == {v.Tier.T1: 900, v.Tier.T2: 3600, v.Tier.T3: 14400}
    assert v.TIER_SLO == {v.Tier.T1: 0.995, v.Tier.T2: 0.99, v.Tier.T3: 0.98}


def test_outbox_topics_are_fourteen_coarse_topics_on_two_channels() -> None:
    assert len(v.OutboxTopic) == 14  # R58 X1's twelve plus B14 ``job`` and D48 ``action``
    assert {c.value for c in v.NotifyChannel} == {"sibyl_policy", "sibyl_outbox"}
    policy_topics = {t for t, c in v.TOPIC_CHANNEL.items() if c is v.NotifyChannel.POLICY}
    assert policy_topics == {v.OutboxTopic.POLICY, v.OutboxTopic.KILLSWITCH}
    assert set(v.TOPIC_CHANNEL) == set(v.OutboxTopic)


def test_every_sse_event_maps_to_exactly_one_topic() -> None:
    assert set(v.SSE_EVENT_TOPIC) == set(v.SseEventType) - {v.SseEventType.RESET}
    for event, topic in v.SSE_EVENT_TOPIC.items():
        assert isinstance(topic, v.OutboxTopic), event


def test_outbox_event_types_include_anchor_now_once() -> None:
    assert v.OUTBOX_EVENT_TOPIC["audit.anchor_now"] is v.OutboxTopic.AUDIT
    spellings = [e for e in v.OUTBOX_EVENT_TOPIC if "anchor" in e]
    assert spellings == ["audit.anchor_now"]


def test_job_requested_is_worker_facing() -> None:
    assert v.OUTBOX_EVENT_TOPIC["job.requested"] is v.OutboxTopic.JOB
    assert v.TOPIC_CHANNEL[v.OutboxTopic.JOB] is v.NotifyChannel.OUTBOX
    assert v.OutboxTopic.JOB not in set(v.SSE_EVENT_TOPIC.values())


def test_rule_ids_cover_r1_r9_and_l1_l7() -> None:
    codes = {f"R{i}" for i in range(1, 10)} | {f"L{i}" for i in range(1, 8)}
    assert set(v.RULE_SHORT_CODES) == codes
    assert v.RULE_SHORT_CODES["R9"] is v.RuleId.HEARTBEAT_MISSING
    assert v.RULE_SHORT_CODES["L7"] is v.RuleId.CONTINUITY_UNVERIFIED
    pattern = re.compile(v.RULE_ID_PATTERN)
    for rule in v.RuleId:
        assert pattern.fullmatch(rule.value), rule
        assert rule in v.RULE_KIND


def test_problem_codes_have_http_status_and_snake_case() -> None:
    for code in v.ProblemCode:
        assert re.fullmatch(r"[a-z][a-z0-9_]+", code.value)
        assert 400 <= v.PROBLEM_STATUS[code] <= 599, code
    assert set(v.PROBLEM_STATUS) == set(v.ProblemCode)
    assert v.PROBLEM_STATUS[v.ProblemCode.INVALID_TRANSITION] == 409
    assert v.PROBLEM_STATUS[v.ProblemCode.STEP_UP_REQUIRED] == 403
    assert v.problem_type_uri(v.ProblemCode.DEMO_MODE) == "https://sibyl.dev/problems/demo_mode"


def test_gateway_error_codes_have_openai_types() -> None:
    assert set(v.GATEWAY_ERROR_STATUS) == set(v.GatewayErrorCode)
    assert v.GATEWAY_ERROR_STATUS[v.GatewayErrorCode.SIBYL_AGENT_KILLED] == (
        403,
        "permission_error",
    )


def test_ingest_reject_reasons_include_step4_additions() -> None:
    assert {"env_mismatch", "agent_not_permitted"} <= {r.value for r in v.RejectReason}
    assert len(v.RejectReason) == 10


def test_snapshot_reject_causes_in_verification_order() -> None:
    assert [c.value for c in v.SnapshotRejectCause] == [
        "malformed",
        "unknown_kid",
        "bad_signature",
        "non_monotonic",
        "future_issued",
        "bad_ttl",
    ]


def test_value_sets_have_unique_lowercase_values() -> None:
    sets = _value_sets()
    assert len(sets) >= 60
    for value_set in sets:
        values = [m.value for m in value_set]
        assert len(values) == len(set(values)), value_set
        if issubclass(value_set, enum.StrEnum):
            for value in values:
                assert value == value.strip() and value, (value_set, value)


def test_key_set_reject_causes_in_verification_order() -> None:
    assert [c.value for c in v.KeySetRejectCause] == [
        "malformed",
        "unknown_signer",
        "signer_expired",
        "bad_signature",
        "non_monotonic",
        "sequence_gap",
        "chain_broken",
    ]
