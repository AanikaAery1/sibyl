"""Routing, incident, queue, alert, read, governance and edge schemas (API.md §5.7-§5.13, §4)."""

from __future__ import annotations

from .dsl import (
    N_TS,
    N_UUID,
    REASON,
    TS,
    UUID,
    Schema,
    array,
    body_obj,
    boolean,
    enum,
    free_object,
    integer,
    nullable,
    obj,
    ref,
    ro,
    string,
)

KID_PATTERN = "^[A-Za-z0-9._-]{1,64}$"


def _routing() -> dict[str, Schema]:
    return {
        "PreemptiveBreakerClear": body_obj(
            {"reason": REASON},
            ("reason",),
            description="why the tripped pre-emptive breaker may be re-armed (B19)",
        ),
        "PreemptiveBreakerCleared": obj(
            {"agent_id": UUID, "tripped_at": TS, "cleared_at": TS, "cleared_by_user_id": UUID},
            ("agent_id", "tripped_at", "cleared_at", "cleared_by_user_id"),
        ),
        "RoutingTransition": obj(
            {
                "id": UUID,
                "failover_id": N_UUID,
                "from_state": nullable(ref("RoutingStateEnum")),
                "to_state": ref("RoutingStateEnum"),
                "from_target": free_object("{kind, provider_id, model_id, agent_id, step_id}"),
                "to_target": free_object("{kind, provider_id, model_id, agent_id, step_id}"),
                "trigger": ref("TransitionTrigger"),
                "actor_kind": ref("ActorKind"),
                "actor_user_id": N_UUID,
                "rule_codes": array(string()),
                "alert_ids": array(UUID),
                "health_snapshot_id": N_UUID,
                "approval_id": N_UUID,
                "inverse_of": N_UUID,
                "undone_by": ro(N_UUID),
                "operator_hold_until": N_TS,
                "routing_version": integer(format="int64"),
                "reason": {"type": ["string", "null"]},
                "audit_seq": integer(format="int64"),
                "created_at": TS,
            },
            ("id", "to_state", "trigger", "actor_kind", "routing_version", "created_at"),
        ),
        "RoutingState": obj(
            {
                "agent_id": UUID,
                "state": ref("RoutingStateEnum"),
                "target_kind": ref("TargetKind"),
                "target_provider_id": N_UUID,
                "target_model_id": N_UUID,
                "target_agent_id": N_UUID,
                "current_step_id": N_UUID,
                "canary_pct": integer(minimum=0, maximum=100),
                "routing_version": integer(format="int64"),
                "operator_hold_until": N_TS,
                "state_since": TS,
                "last_transition": nullable(ref("RoutingTransition")),
                "pending_approval": nullable(ref("Approval")),
            },
            ("agent_id", "state", "target_kind", "routing_version", "state_since"),
        ),
        "Approval": obj(
            {
                "id": UUID,
                "incident_id": UUID,
                "agent_id": UUID,
                "requested_action": ref("ApprovalAction"),
                "tier": integer(minimum=1, maximum=3),
                "requested_by_kind": enum("rule", "human"),
                "requested_by_user_id": N_UUID,
                "alert_id": N_UUID,
                "evidence": free_object("refs and stats only, <= 8 KB"),
                "risk": {"type": ["string", "null"]},
                "expires_at": TS,
                "timeout_policy": ref("ApprovalTimeoutPolicy"),
                "state": ref("ApprovalState"),
                "decided_by_user_id": N_UUID,
                "decided_at": N_TS,
                "decision_reason": {"type": ["string", "null"]},
            },
            ("id", "incident_id", "agent_id", "requested_action", "tier", "expires_at", "state"),
        ),
    }


def _incidents() -> dict[str, Schema]:
    return {
        "Incident": obj(
            {
                "id": {**UUID, "description": "= failover.id"},
                "agent_id": UUID,
                "kind": ref("FailoverKind"),
                "state": ref("FailoverState"),
                "step": ref("FailoverStep"),
                "priority": string(),
                "actor_kind": ref("ActorKind"),
                "requested_by_user_id": N_UUID,
                "trigger_alert_id": N_UUID,
                "rule_codes": array(string()),
                "from_state": nullable(ref("RoutingStateEnum")),
                "to_state": nullable(ref("RoutingStateEnum")),
                "chosen_step": nullable(free_object("fallback step chosen")),
                "approval": nullable(ref("Approval")),
                "transition": nullable(ref("RoutingTransition")),
                "routing": ref("RoutingState"),
                "alert": nullable(free_object("triggering alert summary")),
                "health_evidence": nullable(free_object("factors at trigger")),
                "handoff_tasks": array(ref("HandoffTaskSummary")),
                "undo_plan": nullable(free_object("inverse transition preview")),
                "step_results": free_object("per-step results"),
                "operator_hold_until": N_TS,
                "error": {"type": ["string", "null"]},
                "available_actions": ro(array(ref("IncidentActionName"))),
                "created_at": TS,
                "finished_at": N_TS,
            },
            ("id", "agent_id", "kind", "state", "step", "actor_kind", "routing", "created_at"),
        ),
        "IncidentCreate": body_obj(
            {
                "agent_id": UUID,
                "action": ref("IncidentCreateAction"),
                "target": body_obj(
                    {
                        "step_id": UUID,
                        "kind": enum("model", "agent"),
                        "provider_id": UUID,
                        "model_id": UUID,
                        "agent_id": UUID,
                    },
                    description="failover only: step_id from the approved chain, or ad hoc",
                ),
                "reason": REASON,
                "evidence_refs": body_obj(
                    {"alert_ids": array(UUID, maxItems=50), "health_snapshot_id": UUID}
                ),
            },
            ("agent_id", "action", "reason"),
        ),
        "IncidentAction": body_obj(
            {
                "action": ref("IncidentActionName"),
                "reason": REASON,
                "expected_routing_version": integer(format="int64"),
            },
            ("action", "reason"),
        ),
        "KillSwitch": obj(
            {
                "id": UUID,
                "scope_kind": ref("KillScopeKind"),
                "scope_id": N_UUID,
                "state": ref("KillSwitchState"),
                "reason": string(),
                "pulled_by": N_UUID,
                "pulled_via_break_glass": boolean(),
                "pulled_at": TS,
                "routing_version_at_pull": integer(format="int64"),
                "affected_agent_ids": array(UUID),
                "acks": array(ref("KillSwitchAck")),
                "released_by": N_UUID,
                "released_at": N_TS,
            },
            ("id", "scope_kind", "state", "pulled_at", "affected_agent_ids"),
        ),
        "KillSwitchCreate": body_obj(
            {
                "scope_kind": ref("KillScopeKind"),
                "scope_id": UUID,
                "reason": string(minLength=20, maxLength=2000),
            },
            ("scope_kind", "reason"),
        ),
        "KillSwitchAck": obj(
            {
                "kill_switch_id": UUID,
                "gateway_id": string(),
                "snapshot_version": integer(format="int64"),
                "applied_at": TS,
            },
            ("kill_switch_id", "gateway_id", "snapshot_version", "applied_at"),
        ),
        "KillSwitchAckCreate": body_obj(
            {
                "gateway_id": string(minLength=1, maxLength=128),
                "snapshot_version": integer(format="int64", minimum=0),
            },
            ("gateway_id", "snapshot_version"),
        ),
    }


def _queue() -> dict[str, Schema]:
    summary = {
        "id": UUID,
        "agent_id": UUID,
        "incident_id": N_UUID,
        "state": ref("HandoffState"),
        "priority": integer(),
        "summary": string(),
        "failure_mode": nullable(ref("FailureMode")),
        "fidelity": ref("Fidelity"),
        "deadline_at": TS,
        "claimed_by": N_UUID,
        "created_at": TS,
    }
    return {
        "QueueSummary": obj(
            {
                "queued": integer(minimum=0),
                "claimed": integer(minimum=0),
                "expired": integer(minimum=0),
                "returned": integer(minimum=0),
                "completed": integer(minimum=0),
                "completed_despite_failure": integer(
                    minimum=0,
                    description=(
                        "tasks completed by a human while the agent was failing (B13, demo B6)"
                    ),
                ),
                "completed_despite_failure_pct": {
                    "type": ["integer", "null"],
                    "minimum": 0,
                    "maximum": 100,
                    "description": "% of decided (completed + expired + returned) tasks",
                },
                "overdue": integer(minimum=0),
                "total": integer(minimum=0),
                "window_days": integer(minimum=1),
            },
            (
                "queued",
                "claimed",
                "expired",
                "returned",
                "completed",
                "completed_despite_failure",
                "completed_despite_failure_pct",
                "overdue",
                "total",
                "window_days",
            ),
            description="listQueue counters over the last window_days (lane S, B13)",
        ),
        "HandoffTaskSummary": obj(
            summary, ("id", "agent_id", "state", "priority", "fidelity", "deadline_at")
        ),
        "HandoffTask": obj(
            {
                **summary,
                "accountable_user_id": N_UUID,
                "lock_expires_at": N_TS,
                "outcome": nullable(ref("HandoffOutcome")),
                "outcome_note": {"type": ["string", "null"]},
                "next_action": {"type": ["string", "null"]},
                "rating": {"type": ["integer", "null"], "minimum": 1, "maximum": 5},
                "packet_sha256": {"type": ["string", "null"]},
                "claimed_at": N_TS,
                "completed_at": N_TS,
            },
            ("id", "agent_id", "state", "priority", "fidelity", "deadline_at"),
            description="Metadata only; the packet body is GET …/packet.",
        ),
        "HandoffPacket": free_object(
            "sibyl-handoff/1 document (sibyl-schemas)", **{"x-sibyl-document": "sibyl-handoff/1"}
        ),
        "HandoffTaskAction": body_obj(
            {
                "action": ref("HandoffActionName"),
                "reason": string(maxLength=2000),
                "outcome": enum("resolved", "escalated", "abandoned"),
                "outcome_note": string(maxLength=4000),
                "next_action": string(maxLength=2000),
                "rating": integer(minimum=1, maximum=5),
                "accountable_user_id": UUID,
            },
            ("action",),
        ),
        "Checkpoint": obj(
            {
                "id": UUID,
                "agent_id": UUID,
                "task_id": UUID,
                "seq": integer(),
                "step_index": {"type": ["integer", "null"]},
                "step_name": {"type": ["string", "null"]},
                "state": nullable(free_object("inline state <= 64 KB")),
                "state_ref_id": N_UUID,
                "state_sha256": {"type": ["string", "null"]},
                "capture_mode": ref("CaptureMode"),
                "created_at": TS,
            },
            ("id", "agent_id", "task_id", "seq", "capture_mode", "created_at"),
        ),
    }


def _alerts() -> dict[str, Schema]:
    return {
        "Alert": obj(
            {
                "id": UUID,
                "agent_id": N_UUID,
                "provider_id": N_UUID,
                "rule_code": string(),
                "severity": ref("AlertSeverity"),
                "state": ref("AlertState"),
                "fired_at": TS,
                "acked_at": N_TS,
                "resolved_at": N_TS,
                "silenced_until": N_TS,
                "verdict": nullable(ref("Verdict")),
                "verdict_note": {"type": ["string", "null"]},
                "hold_suppressed_count": integer(),
                "health_snapshot_id": N_UUID,
                "provider_incident_id": N_UUID,
                "incident_id": N_UUID,
                "health_snapshot": nullable(free_object("health snapshot at fire time")),
            },
            ("id", "rule_code", "severity", "state", "fired_at"),
        ),
        "AlertAction": body_obj(
            {
                "action": ref("AlertActionName"),
                "reason": string(maxLength=2000),
                "until": TS,
                "verdict": ref("Verdict"),
                "verdict_note": string(maxLength=500),  # sibyl-label/1 note
            },
            ("action",),
        ),
        "AlertBacklog": obj(
            {
                "unverdicted": integer(minimum=0),
                "verdict_wanted": integer(minimum=0),
                "unverdicted_older_than_7d": integer(minimum=0),
                "resolved_last_30d": integer(minimum=0),
                "ratio": {"type": "number", "minimum": 0},
                "target": {"type": "number", "minimum": 0},
                "banner": boolean(),
            },
            (
                "unverdicted",
                "verdict_wanted",
                "unverdicted_older_than_7d",
                "resolved_last_30d",
                "ratio",
                "target",
                "banner",
            ),
            description="Unverdicted-alert backlog SLI (D33); only with ?unverdicted=true",
        ),
        "ProviderIncident": obj(
            {
                "id": UUID,
                "provider_id": UUID,
                "state": ref("ProviderIncidentState"),
                "opened_at": TS,
                "resolved_at": N_TS,
                "affected_agent_ids": array(UUID),
                "legal_hold_id": N_UUID,
                "alerts": array(ref("Alert")),
            },
            ("id", "provider_id", "state", "opened_at", "affected_agent_ids"),
        ),
    }


def _reads() -> dict[str, Schema]:
    horizon = obj(
        {
            "horizon_s": integer(),
            "probability_band": ref("ProbabilityBand"),
            "probability": {"type": ["number", "null"], "description": "model source only"},
            "confidence": ref("Confidence"),
            "contributing_rules": array(string()),
            "abstained": boolean(),
        },
        ("horizon_s", "probability_band", "confidence"),
    )
    return {
        "FleetHealth": obj(
            {
                "counts_by_band": free_object("band -> count"),
                "counts_by_routing_state": free_object("routing state -> count"),
                "open_alerts": integer(),
                "open_incidents": integer(),
                "pending_approvals": integer(),
                "queue_depth": integer(),
                "provider_incidents": array(ref("ProviderIncident")),
            },
            ("counts_by_band", "counts_by_routing_state", "open_alerts", "open_incidents"),
        ),
        "HealthDocument": free_object(
            "sibyl-health/1 document: score, band, provisional, factors[], window,"
            " routing_state_at, policy_version, observation_coverage",
            **{"x-sibyl-document": "sibyl-health/1"},
        ),
        "HealthPoint": obj(
            {
                "evaluated_at": TS,
                "score": integer(minimum=0, maximum=100),
                "band": ref("Band"),
                "provisional": boolean(),
            },
            ("evaluated_at", "score", "band"),
        ),
        "RiskHorizon": horizon,
        "RiskDocument": obj(
            {
                "agent_id": UUID,
                "evaluated_at": TS,
                "horizons": obj(
                    {"15m": horizon, "1h": horizon, "24h": horizon}, ("15m", "1h", "24h")
                ),
                "predicted_failure_mode": nullable(ref("FailureMode")),
                "recommended_action": ref("RecommendedAction"),
                "leading_rules_firing": array(string()),
                "rules_source": string(pattern=r"^(rules/v\d+|model/.+)$"),
            },
            ("agent_id", "horizons", "recommended_action", "rules_source"),
        ),
        "MetricBucket": obj(
            {
                "bucket_start": TS,
                "grain": ref("MetricGrain"),
                "provider": {"type": ["string", "null"]},
                "model": {"type": ["string", "null"]},
                "requests": integer(),
                "errors": integer(),
                "tokens_in": integer(),
                "tokens_out": integer(),
                "cost_usd": ref("Money"),
                "p50_ms": {"type": ["integer", "null"]},
                "p95_ms": {"type": ["integer", "null"]},
                "p99_ms": {"type": ["integer", "null"]},
            },
            ("bucket_start", "grain", "requests", "errors"),
        ),
        "Event": obj(
            {
                "event_id": UUID,
                "event_type": ref("EventType"),
                "ts": TS,
                "agent_id": N_UUID,
                "status": nullable(ref("EventStatus")),
                "trace_id": {"type": ["string", "null"]},
                "span_id": {"type": ["string", "null"]},
                "task_id": N_UUID,
                "call_id": N_UUID,
                "provider": {"type": ["string", "null"]},
                "model": {"type": ["string", "null"]},
                "attrs": free_object("metadata attributes only, never content"),
                "payload_ref": nullable(
                    obj(
                        {
                            "id": UUID,
                            "kind": ref("PayloadKind"),
                            "sha256": ref("Sha256Hex"),
                            "size_bytes": integer(),
                            "state": ref("PayloadState"),
                        }
                    )
                ),
            },
            ("event_id", "event_type", "ts"),
        ),
        "Trace": obj({"trace_id": string(), "spans": array(ref("Event"))}, ("trace_id", "spans")),
        **_runs(),
    }


N_STR: Schema = {"type": ["string", "null"]}
N_INT: Schema = {"type": ["integer", "null"]}
N_NUM: Schema = {"type": ["number", "null"]}
TRACE_HEX: Schema = {"type": ["string", "null"], "pattern": "^[0-9a-f]{32}$"}


def _run_summary_props() -> dict[str, Schema]:
    return {
        "run_id": UUID,
        "agent_id": N_UUID,
        "agent_name": N_STR,
        "parent_run_id": N_UUID,
        "step_index": N_INT,
        "status": ref("RunStatus"),
        "error_type": N_STR,
        "started_at": N_TS,
        "ended_at": N_TS,
        "duration_ms": N_NUM,
        "trace_id": TRACE_HEX,
        "handoff_to_agent": {**N_STR, "description": "agent ref this run handed off to"},
        "step_count": N_INT,
        "tool_calls": N_INT,
        "model_calls": N_INT,
        "cost_usd": N_NUM,
    }


RUN_REQUIRED = ("run_id", "status", "started_at")


def _runs() -> dict[str, Schema]:
    gate = obj(
        {
            "effect": nullable(ref("ToolActionEffect")),
            "rule_id": N_STR,
            "held_action_id": N_UUID,
        },
        ("effect",),
        description="Action Gate outcome recorded on the tool call",
    )
    return {
        "RunStatus": enum("running", "ok", "error", "handed_off", "cancelled"),
        "RunSummary": obj(_run_summary_props(), RUN_REQUIRED),
        "RunModelCall": obj(
            {
                "call_id": N_UUID,
                "provider": N_STR,
                "requested_model": N_STR,
                "served_model": N_STR,
                "model_mismatch": {
                    "type": ["boolean", "null"],
                    "description": "served model is not the requested one or a dated snapshot of"
                    " it; null when either is unknown",
                },
                "system_fingerprint": N_STR,
                "tokens_in": N_INT,
                "tokens_out": N_INT,
                "cost_usd": N_NUM,
                "finish_reasons": nullable(array(string())),
            },
            ("requested_model", "served_model", "model_mismatch"),
        ),
        "RunToolCall": obj(
            {
                "tool_name": N_STR,
                "tool_type": N_STR,
                "tool_call_id": N_STR,
                "side_effect_class": N_STR,
                "handoff_to_agent": N_STR,
                "action_gate": nullable(gate),
            },
            ("tool_name", "action_gate"),
        ),
        "RunStep": obj(
            {
                "kind": enum("model_call", "tool_call", "child_run"),
                "step_index": N_INT,
                "ts": N_TS,
                "event_id": N_UUID,
                "status": N_STR,
                "error_type": N_STR,
                "latency_ms": N_NUM,
                "model_call": nullable(ref("RunModelCall")),
                "tool_call": nullable(ref("RunToolCall")),
                "child_run_id": N_UUID,
            },
            ("kind", "step_index", "ts"),
        ),
        "RunHandoff": obj(
            {
                "from_run_id": UUID,
                "to_agent": string(),
                "to_agent_id": {**N_UUID, "description": "the registered agent, when resolvable"},
                "via": enum("run", "tool"),
                "ts": N_TS,
                "event_id": N_UUID,
            },
            ("from_run_id", "to_agent", "via"),
        ),
        "RunNode": obj(
            {
                **_run_summary_props(),
                "steps": array(ref("RunStep")),
                "children": array(ref("RunNode")),
                "handoffs": array(ref("RunHandoff")),
            },
            (*RUN_REQUIRED, "steps", "children", "handoffs"),
        ),
        "RunDetail": obj(
            {
                **_run_summary_props(),
                "steps": array(ref("RunStep")),
                "children": array(ref("RunNode")),
                "handoffs": array(ref("RunHandoff")),
                "truncated": boolean(description="a size or depth bound cut the tree"),
                "run_count": integer(minimum=1),
            },
            (*RUN_REQUIRED, "steps", "children", "handoffs", "truncated", "run_count"),
        ),
    }


def _governance() -> dict[str, Schema]:
    return {
        "AuditEvent": obj(
            {
                "seq": integer(format="int64"),
                "action": string(),
                "actor_type": ref("AuditActorType"),
                "actor_id": N_UUID,
                "actor_key_id": N_UUID,
                "actor_session_id": N_UUID,
                "resource_type": string(),
                "resource_id": N_UUID,
                "resource_ref": {"type": ["string", "null"]},
                "reason": {"type": ["string", "null"]},
                "detail": free_object("refs and hashes only"),
                "occurred_at": TS,
                "recorded_at": TS,
                "request_id": N_UUID,
                "is_evidence": boolean(),
                "severity": string(),
                "prev_hash": ref("Sha256Hex"),
                "hash": ref("Sha256Hex"),
            },
            ("seq", "action", "actor_type", "resource_type", "recorded_at", "hash"),
        ),
        "AuditAnchor": obj(
            {
                "id": UUID,
                "kind": ref("AnchorKind"),
                "seq_from": integer(format="int64"),
                "seq_to": integer(format="int64"),
                "head_hash": ref("Sha256Hex"),
                "signing_kid": string(),
                "signature": string(),
                "anchored_at": TS,
                "prev_anchor_id": N_UUID,
            },
            ("id", "kind", "seq_from", "seq_to", "head_hash", "signing_kid", "signature"),
        ),
        "SigningKeyPublic": obj(
            {
                "kid": string(),
                "purpose": enum("snapshot", "audit_anchor", "agent_token"),
                "algorithm": string(),
                "public_key": string(description="base64url raw Ed25519 public key"),
                "state": string(),
                "activated_at": TS,
                "retiring_until": N_TS,
            },
            ("kid", "purpose", "algorithm", "public_key", "state"),
        ),
        "SigningKeyList": obj({"data": array(ref("SigningKeyPublic"))}, ("data",)),
        "VerificationRequest": body_obj(
            {"from_seq": integer(minimum=0), "to_seq": integer(minimum=0)}
        ),
        "VerificationResult": obj(
            {
                "ok": boolean(),
                "rows": integer(),
                "anchors_checked": integer(),
                "first_break_seq": {"type": ["integer", "null"]},
                "kind": nullable(ref("ChainBreakKind")),
            },
            ("ok", "rows", "anchors_checked"),
        ),
        "AuditExportCreate": body_obj(
            {
                "from_seq": integer(minimum=0),
                "to_seq": integer(minimum=0),
                "format": ref("ExportFormat"),
                "include_anchors": {"const": True, "default": True},
            },
            ("from_seq", "to_seq", "format"),
        ),
        "AuditExport": obj(
            {
                "id": UUID,
                "state": ref("JobState"),
                "from_seq": integer(),
                "to_seq": integer(),
                "format": ref("ExportFormat"),
                "anchor_id": N_UUID,
                "export_sha256": {"type": ["string", "null"]},
                "download_url": {"type": ["string", "null"], "format": "uri"},
                "download_expires_at": N_TS,
                "payload_ref_id": N_UUID,
            },
            ("id", "state", "from_seq", "to_seq", "format"),
        ),
        "ExportCreate": body_obj(
            {"kind": string(maxLength=40), "filter": free_object("export filter")},
            ("kind", "filter"),
        ),
        "ErasureRequest": obj(
            {
                "id": UUID,
                "scope_kind": ref("ErasureScopeKind"),
                "scope_ref": {"type": ["string", "null"], "description": "stored hash only"},
                "legal_basis": string(),
                "reason": string(),
                "state": ref("ErasureState"),
                "requested_by": N_UUID,
                "approved_by": N_UUID,
                "blocking_hold_ids": array(UUID),
                "execution_log": array(free_object("execution step")),
                "affected_objects": free_object("table -> count"),
                "retained_tables": array(string()),
                "resolution": {"type": ["string", "null"], "maxLength": 500},
                "error": {"type": ["string", "null"], "description": "stable error code only"},
                "origin": {"type": ["string", "null"], "description": "api or restore"},
                "backups_expire_at": N_TS,
                "completion_anchor_id": N_UUID,
                "created_at": TS,
                "completed_at": N_TS,
            },
            ("id", "scope_kind", "legal_basis", "state", "created_at"),
        ),
        "ErasureRequestCreate": body_obj(
            {
                "scope_kind": ref("ErasureScopeKind"),
                "scope_ref": string(writeOnly=True, maxLength=512),
                "agent_ids": array(UUID, maxItems=500),
                "window_from": TS,
                "window_to": TS,
                "legal_basis": string(maxLength=60),
                "reason": REASON,
            },
            ("scope_kind", "legal_basis", "reason"),
        ),
        "ErasureAction": body_obj(
            {"action": ref("ErasureActionName"), "reason": REASON}, ("action", "reason")
        ),
        "ErasureCertificate": obj(
            {
                "request_id": UUID,
                "certificate": free_object("JCS JSON certificate body"),
                "certificate_sha256": ref("Sha256Hex"),
                "anchor_id": UUID,
                "backups_expire_at": TS,
            },
            ("request_id", "certificate", "certificate_sha256", "backups_expire_at"),
        ),
        "LegalHold": obj(
            {
                "id": UUID,
                "scope_kind": ref("HoldScopeKind"),
                "scope_ref": {"type": ["string", "null"]},
                "provider_incident_id": N_UUID,
                "agent_ids": array(UUID),
                "window_from": TS,
                "window_to": N_TS,
                "reason": string(),
                "state": ref("HoldState"),
                "expires_at": N_TS,
                "placed_by": N_UUID,
                "created_at": TS,
                "reopened_erasure_ids": array(
                    UUID,
                    description="release only: hold_blocked erasures re-opened as requested",
                ),
            },
            ("id", "scope_kind", "window_from", "state"),
        ),
        "LegalHoldCreate": body_obj(
            {
                "scope_kind": ref("HoldScopeKind"),
                "scope_ref": string(maxLength=512),
                "provider_incident_id": UUID,
                "agent_ids": array(UUID, maxItems=500),
                "window_from": TS,
                "window_to": TS,
                "reason": REASON,
                "expires_at": TS,
            },
            ("scope_kind", "window_from", "reason"),
        ),
    }


def _edge() -> dict[str, Schema]:
    return {
        "PolicySnapshot": free_object(
            "sibyl.policy_snapshot/1 tenant block; detached Ed25519 signature in headers",
            **{"x-sibyl-document": "sibyl.policy_snapshot/1"},
        ),
        "CredentialBundle": obj(
            {
                "expires_in_s": integer(const=300),
                "items": {
                    "type": "object",
                    "additionalProperties": obj(
                        {
                            "auth_scheme": string(),
                            "secret": string(description="sealed to the gateway X25519 key"),
                            "base_url": string(format="uri"),
                            "key_version": integer(),
                        },
                        ("auth_scheme", "secret", "base_url", "key_version"),
                    ),
                },
            },
            ("expires_in_s", "items"),
        ),
        # Signed key set (security M6): sibyl.policy_snapshot/1 $defs/key_set. Closed objects:
        # the body is signed over JCS, so no field may be added in transit.
        "KeySet": body_obj(
            {
                "kid": string(pattern=KID_PATTERN, description="an active key of the previous set"),
                "alg": string(const="Ed25519"),
                "sig": string(
                    pattern="^[A-Za-z0-9_-]{86}$",
                    description="base64url Ed25519 signature over JCS(body)",
                ),
                "body": ref("KeySetBody"),
            },
            ("kid", "alg", "sig", "body"),
            description="Signed key set; verify per sibyl.policy_snapshot/1 $defs/key_set",
            **{"x-sibyl-document": "sibyl.policy_snapshot/1#/$defs/key_set"},
        ),
        "KeySetChain": obj(
            {
                "data": array(ref("KeySet"), maxItems=1000),
                "latest_sequence": integer(minimum=0, maximum=9007199254740991),
            },
            ("data", "latest_sequence"),
            description=(
                "Every issued key set with sequence > since, ascending; verify each in order"
                " from the pinned key (B10)"
            ),
        ),
        "KeySetResponse": {
            "oneOf": [ref("KeySet"), ref("KeySetChain")],
            "description": "KeySet without ?since=, KeySetChain with it",
        },
        "KeySetBody": body_obj(
            {
                "sequence": integer(minimum=1, maximum=9007199254740991),
                "issued_at": string(format="date-time"),
                "keys": array(ref("PublishedSigningKey"), minItems=1),
                "next_key": nullable(ref("PublishedSigningKey")),
            },
            ("sequence", "issued_at", "keys", "next_key"),
        ),
        "PublishedSigningKey": body_obj(
            {
                "kid": string(pattern=KID_PATTERN),
                "alg": string(const="Ed25519"),
                "public_key": string(
                    pattern="^[A-Za-z0-9_-]{43}$", description="base64url raw Ed25519 key"
                ),
                "status": enum("active", "retiring"),
                "not_after": string(format="date-time"),
            },
            ("kid", "alg", "public_key"),
        ),
        "IngestEventBatch": body_obj(
            {
                "schema": string(const="sibyl-event/1"),
                "events": array(
                    free_object("sibyl-event/1 event", **{"x-sibyl-document": "sibyl-event/1"}),
                    minItems=1,
                    maxItems=1000,
                ),
            },
            ("schema", "events"),
        ),
        "IngestResponse": obj(
            {
                "schema": string(const="sibyl-ingest-response/1"),
                "batch_id": N_UUID,
                "accepted": integer(minimum=0),
                "rejected": array(
                    obj(
                        {
                            "index": integer(),
                            "event_id": N_UUID,
                            "reason": string(),
                            "detail": string(),
                        },
                        ("index", "reason"),
                    )
                ),
                "warnings": array(string()),
                "replayed": boolean(),
            },
            ("schema", "accepted", "rejected", "replayed"),
        ),
        "OtlpExportResponse": obj(
            {
                "partial_success": obj(
                    {
                        "rejected_spans": integer(),
                        "rejected_log_records": integer(),
                        "error_message": string(),
                    }
                )
            },
            description="OTLP Export*ServiceResponse (JSON form); empty on full success",
        ),
        "OtlpExportRequest": free_object(
            "OTLP ExportTraceServiceRequest / ExportLogsServiceRequest (JSON form)"
        ),
    }


def ops_schemas() -> dict[str, Schema]:
    return {
        **_routing(),
        **_incidents(),
        **_queue(),
        **_alerts(),
        **_reads(),
        **_governance(),
        **_edge(),
    }
