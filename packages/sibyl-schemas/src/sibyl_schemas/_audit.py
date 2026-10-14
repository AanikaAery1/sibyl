"""Audit taxonomy (security-auditor §3 + Step 4/5 additions, chair rulings G0-2, G0-4,
G0-6 and G0-11).

One row per audit action: the actor types allowed to emit it, the resource it names, the
`detail` keys `audit_append()` requires, whether a human must give a reason (†), whether the
row is evidence, and its severity. `services/control` imports this registry and a DB test
diffs it against the seeded `sibyl.audit_action` rows after migrating.

Actor letters in the table: H human, R rule, P policy, S system, A agent, K api_key.
Every API-key principal, agent-bound keys included, is recorded as `api_key` with its key id
(G0-6), so every action that allows A also allows K; `agent` stays for compatibility.
`access.denied` records whoever attempted the request (human or api_key) and `system` only
when the request could not be authenticated (G0-11).
Flags: R reason required for a human actor, E evidence row.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from sibyl_schemas._enums import ActorType
from sibyl_schemas._enums_health import AuditSeverity

_ACTOR_LETTERS: Final = MappingProxyType(
    {
        "H": ActorType.HUMAN,
        "R": ActorType.RULE,
        "P": ActorType.POLICY,
        "S": ActorType.SYSTEM,
        "A": ActorType.AGENT,
        "K": ActorType.API_KEY,
    }
)


@dataclass(frozen=True, slots=True)
class AuditActionSpec:
    name: str
    domain: str
    actor_types: frozenset[ActorType]
    resource_type: str
    required_fields: tuple[str, ...]
    reason_required: bool
    is_evidence: bool
    severity: AuditSeverity


def _a(
    name: str,
    domain: str,
    actors: str,
    resource_type: str,
    fields: str,
    flags: str,
    severity: AuditSeverity,
) -> AuditActionSpec:
    return AuditActionSpec(
        name=name,
        domain=domain,
        actor_types=frozenset(_ACTOR_LETTERS[letter] for letter in actors),
        resource_type=resource_type,
        required_fields=tuple(fields.split()),
        reason_required="R" in flags,
        is_evidence="E" in flags,
        severity=severity,
    )


_INFO = AuditSeverity.INFO
_NOTICE = AuditSeverity.NOTICE
_WARNING = AuditSeverity.WARNING
_CRITICAL = AuditSeverity.CRITICAL

_ROWS: Final = (
    _a("audit.genesis", "audit", "S", "tenant", "chain_version", "E", _INFO),
    _a("audit.anchored", "audit", "S", "audit_anchor", "anchor_id seq_from seq_to kid", "E", _INFO),
    _a("audit.verified", "audit", "HS", "tenant", "from_seq to_seq anchors_checked", "E", _INFO),
    _a("audit.verify_failed", "audit", "HS", "tenant", "first_break_seq kind", "E", _CRITICAL),
    _a(
        "audit.exported",
        "audit",
        "HK",
        "tenant",
        "from_seq to_seq export_sha256 format",
        "E",
        _NOTICE,
    ),
    # G0-12 (a): audit.exported is written at request time (export_sha256 null); the worker
    # records the finished object with its digest and the anchor it was cut at.
    _a(
        "audit.export_completed",
        "audit",
        "S",
        "tenant",
        "export_sha256 anchor_id",
        "E",
        _NOTICE,
    ),
    _a(
        "audit.partition_sealed",
        "audit",
        "S",
        "audit_partition",
        "partition seq_from seq_to export_ref anchor_id",
        "E",
        _INFO,
    ),
    _a("tenant.created", "tenant", "SH", "tenant", "slug residency_region", "RE", _NOTICE),
    _a("tenant.suspended", "tenant", "SH", "tenant", "slug residency_region", "RE", _NOTICE),
    _a("tenant.reinstated", "tenant", "SH", "tenant", "slug residency_region", "RE", _NOTICE),
    _a("config.changed", "tenant", "H", "tenant", "field before after", "RE", _NOTICE),
    _a(
        "residency.warning",
        "policy",
        "P",
        "agent",
        "declared_region provider_region provider_id",
        "E",
        _WARNING,
    ),
    _a(
        "asset.discovered",
        "registry",
        "SK",
        "agent",
        "slug api_key_id default_fail_mode",
        "E",
        _NOTICE,
    ),
    _a("asset.created", "registry", "HAK", "agent", "fields_changed profile_hash", "E", _INFO),
    _a("asset.updated", "registry", "HAK", "agent", "fields_changed profile_hash", "E", _INFO),
    _a(
        "asset.approved",
        "registry",
        "H",
        "agent",
        "lifecycle_from lifecycle_to approval_ref",
        "RE",
        _NOTICE,
    ),
    _a("asset.retired", "registry", "H", "agent", "lifecycle_from", "RE", _NOTICE),
    _a(
        "agent_identity.changed",
        "registry",
        "H",
        "agent_identity",
        "identity_version added removed widened",
        "RE",
        _WARNING,
    ),
    _a(
        "snapshot.issued",
        "policy",
        "S",
        "policy_snapshot",
        "version snapshot_sha256 kid expires_at agents_count",
        "E",
        _INFO,
    ),
    _a(
        "snapshot.rejected",
        "policy",
        "S",
        "gateway",
        "gateway_id offered_version held_version cause",
        "E",
        _CRITICAL,
    ),
    _a(
        "policy.violated",
        "policy",
        "P",
        "agent",
        "rule tool_or_model allowed_hash span_id enforcement",
        "E",
        _WARNING,
    ),
    _a("policy.blocked", "policy", "P", "agent", "rule span_id", "E", _WARNING),
    _a(
        "policy.stale_bypass",
        "policy",
        "S",
        "agent",
        "window_start window_end calls snapshot_version age_s",
        "E",
        _WARNING,
    ),
    _a(
        "policy.fail_closed_block",
        "policy",
        "S",
        "agent",
        "window_start window_end calls_refused",
        "E",
        _WARNING,
    ),
    _a("policy.no_snapshot_refusal", "policy", "S", "gateway", "gateway_id since", "E", _CRITICAL),
    _a(
        "route.changed",
        "routing",
        "RPSH",
        "agent",
        "transition_id from_target to_target trigger",
        "RE",
        _NOTICE,
    ),
    _a(
        "failover.proposed",
        "routing",
        "R",
        "agent",
        "transition_id rules evidence_hashes risk approval_id",
        "E",
        _NOTICE,
    ),
    _a(
        "failover.started",
        "routing",
        "RS",
        "agent",
        "transition_id to_target steps_ok",
        "E",
        _NOTICE,
    ),
    _a(
        "failover.completed",
        "routing",
        "RSH",
        "agent",
        "transition_id to_target steps_ok",
        "E",
        _NOTICE,
    ),
    _a("failover.rolled_back", "routing", "RSH", "agent", "transition_id cause", "E", _WARNING),
    _a(
        "failover.undone",
        "routing",
        "H",
        "agent",
        "undo_of_transition_id operator_hold_until",
        "RE",
        _NOTICE,
    ),
    _a("failback.started", "routing", "RH", "agent", "transition_id canary_pct", "E", _INFO),
    _a("failback.completed", "routing", "RS", "agent", "transition_id canary_pct", "E", _INFO),
    _a(
        "quarantine.applied",
        "routing",
        "RPH",
        "agent",
        "cause policy_violation_ids",
        "RE",
        _WARNING,
    ),
    _a("quarantine.released", "routing", "H", "agent", "quarantined_for_s", "RE", _NOTICE),
    _a(
        "preemptive.breaker_tripped",
        "routing",
        "S",
        "agent",
        "agent_id trips window_s",
        "E",
        _WARNING,
    ),
    _a("preemptive.breaker_cleared", "routing", "H", "agent", "agent_id tripped_at", "RE", _NOTICE),
    _a(
        "approval.requested",
        "approval",
        "RH",
        "approval",
        "approval_id agent_id risk action requested_by_actor timeout_policy expires_at",
        "E",
        _NOTICE,
    ),
    _a(
        "approval.granted",
        "approval",
        "H",
        "approval",
        "approval_id agent_id decided_by decision_session_id elapsed_s",
        "RE",
        _NOTICE,
    ),
    _a(
        "approval.denied",
        "approval",
        "H",
        "approval",
        "approval_id agent_id decided_by decision_session_id elapsed_s",
        "RE",
        _NOTICE,
    ),
    _a(
        "approval.expired",
        "approval",
        "S",
        "approval",
        "approval_id timeout_policy_applied",
        "E",
        _WARNING,
    ),
    _a(
        "override.by_human",
        "routing",
        "H",
        "agent",
        "agent_id from_state to_state prev_target new_target transition_id"
        " automated_decision_overridden",
        "RE",
        _WARNING,
    ),
    _a(
        "handoff.created",
        "handoff",
        "RASHK",
        "handoff_task",
        "task_id packet_sha256 fidelity trigger",
        "E",
        _NOTICE,
    ),
    _a(
        "handoff.claimed",
        "handoff",
        "HS",
        "handoff_task",
        "task_id operator_id outcome",
        "E",
        _INFO,
    ),
    _a(
        "handoff.completed",
        "handoff",
        "HS",
        "handoff_task",
        "task_id operator_id outcome",
        "E",
        _INFO,
    ),
    _a(
        "handoff.returned",
        "handoff",
        "HS",
        "handoff_task",
        "task_id operator_id outcome",
        "E",
        _INFO,
    ),
    _a(
        "handoff.reassigned",
        "handoff",
        "HS",
        "handoff_task",
        "task_id operator_id outcome",
        "E",
        _INFO,
    ),
    _a("handoff.expired", "handoff", "S", "handoff_task", "task_id ttl_s", "E", _WARNING),
    _a("handoff.lock_extended", "handoff", "HS", "handoff_task", "task_id", "", _INFO),
    _a("handoff.claim_released", "handoff", "HS", "handoff_task", "task_id", "E", _INFO),
    _a("alert.fired", "alert", "R", "alert", "alert_id rules severity scope", "E", _WARNING),
    _a("alert.acked", "alert", "H", "alert", "alert_id", "", _INFO),
    _a("alert.labelled", "alert", "H", "alert", "alert_id", "", _INFO),
    _a("alert.silenced", "alert", "H", "alert", "alert_id", "", _INFO),
    _a(
        "capture.policy_set",
        "policy",
        "H",
        "capture_policy",
        "capture_mode retention_days redaction_profile_hash previous_version scope",
        "RE",
        _NOTICE,
    ),
    _a(
        "redaction.profile_created",
        "policy",
        "HS",
        "redaction_profile",
        "profile_id version content_hash",
        "E",
        _INFO,
    ),
    _a(
        "retention.partition_dropped",
        "lifecycle",
        "S",
        "partition",
        "table partition rows anchor_id",
        "E",
        _INFO,
    ),
    _a(
        "retention.objects_swept",
        "lifecycle",
        "S",
        "tenant",
        "date_prefix objects bytes holds_skipped",
        "E",
        _INFO,
    ),
    _a("user.provisioned", "identity", "HS", "app_user", "user_id issuer_id via", "E", _NOTICE),
    _a("user.disabled", "identity", "HS", "app_user", "user_id issuer_id via", "E", _NOTICE),
    _a("user.deprovisioned", "identity", "HS", "app_user", "user_id issuer_id via", "E", _NOTICE),
    _a(
        "membership.granted",
        "identity",
        "HS",
        "membership",
        "user_id role scope_kind scope_id",
        "RE",
        _NOTICE,
    ),
    _a(
        "membership.revoked",
        "identity",
        "H",
        "membership",
        "user_id role scope_kind scope_id",
        "RE",
        _NOTICE,
    ),
    _a(
        "oidc_issuer.configured",
        "identity",
        "H",
        "oidc_issuer",
        "issuer_url fields_changed",
        "RE",
        _WARNING,
    ),
    _a(
        "oidc_issuer.changed",
        "identity",
        "H",
        "oidc_issuer",
        "issuer_url fields_changed",
        "RE",
        _WARNING,
    ),
    _a(
        "oidc_issuer.disabled",
        "identity",
        "H",
        "oidc_issuer",
        "issuer_url fields_changed",
        "RE",
        _WARNING,
    ),
    _a("access.login", "access", "H", "session", "session_id issuer_id amr", "E", _INFO),
    _a("access.login_failed", "access", "S", "tenant", "issuer_id cause ip_hash", "E", _NOTICE),
    _a("access.logout", "access", "HS", "session", "session_id cause", "", _INFO),
    _a("session.revoked", "access", "HS", "session", "session_id cause", "", _INFO),
    _a(
        "access.denied",
        "access",
        "SHK",
        "any",
        "permission resource_type resource_id",
        "E",
        _NOTICE,
    ),
    _a("access.step_up", "access", "H", "session", "session_id for_action", "E", _INFO),
    _a(  # B21: key-initiated break-glass records the key (api_key); system for the worker
        "access.break_glass",
        "access",
        "SK",
        "kill_switch",
        "api_key_id action_taken scope_kind scope_id ip_hash",
        "E",
        _CRITICAL,
    ),
    _a(
        "api_key.created",
        "identity",
        "HS",
        "api_key",
        "key_id prefix scopes agent_id grace_until",
        "RE",
        _NOTICE,
    ),
    _a(
        "api_key.rotated",
        "identity",
        "HS",
        "api_key",
        "key_id prefix scopes agent_id grace_until",
        "RE",
        _NOTICE,
    ),
    _a(
        "api_key.revoked",
        "identity",
        "HS",
        "api_key",
        "key_id prefix scopes agent_id grace_until",
        "RE",
        _NOTICE,
    ),
    _a(
        "api_key.expired",
        "identity",
        "HS",
        "api_key",
        "key_id prefix scopes agent_id grace_until",
        "RE",
        _NOTICE,
    ),
    _a(
        "api_key.anomaly",
        "identity",
        "R",
        "api_key",
        "key_id prior_ip_class new_ip_class",
        "E",
        _WARNING,
    ),
    _a(
        "credential.created",
        "security",
        "HS",
        "provider_credential",
        "credential_id provider_id base_url allowlist_basis key_version",
        "RE",
        _NOTICE,
    ),
    _a(
        "credential.rotated",
        "security",
        "HS",
        "provider_credential",
        "credential_id provider_id base_url allowlist_basis key_version",
        "RE",
        _NOTICE,
    ),
    _a(
        "credential.revoked",
        "security",
        "HS",
        "provider_credential",
        "credential_id provider_id base_url allowlist_basis key_version",
        "RE",
        _NOTICE,
    ),
    _a(
        "credential.verified",
        "security",
        "HS",
        "provider_credential",
        "credential_id provider_id base_url allowlist_basis key_version",
        "RE",
        _NOTICE,
    ),
    _a(
        "credential.bundle_issued",
        "security",
        "SAK",
        "provider_credential",
        "credential_ids",
        "E",
        _INFO,
    ),
    _a(
        "credential.probe_failed",
        "security",
        "S",
        "provider_credential",
        "credential_id http_status",
        "E",
        _WARNING,
    ),
    _a(
        "tenant_key.created",
        "security",
        "SH",
        "tenant_key",
        "key_id purpose version kek_id",
        "E",
        _NOTICE,
    ),
    _a(
        "tenant_key.rotated",
        "security",
        "SH",
        "tenant_key",
        "key_id purpose version kek_id",
        "E",
        _NOTICE,
    ),
    _a(
        "tenant_key.retired",
        "security",
        "SH",
        "tenant_key",
        "key_id purpose version kek_id",
        "E",
        _NOTICE,
    ),
    _a(
        "tenant_key.shredded",
        "security",
        "S",
        "tenant_key",
        "key_id purpose version erasure_request_id",
        "E",
        _CRITICAL,
    ),
    _a(
        "kek.rotated", "security", "S", "kek", "old_kek_id new_kek_id keys_rewrapped", "E", _WARNING
    ),
    _a("signing_key.activated", "security", "S", "signing_key", "kid purpose", "E", _NOTICE),
    _a("signing_key.retired", "security", "S", "signing_key", "kid purpose", "E", _NOTICE),
    _a(
        "signing_key.compromised",
        "security",
        "H",
        "signing_key",
        "kid successor_kid reanchor_from_seq",
        "RE",
        _CRITICAL,
    ),
    _a(
        "killswitch.pulled",
        "killswitch",
        "HK",
        "kill_switch",
        "scope_kind scope_id snapshot_version session_id",
        "RE",
        _CRITICAL,
    ),
    _a(
        "killswitch.applied",
        "killswitch",
        "SK",  # lane S: the gateway key that applied it acts as api_key (G0-6)
        "kill_switch",
        "gateway_id snapshot_version applied_at",
        "E",
        _INFO,
    ),
    _a(
        "killswitch.released",
        "killswitch",
        "H",
        "kill_switch",
        "scope_kind scope_id killed_for_s",
        "RE",
        _WARNING,
    ),
    _a(
        "hold.placed",
        "lifecycle",
        "HS",
        "legal_hold",
        "hold_id scope_kind scope_ref incident_id expires_at",
        "RE",
        _NOTICE,
    ),
    _a(
        "hold.released",
        "lifecycle",
        "HS",
        "legal_hold",
        "hold_id scope_kind scope_ref incident_id expires_at",
        "RE",
        _NOTICE,
    ),
    _a(
        "erasure.requested",
        "lifecycle",
        "HS",
        "erasure_request",
        "request_id scope_kind legal_basis",
        "E",
        _NOTICE,
    ),
    _a(
        "erasure.approved",
        "lifecycle",
        "H",
        "erasure_request",
        "request_id approver_id",
        "RE",
        _WARNING,
    ),
    _a(
        "erasure.rejected",
        "lifecycle",
        "H",
        "erasure_request",
        "request_id approver_id",
        "RE",
        _WARNING,
    ),
    _a("erasure.cancelled", "lifecycle", "HS", "erasure_request", "request_id", "RE", _WARNING),
    _a(
        "erasure.blocked_by_hold",
        "lifecycle",
        "SHK",  # G0-12 (b): the api writes it for the requesting principal, the worker as system
        "erasure_request",
        "request_id hold_ids",
        "E",
        _WARNING,
    ),
    _a(
        "erasure.keys_shredded",
        "lifecycle",
        "S",
        "erasure_request",
        "request_id counts",
        "E",
        _WARNING,
    ),
    _a(
        "erasure.objects_deleted",
        "lifecycle",
        "S",
        "erasure_request",
        "request_id counts",
        "E",
        _WARNING,
    ),
    _a(
        "erasure.derived_purged",
        "lifecycle",
        "S",
        "erasure_request",
        "request_id counts",
        "E",
        _WARNING,
    ),
    _a(
        "erasure.completed",
        "lifecycle",
        "S",
        "erasure_request",
        "request_id certificate_sha256 anchor_id backups_expire_at",
        "E",
        _CRITICAL,
    ),
    _a(
        "erasure.reshredded_after_restore",
        "lifecycle",
        "S",
        "tenant",
        "erasure_request_id keys_shredded restore_ref",
        "E",
        _CRITICAL,
    ),
    _a(
        "data.revealed",
        "data",
        "H",
        "payload_ref",
        "payload_ref payload_sha256 agent_id reveal_reason",
        "E",
        _NOTICE,
    ),
    _a(
        "data.exported",
        "data",
        "H",
        "tenant",
        "export_kind filter_hash rows export_sha256",
        "RE",
        _NOTICE,
    ),
    _a(
        "observation.gap",
        "telemetry",
        "S",
        "agent",
        "gateway_id last_heartbeat gap_s",
        "E",
        _WARNING,
    ),
    _a(
        "observation.gap_closed",
        "telemetry",
        "S",
        "agent",
        "gateway_id gap_s spilled_events",
        "E",
        _INFO,
    ),
    _a("telemetry.dropped", "telemetry", "S", "gateway", "gateway_id dropped cause", "E", _WARNING),
    _a("ingest.rejected", "telemetry", "S", "tenant", "cause count window", "", _NOTICE),
    _a("rollup.backfill", "ml", "SH", "rollup_job", "job_id grains range", "E", _INFO),
    _a(
        "scoring_config.activated",
        "ml",
        "HS",
        "scoring_config",
        "scoring_config_id config_sha256 version_no",
        "E",
        _NOTICE,
    ),
    _a("ml_model.promoted", "ml", "H", "ml_model", "model_id version horizon_s", "RE", _NOTICE),
    _a("ml_model.demoted", "ml", "HS", "ml_model", "model_id version cause", "E", _WARNING),
    # D48 Action Gate (ACTION-GATE.md §3). Enforcement points act through API keys (K); a human
    # decides a hold (H); the worker expires it (S). `action.allowed` is sampled except for
    # sensitive tools; blocked, escalated and every decision are always written.
    _a(
        "action.allowed",
        "action",
        "K",
        "agent",
        "agent_id tool call_id policy_id rule_id sampled",
        "E",
        _INFO,
    ),
    _a(
        "action.blocked",
        "action",
        "K",
        "agent",
        "agent_id tool call_id policy_id rule_id",
        "E",
        _WARNING,
    ),
    _a(
        "action.escalated",
        "action",
        "K",
        "agent",
        "agent_id tool call_id policy_id rule_id held_action_id",
        "E",
        _NOTICE,
    ),
    _a(
        "action.approved",
        "action",
        "H",
        "held_action",
        "held_action_id agent_id tool decided_by decision_session_id approvals approvals_required"
        " elapsed_s",
        "RE",
        _NOTICE,
    ),
    _a(
        "action.denied",
        "action",
        "H",
        "held_action",
        "held_action_id agent_id tool decided_by decision_session_id elapsed_s",
        "RE",
        _NOTICE,
    ),
    _a(
        "action.expired",
        "action",
        "S",
        "held_action",
        "held_action_id agent_id tool hold_timeout_s decision",
        "E",
        _WARNING,
    ),
    _a(
        "action_policy.created",
        "action",
        "H",
        "action_policy",
        "policy_id version_no scope_kind scope_id document_sha256",
        "RE",
        _NOTICE,
    ),
    _a(
        "action_policy.approved",
        "action",
        "H",
        "action_policy",
        "policy_id version_no approved_by four_eyes supersedes document_sha256",
        "RE",
        _NOTICE,
    ),
    _a(
        "action_policy.retired",
        "action",
        "H",
        "action_policy",
        "policy_id version_no",
        "RE",
        _NOTICE,
    ),
    # Model drift (D51): a human resets or re-freezes an agent's drift baselines.
    _a(
        "drift.baseline_reset",
        "drift",
        "H",
        "agent",
        "agent_id superseded new_baselines since",
        "RE",
        _NOTICE,
    ),
    # Wave 4 HARDEN: a human replaces the tenant's drift threshold overrides (before / after are
    # the eight nullable overrides; null = deployment default).
    _a(
        "drift.thresholds_updated",
        "drift",
        "H",
        "drift_thresholds",
        "before after",
        "RE",
        _NOTICE,
    ),
    # D52 Sibyl Sentinel (advisory). A human configures and tests it and rates findings (H); the
    # worker writes scheduled findings and records an exhausted daily budget (S); an on-demand
    # explain is written in the requesting human's name (H). Money is a decimal string.
    _a(
        "sentinel.config_changed",
        "sentinel",
        "H",
        "sentinel_config",
        "enabled provider model tasks daily_budget_usd sampling_rate credential_changed",
        "RE",
        _NOTICE,
    ),
    _a(
        "sentinel.config_tested",
        "sentinel",
        "H",
        "sentinel_config",
        "provider model ok http_status",
        "E",
        _INFO,
    ),
    _a(
        "sentinel.finding_created",
        "sentinel",
        "HS",
        "sentinel_finding",
        "finding_id kind subject_kind provider model prompt_sha256 tokens_in tokens_out cost_usd"
        " trigger",
        "E",
        _INFO,
    ),
    _a(
        "sentinel.feedback_recorded",
        "sentinel",
        "H",
        "sentinel_finding",
        "finding_id feedback",
        "E",
        _INFO,
    ),
    _a(
        "sentinel.budget_exhausted",
        "sentinel",
        "HS",
        "sentinel_config",
        "day spent_usd daily_budget_usd",
        "E",
        _WARNING,
    ),
    # D53 external monitors. A human registers, updates and revokes a monitor (H) and tests a
    # webhook (H); a monitor key submits findings (K); a human rates an external finding (H);
    # the worker records a delivery that was dead-lettered (S).
    _a(
        "monitor.registered",
        "monitor",
        "H",
        "monitor",
        "monitor_id name kind all_groups group_ids",
        "RE",
        _NOTICE,
    ),
    _a("monitor.updated", "monitor", "H", "monitor", "monitor_id change", "RE", _NOTICE),
    _a(
        "monitor.revoked",
        "monitor",
        "H",
        "monitor",
        "monitor_id keys_revoked webhooks_disabled",
        "RE",
        _WARNING,
    ),
    _a(
        "finding.submitted",
        "monitor",
        "K",
        "external_finding",
        "finding_id monitor_id kind subject_kind severity",
        "E",
        _INFO,
    ),
    _a(
        "finding.feedback_recorded",
        "monitor",
        "H",
        "external_finding",
        "finding_id feedback",
        "E",
        _INFO,
    ),
    _a(
        "webhook.tested",
        "monitor",
        "H",
        "monitor_webhook",
        "monitor_id webhook_id ok http_status",
        "E",
        _INFO,
    ),
    _a(
        "webhook.delivery_failed",
        "monitor",
        "S",
        "monitor_webhook",
        "monitor_id webhook_id event_type attempts http_status error",
        "E",
        _WARNING,
    ),
    # Wave 3 PLUG (D50): an agent first seen in telemetry is registered `discovered` (never
    # routed or gated until an admin confirms it with POST /agents/{id}/claim).
    _a(
        "agent.discovered",
        "registry",
        "SK",
        "agent",
        "slug api_key_id default_fail_mode discovered_via",
        "E",
        _NOTICE,
    ),
)

AUDIT_ACTIONS: Final[Mapping[str, AuditActionSpec]] = MappingProxyType(
    {row.name: row for row in _ROWS}
)
"""Every declared audit action, by name (`audit_append()` refuses anything else)."""

AUDIT_ACTION_NAMES: Final = frozenset(AUDIT_ACTIONS)


AUDIT_CONTENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "prompt",
        "completion",
        "messages",
        "body",
        "content",
        "headers",
        "input",
        "output",
        "input_messages",
        "output_messages",
    }
)
"""Object member names that mark captured content (G0 code review M4).

Audit `detail` and event `attrs` carry references, never content: a member with one of these
names (compared lowercased, at any depth) is refused. Union of the kernel's list (`input`,
`output`) and the database CHECK lists (`input_messages`, `output_messages`); the kernel and
the migrations derive their copies from this set and a drift test holds them together.
"""

AUDIT_HASH_ONLY_KEYS: Final[frozenset[str]] = frozenset({"content_hashes"})
"""Member names whose value is a set of content *digests*, not content (INT-1 item 4).

`sibyl-event/1` carries `content_hashes: {input, output, system}` (SHA-256 of the captured
parts). A member with one of these names (compared lowercased) is exempt from the
`AUDIT_CONTENT_KEYS` denylist only when its value is a flat object whose every value is a
lowercase-hex SHA-256 string, so content cannot hide under it. The database's
`sibyl.audit_hash_only_keys()` / `sibyl.is_hash_only()` mirror this and a drift test holds them
together.
"""

_SHA256_HEX: Final = re.compile(r"[0-9a-f]{64}")


def is_hash_only_subtree(key: object, value: object) -> bool:
    """`key: value` is a digest map exempt from the content-key denylist (see above)."""
    if str(key).lower() not in AUDIT_HASH_ONLY_KEYS or not isinstance(value, Mapping):
        return False
    return all(isinstance(v, str) and _SHA256_HEX.fullmatch(v) for v in value.values())
