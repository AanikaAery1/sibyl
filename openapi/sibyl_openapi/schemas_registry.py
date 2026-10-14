"""Registry, graph, providers, credentials and policy schemas (API.md §5.4-§5.6)."""

from __future__ import annotations

from sibyl_schemas import values as sv

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

SLUG = ref("Slug")
DISCOVERED_VIA: Schema = {
    "type": ["string", "null"],
    "enum": [*(str(v.value) for v in sv.DiscoveredVia), None],
    "description": "How ingest first saw the agent; null for an agent registered via the API",
}
FIRST_TRACE: Schema = {
    "type": ["string", "null"],
    "pattern": "^[0-9a-f]{32}$",
    "description": "Trace of the first telemetry that named a discovered agent",
}
TAGS = array(string(maxLength=64), maxItems=32)
HTTPS_URL = string(format="uri", maxLength=2048)


def _agent_create_props() -> dict[str, Schema]:
    return {
        "slug": SLUG,
        "name": string(minLength=1, maxLength=120),
        "description": string(maxLength=2000),
        "kind": ref("AgentKind"),
        "framework": string(maxLength=60),
        "tier": integer(minimum=1, maximum=3, default=3),
        "risk_class": ref("RiskClass"),
        "fail_mode": ref("FailMode"),
        "agent_group_id": UUID,
        "owner_user_id": UUID,
        "business_process_id": UUID,
        "cost_center": string(maxLength=60),
        "tags": TAGS,
        "version": ref("AgentVersionCreate"),
    }


def _agents() -> dict[str, Schema]:
    summary_props: dict[str, Schema] = {
        "id": ro(UUID),
        "slug": string(),
        "name": string(),
        "kind": ref("AgentKind"),
        "tier": integer(minimum=1, maximum=3),
        "risk_class": ref("RiskClass"),
        "lifecycle": ref("Lifecycle"),
        "fail_mode": ref("FailMode"),
        "is_provisional": boolean(
            description="Discovered from telemetry and not yet confirmed (never routed or gated)"
        ),
        "discovered_via": ro(DISCOVERED_VIA),
        "first_trace_id": ro(FIRST_TRACE),
        "confirmed_at": ro(
            {**N_TS, "description": "When an admin confirmed it (POST /agents/{id}/claim)"}
        ),
        "agent_group_id": N_UUID,
        "routing": obj(
            {
                "state": ref("RoutingStateEnum"),
                "target_kind": ref("TargetKind"),
                "operator_hold_until": N_TS,
            }
        ),
        "health": obj(
            {
                "band": nullable(ref("Band")),
                "score": {"type": ["integer", "null"], "minimum": 0, "maximum": 100},
                "provisional": boolean(),
                "evaluated_at": N_TS,
            },
            description="From the latest health_snapshot; nulls before the first tick",
        ),
        "continuity": obj({"rto_s": integer(), "has_plan": boolean()}),
    }
    agent_props: dict[str, Schema] = {
        **summary_props,
        "description": {"type": ["string", "null"]},
        "framework": {"type": ["string", "null"]},
        "owner_user_id": N_UUID,
        "business_process_id": N_UUID,
        "cost_center": {"type": ["string", "null"]},
        "tags": array(string()),
        "current_version": nullable(ref("AgentVersion")),
        "identity": nullable(ref("AgentIdentity")),
        "continuity_plan_etag": {"type": ["string", "null"]},
        "created_at": ro(TS),
        "updated_at": ro(TS),
    }
    patch = {k: v for k, v in _agent_create_props().items() if k not in {"slug", "version"}}
    for nullable_fk in ("agent_group_id", "owner_user_id", "business_process_id"):
        patch[nullable_fk] = N_UUID
    summary_required = (
        "id",
        "slug",
        "name",
        "kind",
        "tier",
        "lifecycle",
        "fail_mode",
        "is_provisional",
        "routing",
        "health",
    )
    return {
        "AgentSummary": obj(summary_props, summary_required),
        "Agent": obj(agent_props, summary_required),
        "AgentCreate": body_obj(_agent_create_props(), ("slug", "name", "kind", "fail_mode")),
        "AgentPatch": body_obj(patch, minProperties=1),
        "LifecycleChange": body_obj(
            {"to_stage": ref("LifecycleTarget"), "reason": REASON}, ("to_stage", "reason")
        ),
        "LifecycleView": obj(
            {
                "agent_id": UUID,
                "lifecycle": ref("Lifecycle"),
                "transitions": array(
                    obj(
                        {
                            "id": UUID,
                            "from_stage": nullable(ref("Lifecycle")),
                            "to_stage": ref("Lifecycle"),
                            "actor_user_id": N_UUID,
                            "reason": {"type": ["string", "null"]},
                            "audit_seq": integer(format="int64"),
                            "created_at": TS,
                        }
                    )
                ),
            },
            ("agent_id", "lifecycle", "transitions"),
        ),
        "AgentIdentity": obj(
            {
                "agent_id": ro(UUID),
                "allowed_tools": array(string()),
                "allowed_models": array(string()),
                "allowed_providers": array(string()),
                "enforcement": ref("Enforcement"),
                "identity_version": ro(integer(format="int64")),
                "tools_hash": ro(ref("Sha256Hex")),
            },
            ("allowed_tools", "allowed_models", "allowed_providers", "enforcement"),
        ),
        "AgentIdentityPut": body_obj(
            {
                "allowed_tools": array(string(maxLength=200), maxItems=500),
                "allowed_models": array(string(maxLength=200), maxItems=200),
                "allowed_providers": array(string(maxLength=200), maxItems=50),
                "enforcement": ref("Enforcement"),
                "reason": REASON,
            },
            ("allowed_tools", "allowed_models", "allowed_providers", "enforcement"),
        ),
        "AgentVersionCreate": body_obj(
            {
                "primary_model_id": UUID,
                "config": free_object("agent config, <= 4 KB"),
                "prompt": string(
                    maxLength=262144, description="stored as payload_refs kind=prompt"
                ),
                "prompt_sha256": ref("Sha256Hex"),
                "declared_tool_ids": array(UUID, maxItems=500),
                "declared_data_source_ids": array(UUID, maxItems=500),
            },
            ("primary_model_id",),
        ),
        "AgentVersion": obj(
            {
                "id": ro(UUID),
                "agent_id": UUID,
                "version_no": integer(minimum=1),
                "primary_model_id": UUID,
                "prompt_sha256": {"type": ["string", "null"]},
                "prompt_ref_id": N_UUID,
                "config": free_object("agent config"),
                "declared_tool_ids": array(UUID),
                "declared_data_source_ids": array(UUID),
                "source": string(),
                "created_at": ro(TS),
            },
            ("id", "agent_id", "version_no", "primary_model_id"),
        ),
        "AiBom": obj(
            {
                "agent_id": UUID,
                "version_no": integer(),
                "bom_sha256": ref("Sha256Hex"),
                "spec_version": string(const="1.6"),
                "generated_at": TS,
                "document": free_object("CycloneDX 1.6 JSON"),
            },
            ("agent_id", "version_no", "bom_sha256", "generated_at"),
        ),
    }


def _graph() -> dict[str, Schema]:
    edge_type = string(pattern=r"^[a-z][a-z_]{2,40}$", examples=["reads_data", "writes_data"])
    return {
        "DependencyEdge": obj(
            {
                "id": ro(UUID),
                "src_kind": ref("NodeKind"),
                "src_id": UUID,
                "dst_kind": ref("NodeKind"),
                "dst_id": UUID,
                "edge_type": edge_type,
                "origin": string(),
                "attrs": free_object("edge attributes"),
                "valid_from": TS,
                "valid_to": N_TS,
            },
            ("id", "src_kind", "src_id", "dst_kind", "dst_id", "edge_type", "valid_from"),
        ),
        "DependencyEdgeCreate": body_obj(
            {
                "src_kind": ref("NodeKind"),
                "src_id": UUID,
                "dst_kind": ref("NodeKind"),
                "dst_id": UUID,
                "edge_type": edge_type,
                "origin": enum("declared", default="declared"),
                "attrs": free_object("edge attributes"),
            },
            ("src_kind", "src_id", "dst_kind", "dst_id", "edge_type"),
        ),
        "BlastRadius": obj(
            {
                "graph_version": integer(format="int64"),
                "affected_agent_ids": array(UUID),
                "affected_process_ids": array(UUID),
                "by_depth": free_object("depth -> node ids"),
            },
            ("graph_version", "affected_agent_ids", "affected_process_ids", "by_depth"),
        ),
    }


def _catalog_entity(name: str, extra: dict[str, Schema], create_required: tuple[str, ...]):
    base = {"id": ro(UUID), "slug": SLUG, "name": string(maxLength=120), **extra}
    writable = {k: v for k, v in base.items() if k != "id"}
    patchable = {k: v for k, v in writable.items() if k != "slug"}
    return {
        name: obj({**base, "created_at": ro(TS)}, ("id", "slug", "name")),
        f"{name}Create": body_obj(writable, ("slug", "name", *create_required)),
        f"{name}Patch": body_obj(patchable, minProperties=1),
    }


def _catalog() -> dict[str, Schema]:
    return {
        **_catalog_entity(
            "Tool",
            {
                "kind": string(maxLength=40),
                "parent_tool_id": N_UUID,
                "endpoint": {"type": ["string", "null"], "maxLength": 2048},
                "permissions": array(string()),
                "is_approved": boolean(description="changing it needs agents:approve"),
            },
            ("kind",),
        ),
        **_catalog_entity(
            "DataSource",
            {
                "kind": string(maxLength=40),
                "classification": string(maxLength=40, examples=["internal", "pii", "restricted"]),
                "residency_region": {"type": ["string", "null"], "maxLength": 32},
                "attrs": free_object("data source attributes"),
            },
            ("kind",),
        ),
        **_catalog_entity(
            "BusinessProcess",
            {"owner_user_id": N_UUID, "criticality": string(maxLength=40)},
            (),
        ),
    }


def _providers() -> dict[str, Schema]:
    return {
        "Provider": obj(
            {
                "id": ro(UUID),
                "slug": SLUG,
                "name": string(),
                "provider_kind": string(),
                "dialect": ref("Dialect"),
                "base_url": HTTPS_URL,
                "status_feed_url": {"type": ["string", "null"], "format": "uri"},
                "allowlist_basis": ro({"type": ["string", "null"]}),
                "is_enabled": boolean(),
                "latest_status": nullable(ref("ProviderStatus")),
            },
            ("id", "slug", "name", "provider_kind", "dialect", "base_url", "is_enabled"),
        ),
        "ProviderCreate": body_obj(
            {
                "slug": SLUG,
                "name": string(maxLength=120),
                "provider_kind": string(maxLength=40),
                "dialect": ref("Dialect"),
                "base_url": HTTPS_URL,
                "status_feed_url": HTTPS_URL,
            },
            ("slug", "name", "provider_kind", "dialect", "base_url"),
        ),
        "ProviderPatch": body_obj(
            {
                "name": string(maxLength=120),
                "base_url": HTTPS_URL,
                "status_feed_url": {"type": ["string", "null"], "format": "uri"},
                "is_enabled": boolean(),
            },
            minProperties=1,
        ),
        "ProviderStatus": obj(
            {
                "provider_id": UUID,
                "status": ref("ProviderStatusEnum"),
                "observed_at": TS,
                "source": string(),
                "detail": {"type": ["string", "null"]},
            },
            ("provider_id", "status", "observed_at"),
        ),
        "Model": obj(
            {
                "id": ro(UUID),
                "provider_id": UUID,
                "model_name": string(),
                "catalog_id": {"type": ["string", "null"]},
                "input_usd_per_1m": nullable(ref("Money")),
                "output_usd_per_1m": nullable(ref("Money")),
                "is_allowed": boolean(),
                "is_discovered": boolean(),
                "context_limit": {"type": ["integer", "null"]},
                "deprecated_on": {"type": ["string", "null"], "format": "date"},
                "retires_on": {"type": ["string", "null"], "format": "date"},
            },
            ("id", "provider_id", "model_name", "is_allowed"),
        ),
        "ModelCreate": body_obj(
            {
                "provider_id": UUID,
                "model_name": string(maxLength=200),
                "catalog_id": string(maxLength=200),
                "input_usd_per_1m": ref("Money"),
                "output_usd_per_1m": ref("Money"),
            },
            ("provider_id", "model_name"),
        ),
        "ModelPatch": body_obj(
            {
                "is_allowed": boolean(),
                "input_usd_per_1m": ref("Money"),
                "output_usd_per_1m": ref("Money"),
                "deprecated_on": {"type": ["string", "null"], "format": "date"},
                "retires_on": {"type": ["string", "null"], "format": "date"},
            },
            minProperties=1,
        ),
        "ModelCatalogEntry": obj(
            {
                "catalog_id": string(),
                "provider_kind": string(),
                "model_name": string(),
                "input_usd_per_1m": ref("Money"),
                "output_usd_per_1m": ref("Money"),
                "context_limit": {"type": ["integer", "null"]},
            },
            ("catalog_id", "provider_kind", "model_name"),
        ),
        "ProviderCredentialMeta": obj(
            {
                "id": ro(UUID),
                "name": string(),
                "provider_id": UUID,
                "purpose": string(),
                "base_url": HTTPS_URL,
                "allowlist_basis": {"type": ["string", "null"]},
                "auth_scheme": string(),
                "secret_hint": string(maxLength=8),
                "status": string(),
                "key_version": integer(),
                "expires_at": N_TS,
                "last_used_at": N_TS,
                "last_verified_at": N_TS,
            },
            ("id", "name", "provider_id", "purpose", "base_url", "status", "key_version"),
            description="Never carries ciphertext, nonce or secret hash.",
        ),
        "ProviderCredentialCreate": body_obj(
            {
                "provider_id": UUID,
                "name": string(maxLength=80),
                "purpose": enum("fallback", default="fallback"),
                "base_url": HTTPS_URL,
                "auth_scheme": string(maxLength=40),
                "secret": string(writeOnly=True, minLength=1, maxLength=8192),
            },
            ("provider_id", "name", "base_url", "auth_scheme", "secret"),
        ),
        "ProviderCredentialRotate": body_obj(
            {
                "secret": string(writeOnly=True, minLength=1, maxLength=8192),
                "grace_s": integer(minimum=0, maximum=86400, default=3600),
            },
            ("secret",),
        ),
    }


def _capture() -> dict[str, Schema]:
    return {
        "CapturePolicy": obj(
            {
                "id": ro(UUID),
                "scope_kind": ref("CapturePolicyScope"),
                "agent_id": N_UUID,
                "capture_mode": ref("CaptureMode"),
                "redaction_profile_id": UUID,
                "payload_retention_days": integer(minimum=1, maximum=365),
                "max_payload_bytes": {"type": ["integer", "null"]},
                "header_allowlist": array(string()),
                "consequences_version": string(),
                "version_no": ro(integer()),
                "superseded_by": ro(N_UUID),
                "created_at": ro(TS),
            },
            ("id", "scope_kind", "capture_mode", "redaction_profile_id", "version_no"),
        ),
        "CapturePolicyCreate": body_obj(
            {
                "scope_kind": ref("CapturePolicyScope"),
                "agent_id": UUID,
                "capture_mode": ref("CaptureMode"),
                "redaction_profile_id": UUID,
                "payload_retention_days": integer(minimum=1, maximum=365),
                "max_payload_bytes": integer(minimum=1),
                "header_allowlist": array(string(maxLength=100), maxItems=64),
                "consequences_version": string(maxLength=40),
                "acknowledged": {"const": True},
            },
            (
                "scope_kind",
                "capture_mode",
                "redaction_profile_id",
                "payload_retention_days",
                "consequences_version",
                "acknowledged",
            ),
        ),
        "EffectiveCapturePolicy": obj(
            {
                "agent_id": N_UUID,
                "policy": ref("CapturePolicy"),
                "redaction_profile": ref("RedactionProfile"),
                "source": enum("tenant", "agent"),
            },
            ("policy", "redaction_profile", "source"),
        ),
        "RedactionProfile": obj(
            {
                "id": ro(UUID),
                "name": string(),
                "detectors": array(string()),
                "replacement_format": string(),
                "content_hash": ro(ref("Sha256Hex")),
                "is_system": ro(boolean()),
                "created_at": ro(TS),
            },
            ("id", "name", "detectors", "content_hash"),
        ),
        "RedactionProfileCreate": body_obj(
            {
                "name": string(maxLength=80),
                "detectors": array(string(maxLength=60), minItems=1, uniqueItems=True),
                "replacement_format": string(maxLength=80),
            },
            ("name", "detectors"),
        ),
    }


def _continuity() -> dict[str, Schema]:
    plan_props: dict[str, Schema] = {
        "rto_s": integer(minimum=1, description="silent -> 900/3600/14400 by tier (D23)"),
        "rpo_s": integer(minimum=0),
        "credential_mode": string(maxLength=40),
        "degraded_mode": ref("DegradedMode"),
        "inline_fallback": boolean(),
        "preemptive_mode": ref("PreemptiveMode"),
        "approval_timeout_s": integer(minimum=30, maximum=86400, default=600),
        "approval_timeout_policy": ref("ApprovalTimeoutPolicy"),
        "fallback_chain_id": N_UUID,
        "on_call_user_id": N_UUID,
        "on_call_ref": {"type": ["string", "null"], "maxLength": 200},
        "budget_usd_month": nullable(ref("Money")),
        "max_inflight": {"type": ["integer", "null"], "minimum": 1},
        "rps_limit": {"type": ["integer", "null"], "minimum": 1},
        "drill_schedule": {"type": ["string", "null"], "maxLength": 100},
        "expected_cadence_s": {
            "type": ["integer", "null"],
            "minimum": 1,
            "description": "expected heartbeat cadence in seconds for the health engine (R9);"
            " null or omitted: none declared",
        },
    }
    step = {
        "kind": ref("FallbackKind"),
        "provider_id": UUID,
        "model_id": UUID,
        "backup_agent_id": UUID,
        "credential_id": UUID,
        "risk": enum("low", "medium", "high"),
        "max_attempts": integer(minimum=1, maximum=10),
        "params": free_object("step parameters"),
    }
    return {
        "ContinuityPlan": obj(
            {
                "agent_id": ro(UUID),
                **plan_props,
                "row_version": ro(integer(format="int64")),
                "updated_at": ro(TS),
            },
            ("agent_id", "rto_s", "degraded_mode", "approval_timeout_policy", "row_version"),
        ),
        "ContinuityPlanPut": body_obj(
            {**plan_props, "reason": REASON}, ("degraded_mode", "approval_timeout_policy")
        ),
        "FallbackStepInput": body_obj(step, ("kind", "risk")),
        "FallbackStep": obj(
            {"id": ro(UUID), "position": integer(), **step, "viable": ro(boolean())},
            ("id", "position", "kind"),
        ),
        "FallbackChain": obj(
            {
                "id": ro(UUID),
                "agent_id": UUID,
                "status": ref("FallbackChainStatus"),
                "steps": array(ref("FallbackStep")),
                "note": {"type": ["string", "null"]},
                "requested_by_user_id": N_UUID,
                "approved_by_user_id": N_UUID,
                "approved_at": N_TS,
                "created_at": ro(TS),
            },
            ("id", "agent_id", "status", "steps"),
        ),
        "FallbackChainCreate": body_obj(
            {
                "steps": array(ref("FallbackStepInput"), minItems=1, maxItems=10),
                "note": string(maxLength=2000),
                "clone_from_chain_id": UUID,
            },
            ("steps",),
        ),
        "FallbackChainPut": body_obj(
            {
                "steps": array(ref("FallbackStepInput"), minItems=1, maxItems=10),
                "note": string(maxLength=2000),
            },
            ("steps",),
        ),
        "FallbackChainAction": body_obj(
            {"action": ref("FallbackChainActionName"), "reason": REASON}, ("action", "reason")
        ),
    }


def _alert_rules() -> dict[str, Schema]:
    tunables: dict[str, Schema] = {
        "thresholds": free_object("rule thresholds per tier"),
        "window_s": integer(minimum=10),
        "min_samples": integer(minimum=0),
        "hysteresis": obj({"in": integer(minimum=1), "out": integer(minimum=1)}),
        "cooldown_s": integer(minimum=0),
        "severity": ref("AlertSeverity"),
        "penalty": integer(minimum=0, maximum=100),
        "horizon_s": {"type": ["integer", "null"], "minimum": 0},
        "tier_applicability": array(integer(minimum=1, maximum=3)),
        "what_to_do_template": string(maxLength=4000),
        "enabled": boolean(),
    }
    code = string(pattern=r"^[a-z][a-z0-9_]{2,40}$")
    return {
        "AlertRule": obj(
            {
                "id": ro(UUID),
                "code": code,
                "kind": enum("detected", "leading", "custom"),
                "scope": string(),
                "origin": enum("seed", "custom"),
                "overridden": ro(boolean()),
                **tunables,
            },
            ("id", "code", "kind", "origin", "enabled"),
        ),
        "AlertRuleCreate": body_obj(
            {"code": code, "kind": enum("custom"), "scope": string(maxLength=40), **tunables},
            ("code", "scope", "severity", "window_s"),
        ),
        "AlertRulePatch": body_obj(tunables, minProperties=1),
    }


def registry_schemas() -> dict[str, Schema]:
    return {
        **_agents(),
        **_graph(),
        **_catalog(),
        **_providers(),
        **_capture(),
        **_continuity(),
        **_alert_rules(),
    }
