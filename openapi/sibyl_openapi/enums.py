"""Value sets rendered as OpenAPI enum schemas (DATAMODEL §4.0, API.md §2.2/§11).

Every set that ``sibyl_schemas.values`` defines is imported from it (G0 single source; see
``SCHEMAS_SOURCES``). The remainder are API-surface vocabularies the schemas package does not
carry (action names, membership scopes …); ``test_openapi_enums_single_source`` fails
if one of them appears in ``sibyl_schemas`` without being switched to an import here.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

from sibyl_schemas import values as sv

from .dsl import Schema, enum


def _values(members: Iterable[Enum]) -> tuple[str, ...]:
    return tuple(str(member.value) for member in members)


SCOPES: tuple[str, ...] = _values(sv.Scope)

# M column of API.md §2.2: the only scopes an API key may carry (catalogue order).
KEY_SCOPES: tuple[str, ...] = tuple(s.value for s in sv.Scope if s in sv.MACHINE_SCOPES)

SCHEMAS_SOURCES: dict[str, Iterable[Enum]] = {
    "Lifecycle": sv.Lifecycle,
    "AgentKind": sv.AgentKind,
    "RiskClass": sv.RiskClass,
    "FailMode": sv.FailMode,
    "Band": sv.HealthBand,
    "RoutingStateEnum": sv.RoutingState,
    "TargetKind": sv.TargetKind,
    "TransitionTrigger": sv.TransitionTrigger,
    "ActorKind": sv.ActorKind,
    "AuditActorType": sv.ActorType,
    "FailoverKind": sv.SagaKind,
    "FailoverState": sv.SagaState,
    "FailoverStep": sv.SagaStep,
    "FallbackKind": sv.FallbackKind,
    "ApprovalAction": sv.ApprovalAction,
    "ApprovalState": sv.ApprovalState,
    "ApprovalTimeoutPolicy": sv.ApprovalTimeoutPolicy,
    "ApiKeyStatus": sv.ApiKeyStatus,
    "TenantKeyPurpose": sv.TenantKeyPurpose,
    "TenantKeyState": sv.TenantKeyState,
    "ApiKeyEnv": sv.ApiKeyEnv,
    "Scope": sv.Scope,
    "RoleName": sv.Role,
    "CaptureMode": sv.CaptureMode,
    "HandoffState": sv.HandoffState,
    "HandoffOutcome": sv.HandoffOutcome,
    "Fidelity": sv.Fidelity,
    "FailureMode": sv.FailureMode,
    "AlertState": sv.AlertState,
    "AlertSeverity": sv.AlertSeverity,
    "Verdict": sv.Verdict,
    "ProviderStatusEnum": sv.ProviderStatus,
    "Dialect": sv.Dialect,
    "ErasureState": sv.ErasureState,
    "HoldState": sv.HoldState,
    "KillSwitchState": sv.KillSwitchState,
    "KillScopeKind": sv.KillSwitchScope,
    "EventType": sv.EventType,
    "EventStatus": sv.EventStatus,
    "PayloadKind": sv.PayloadKind,
    "PayloadState": sv.PayloadState,
    "DegradedMode": sv.DegradedMode,
    "PreemptiveMode": sv.PreemptiveMode,
    "Enforcement": sv.IdentityEnforcement,
    "ProbabilityBand": sv.ProbabilityBand,
    "Confidence": sv.Confidence,
    "RecommendedAction": sv.RecommendedAction,
    "MetricGrain": sv.FeatureGrain,
    "AnchorKind": sv.AnchorKind,
    "JobState": sv.JobState,
    "ChainBreakKind": sv.ChainBreakKind,
    "ToolActionEffect": sv.ToolActionEffect,
    "IncidentCreateAction": [a for a in sv.IncidentAction if a in sv.INCIDENT_CREATE_ACTIONS],
    "IncidentActionName": [a for a in sv.IncidentAction if a in sv.INCIDENT_TRANSITION_ACTIONS],
}
"""OpenAPI schema name → the ``sibyl_schemas`` value set it renders."""

_API_ONLY: dict[str, tuple[str, ...]] = {
    "ApiKeyScope": KEY_SCOPES,
    "MembershipScopeKind": ("tenant", "agent_group"),
    "UserStatus": ("invited", "active", "disabled", "deprovisioned"),
    "TenantStatus": ("active", "suspended", "erasing", "erased"),
    "CapturePolicyScope": ("tenant", "agent"),
    "ProviderIncidentState": ("open", "resolved"),
    "ErasureScopeKind": ("tenant", "agent", "subject"),
    "HoldScopeKind": ("tenant", "agent", "incident", "subject"),
    "ExportFormat": ("jsonl", "csv"),
    "NodeKind": ("agent", "tool", "data_source", "model", "provider", "business_process"),
    "AlertActionName": ("ack", "silence", "close"),
    "HandoffActionName": (
        "claim",
        "extend_lock",
        "release_claim",
        "complete",
        "return",
        "reassign",
    ),
    "ErasureActionName": ("approve", "reject", "cancel"),
    "FallbackChainActionName": ("approve", "retire"),
    "FallbackChainStatus": ("draft", "approved", "retired"),
    "LifecycleTarget": ("proposed", "approved", "deployed", "monitored", "retired"),
}
"""API-surface vocabularies with no ``sibyl_schemas`` counterpart."""

_GENERATED = {name: _values(members) for name, members in SCHEMAS_SOURCES.items()}
VALUE_SETS: dict[str, tuple[str, ...]] = {
    name: _GENERATED[name] if name in _GENERATED else _API_ONLY[name]
    for name in (
        "Lifecycle",
        "AgentKind",
        "RiskClass",
        "FailMode",
        "Band",
        "RoutingStateEnum",
        "TargetKind",
        "TransitionTrigger",
        "ActorKind",
        "AuditActorType",
        "FailoverKind",
        "FailoverState",
        "FailoverStep",
        "FallbackKind",
        "ApprovalAction",
        "ApprovalState",
        "ApprovalTimeoutPolicy",
        "ApiKeyStatus",
        "TenantKeyPurpose",
        "TenantKeyState",
        "ApiKeyEnv",
        "ApiKeyScope",
        "Scope",
        "RoleName",
        "MembershipScopeKind",
        "UserStatus",
        "TenantStatus",
        "CaptureMode",
        "CapturePolicyScope",
        "HandoffState",
        "HandoffOutcome",
        "Fidelity",
        "FailureMode",
        "AlertState",
        "AlertSeverity",
        "Verdict",
        "ProviderStatusEnum",
        "ProviderIncidentState",
        "Dialect",
        "ErasureState",
        "ErasureScopeKind",
        "HoldState",
        "HoldScopeKind",
        "KillSwitchState",
        "KillScopeKind",
        "EventType",
        "EventStatus",
        "PayloadKind",
        "PayloadState",
        "AnchorKind",
        "ChainBreakKind",
        "ExportFormat",
        "JobState",
        "DegradedMode",
        "PreemptiveMode",
        "Enforcement",
        "ProbabilityBand",
        "Confidence",
        "RecommendedAction",
        "MetricGrain",
        "NodeKind",
        "IncidentCreateAction",
        "IncidentActionName",
        "AlertActionName",
        "HandoffActionName",
        "ErasureActionName",
        "FallbackChainActionName",
        "FallbackChainStatus",
        "LifecycleTarget",
        "ToolActionEffect",
    )
}

# Value sets the docs leave open; rendered with x-extensible-enum so additions stay additive.
EXTENSIBLE: frozenset[str] = frozenset({"NodeKind", "RecommendedAction"})


def enum_schemas() -> dict[str, Schema]:
    out: dict[str, Schema] = {}
    for name, values in VALUE_SETS.items():
        schema = enum(*values)
        if name in EXTENSIBLE:
            schema["x-extensible-enum"] = True
        out[name] = schema
    return out
