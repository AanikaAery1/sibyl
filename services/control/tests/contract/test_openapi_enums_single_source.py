"""G0: every enum the OpenAPI document shares with ``sibyl_schemas`` renders the schemas set."""

from __future__ import annotations

import enum
from collections.abc import Iterable

import pytest
from sibyl_control.api.contract import load_document
from sibyl_schemas import values as sv

# OpenAPI component name -> the schemas value set it must equal (order included).
SHARED: dict[str, Iterable[enum.Enum]] = {
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
    "ApiKeyScope": [s for s in sv.Scope if s in sv.MACHINE_SCOPES],
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

_SCHEMAS = load_document()["components"]["schemas"]
_ENUMS = {
    name: s["enum"] for name, s in _SCHEMAS.items() if "enum" in s and s.get("type") == "string"
}


@pytest.mark.parametrize("name", sorted(SHARED))
def test_shared_enum_equals_schemas(name: str) -> None:
    assert _ENUMS[name] == [str(m.value) for m in SHARED[name]]


def test_no_api_only_enum_shadows_a_schemas_value_set() -> None:
    schemas_names = {
        n for n, o in vars(sv).items() if isinstance(o, type) and issubclass(o, enum.Enum)
    }
    api_only = set(_ENUMS) - set(SHARED)
    assert not (api_only & schemas_names), "import these from sibyl_schemas.values"
