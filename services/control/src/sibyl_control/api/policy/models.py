"""Request bodies of the policy module (OpenAPI ``components.schemas``, ``additionalProperties:
false``). Contract enums are ``Literal``; a few fields are deliberately looser than the contract
so the handler can answer with the contract's own problem code (``capture_mode_required``,
``code_pattern``)."""

from __future__ import annotations

from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

MONEY_PATTERN = r"^-?[0-9]+\.[0-9]{4}$"

CaptureMode = Literal["full", "redacted", "metadata"]
DegradedMode = Literal["continue", "safe_no_tools", "queue_only"]
PreemptiveMode = Literal["auto", "degrade_then_auto", "approval"]
TimeoutPolicy = Literal["hold", "fail_safe"]
FallbackKind = Literal[
    "retry",
    "alt_model_same_provider",
    "alt_provider",
    "backup_agent",
    "degraded_safe_mode",
    "human_queue",
]
Severity = Literal["info", "warning", "critical"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


Reason = Annotated[str, StringConstraints(min_length=10, max_length=2000)]


class _Reasoned(_Body):
    """An audited human write: the optional ``reason`` lands on the audit row (else the
    ``X-Sibyl-Reason`` header, else the route label); it is never a column."""

    reason: Reason | None = None


class OptionalReasonBody(_Reasoned):
    """``POST /alert-rules/{id}/reset``: the body is optional and carries only a reason."""


class CapturePolicyCreate(_Reasoned):
    scope_kind: Literal["tenant", "agent"]
    agent_id: UUID | None = None
    capture_mode: CaptureMode | None = None  # absent -> 422 capture_mode_required (D12)
    redaction_profile_id: UUID
    payload_retention_days: int = Field(ge=1, le=365)
    max_payload_bytes: int | None = Field(default=None, ge=1)
    header_allowlist: list[str] = Field(default_factory=list, max_length=64)
    consequences_version: str = Field(max_length=40)
    acknowledged: Literal[True]


class RedactionProfileCreate(_Body):
    name: str = Field(min_length=1, max_length=80)
    detectors: list[str] = Field(min_length=1)
    replacement_format: str | None = Field(default=None, max_length=80)

    @model_validator(mode="after")
    def _unique(self) -> RedactionProfileCreate:
        if len(set(self.detectors)) != len(self.detectors):
            raise ValueError("detectors must be unique")
        if any(len(d) > 60 for d in self.detectors):
            raise ValueError("detector ids are at most 60 characters")
        return self


class ContinuityPlanPut(_Body):
    rto_s: int | None = Field(default=None, ge=1)
    rpo_s: int | None = Field(default=None, ge=0)
    credential_mode: Literal["passthrough", "vaulted_fallback"] = "passthrough"
    degraded_mode: DegradedMode
    inline_fallback: bool | None = None
    preemptive_mode: PreemptiveMode | None = None
    approval_timeout_s: int = Field(default=600, ge=30, le=86400)
    approval_timeout_policy: TimeoutPolicy
    fallback_chain_id: UUID | None = None
    on_call_user_id: UUID | None = None
    on_call_ref: str | None = Field(default=None, max_length=200)
    budget_usd_month: str | None = Field(default=None, pattern=MONEY_PATTERN)
    max_inflight: int | None = Field(default=None, ge=1)
    rps_limit: int | None = Field(default=None, ge=1)
    drill_schedule: str | None = Field(default=None, max_length=100)
    # R9 heartbeat cadence for the health engine (0008 CHECK: NULL or > 0); strict: a JSON
    # integer only, never "60" or 60.5.
    expected_cadence_s: int | None = Field(default=None, gt=0, strict=True)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)


class FallbackStepInput(_Body):
    kind: FallbackKind
    provider_id: UUID | None = None
    model_id: UUID | None = None
    backup_agent_id: UUID | None = None
    credential_id: UUID | None = None
    risk: Literal["low", "medium", "high"]
    max_attempts: int | None = Field(default=None, ge=1, le=10)
    params: dict[str, Any] | None = None


class FallbackChainCreate(_Reasoned):
    steps: list[FallbackStepInput] = Field(min_length=1, max_length=10)
    note: str | None = Field(default=None, max_length=2000)
    clone_from_chain_id: UUID | None = None


class FallbackChainPut(_Reasoned):
    steps: list[FallbackStepInput] = Field(min_length=1, max_length=10)
    note: str | None = Field(default=None, max_length=2000)


class FallbackChainAction(_Body):
    action: Literal["approve", "retire"]
    reason: str = Field(min_length=10, max_length=2000)


class Hysteresis(_Body):
    in_: int | None = Field(default=None, ge=1, alias="in")
    out: int | None = Field(default=None, ge=1)

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class _AlertRuleFields(_Reasoned):
    thresholds: dict[str, Any] | None = None
    window_s: int | None = Field(default=None, ge=10)
    min_samples: int | None = Field(default=None, ge=0)
    hysteresis: Hysteresis | None = None
    cooldown_s: int | None = Field(default=None, ge=0)
    severity: Severity | None = None
    penalty: int | None = Field(default=None, ge=0, le=100)
    horizon_s: int | None = Field(default=None, ge=0)
    tier_applicability: list[int] | None = None
    what_to_do_template: str | None = Field(default=None, max_length=4000)
    enabled: bool | None = None

    @model_validator(mode="after")
    def _tiers(self) -> _AlertRuleFields:
        tiers = self.tier_applicability
        if tiers is not None and (not tiers or any(t not in (1, 2, 3) for t in tiers)):
            raise ValueError("tier_applicability is a non-empty subset of 1, 2, 3")
        return self


class AlertRuleCreate(_AlertRuleFields):
    code: str = Field(max_length=200)  # pattern checked in the handler -> 422 code_pattern
    kind: Literal["custom"] | None = None
    scope: Literal["agent", "provider", "platform"]
    severity: Severity
    window_s: int = Field(ge=10)


class AlertRulePatch(_AlertRuleFields):
    @model_validator(mode="after")
    def _not_empty(self) -> AlertRulePatch:
        if not self.model_fields_set - {"reason"}:
            raise ValueError("at least one property is required")
        return self
