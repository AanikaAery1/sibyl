"""Sibyl Sentinel (D52): the advisory monitoring agent's vocabulary, API bodies and the
structured outputs it asks a language model for.

Sentinel is opt-in per tenant, runs on the tenant's own Anthropic, OpenAI or Gemini key and is
**advisory only**: a finding explains, recommends or flags; it never allows, blocks, approves,
fails over or changes policy. The output models below are what the model must answer with
(JSON-schema structured output where the provider supports it, JSON mode plus validation and
one repair attempt otherwise). They are lenient on length (over-long text is truncated, extra
keys ignored) and strict on shape and enums, because model output is untrusted data.
"""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from sibyl_schemas._enums_sentinel import (
    SentinelFeedback,
    SentinelProvider,
    SentinelSeverity,
    SentinelSubjectKind,
    SentinelTask,
    SentinelTrigger,
)

DEFAULT_ANTHROPIC_MODEL: Final = "claude-fable-5-1"
"""Default Claude model for Sentinel on Anthropic; OpenAI and Gemini need an explicit model."""
MODEL_ID_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
MONEY_PATTERN: Final = r"^[0-9]{1,30}(\.[0-9]{1,18})?$"
MAX_SECRET_CHARS: Final = 4096
MAX_DAILY_BUDGET_USD: Final = Decimal("10000")


FindingKind = SentinelTask
SubjectKind = SentinelSubjectKind
FindingSeverity = SentinelSeverity
FindingFeedback = SentinelFeedback
FindingTrigger = SentinelTrigger


SUBJECT_OF_KIND: Final = {
    SentinelTask.INCIDENT_EXPLANATION: SubjectKind.INCIDENT,
    SentinelTask.HELD_ACTION_REVIEW: SubjectKind.HELD_ACTION,
    SentinelTask.SEMANTIC_DRIFT: SubjectKind.AGENT,
    SentinelTask.FLEET_SUMMARY: SubjectKind.FLEET,
}
DEFAULT_TASKS: Final = tuple(SentinelTask)


# --- API bodies ----------------------------------------------------------------------------


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _money(value: str) -> str:
    try:
        amount = Decimal(value)
    except InvalidOperation:
        raise ValueError("not a decimal amount") from None
    if amount < 0 or amount > MAX_DAILY_BUDGET_USD:
        raise ValueError(f"must be between 0 and {MAX_DAILY_BUDGET_USD}")
    return value


class SentinelConfigPut(_Body):
    """``PUT /sentinel/config``. ``api_key`` is write-only: omitted keeps the vaulted key, a
    value replaces it; it is never echoed, logged or audited."""

    enabled: bool
    provider: SentinelProvider
    model: str | None = Field(default=None, pattern=MODEL_ID_PATTERN)
    api_key: SecretStr | None = None
    base_url: str | None = Field(default=None, min_length=8, max_length=2048)
    daily_budget_usd: str = Field(pattern=MONEY_PATTERN)
    sampling_rate: float = Field(ge=0, le=1)
    tasks: list[SentinelTask] = Field(default_factory=lambda: list(DEFAULT_TASKS), max_length=4)
    price_in_usd_per_mtok: str | None = Field(default=None, pattern=MONEY_PATTERN)
    price_out_usd_per_mtok: str | None = Field(default=None, pattern=MONEY_PATTERN)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)

    _budget = field_validator("daily_budget_usd")(_money)

    @field_validator("api_key")
    @classmethod
    def _secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and not 8 <= len(value.get_secret_value()) <= MAX_SECRET_CHARS:
            raise ValueError(f"api_key must be 8..{MAX_SECRET_CHARS} characters")
        if value is not None and re.search(r"\s", value.get_secret_value()):
            raise ValueError("api_key must not contain whitespace")
        return value

    @model_validator(mode="after")
    def _shape(self) -> SentinelConfigPut:
        if len(set(self.tasks)) != len(self.tasks):
            raise ValueError("tasks must be unique")
        if self.provider is not SentinelProvider.ANTHROPIC and self.model is None:
            raise ValueError(f"model is required for provider {self.provider.value}")
        if (self.price_in_usd_per_mtok is None) != (self.price_out_usd_per_mtok is None):
            raise ValueError("price_in_usd_per_mtok and price_out_usd_per_mtok go together")
        return self

    def resolved_model(self) -> str:
        return self.model or DEFAULT_ANTHROPIC_MODEL


class SentinelFeedbackBody(_Body):
    feedback: FindingFeedback


class SentinelExplainBody(_Body):
    subject_kind: Literal["incident", "held_action"]
    subject_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )


# --- structured model outputs ----------------------------------------------------------------


def _clip(limit: int) -> Any:
    def clip(value: Any) -> Any:
        return value[:limit] if isinstance(value, str) else value

    return BeforeValidator(clip)


def _clip_list(limit: int, item_limit: int) -> Any:
    def clip(value: Any) -> Any:
        if not isinstance(value, list):
            return value
        return [v[:item_limit] if isinstance(v, str) else v for v in value[:limit]]

    return BeforeValidator(clip)


Short = Annotated[str, _clip(600)]
Long = Annotated[str, _clip(2000)]
Points = Annotated[list[str], _clip_list(8, 400)]
Confidence = Literal["low", "medium", "high"]
SeverityOut = Literal["info", "warning", "critical"]


class _Output(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class IncidentExplanation(_Output):
    severity: SeverityOut
    summary: Short
    what_failed: Long
    likely_cause: Long
    what_sibyl_did: Long
    what_to_check: Points
    confidence: Confidence


class HeldActionReview(_Output):
    """A recommendation for the human approver; Sentinel never decides the hold."""

    severity: SeverityOut
    summary: Short
    advice: Literal["approve", "deny", "needs_more_info"]
    reasoning: Long
    risks: Points
    confidence: Confidence


class DriftReview(_Output):
    severity: SeverityOut
    summary: Short
    purpose_drift: bool
    injection_like: bool
    evidence: Points
    recommendation: Long
    confidence: Confidence


class FleetSummary(_Output):
    severity: SeverityOut
    summary: Long
    highlights: Points
    concerns: Points
    recommendation: Long


OUTPUT_MODELS: Final[dict[SentinelTask, type[_Output]]] = {
    SentinelTask.INCIDENT_EXPLANATION: IncidentExplanation,
    SentinelTask.HELD_ACTION_REVIEW: HeldActionReview,
    SentinelTask.SEMANTIC_DRIFT: DriftReview,
    SentinelTask.FLEET_SUMMARY: FleetSummary,
}

_KEEP = frozenset({"type", "properties", "required", "items", "enum", "description"})


def _clean(node: Any) -> Any:
    if isinstance(node, dict):
        if "const" in node:
            return {"type": "string", "enum": [node["const"]]}
        out = {k: _clean(v) for k, v in node.items() if k in _KEEP and k != "properties"}
        if "properties" in node:
            out["properties"] = {name: _clean(sub) for name, sub in node["properties"].items()}
        if node.get("type") == "object":
            out["required"] = list(out.get("properties", {}))
            out["additionalProperties"] = False
        return out
    if isinstance(node, list):
        return [_clean(item) for item in node]
    return node


def output_schema(kind: SentinelTask) -> dict[str, Any]:
    """The provider-neutral JSON Schema of one output model: every property required, no
    additional properties, only keywords every provider's structured-output mode accepts."""
    from sibyl_schemas.models._base import inline_local_refs

    raw = inline_local_refs(OUTPUT_MODELS[kind].model_json_schema())
    schema: dict[str, Any] = _clean(raw)
    return schema


__all__ = [
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_TASKS",
    "MODEL_ID_PATTERN",
    "OUTPUT_MODELS",
    "SUBJECT_OF_KIND",
    "DriftReview",
    "FindingFeedback",
    "FindingKind",
    "FindingSeverity",
    "FindingTrigger",
    "FleetSummary",
    "HeldActionReview",
    "IncidentExplanation",
    "SentinelConfigPut",
    "SentinelExplainBody",
    "SentinelFeedbackBody",
    "SentinelProvider",
    "SentinelTask",
    "SubjectKind",
    "output_schema",
]
