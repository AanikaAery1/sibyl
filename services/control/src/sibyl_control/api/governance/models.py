"""Request bodies of the governance module (OpenAPI components, ``additionalProperties: false``)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator

Reason = Annotated[str, StringConstraints(min_length=10, max_length=2000)]
ExportFormat = Literal["jsonl", "csv"]
LegalBasis = Literal["gdpr_art17", "dpdp_s12", "contract_end", "tenant_offboarding", "other"]
ErasureScope = Literal["tenant", "agent", "subject"]
HoldScope = Literal["tenant", "agent", "incident", "subject"]
ErasureVerb = Literal["approve", "reject", "cancel"]


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerificationRequest(_Body):
    from_seq: Annotated[int, Field(ge=0)] | None = None
    to_seq: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.from_seq is not None and self.to_seq is not None and self.to_seq < self.from_seq:
            raise ValueError("to_seq must not be below from_seq")
        return self


class AuditExportCreate(_Body):
    from_seq: Annotated[int, Field(ge=0)]
    to_seq: Annotated[int, Field(ge=0)]
    format: ExportFormat
    include_anchors: Literal[True] = True

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.to_seq < self.from_seq:
            raise ValueError("to_seq must not be below from_seq")
        return self


class ExportCreate(_Body):
    kind: Annotated[str, StringConstraints(max_length=40)]
    filter: dict[str, object]


class ErasureRequestCreate(_Body):
    scope_kind: ErasureScope
    scope_ref: Annotated[str, StringConstraints(min_length=1, max_length=512)] | None = None
    agent_ids: Annotated[list[UUID], Field(max_length=500)] | None = None
    window_from: AwareDatetime | None = None
    window_to: AwareDatetime | None = None
    legal_basis: LegalBasis
    reason: Reason


class ErasureAction(_Body):
    action: ErasureVerb
    reason: Reason


class LegalHoldCreate(_Body):
    scope_kind: HoldScope
    scope_ref: Annotated[str, StringConstraints(min_length=1, max_length=512)] | None = None
    provider_incident_id: UUID | None = None
    agent_ids: Annotated[list[UUID], Field(max_length=500)] | None = None
    window_from: AwareDatetime
    window_to: AwareDatetime | None = None
    reason: Reason
    expires_at: AwareDatetime | None = None


class ReasonBody(_Body):
    reason: Reason


__all__ = [
    "AuditExportCreate",
    "ErasureAction",
    "ErasureRequestCreate",
    "ExportCreate",
    "LegalHoldCreate",
    "ReasonBody",
    "VerificationRequest",
    "datetime",
]
