"""`sibyl-ingest-response/1`: the 202 body of `POST /v1/events` (API §4.4)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import MISSING, Field

from sibyl_schemas._enums import RejectReason
from sibyl_schemas.models._base import Lax, UuidV7, WireModel


class Rejection(WireModel):
    index: Annotated[int, Field(ge=0, le=999)]
    event_id: Annotated[str, Field(max_length=64)] | MISSING = MISSING
    reason: Lax[RejectReason]
    detail: Annotated[str, Field(max_length=500)] | MISSING = MISSING


class IngestResponse(WireModel):
    schema_: Literal["sibyl-ingest-response/1"] = Field(alias="schema")
    batch_id: UuidV7
    accepted: Annotated[int, Field(ge=0, le=1000)]
    rejected: Annotated[list[Rejection], Field(max_length=1000)]
    warnings: Annotated[list[Annotated[str, Field(max_length=500)]], Field(max_length=100)]
    replayed: bool
