"""Request bodies of the registry module (OpenAPI components, ``additionalProperties: false``)."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
Money = Annotated[str, StringConstraints(pattern=r"^-?[0-9]+\.[0-9]{4}$")]
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Reason = Annotated[str, StringConstraints(min_length=10, max_length=2000)]
Tag = Annotated[str, StringConstraints(max_length=64)]

AgentKind = Literal[
    "chatbot",
    "copilot",
    "autonomous_agent",
    "multi_agent",
    "rag_pipeline",
    "mcp_server",
    "model_endpoint",
    "workflow",
]
RiskClass = Literal["unclassified", "minimal", "limited", "high", "unacceptable"]
FailMode = Literal["open", "closed"]
LifecycleTarget = Literal["proposed", "approved", "deployed", "monitored", "retired"]
Enforcement = Literal["observe", "block"]
NodeKind = Literal["agent", "tool", "data_source", "model", "provider", "business_process"]
Dialect = Literal["openai_compatible", "anthropic", "gemini"]
ProviderKind = Literal[
    "openai", "anthropic", "azure_openai", "bedrock", "vertex", "ollama", "custom"
]
ToolKind = Literal[
    "function", "mcp_server", "mcp_tool", "http_api", "code_interpreter", "retrieval"
]
DataSourceKind = Literal[
    "vector_index", "database", "document_store", "api", "filesystem", "saas", "stream"
]
Classification = Literal["public", "internal", "confidential", "restricted", "pii"]
Criticality = Literal["low", "medium", "high", "critical"]


class Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Reasoned(Body):
    """An audited human write: the optional ``reason`` lands on the audit row (else the
    ``X-Sibyl-Reason`` header, else the route label); it is never a column."""

    reason: Reason | None = None


class PatchBody(Reasoned):
    @model_validator(mode="after")
    def _not_empty(self) -> Self:
        if not self.model_fields_set - {"reason"}:
            raise ValueError("send at least one field")
        return self

    def changes(self) -> dict[str, Any]:
        """The fields the caller sent, without ``reason``."""
        return {f: getattr(self, f) for f in self.model_fields_set if f != "reason"}


class AgentVersionCreate(Body):
    primary_model_id: UUID
    config: dict[str, Any] | None = None
    prompt: Annotated[str, StringConstraints(max_length=262144)] | None = None
    prompt_sha256: Sha256Hex | None = None
    declared_tool_ids: Annotated[list[UUID], Field(max_length=500)] = []
    declared_data_source_ids: Annotated[list[UUID], Field(max_length=500)] = []


class AgentCreate(Body):
    slug: Slug
    name: Annotated[str, StringConstraints(min_length=1, max_length=120)]
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None
    kind: AgentKind
    framework: Annotated[str, StringConstraints(max_length=60)] | None = None
    tier: Annotated[int, Field(ge=1, le=3)] = 3
    risk_class: RiskClass = "unclassified"
    fail_mode: FailMode
    agent_group_id: UUID | None = None
    owner_user_id: UUID | None = None
    business_process_id: UUID | None = None
    cost_center: Annotated[str, StringConstraints(max_length=60)] | None = None
    tags: Annotated[list[Tag], Field(max_length=32)] = []
    version: AgentVersionCreate | None = None


class AgentPatch(PatchBody):
    name: Annotated[str, StringConstraints(min_length=1, max_length=120)] | None = None
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None
    kind: AgentKind | None = None
    framework: Annotated[str, StringConstraints(max_length=60)] | None = None
    tier: Annotated[int, Field(ge=1, le=3)] | None = None
    risk_class: RiskClass | None = None
    fail_mode: FailMode | None = None
    agent_group_id: UUID | None = None
    owner_user_id: UUID | None = None
    business_process_id: UUID | None = None
    cost_center: Annotated[str, StringConstraints(max_length=60)] | None = None
    tags: Annotated[list[Tag], Field(max_length=32)] | None = None


class LifecycleChange(Body):
    to_stage: LifecycleTarget
    reason: Reason


class AgentIdentityPut(Body):
    allowed_tools: Annotated[
        list[Annotated[str, StringConstraints(max_length=200)]], Field(max_length=500)
    ]
    allowed_models: Annotated[
        list[Annotated[str, StringConstraints(max_length=200)]], Field(max_length=200)
    ]
    allowed_providers: Annotated[
        list[Annotated[str, StringConstraints(max_length=200)]], Field(max_length=50)
    ]
    enforcement: Enforcement
    reason: Reason | None = None


class DependencyEdgeCreate(Body):
    src_kind: NodeKind
    src_id: UUID
    dst_kind: NodeKind
    dst_id: UUID
    edge_type: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z_]{2,40}$")]
    origin: Literal["declared"] = "declared"
    attrs: dict[str, Any] = {}


class ToolCreate(Reasoned):
    slug: Slug
    name: Annotated[str, StringConstraints(max_length=120)]
    kind: ToolKind
    parent_tool_id: UUID | None = None
    endpoint: Annotated[str, StringConstraints(max_length=2048)] | None = None
    permissions: list[str] = []
    is_approved: bool = False


class ToolPatch(PatchBody):
    name: Annotated[str, StringConstraints(max_length=120)] | None = None
    kind: ToolKind | None = None
    parent_tool_id: UUID | None = None
    endpoint: Annotated[str, StringConstraints(max_length=2048)] | None = None
    permissions: list[str] | None = None
    is_approved: bool | None = None


class DataSourceCreate(Reasoned):
    slug: Slug
    name: Annotated[str, StringConstraints(max_length=120)]
    kind: DataSourceKind
    classification: Classification = "internal"
    residency_region: Annotated[str, StringConstraints(max_length=32)] | None = None
    attrs: dict[str, Any] = {}


class DataSourcePatch(PatchBody):
    name: Annotated[str, StringConstraints(max_length=120)] | None = None
    kind: DataSourceKind | None = None
    classification: Classification | None = None
    residency_region: Annotated[str, StringConstraints(max_length=32)] | None = None
    attrs: dict[str, Any] | None = None


class BusinessProcessCreate(Reasoned):
    slug: Slug
    name: Annotated[str, StringConstraints(max_length=120)]
    owner_user_id: UUID | None = None
    criticality: Criticality = "medium"


class BusinessProcessPatch(PatchBody):
    name: Annotated[str, StringConstraints(max_length=120)] | None = None
    owner_user_id: UUID | None = None
    criticality: Criticality | None = None


Url = Annotated[str, StringConstraints(min_length=1, max_length=2048)]


class ProviderCreate(Reasoned):
    slug: Slug
    name: Annotated[str, StringConstraints(max_length=120)]
    provider_kind: ProviderKind
    dialect: Dialect
    base_url: Url
    status_feed_url: Url | None = None


class ProviderPatch(PatchBody):
    name: Annotated[str, StringConstraints(max_length=120)] | None = None
    base_url: Url | None = None
    status_feed_url: Url | None = None
    is_enabled: bool | None = None


class ModelCreate(Reasoned):
    provider_id: UUID
    model_name: Annotated[str, StringConstraints(min_length=1, max_length=200)]
    catalog_id: Annotated[str, StringConstraints(max_length=200)] | None = None
    input_usd_per_1m: Money | None = None
    output_usd_per_1m: Money | None = None


class ModelPatch(PatchBody):
    is_allowed: bool | None = None
    input_usd_per_1m: Money | None = None
    output_usd_per_1m: Money | None = None
    deprecated_on: date | None = None
    retires_on: date | None = None
