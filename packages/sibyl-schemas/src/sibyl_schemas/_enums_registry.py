"""Registry, lifecycle, provider, key and erasure value sets (frozen)."""

from __future__ import annotations

from enum import StrEnum


class Lifecycle(StrEnum):
    DISCOVERED = "discovered"
    PROPOSED = "proposed"
    APPROVED = "approved"
    DEPLOYED = "deployed"
    MONITORED = "monitored"
    RETIRED = "retired"


class RiskClass(StrEnum):
    UNCLASSIFIED = "unclassified"
    MINIMAL = "minimal"
    LIMITED = "limited"
    HIGH = "high"
    UNACCEPTABLE = "unacceptable"


class AgentKind(StrEnum):
    CHATBOT = "chatbot"
    COPILOT = "copilot"
    AUTONOMOUS_AGENT = "autonomous_agent"
    MULTI_AGENT = "multi_agent"
    RAG_PIPELINE = "rag_pipeline"
    MCP_SERVER = "mcp_server"
    MODEL_ENDPOINT = "model_endpoint"
    WORKFLOW = "workflow"


class FailMode(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class ProviderKind(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    BEDROCK = "bedrock"
    VERTEX = "vertex"
    OLLAMA = "ollama"
    CUSTOM = "custom"


class Dialect(StrEnum):
    OPENAI_COMPATIBLE = "openai_compatible"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"


class ApiKeyEnv(StrEnum):
    LIVE = "live"
    TEST = "test"


class ApiKeyStatus(StrEnum):
    ACTIVE = "active"
    ROTATING = "rotating"
    REVOKED = "revoked"
    EXPIRED = "expired"


class ErasureState(StrEnum):
    REQUESTED = "requested"
    HOLD_BLOCKED = "hold_blocked"
    APPROVED = "approved"
    EXECUTING = "executing"
    KEYS_SHREDDED = "keys_shredded"
    OBJECTS_DELETED = "objects_deleted"
    DERIVED_PURGED = "derived_purged"
    VERIFIED = "verified"
    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class HoldState(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"


class TenantKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    SHREDDED = "shredded"


class JobState(StrEnum):
    """Async job lifecycle (B14; ``sibyl.job.state``, OpenAPI ``JobState``)."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class JobKind(StrEnum):
    """What the jobs worker loop runs (B14). Only ``credential_probe`` has a runner in Phase 1;
    ``agent_bom`` is cut to Phase 1.5, the audit/data exports belong to lane U."""

    CREDENTIAL_PROBE = "credential_probe"
    AGENT_BOM = "agent_bom"
    AUDIT_VERIFY = "audit_verify"
    AUDIT_EXPORT = "audit_export"
    DATA_EXPORT = "data_export"


class SigningKeyState(StrEnum):
    """``sibyl.signing_key.state`` (B10): ``next`` is pre-published in the key set's
    ``next_key`` before it becomes ``active``; ``retiring`` still verifies until ``not_after``."""

    NEXT = "next"
    ACTIVE = "active"
    RETIRING = "retiring"
    RETIRED = "retired"
    COMPROMISED = "compromised"


class TenantKeyPurpose(StrEnum):
    """Per-tenant data keys (D17 crypto-shred), rotated via
    `POST /api/v1/tenant-keys/{purpose}/rotate`."""

    PAYLOAD = "payload"
    CREDENTIAL = "credential"
    CONFIG = "config"
