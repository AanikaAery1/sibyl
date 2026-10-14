"""`sibyl.policy_snapshot/1`: signed body, detached-signature envelope and signed key set.

The signature covers `canonicalize(body)` (RFC 8785). TTL/grace bounds are verifier
checks (cause `bad_ttl`), deliberately not model constraints.

Untrusted bytes must be parsed with `parse_signed_snapshot` / `parse_signing_key_set` (or
`model_validate_json`, which these models route through `parse_json_strict`): a last-wins
JSON parser accepts an envelope with two `body` members, so a verifier that checked the
first body would act on the second (security review M5).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import MISSING, Field, StringConstraints

from sibyl_schemas._enums import (
    ApiKeyEnv,
    CaptureMode,
    DegradedMode,
    Dialect,
    FailMode,
    FallbackKind,
    IdentityEnforcement,
    KillSwitchScope,
    ProviderKind,
    RiskClass,
    RoutingState,
    SignatureAlgorithm,
    SigningKeyStatus,
    StepRisk,
    TargetKind,
)
from sibyl_schemas.canonical import MAX_SAFE_INTEGER, parse_json_strict
from sibyl_schemas.models._base import (
    KeyedMap,
    Lax,
    NonNegInt,
    PosInt,
    Sha256Hex,
    TierInt,
    Timestamp,
    Uuid,
    WireModel,
)
from sibyl_schemas.models.action_policy import ActionPolicy

KidStr = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,64}$")]
Money = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]{0,11})(\.[0-9]{1,4})?$")]
KeyPrefix = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9]{12}$")]
ModelName = Annotated[str, Field(min_length=1, max_length=200)]
MachineScopeName = Literal[
    "agents:read",
    "agents:write",
    "routing:read",
    "killswitch:pull",
    "gateway:proxy",
    "ingest:write",
    "handoff:write",
    "actions:hold",
]
"""Wire spelling of `values.MACHINE_SCOPES` (the only scopes an API key can hold) minus the
monitor-bound scopes: monitor keys (D53) never reach the gateway's snapshot."""


class SnapshotApiKey(WireModel):
    key_id: Uuid
    secret_hash: Sha256Hex
    env: Lax[ApiKeyEnv]
    scopes: Annotated[
        list[MachineScopeName], Field(min_length=1, json_schema_extra={"uniqueItems": True})
    ]
    agent_id: Uuid | None
    status: Literal["active", "rotating"]
    rotation_grace_until: Timestamp | MISSING = MISSING
    expires_at: Timestamp


class SnapshotProvider(WireModel):
    slug: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]
    provider_kind: Lax[ProviderKind]
    dialect: Lax[Dialect]
    base_url: Annotated[str, StringConstraints(pattern=r"^https://[^\s]+$", max_length=512)]
    """https only; dev doubles come in through the DB `base_url_dev_host` allowlist."""
    is_enabled: bool


class SnapshotTarget(WireModel):
    provider_id: Uuid
    model: ModelName


ProfileKey = Annotated[str, StringConstraints(pattern=r"^[a-z0-9_-]{1,32}$")]


class CaptureProfile(WireModel):
    profile_hash: Sha256Hex
    detectors_ref: Annotated[str, StringConstraints(pattern=r"^detectors/v[0-9]+$")]


class SnapshotCapture(WireModel):
    mode: Lax[CaptureMode]
    profile: ProfileKey


class SnapshotRoute(WireModel):
    """`step_position` names the active chain step; explicit target fields are for ad hoc
    operator failovers to a target outside the approved chain (API §6.3)."""

    state: Lax[RoutingState]
    target_kind: Lax[TargetKind]
    provider_id: Uuid | MISSING = MISSING
    model: ModelName | MISSING = MISSING
    agent_id: Uuid | MISSING = MISSING
    step_position: PosInt | MISSING = MISSING
    canary_pct: Annotated[int, Field(ge=0, le=100)]
    since: Timestamp
    transition_id: Uuid | MISSING = MISSING
    operator_hold_until: Timestamp | MISSING = MISSING


class FallbackStep(WireModel):
    """Identified by `position` within the immutable `(chain_id, version)`."""

    position: PosInt
    kind: Lax[FallbackKind]
    provider_id: Uuid | MISSING = MISSING
    model: ModelName | MISSING = MISSING
    agent_id: Uuid | MISSING = MISSING
    credential_id: Uuid | MISSING = MISSING
    max_attempts: Annotated[int, Field(ge=1, le=10)] | MISSING = MISSING
    risk: Lax[StepRisk] | MISSING = MISSING
    viable: bool


class FallbackChain(WireModel):
    chain_id: Uuid
    version: PosInt
    steps: Annotated[list[FallbackStep], Field(min_length=1)]


class AgentLimits(WireModel):
    max_inflight: PosInt | None
    rps: Annotated[float, Field(gt=0)] | None
    budget_usd_month: Money | None
    spent_usd_month: Money


class AgentIdentity(WireModel):
    identity_version: NonNegInt
    enforcement: Lax[IdentityEnforcement]
    allowed_models: list[str] | None
    allowed_tools: list[str] | None
    allowed_providers: list[Uuid] | None


MAX_AGENT_ACTION_POLICIES = 16
MAX_TENANT_ACTION_POLICIES = 1024


class SnapshotAgent(WireModel):
    """`action_policies` (Action Gate, D48) lists the ids of the active approved policies that
    apply to this agent, agent-specific first; the documents live once per tenant in
    `TenantBlock.action_policies` so a policy shared by many agents is signed once (B4)."""

    slug: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_./-]{0,127}$")]
    tier: TierInt
    fail_mode: Lax[FailMode]
    risk_class: Lax[RiskClass]
    capture: SnapshotCapture
    degraded_mode: Lax[DegradedMode]
    inline_fallback: bool
    primary: SnapshotTarget
    route: SnapshotRoute
    fallback_chain: FallbackChain | None
    limits: AgentLimits
    identity: AgentIdentity
    action_policies: (
        Annotated[
            list[Uuid],
            Field(max_length=MAX_AGENT_ACTION_POLICIES, json_schema_extra={"uniqueItems": True}),
        ]
        | MISSING
    ) = MISSING


class SnapshotKillSwitch(WireModel):
    kill_switch_id: Uuid
    scope_kind: Lax[KillSwitchScope]
    scope_id: Uuid | None
    pulled_at: Timestamp


class TenantBlock(WireModel):
    routing_version: Annotated[int, Field(ge=0, le=MAX_SAFE_INTEGER)]
    unknown_agent_fail_mode: Lax[FailMode]
    demo_mode: bool
    capture_profiles: Annotated[KeyedMap[ProfileKey, CaptureProfile], Field(min_length=1)]
    api_keys: KeyedMap[KeyPrefix, SnapshotApiKey]
    providers: KeyedMap[Uuid, SnapshotProvider]
    agents: KeyedMap[Uuid, SnapshotAgent]
    kill_switches: list[SnapshotKillSwitch]
    action_policies: (
        Annotated[KeyedMap[Uuid, ActionPolicy], Field(max_length=MAX_TENANT_ACTION_POLICIES)]
        | MISSING
    ) = MISSING
    """policy_id -> active approved `sibyl-action-policy/1` document (Action Gate). A consumer
    treats a key that differs from the document's `policy_id`, or an agent reference with no
    document, as a missing policy and fails closed for that agent's tool calls."""


class PolicySnapshot(WireModel):
    schema_: Literal["sibyl.policy_snapshot/1"] = Field(alias="schema")
    version: Annotated[int, Field(ge=1, le=MAX_SAFE_INTEGER)]
    issued_at: Timestamp
    expires_at: Timestamp
    ttl_s: NonNegInt
    grace_s: NonNegInt
    kid: KidStr
    tenants: Annotated[KeyedMap[Uuid, TenantBlock], Field(min_length=1)]


class _StrictJsonModel(WireModel):
    """`model_validate_json` goes through `parse_json_strict`: duplicate members (at any
    depth), NaN/Infinity, oversize and over-deep input are refused before validation."""

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Any = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        raw = bytes(json_data) if isinstance(json_data, bytearray) else json_data
        return cls.model_validate(
            parse_json_strict(raw),
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


class SignedPolicySnapshot(_StrictJsonModel):
    """Envelope `{kid, alg, sig, body}`; `sig` covers JCS(body). Over HTTP the detached form
    is preferred (body bytes = JCS(body), signature in headers) so the gateway verifies the
    raw bytes it received (B4). A verifier also refuses `kid != body.kid` (`unknown_kid`)."""

    kid: KidStr
    alg: Lax[SignatureAlgorithm]
    sig: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]
    body: PolicySnapshot


class SigningKey(WireModel):
    kid: KidStr
    alg: Lax[SignatureAlgorithm]
    public_key: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{43}$")]
    status: Lax[SigningKeyStatus] | MISSING = MISSING
    not_after: Timestamp | MISSING = MISSING


class SigningKeySetBody(WireModel):
    """The signed content of a key set: the keys a verifier trusts and the pre-published
    successor (R33). `next_key` is inside the signature, so it cannot be swapped in transit."""

    sequence: Annotated[int, Field(ge=1, le=MAX_SAFE_INTEGER)]
    issued_at: Timestamp
    keys: Annotated[list[SigningKey], Field(min_length=1)]
    next_key: SigningKey | None


class SigningKeySet(_StrictJsonModel):
    """`/.well-known/sibyl-keys.json` and `GET /api/v1/policy/keys` (security M6).

    `{kid, alg, sig, body}`: `sig` is Ed25519 over JCS(body) by `kid`, an active key of the
    previously accepted set (the pinned first key for sequence 1). A verifier accepts the set
    only if every active key in it was already trusted or was the previous set's `next_key`,
    and the signer is not past `not_after` (`KeySetRejectCause` gives the check order).
    """

    kid: KidStr
    alg: Lax[SignatureAlgorithm]
    sig: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_-]{86}$")]
    body: SigningKeySetBody


def parse_signed_snapshot(raw: str | bytes) -> SignedPolicySnapshot:
    """Strictly parse an untrusted snapshot envelope (raises `CanonicalizationError` or
    pydantic `ValidationError`, both `ValueError`s)."""
    return SignedPolicySnapshot.model_validate(parse_json_strict(raw))


def parse_signing_key_set(raw: str | bytes) -> SigningKeySet:
    """Strictly parse an untrusted signed key set."""
    return SigningKeySet.model_validate(parse_json_strict(raw))
