"""Signed policy snapshot: verification (API §3.5 order) and the SDK's one-agent view.

Two wire forms are accepted. Detached (preferred over HTTP): the response body is JCS(body)
and `X-Sibyl-Snapshot-Kid` / `X-Sibyl-Snapshot-Signature` sign those raw bytes (B4).
Envelope: `{kid, alg, sig, body}` with `sig` over JCS(body). Both are parsed strictly
(duplicate members refused) before any check. Order: malformed, unknown_kid,
bad_signature, non_monotonic, future_issued, bad_ttl.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, cast
from uuid import UUID

from sibyl_schemas.action_gate import ActionPolicy
from sibyl_schemas.canonical import canonicalize, parse_json_strict
from sibyl_schemas.models import PolicySnapshot as PolicySnapshotBody
from sibyl_schemas.models import SignedPolicySnapshot
from sibyl_schemas.values import (
    SNAPSHOT_GRACE_BOUNDS_S,
    SNAPSHOT_MAX_FUTURE_SKEW_S,
    SNAPSHOT_TTL_BOUNDS_S,
    SnapshotRejectCause,
)

from sibyl._ids import is_uuid, parse_rfc3339
from sibyl._keys import KeySetVerifier, verify_ed25519
from sibyl._types import CaptureMode, FailMode, Freshness, RoutingState

KID_HEADER = "x-sibyl-snapshot-kid"
SIG_HEADER = "x-sibyl-snapshot-signature"


class SnapshotRejected(ValueError):
    def __init__(self, cause: SnapshotRejectCause) -> None:
        super().__init__(f"snapshot rejected: {cause.value}")
        self.cause = cause


@dataclass(frozen=True)
class VerifiedSnapshot:
    body: dict[str, Any] = field(repr=False)
    version: int
    issued_at: float
    kid: str
    sig: str = field(repr=False)
    form: Literal["detached", "envelope"]
    raw: bytes = field(repr=False)


def _reject(cause: SnapshotRejectCause) -> SnapshotRejected:
    return SnapshotRejected(cause)


Form = Literal["detached", "envelope"]


def _parse(raw: bytes, headers: Mapping[str, str]) -> tuple[dict[str, Any], str, str, bytes, Form]:
    """(body, kid, sig, signed bytes, form); anything unparseable is `malformed`."""
    try:
        document = parse_json_strict(raw)
        if headers.get(SIG_HEADER):
            PolicySnapshotBody.model_validate(document)
            kid = headers.get(KID_HEADER, "")
            return document, kid, headers[SIG_HEADER], raw, "detached"
        SignedPolicySnapshot.model_validate(document)
    except (ValueError, RecursionError, TypeError):
        raise _reject(SnapshotRejectCause.MALFORMED) from None
    body = document["body"]
    if body.get("kid") != document["kid"]:
        raise _reject(SnapshotRejectCause.UNKNOWN_KID)
    return body, document["kid"], document["sig"], canonicalize(body), "envelope"


def verify_snapshot(
    raw: bytes,
    headers: Mapping[str, str],
    keys: KeySetVerifier,
    *,
    held_version: int,
    now: float,
) -> VerifiedSnapshot:
    body, kid, sig, signed, form = _parse(raw, {k.lower(): v for k, v in headers.items()})
    if body.get("kid") != kid:
        raise _reject(SnapshotRejectCause.UNKNOWN_KID)
    public = keys.public_key(kid, now=datetime.fromtimestamp(now, tz=UTC))
    if public is None:
        raise _reject(SnapshotRejectCause.UNKNOWN_KID)
    if not verify_ed25519(signed, sig, public):
        raise _reject(SnapshotRejectCause.BAD_SIGNATURE)
    if body["version"] <= held_version:
        raise _reject(SnapshotRejectCause.NON_MONOTONIC)
    issued = parse_rfc3339(body["issued_at"])
    if issued > now + SNAPSHOT_MAX_FUTURE_SKEW_S:
        raise _reject(SnapshotRejectCause.FUTURE_ISSUED)
    ttl = parse_rfc3339(body["expires_at"]) - issued
    lo, hi = SNAPSHOT_TTL_BOUNDS_S
    g_lo, g_hi = SNAPSHOT_GRACE_BOUNDS_S
    if not (lo <= ttl <= hi and ttl == body["ttl_s"] and g_lo <= body["grace_s"] <= g_hi):
        raise _reject(SnapshotRejectCause.BAD_TTL)
    return VerifiedSnapshot(body, int(body["version"]), issued, kid, sig, form, raw)


# ------------------------------------------------------------------ the SDK's view


@dataclass(frozen=True)
class PolicySnapshot:
    """One agent's slice of a verified snapshot (API §8.2, B5 seven routing states)."""

    agent_id: UUID
    tenant_id: UUID
    slug: str
    policy_version: int
    issued_at: datetime
    ttl_s: int
    grace_s: int
    max_stale_s: float
    state: RoutingState
    fail_mode: FailMode
    capture_mode: CaptureMode
    tier: int
    primary: dict[str, str]
    fallback_chain: list[dict[str, Any]]
    kill_reason: str | None = None
    key_scopes: tuple[str, ...] = ()
    action_policies: tuple[ActionPolicy, ...] = ()
    action_policy_missing: bool = False
    """An agent reference without a usable tenant document: tool calls fail closed."""

    def freshness_at(self, now: float) -> Freshness:
        age = now - self.issued_at.timestamp()
        if age <= self.ttl_s:
            return "fresh"
        if age <= self.ttl_s + self.grace_s:
            return "stale"
        if age <= self.max_stale_s:
            return "expired"
        return "unavailable"

    @property
    def freshness(self) -> Freshness:
        return self.freshness_at(time.time())

    def age_s(self, now: float) -> float:
        return max(0.0, now - self.issued_at.timestamp())


def _find_agent(
    tenants: Mapping[str, Any], agent_ref: str | None, key_prefix: str
) -> tuple[str, dict[str, Any], str, dict[str, Any]] | None:
    """(tenant_id, tenant block, agent_id, agent) for a uuid, a slug or the key's binding."""
    for tenant_id, block in tenants.items():
        agents: dict[str, Any] = block["agents"]
        wanted = agent_ref
        if wanted is None:
            bound = block["api_keys"].get(key_prefix, {}).get("agent_id")
            wanted = bound or (next(iter(agents)) if len(agents) == 1 else None)
        if wanted is None:
            continue
        if is_uuid(wanted) and wanted in agents:
            return tenant_id, block, wanted, agents[wanted]
        for agent_id, agent in agents.items():
            if agent["slug"] == wanted:
                return tenant_id, block, agent_id, agent
    return None


def _kill_reason(block: Mapping[str, Any], agent_id: str, agent: Mapping[str, Any]) -> str | None:
    if agent["route"]["state"] == "killed":
        return "agent route state is killed"
    for switch in block["kill_switches"]:
        if switch["scope_kind"] == "tenant":
            return "tenant kill switch pulled"
        if switch["scope_kind"] == "agent" and switch["scope_id"] == agent_id:
            return "agent kill switch pulled"
    return None


def resolve_action_policies(
    block: Mapping[str, Any], agent: Mapping[str, Any]
) -> tuple[tuple[ActionPolicy, ...], bool]:
    """(policies in the agent's order, missing): a dangling or mismatched reference, or a
    document that does not validate, marks the set missing (enforcement fails closed)."""
    refs = agent.get("action_policies") or []
    docs = block.get("action_policies") or {}
    found: list[ActionPolicy] = []
    missing = False
    for ref in refs:
        doc = docs.get(ref)
        if not isinstance(doc, Mapping) or doc.get("policy_id") != ref:
            missing = True
            continue
        try:
            found.append(ActionPolicy.model_validate(doc))
        except ValueError:
            missing = True
    return tuple(found), missing


def agent_view(
    verified: VerifiedSnapshot, *, agent_ref: str | None, key_prefix: str, max_stale_s: float
) -> PolicySnapshot | None:
    body = verified.body
    found = _find_agent(body["tenants"], agent_ref, key_prefix)
    if found is None:
        return None
    tenant_id, block, agent_id, agent = found
    reason = _kill_reason(block, agent_id, agent)
    state = cast(RoutingState, "killed" if reason else agent["route"]["state"])
    chain = agent.get("fallback_chain") or {}
    key = block["api_keys"].get(key_prefix, {})
    policies, missing = resolve_action_policies(block, agent)
    return PolicySnapshot(
        agent_id=UUID(agent_id),
        tenant_id=UUID(tenant_id),
        slug=agent["slug"],
        policy_version=verified.version,
        issued_at=datetime.fromtimestamp(verified.issued_at, tz=UTC),
        ttl_s=int(body["ttl_s"]),
        grace_s=int(body["grace_s"]),
        max_stale_s=max_stale_s,
        state=state,
        fail_mode=cast(FailMode, agent["fail_mode"]),
        capture_mode=cast(CaptureMode, agent["capture"]["mode"]),
        tier=int(agent["tier"]),
        primary={k: str(v) for k, v in agent["primary"].items()},
        fallback_chain=list(chain.get("steps", [])),
        kill_reason=reason,
        key_scopes=tuple(key.get("scopes", ())),
        action_policies=policies,
        action_policy_missing=missing,
    )
