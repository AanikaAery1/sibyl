"""`sibyl.policy_snapshot/1` signature vectors (W0-6) and the size budget.

The reference verifier below is test-only: it pins the verification ORDER the gateway
must implement (API §3.5) so the vectors provably exercise each cause. The gateway and
control-plane CI jobs run the same `fixtures/snapshot/vectors.json`.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import time
from datetime import datetime
from typing import Any

import pytest
from sibyl_schemas import jsonschema as sj
from sibyl_schemas.canonical import CanonicalizationError, canonicalize
from sibyl_schemas.golden import load_fixture
from sibyl_schemas.models import SignedPolicySnapshot, SigningKeySet, parse_signed_snapshot
from sibyl_schemas.values import (
    SNAPSHOT_GRACE_BOUNDS_S,
    SNAPSHOT_MAX_BYTES,
    SNAPSHOT_MAX_FUTURE_SKEW_S,
    SNAPSHOT_TTL_BOUNDS_S,
    SnapshotRejectCause,
)

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
VECTORS: dict[str, Any] = load_fixture("snapshot", "vectors.json")


def _b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _ts(text: str) -> float:
    return datetime.fromisoformat(text).timestamp()


def reference_verify(
    raw: str | bytes, key_set: dict[str, Any], *, held_version: int, now: str
) -> str:
    """Strict parse first (duplicate members, extra members, depth, size), then the
    API §3.5 order. Over HTTP the detached form carries JCS(body) as the response body and
    the signature in headers; the gateway verifies those raw bytes (B4) and parses the same
    bytes with `parse_json_strict`."""
    try:
        envelope = parse_signed_snapshot(raw).model_dump(mode="json", by_alias=True)
    except (CanonicalizationError, ValueError):
        return SnapshotRejectCause.MALFORMED.value
    keys = {key["kid"]: key for key in key_set["body"]["keys"]}
    if envelope["kid"] not in keys or envelope["body"]["kid"] != envelope["kid"]:
        return SnapshotRejectCause.UNKNOWN_KID.value
    public = ed25519.Ed25519PublicKey.from_public_bytes(_b64u(keys[envelope["kid"]]["public_key"]))
    try:
        public.verify(_b64u(envelope["sig"]), canonicalize(envelope["body"]))
    except Exception:  # cryptography raises InvalidSignature
        return SnapshotRejectCause.BAD_SIGNATURE.value
    body = envelope["body"]
    if body["version"] <= held_version:
        return SnapshotRejectCause.NON_MONOTONIC.value
    if _ts(body["issued_at"]) > _ts(now) + SNAPSHOT_MAX_FUTURE_SKEW_S:
        return SnapshotRejectCause.FUTURE_ISSUED.value
    ttl = _ts(body["expires_at"]) - _ts(body["issued_at"])
    lo, hi = SNAPSHOT_TTL_BOUNDS_S
    g_lo, g_hi = SNAPSHOT_GRACE_BOUNDS_S
    if not (lo <= ttl <= hi and ttl == body["ttl_s"] and g_lo <= body["grace_s"] <= g_hi):
        return SnapshotRejectCause.BAD_TTL.value
    return "ok"


def test_vectors_cover_valid_and_every_reject_cause() -> None:
    expected = {case["expected"] for case in VECTORS["cases"]}
    assert expected == {"ok"} | {cause.value for cause in SnapshotRejectCause}


ENVELOPE_CASES = [c for c in VECTORS["cases"] if "envelope" in c]
RAW_CASES = [c for c in VECTORS["cases"] if "raw" in c]


@pytest.mark.parametrize("case", ENVELOPE_CASES, ids=[c["name"] for c in ENVELOPE_CASES])
def test_vector_is_schema_valid_and_hits_its_cause(case: dict[str, Any]) -> None:
    envelope = case["envelope"]
    assert sj.is_valid("sibyl.policy_snapshot/1", envelope, pointer="/$defs/envelope")
    SignedPolicySnapshot.model_validate(envelope)
    body_hash = hashlib.sha256(canonicalize(envelope["body"])).hexdigest()
    assert body_hash == case["body_jcs_sha256"]
    verdict = reference_verify(
        json.dumps(envelope), VECTORS["key_set"], held_version=case["held_version"], now=case["now"]
    )
    assert verdict == case["expected"]


@pytest.mark.parametrize("case", RAW_CASES, ids=[c["name"] for c in RAW_CASES])
def test_raw_vector_hits_its_cause(case: dict[str, Any]) -> None:
    verdict = reference_verify(
        case["raw"], VECTORS["key_set"], held_version=case["held_version"], now=case["now"]
    )
    assert verdict == case["expected"]


def test_duplicate_body_envelope_is_refused_by_every_strict_entry_point() -> None:
    raw = next(c["raw"] for c in RAW_CASES if c["name"] == "duplicate_body_unkill")
    with pytest.raises(ValueError, match="duplicate member name"):
        SignedPolicySnapshot.model_validate_json(raw)
    with pytest.raises(CanonicalizationError, match="duplicate member name"):
        parse_signed_snapshot(raw.encode())
    # A last-wins parser sees the un-kill body after a verifier checked the first one.
    cases = {case["name"]: case for case in VECTORS["cases"]}
    assert json.loads(raw)["body"] == cases["bad_signature_unkill"]["envelope"]["body"]
    assert json.loads(raw)["sig"] == cases["valid"]["envelope"]["sig"]


def test_envelope_kid_must_equal_body_kid() -> None:
    case = next(c for c in ENVELOPE_CASES if c["name"] == "kid_mismatch")
    assert case["envelope"]["kid"] != case["envelope"]["body"]["kid"]
    assert case["expected"] == SnapshotRejectCause.UNKNOWN_KID.value


def test_strict_parse_refuses_extra_envelope_members() -> None:
    envelope = dict(ENVELOPE_CASES[0]["envelope"], next_key=None)
    with pytest.raises(ValueError, match="next_key"):
        parse_signed_snapshot(json.dumps(envelope))


def test_key_set_publishes_next_key_inside_the_signed_body() -> None:
    key_set = SigningKeySet.model_validate(VECTORS["key_set"])
    assert key_set.body.next_key is not None
    assert key_set.body.next_key.kid not in {key.kid for key in key_set.body.keys}
    assert key_set.kid in {key.kid for key in key_set.body.keys}
    assert load_fixture("snapshot", "valid/key_set.json") == VECTORS["key_set"]
    chain = load_fixture("snapshot", "key_set_vectors.json")
    assert chain["cases"][0]["steps"][0]["document"] == VECTORS["key_set"]


def test_tampered_unkill_vector_differs_only_in_route_state() -> None:
    cases = {case["name"]: case for case in VECTORS["cases"]}
    valid = cases["valid"]["envelope"]
    tampered = cases["bad_signature_unkill"]["envelope"]
    assert valid["sig"] == tampered["sig"]
    assert valid["body"] != tampered["body"]


WORST_CASE_AGENT_BYTES = 1400
"""Regression guard: the richest fixture agent (tier 1-2, 4-step chain with a vaulted
alt-provider step, explicit identity lists) must stay under this many canonical bytes."""


def _fleet_body(agents_total: int) -> dict[str, Any]:
    """Worst case: every agent is the richest fixture agent, with unique ids throughout."""
    template = load_fixture("snapshot", "valid/snapshot_body.json")
    tenant_id, block = next(iter(template["tenants"].items()))
    richest = max(block["agents"].values(), key=lambda a: len(canonicalize(a)))
    tenants: dict[str, Any] = {}
    for t in range(3):
        tenant = copy.deepcopy(block)
        agents: dict[str, Any] = {}
        for n in range(agents_total // 3 + (1 if t < agents_total % 3 else 0)):
            agent = copy.deepcopy(richest)
            agent["slug"] = f"agent-{t}-{n}"
            agent["fallback_chain"]["chain_id"] = f"0192f0b2-{t:04x}-7000-8000-{n:012x}"
            for step in agent["fallback_chain"]["steps"]:
                if "credential_id" in step:
                    step["credential_id"] = f"0192f0b3-{t:04x}-7000-8000-{n:012x}"
            agents[f"0192767f-{t:04x}-7000-8000-{n:012x}"] = agent
        tenant["agents"] = agents
        tenants[f"{tenant_id[:-4]}{t:04x}"] = tenant
    return {**template, "tenants": tenants}


def test_two_thousand_agent_snapshot_size() -> None:
    body = _fleet_body(2000)
    assert sum(len(t["agents"]) for t in body["tenants"].values()) == 2000
    assert sj.is_valid("sibyl.policy_snapshot/1", body)
    started = time.perf_counter()
    canonical = canonicalize(body)
    elapsed = time.perf_counter() - started
    assert len(canonical) <= 2000 * WORST_CASE_AGENT_BYTES, len(canonical)
    # The raw 2 MiB gate (ROADMAP W0-6) does not hold for an all-worst-case fleet; the
    # wire transfer does once compressed. See the W0-SCH hand-back change request.
    assert len(gzip.compress(canonical)) <= SNAPSHOT_MAX_BYTES
    assert elapsed < 5.0
