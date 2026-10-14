"""Test-only snapshot signer, snapshot body builder and key material (never deploy)."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sibyl_schemas.canonical import canonicalize
from sibyl_schemas.golden import load_fixture

PEPPER = hashlib.sha256(b"sibyl-gateway-test-pepper").digest()
TENANT = UUID("0192767f-0000-7000-8000-00000000a001")
OTHER_TENANT = UUID("0192767f-0000-7000-8000-00000000b001")
BILLING = UUID("0192767f-0000-7000-8000-00000000c010")  # tier 2, failed_over at step 2
QUOTE = UUID("0192767f-0000-7000-8000-00000000c011")  # tier 1, active, fail closed
UNCLAIMED = UUID("0192767f-0000-7000-8000-00000000c012")  # killed
OPENAI = UUID("0192f0a1-7b2c-7e3d-9a4b-5c6d7e8f9a11")
ANTHROPIC = UUID("0192f0a1-7b2c-7e3d-9a4b-5c6d7e8f9a12")
SIM = UUID("0192f0a1-7b2c-7e3d-9a4b-5c6d7e8f9a13")
CRED = UUID("0192f0b2-0000-7000-8000-0000000000e1")


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def iso(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


class TestSigner:
    __test__ = False

    def __init__(self, kid: str = "snap-test-1") -> None:
        self.kid = kid
        self._key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> str:
        return b64u(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def sign(self, raw: bytes) -> str:
        return b64u(self._key.sign(raw))

    def key_set(self) -> dict[str, Any]:
        return {
            "keys": [{"kid": self.kid, "alg": "Ed25519", "public_key": self.public_key}],
            "next_key": None,
        }

    def deliver(self, body: dict[str, Any]) -> tuple[bytes, str, str]:
        body = {**body, "kid": self.kid}
        raw = canonicalize(body)
        return raw, self.kid, self.sign(raw)


def make_key(prefix: str, env: str = "live") -> tuple[str, str]:
    """(plaintext ``sbl_`` key, hex HMAC secret hash) for a 12-char prefix."""
    secret = b64u(secrets.token_bytes(32))
    digest = hmac.new(PEPPER, secret.encode(), hashlib.sha256).hexdigest()
    return f"sbl_{env}_{prefix}_{secret}", digest


GATEWAY_PREFIX = "GwKey0000001"
BOUND_PREFIX = "BoundKey0001"
READONLY_PREFIX = "ReadOnly0001"
GATEWAY_KEY, _GW_HASH = make_key(GATEWAY_PREFIX)
BOUND_KEY, _BOUND_HASH = make_key(BOUND_PREFIX)
READONLY_KEY, _RO_HASH = make_key(READONLY_PREFIX)


def tenant_block(**changes: Any) -> dict[str, Any]:
    """The schemas fixture tenant block with our test keys and ``changes`` applied."""
    template = load_fixture("snapshot", "valid/snapshot_body.json")
    block = copy.deepcopy(template["tenants"][str(TENANT)])
    far = iso(datetime.now(UTC) + timedelta(days=300))
    block["api_keys"] = {
        GATEWAY_PREFIX: _key_entry("1", _GW_HASH, ["gateway:proxy", "routing:read"], None, far),
        BOUND_PREFIX: _key_entry("2", _BOUND_HASH, ["gateway:proxy"], str(QUOTE), far),
        READONLY_PREFIX: _key_entry("3", _RO_HASH, ["routing:read"], None, far),
    }
    block.update(changes)
    return block


def _key_entry(
    n: str, digest: str, scopes: list[str], agent: str | None, exp: str
) -> dict[str, Any]:
    return {
        "key_id": f"0192f0c1-0000-7000-8000-00000000000{n}",
        "secret_hash": digest,
        "env": "live",
        "scopes": scopes,
        "agent_id": agent,
        "status": "active",
        "expires_at": exp,
    }


def body(
    version: int,
    *,
    issued_at: datetime | None = None,
    ttl_s: int = 60,
    grace_s: int = 300,
    tenants: dict[str, Any] | None = None,
) -> dict[str, Any]:
    issued = issued_at or datetime.now(UTC).replace(microsecond=0)
    return {
        "schema": "sibyl.policy_snapshot/1",
        "version": version,
        "issued_at": iso(issued),
        "expires_at": iso(issued + timedelta(seconds=ttl_s)),
        "ttl_s": ttl_s,
        "grace_s": grace_s,
        "kid": "set-by-signer",
        "tenants": tenants if tenants is not None else {str(TENANT): tenant_block()},
    }


def set_agent(block: dict[str, Any], agent: UUID, **changes: Any) -> dict[str, Any]:
    entry = block["agents"][str(agent)]
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(entry.get(key), dict):
            entry[key] = {**entry[key], **value}
        else:
            entry[key] = value
    return block


class Clock:
    def __init__(self, now: datetime | None = None) -> None:
        self.now = now or datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)
