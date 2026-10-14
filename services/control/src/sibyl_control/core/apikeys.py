"""Tenant API keys: ``sbl_<env>_<prefix12>_<secret>`` (API.md §2.1, security-auditor §2.2).

Stored as ``HMAC-SHA-256(SIBYL_KEY_PEPPER, secret)``; looked up by ``prefix12`` through
``sibyl.api_key_lookup(prefix)`` (the only pre-tenant read). Verification is constant-time and an
unknown prefix costs the same HMAC + compare as a known one. Every rejection maps to one
identical 401 for the caller; the internal ``RejectReason`` is for audit and metrics only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import secrets
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from uuid import UUID

from .authz import BREAK_GLASS_SCOPE, KEY_SCOPES, MONITOR_SCOPES
from .problems import ProblemError

KEY_PATTERN = r"^sbl_(live|test)_[A-Za-z0-9]{12}_[A-Za-z0-9_-]{43}$"
_KEY_RE = re.compile(r"^sbl_(live|test)_([A-Za-z0-9]{12})_([A-Za-z0-9_-]{43})$")
_KEY_SEARCH_RE = re.compile(r"sbl_(live|test)_[A-Za-z0-9]{12}_")
_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
PREFIX_LEN = 12
SECRET_BYTES = 32
DEFAULT_KEY_LIFETIME = timedelta(days=365)
MAX_KEY_LIFETIME = timedelta(days=400)
MIN_PEPPER_BYTES = 32
_DUMMY_HASH = hashlib.sha256(b"sibyl-dummy-key").digest()

Env = str  # "live" | "test"


class RejectReason(StrEnum):
    MALFORMED = "malformed"
    UNKNOWN = "unknown_prefix"
    BAD_SECRET = "bad_secret"  # noqa: S105  (a reason label, not a secret)
    REVOKED = "revoked"
    EXPIRED = "expired"
    GRACE_ELAPSED = "rotation_grace_elapsed"
    ENV_MISMATCH = "env_mismatch"


class ApiKeyRejected(Exception):
    """Internal rejection; ``problem()`` is the uniform external 401."""

    def __init__(self, reason: RejectReason) -> None:
        super().__init__(f"api key rejected: {reason.value}")
        self.reason = reason

    def problem(self) -> ProblemError:
        return ProblemError("unauthenticated")


@dataclass(frozen=True)
class ParsedKey:
    env: Env
    prefix: str
    secret: str = field(repr=False)


@dataclass(frozen=True)
class GeneratedKey:
    plaintext: str = field(repr=False)
    env: Env
    prefix: str
    secret_hash: bytes = field(repr=False)


@dataclass(frozen=True)
class KeyRecord:
    """Row shape returned by ``sibyl.api_key_lookup(prefix)``."""

    tenant_id: UUID
    id: UUID
    env: Env
    secret_hash: bytes = field(repr=False)
    scopes: frozenset[str] = frozenset()
    agent_id: UUID | None = None
    status: str = "active"
    expires_at: datetime | None = None
    rotation_grace_until: datetime | None = None
    monitor_id: UUID | None = None  # D53: the external monitor the key is bound to


@dataclass(frozen=True)
class VerifiedKey:
    record: KeyRecord
    prefix: str


KeyLookup = Callable[[str], Awaitable[KeyRecord | None]]


def parse_api_key(value: str) -> ParsedKey:
    match = _KEY_RE.fullmatch(value or "")
    if match is None:
        raise ApiKeyRejected(RejectReason.MALFORMED)
    env, prefix, secret = match.groups()
    return ParsedKey(env, prefix, secret)


def hash_secret(secret: str, pepper: bytes) -> bytes:
    return hmac.new(pepper, secret.encode("ascii"), hashlib.sha256).digest()


def generate_api_key(env: Env, pepper: bytes) -> GeneratedKey:
    if env not in ("live", "test"):
        raise ValueError("env must be live or test")
    prefix = "".join(secrets.choice(_BASE62) for _ in range(PREFIX_LEN))
    secret = base64.urlsafe_b64encode(secrets.token_bytes(SECRET_BYTES)).rstrip(b"=").decode()
    plaintext = f"sbl_{env}_{prefix}_{secret}"
    return GeneratedKey(plaintext, env, prefix, hash_secret(secret, pepper))


def _status_reason(record: KeyRecord, now: datetime) -> RejectReason | None:
    if record.status == "revoked":
        return RejectReason.REVOKED
    if record.status == "expired" or (record.expires_at is not None and record.expires_at <= now):
        return RejectReason.EXPIRED
    if record.status == "rotating" and (
        record.rotation_grace_until is None or record.rotation_grace_until <= now
    ):
        return RejectReason.GRACE_ELAPSED
    if record.status not in ("active", "rotating"):
        return RejectReason.REVOKED
    return None


async def verify_api_key(
    presented: str,
    lookup: KeyLookup,
    pepper: bytes,
    *,
    now: datetime,
    expected_env: Env | None = None,
) -> VerifiedKey:
    """Verify ``presented``; raises ``ApiKeyRejected``. One HMAC and one compare on every path."""
    try:
        parsed = parse_api_key(presented)
    except ApiKeyRejected:
        hmac.compare_digest(hash_secret("x", pepper), _DUMMY_HASH)
        raise
    record = await lookup(parsed.prefix)
    computed = hash_secret(parsed.secret, pepper)
    if record is None:
        hmac.compare_digest(computed, _DUMMY_HASH)
        raise ApiKeyRejected(RejectReason.UNKNOWN)
    if not hmac.compare_digest(computed, record.secret_hash):
        raise ApiKeyRejected(RejectReason.BAD_SECRET)
    if record.env != parsed.env or (expected_env is not None and parsed.env != expected_env):
        raise ApiKeyRejected(RejectReason.ENV_MISMATCH)
    reason = _status_reason(record, now)
    if reason is not None:
        raise ApiKeyRejected(reason)
    return VerifiedKey(record, parsed.prefix)


def validate_key_scopes(
    scopes: Iterable[str],
    *,
    agent_id: UUID | None,
    env: Env,
    monitor_id: UUID | None = None,
) -> frozenset[str]:
    """Scopes ⊆ M; ``killswitch:pull`` is exclusive, tenant-level and live only (rule 3);
    monitor scopes only on a key bound to a monitor, which holds nothing else (D53)."""
    scope_set = frozenset(scopes)
    if not scope_set or not scope_set <= KEY_SCOPES:
        raise ProblemError("invalid_scope", "API keys may only carry M-marked scopes")
    if monitor_id is None and scope_set & MONITOR_SCOPES:
        raise ProblemError(
            "invalid_scope", "monitor scopes are issued only through POST /monitors/{id}/keys"
        )
    if monitor_id is not None and (not scope_set <= MONITOR_SCOPES or agent_id is not None):
        raise ProblemError("invalid_scope", "a monitor key holds monitor scopes only")
    if BREAK_GLASS_SCOPE in scope_set and (
        scope_set != {BREAK_GLASS_SCOPE} or agent_id is not None or env != "live"
    ):
        raise ProblemError(
            "break_glass_scope_exclusive",
            "killswitch:pull keys carry no other scope, are tenant-level and live",
        )
    return scope_set


def validate_expiry(expires_at: datetime | None, *, now: datetime) -> datetime:
    if expires_at is None:
        return now + DEFAULT_KEY_LIFETIME
    if expires_at <= now or expires_at > now + MAX_KEY_LIFETIME:
        raise ProblemError("expires_at_out_of_range", "expires_at must be within 400 days")
    return expires_at


def reject_credentials_in_url(query_items: Iterable[tuple[str, str]]) -> None:
    for _name, value in query_items:
        if _KEY_SEARCH_RE.search(value or ""):
            raise ProblemError("credential_in_url", "send API keys in the Authorization header")


def reject_key_from_browser(headers: Mapping[str, str]) -> None:
    lowered = {k.lower(): v for k, v in headers.items()}
    if "origin" in lowered and _KEY_SEARCH_RE.search(lowered.get("authorization", "")):
        raise ProblemError("key_from_browser", "API keys are for servers, not browsers")


def pepper_from_env(value: str) -> bytes:
    """Decode ``SIBYL_KEY_PEPPER`` (hex or base64url); at least 32 bytes."""
    raw: bytes | None = None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (binascii.Error, ValueError):
            raw = None
    if raw is None or len(raw) < MIN_PEPPER_BYTES:
        raise ValueError("SIBYL_KEY_PEPPER must decode to at least 32 bytes")
    return raw
