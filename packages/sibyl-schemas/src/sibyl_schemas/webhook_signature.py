"""Monitor webhook signatures (D53): ``Sibyl-Signature: t=<unix seconds>,v1=<hex>``.

``v1`` is ``HMAC-SHA256(secret, "<t>." + raw body)`` in lowercase hex, the scheme Stripe and
GitHub receivers already know. The worker signs every delivery with the webhook's secret (shown
once when the webhook is created); a receiver verifies with ``verify`` against the raw request
bytes, rejects a timestamp more than ``tolerance_s`` away from its clock (replay window) and
compares in constant time. Several ``v1`` values may appear while a secret is being rotated; any
one matching is enough. The secret never appears in an error message.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

from sibyl_schemas._enums_monitor import SIGNATURE_HEADER, SIGNATURE_TOLERANCE_S

SCHEME: Final = "v1"
SECRET_PREFIX: Final = "whsec_"  # noqa: S105 (a format prefix, not a secret)
MAX_HEADER_CHARS: Final = 2048
_HEX64: Final = re.compile(r"[0-9a-f]{64}")

__all__ = [
    "SCHEME",
    "SECRET_PREFIX",
    "SIGNATURE_HEADER",
    "SIGNATURE_TOLERANCE_S",
    "SignatureError",
    "parse_header",
    "sign",
    "signature_header",
    "verify",
]


class SignatureError(ValueError):
    """The signature header is missing, malformed, stale or does not match (no secret inside)."""


@dataclass(frozen=True)
class ParsedSignature:
    timestamp: int
    signatures: tuple[str, ...]


def _key(secret: str | bytes) -> bytes:
    raw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    if not raw:
        raise SignatureError("empty webhook secret")
    return raw


def sign(secret: str | bytes, timestamp: int, body: bytes) -> str:
    """The lowercase hex ``v1`` signature of ``body`` at ``timestamp``."""
    message = str(int(timestamp)).encode("ascii") + b"." + bytes(body)
    return hmac.new(_key(secret), message, hashlib.sha256).hexdigest()


def signature_header(secret: str | bytes, body: bytes, *, timestamp: int | None = None) -> str:
    """The full header value for ``body`` (``timestamp`` defaults to now)."""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    return f"t={ts},{SCHEME}={sign(secret, ts, body)}"


def parse_header(value: str | None) -> ParsedSignature:
    if not value or len(value) > MAX_HEADER_CHARS:
        raise SignatureError(f"missing or oversized {SIGNATURE_HEADER} header")
    timestamp: int | None = None
    signatures: list[str] = []
    for part in value.split(","):
        name, sep, item = part.strip().partition("=")
        if not sep:
            raise SignatureError(f"malformed {SIGNATURE_HEADER} header")
        if name == "t":
            if not item.isdigit() or len(item) > 12:
                raise SignatureError(f"malformed {SIGNATURE_HEADER} timestamp")
            timestamp = int(item)
        elif name == SCHEME and _HEX64.fullmatch(item.lower()):
            signatures.append(item.lower())
    if timestamp is None or not signatures:
        raise SignatureError(f"{SIGNATURE_HEADER} needs t= and {SCHEME}=")
    return ParsedSignature(timestamp, tuple(signatures))


def verify(
    secret: str | bytes | Iterable[str | bytes],
    header: str | None,
    body: bytes,
    *,
    tolerance_s: int = SIGNATURE_TOLERANCE_S,
    now: float | None = None,
) -> int:
    """Verify ``header`` over the raw ``body``; returns the signed timestamp.

    ``secret`` may be several secrets (rotation). Raises ``SignatureError`` when the header is
    malformed, the timestamp is outside ``tolerance_s`` or no signature matches.
    """
    parsed = parse_header(header)
    clock = time.time() if now is None else now
    if tolerance_s >= 0 and abs(clock - parsed.timestamp) > tolerance_s:
        raise SignatureError("webhook signature timestamp is outside the tolerance window")
    secrets = [secret] if isinstance(secret, str | bytes) else list(secret)
    matched = False
    for candidate in secrets:
        expected = sign(candidate, parsed.timestamp, body)
        for given in parsed.signatures:
            matched |= hmac.compare_digest(expected, given)
    if not matched:
        raise SignatureError("webhook signature does not match")
    return parsed.timestamp
