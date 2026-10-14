"""Sealed, short-lived OIDC login state carried in ``__Host-sibyl_oidc_state`` (10 min).

The cookie binds ``state``, ``nonce`` and the PKCE verifier to the browser that started the flow,
so the api keeps no pre-login rows. AES-256-GCM under a key derived from ``SIBYL_SESSION_SECRET``;
tampering, a foreign key or expiry all read as "no state".
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AAD = b"sibyl-oidc-state/v1"
_NONCE = 12


@dataclass(frozen=True)
class LoginState:
    state: str
    nonce: str
    verifier: str
    tenant_id: str
    issuer_id: str
    return_to: str
    issued_at: int
    purpose: str = "login"  # login | step_up
    session_id: str | None = None
    for_action: str | None = None


def new_login_state(
    *,
    tenant_id: str,
    issuer_id: str,
    return_to: str,
    now: datetime,
    purpose: str = "login",
    session_id: str | None = None,
    for_action: str | None = None,
) -> LoginState:
    return LoginState(
        state=secrets.token_urlsafe(32),
        nonce=secrets.token_urlsafe(32),
        verifier=secrets.token_urlsafe(48),
        tenant_id=tenant_id,
        issuer_id=issuer_id,
        return_to=return_to,
        issued_at=int(now.timestamp()),
        purpose=purpose,
        session_id=session_id,
        for_action=for_action,
    )


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def seal_state(key: bytes, state: LoginState) -> str:
    nonce = os.urandom(_NONCE)
    raw = json.dumps(asdict(state), separators=(",", ":")).encode()
    sealed = nonce + AESGCM(key).encrypt(nonce, raw, _AAD)
    return base64.urlsafe_b64encode(sealed).rstrip(b"=").decode("ascii")


def open_state(key: bytes, value: str | None, *, now: datetime, ttl_s: int) -> LoginState | None:
    if not value or len(value) > 4096:
        return None
    try:
        sealed = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        raw = AESGCM(key).decrypt(sealed[:_NONCE], sealed[_NONCE:], _AAD)
        doc: dict[str, Any] = json.loads(raw)
        state = LoginState(**doc)
    except (InvalidTag, ValueError, TypeError):
        return None
    age = int(now.timestamp()) - state.issued_at
    if age < -60 or age > ttl_s:
        return None
    return state


def safe_return_to(value: str | None) -> str:
    """Only same-origin absolute paths; anything else (``//host``, schemes, ``\\``) → ``/``."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or any(ord(c) < 0x20 for c in value) or len(value) > 2048:
        return "/"
    return value
