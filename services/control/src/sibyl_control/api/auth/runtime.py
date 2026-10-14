"""Lazily built lane-local runtime objects, cached on ``app.state`` (see ``common.LANE_STATE``).

Tests pre-seed ``lane_state(request)`` with fakes (``oidc``, ``kek``, ``auth_settings``,
``blob``); production builds them from ``Settings`` on first use.
"""

from __future__ import annotations

from typing import Any

from fastapi import Request

from ...core.crypto.deks import PgDekProvider, kek_from_settings
from ...core.crypto.envelope import KeyEncryptionKey
from ...core.problems import ProblemError
from ..deps import get_services
from .common import lane_state, require_db
from .config import AuthSettings, auth_settings
from .oidc import OidcClient
from .principals import default_oidc_client


def settings_for(request: Request) -> AuthSettings:
    state = lane_state(request)
    if "auth_settings" not in state:
        state["auth_settings"] = auth_settings()
    value: AuthSettings = state["auth_settings"]
    return value


def oidc_for(request: Request) -> OidcClient:
    state = lane_state(request)
    if "oidc" not in state:
        state["oidc"] = default_oidc_client(get_services(request).settings)
    client: OidcClient = state["oidc"]
    return client


def kek_for(request: Request) -> KeyEncryptionKey:
    state = lane_state(request)
    if "kek" not in state:
        state["kek"] = kek_from_settings(get_services(request).settings)
    kek: KeyEncryptionKey = state["kek"]
    return kek


def deks_for(request: Request) -> PgDekProvider:
    state = lane_state(request)
    if "deks" not in state:
        state["deks"] = PgDekProvider(require_db(get_services(request)), kek_for(request))
    deks: PgDekProvider = state["deks"]
    return deks


def public_url(request: Request) -> str:
    settings = get_services(request).settings
    if settings is None:
        return str(request.base_url).rstrip("/")
    return settings.public_url.rstrip("/")


def session_secret_key(request: Request, label: str) -> bytes:
    try:
        return settings_for(request).derived_key(label)
    except RuntimeError:
        raise ProblemError("service_unavailable", "SIBYL_SESSION_SECRET is not set") from None


def get(request: Request, name: str, default: Any = None) -> Any:
    return lane_state(request).get(name, default)
