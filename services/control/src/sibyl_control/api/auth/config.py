"""Lane A settings (``SIBYL_*``), read beside the kernel ``Settings`` without editing it.

``SIBYL_SESSION_SECRET`` keys the sealed OIDC-state cookie and the IP hash.
``SIBYL_OIDC_CLIENT_SECRET`` is the fallback client secret when an ``oidc_issuer`` row carries
none (dev dex). The API audience ``sibyl-api`` is what CLI/script JWTs must carry (dex
``trustedPeers``).
"""

from __future__ import annotations

import hashlib
import hmac
from functools import cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

SESSION_COOKIE = "__Host-sibyl_session"
STATE_COOKIE = "__Host-sibyl_oidc_state"
SESSION_BEARER_PREFIX = "sibyl_sess_"


class AuthSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SIBYL_", extra="ignore")

    session_secret: SecretStr | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_api_audience: str = "sibyl-api"
    oidc_scopes: str = "openid email profile"
    session_absolute_s: int = 8 * 3600
    session_idle_s: int = 30 * 60
    session_touch_s: int = 60
    state_ttl_s: int = 600
    bearer_max_lifetime_s: int = 3600
    step_up_require_auth_time: bool = False
    cookie_secure: bool = True
    tenant_host_suffix: str | None = None

    def secret(self) -> bytes:
        if self.session_secret is None or len(self.session_secret.get_secret_value()) < 32:
            raise RuntimeError("SIBYL_SESSION_SECRET must be set (at least 32 characters)")
        return self.session_secret.get_secret_value().encode()

    def derived_key(self, label: str) -> bytes:
        return hmac.new(self.secret(), f"sibyl/{label}/v1".encode(), hashlib.sha256).digest()

    def ip_hash(self, ip: str | None) -> bytes | None:
        if not ip:
            return None
        try:
            key = self.derived_key("ip-hash")
        except RuntimeError:
            return None
        return hmac.new(key, ip.encode(), hashlib.sha256).digest()


@cache
def auth_settings() -> AuthSettings:
    return AuthSettings()
