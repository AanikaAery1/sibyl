"""Request bodies for the provider-credential routes (OpenAPI ``ProviderCredential*``).

``secret`` is a ``SecretStr``: it never appears in a repr, a log line or a validation error.
"""

from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

MAX_SECRET_CHARS = 8192
MAX_GRACE_S = 86400
DEFAULT_GRACE_S = 3600


def _check_secret(value: SecretStr) -> SecretStr:
    if not 1 <= len(value.get_secret_value()) <= MAX_SECRET_CHARS:
        raise ValueError(f"secret must be 1..{MAX_SECRET_CHARS} characters")
    return value


class ProviderCredentialCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: UUID
    name: str = Field(min_length=1, max_length=80)
    purpose: Literal["fallback"] = "fallback"
    base_url: str = Field(min_length=1, max_length=2048)
    auth_scheme: str = Field(min_length=1, max_length=40)
    secret: SecretStr
    reason: str | None = Field(default=None, min_length=10, max_length=2000)

    _secret = field_validator("secret")(_check_secret)


class ProviderCredentialRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret: SecretStr
    grace_s: int = Field(default=DEFAULT_GRACE_S, ge=0, le=MAX_GRACE_S)
    reason: str | None = Field(default=None, min_length=10, max_length=2000)

    _secret = field_validator("secret")(_check_secret)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=10, max_length=2000)
