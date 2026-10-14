"""Startup assertion for the unconditional secrets scrub (D12, security-auditor §5.3).

The gateway cannot import ``sibyl_control``, so it checks its own scrubber before serving:
the salt is present and long enough (live gateways refuse to start without one), the detector
registry is the baseline superset with a self-consistent ``PROFILE_HASH``, and a canary of
every key family the gateway handles is actually replaced.
"""

from __future__ import annotations

import logging
import os
import secrets

from sibyl_schemas.canonical import canonical_sha256
from sibyl_schemas.scrub import (
    DETECTORS,
    PROFILE_HASH,
    ScrubField,
    SecretsScrubber,
    profile_document,
)

log = logging.getLogger("sibyl.gateway.telemetry")
MIN_SALT_BYTES = 16
BASELINE_DETECTORS = frozenset(
    {
        "sibyl_key",
        "openai_key",
        "anthropic_key",
        "aws_access_key",
        "aws_secret_key",
        "gcp_sa_key",
        "azure_conn_string",
        "github_token",
        "slack_token",
        "stripe_key",
        "jwt",
        "bearer_header",
        "basic_auth_url",
        "dsn",
        "pem_block",
        "ssh_key",
        "generic_secret_kv",
        "high_entropy",
    }
)


class ScrubberUnsafe(RuntimeError):
    """The gateway must not serve: content could leave unscrubbed."""


def _canaries() -> list[str]:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    tail = "".join(secrets.choice(alphabet) for _ in range(43))
    prefix = "".join(secrets.choice(alphabet) for _ in range(12))
    return [
        f"sbl_live_{prefix}_{tail}",
        "sk-proj-" + "".join(secrets.choice(alphabet) for _ in range(40)),
        "Authorization: Bearer " + "".join(secrets.choice(alphabet) for _ in range(40)),
    ]


def checked_scrubber(salt: bytes | None, *, env: str) -> SecretsScrubber:
    if salt is None or len(salt) < MIN_SALT_BYTES:
        if env == "live":
            raise ScrubberUnsafe("SIBYL_SCRUB_SALT (>= 16 bytes) is required on a live gateway")
        log.warning("SIBYL_SCRUB_SALT missing: a random per-process salt is used (test env)")
        salt = os.urandom(32)
    ids = {detector.id for detector in DETECTORS}
    if not BASELINE_DETECTORS <= ids:
        raise ScrubberUnsafe(f"baseline detectors missing: {sorted(BASELINE_DETECTORS - ids)}")
    if canonical_sha256(profile_document()) != PROFILE_HASH:
        raise ScrubberUnsafe("scrub PROFILE_HASH does not match the detector registry")
    scrubber = SecretsScrubber(salt)
    for canary in _canaries():
        result = scrubber.scrub(f"canary {canary} end", ScrubField.HEADER)
        if result.secrets_scrubbed < 1 or canary.split()[-1] in result.text:
            raise ScrubberUnsafe("scrub canary survived")
    return scrubber
