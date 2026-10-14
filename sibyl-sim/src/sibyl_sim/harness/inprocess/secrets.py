"""Dev-only secrets for the in-process stack (R46: the harness never ships).

Derived from fixed labels so a template database built yesterday still opens today (its tenant
DEKs are wrapped under this KEK, its keys hashed with this pepper). They protect nothing real
and must never be used outside `sibyl-sim`.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field

_LABEL = b"sibyl-sim/dev-only/"


def _derive(name: str) -> bytes:
    return hashlib.sha256(_LABEL + name.encode()).digest()


@dataclass(frozen=True)
class StackSecrets:
    pepper: bytes = field(default_factory=lambda: _derive("pepper"), repr=False)
    kek: bytes = field(default_factory=lambda: _derive("kek"), repr=False)
    kek_id: str = "sim-kek-1"
    scrub_salt: bytes = field(default_factory=lambda: _derive("scrub-salt"), repr=False)
    subject_salt: bytes = field(default_factory=lambda: _derive("subject-salt"), repr=False)
    snapshot_seed: bytes = field(default_factory=lambda: _derive("snapshot-seed"), repr=False)
    snapshot_kid: str = "sim-snapshot-1"
    anchor_seed: bytes = field(default_factory=lambda: _derive("anchor-seed"), repr=False)
    anchor_kid: str = "sim-anchor-1"
    ledger_seed: bytes = field(default_factory=lambda: _derive("ledger-seed"), repr=False)

    @property
    def kek_b64(self) -> str:
        return base64.urlsafe_b64encode(self.kek).decode()

    @property
    def snapshot_ref_env(self) -> str:
        return "SIBYL_SIM_SNAPSHOT_SEED"

    def signer_environ(self) -> dict[str, str]:
        """The mapping handed to the api's `SignerResolver` (never `os.environ`)."""
        return {self.snapshot_ref_env: self.snapshot_seed.hex()}


DEV_SECRETS = StackSecrets()
