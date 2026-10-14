"""Gateway configuration from ``SIBYL_*`` environment variables (12-factor, D4).

Names already used by deploy/compose: ``SIBYL_HTTP_PORT`` (8080), ``SIBYL_CONTROL_URL``,
``SIBYL_INGEST_URL``, ``SIBYL_SNAPSHOT_DIR``, ``SIBYL_ENV``, ``SIBYL_GATEWAY_TENANT_KEYS``
(comma list, one ``sbl_`` key per fronted tenant, R26). New here (FIX-INF change request):
``SIBYL_KEY_PEPPER`` (same value as the api; verifies keys locally),
``SIBYL_SNAPSHOT_PINNED_KEY(_FILE)`` (the first signing key, ``$defs/signing_key`` JSON; the
gateway follows the signed rotation chain from it), ``SIBYL_SNAPSHOT_KEYS(_FILE)`` (a static
key list for dev only: rotations are not followed), ``SIBYL_INGEST_KEY`` (``ingest:write``;
one tenant), ``SIBYL_INGEST_KEYS`` (B-03: comma list, one ``ingest:write`` key per fronted
tenant, in the order of ``SIBYL_GATEWAY_TENANT_KEYS``),
``SIBYL_SCRUB_SALT``, ``SIBYL_DEV_HOSTS``, ``SIBYL_GATEWAY_ID``, ``SIBYL_POLICY_POLL_S``,
``SIBYL_UPSTREAM_{CONNECT,TTFB}_S``, ``SIBYL_UPSTREAM_CA_FILE``, ``SIBYL_CONTROL_CA_FILE``.

An incomplete configuration still boots (compose: "empty is valid") so ``/healthz`` answers and
the last verified snapshot on disk keeps serving; ``problems()`` lists what is missing and the
data plane refuses with ``sibyl_no_snapshot`` until a verified snapshot exists.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

_KEY = re.compile(r"^sbl_(live|test)_([A-Za-z0-9]{12})_[A-Za-z0-9_-]{43}$")


def _pepper(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        try:
            raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        except (binascii.Error, ValueError):
            return None
    return raw if len(raw) >= 32 else None


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(part.strip() for part in (value or "").split(",") if part.strip())


@dataclass(frozen=True)
class GatewayConfig:
    http_port: int = 8080
    gateway_id: str = "gw"
    env: str = "live"
    control_url: str | None = None
    ingest_url: str | None = None
    tenant_keys: tuple[str, ...] = field(default=(), repr=False)
    ingest_key: str | None = field(default=None, repr=False)
    ingest_keys: tuple[str, ...] = field(default=(), repr=False)
    pepper: bytes | None = field(default=None, repr=False)
    pinned_key_json: str | None = None
    pinned_keys_json: str | None = None
    snapshot_dir: Path | None = None
    scrub_salt: bytes | None = field(default=None, repr=False)
    dev_hosts: tuple[str, ...] = ()
    poll_s: float = 5.0
    connect_s: float = 5.0
    ttfb_s: float = 60.0
    upstream_ca_file: str | None = None
    control_ca_file: str | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> GatewayConfig:
        env = os.environ if environ is None else environ
        pinned = env.get("SIBYL_SNAPSHOT_KEYS")
        pinned_file = env.get("SIBYL_SNAPSHOT_KEYS_FILE")
        if not pinned and pinned_file and Path(pinned_file).is_file():
            pinned = Path(pinned_file).read_text("utf-8")
        pin = env.get("SIBYL_SNAPSHOT_PINNED_KEY")
        pin_file = env.get("SIBYL_SNAPSHOT_PINNED_KEY_FILE")
        if not pin and pin_file and Path(pin_file).is_file():
            pin = Path(pin_file).read_text("utf-8")
        snapshot_dir = env.get("SIBYL_SNAPSHOT_DIR")
        salt = env.get("SIBYL_SCRUB_SALT")
        return cls(
            http_port=int(env.get("SIBYL_HTTP_PORT") or 8080),
            gateway_id=env.get("SIBYL_GATEWAY_ID") or socket.gethostname()[:48] or "gw",
            env=env.get("SIBYL_ENV", "live"),
            control_url=env.get("SIBYL_CONTROL_URL") or None,
            ingest_url=env.get("SIBYL_INGEST_URL") or None,
            tenant_keys=_csv(env.get("SIBYL_GATEWAY_TENANT_KEYS")),
            ingest_key=env.get("SIBYL_INGEST_KEY") or None,
            ingest_keys=_csv(env.get("SIBYL_INGEST_KEYS")),
            pepper=_pepper(env.get("SIBYL_KEY_PEPPER")),
            pinned_key_json=pin or None,
            pinned_keys_json=pinned or None,
            snapshot_dir=Path(snapshot_dir) if snapshot_dir else None,
            scrub_salt=salt.encode() if salt and len(salt.encode()) >= 16 else None,
            dev_hosts=_csv(env.get("SIBYL_DEV_HOSTS")),
            poll_s=float(env.get("SIBYL_POLICY_POLL_S") or 5.0),
            connect_s=float(env.get("SIBYL_UPSTREAM_CONNECT_S") or 5.0),
            ttfb_s=float(env.get("SIBYL_UPSTREAM_TTFB_S") or 60.0),
            upstream_ca_file=env.get("SIBYL_UPSTREAM_CA_FILE") or None,
            control_ca_file=env.get("SIBYL_CONTROL_CA_FILE") or None,
        )

    def streams(self) -> dict[str, str]:
        """stream name (the key's prefix) -> key, for well-formed keys of this gateway's env."""
        out: dict[str, str] = {}
        for key in self.tenant_keys:
            match = _KEY.fullmatch(key)
            if match and match.group(1) == self.env:
                out[match.group(2)] = key
        return out

    def ingest_routes(self) -> dict[str, str]:
        """stream -> the ``ingest:write`` key its tenant's telemetry is posted with (B-03).

        Ingest files events under the key's tenant, so a tenant's events must go with that
        tenant's key: ``SIBYL_INGEST_KEYS`` pairs with ``SIBYL_GATEWAY_TENANT_KEYS`` by position
        (a missing pair routes nothing, it never shifts a key onto another tenant); a lone
        ``SIBYL_INGEST_KEY`` belongs to the first tenant; with no ingest key at all each tenant
        posts with its own gateway key. A tenant without a route has its telemetry dropped."""
        pairs: list[tuple[str, str]] = []
        if self.ingest_keys:
            pairs = list(zip(self.tenant_keys, self.ingest_keys, strict=False))
        elif self.ingest_key and self.tenant_keys:
            pairs = [(self.tenant_keys[0], self.ingest_key)]
        else:
            pairs = [(k, k) for k in self.tenant_keys]
        out: dict[str, str] = {}
        for tenant_key, ingest_key in pairs:
            match = _KEY.fullmatch(tenant_key)
            if match and match.group(1) == self.env:
                out[match.group(2)] = ingest_key
        return out

    def problems(self) -> list[str]:
        issues: list[str] = []
        if self.env not in ("live", "test"):
            issues.append("SIBYL_ENV must be live or test")
        if self.pepper is None:
            issues.append("SIBYL_KEY_PEPPER missing or shorter than 32 bytes")
        if not self.pinned_key_json and not self.pinned_keys_json:
            issues.append("SIBYL_SNAPSHOT_PINNED_KEY(_FILE) missing: no snapshot can be verified")
        elif not self.pinned_key_json:
            issues.append("static SIBYL_SNAPSHOT_KEYS in use: key rotations are not followed")
        if not self.control_url:
            issues.append("SIBYL_CONTROL_URL missing: snapshots come from disk only")
        if len(self.streams()) != len(self.tenant_keys):
            issues.append("SIBYL_GATEWAY_TENANT_KEYS has malformed or wrong-env keys (ignored)")
        if not self.tenant_keys:
            issues.append("SIBYL_GATEWAY_TENANT_KEYS empty: serving from disk only")
        if self.ingest_keys and len(self.ingest_keys) != len(self.tenant_keys):
            issues.append(
                "SIBYL_INGEST_KEYS does not pair one key per SIBYL_GATEWAY_TENANT_KEYS entry:"
                " telemetry of the unpaired tenants is dropped"
            )
        elif not self.ingest_keys and self.ingest_key and len(self.tenant_keys) > 1:
            issues.append(
                "one SIBYL_INGEST_KEY for several tenants: set SIBYL_INGEST_KEYS; telemetry of"
                " every tenant but the first is dropped (B-03)"
            )
        if self.scrub_salt is None:
            issues.append("SIBYL_SCRUB_SALT missing or < 16 bytes: scrub tokens differ per process")
        return issues
