"""``credential_probe``: does a vaulted provider credential authenticate? (B14, API §5.5)

Runs only in the worker (the api enqueues it from ``POST /provider-credentials/{id}/verify``).

1. In a read-only tenant transaction: load the credential metadata, re-check
   ``sibyl.is_allowlisted_base_url()`` and read the dev-double hosts, read the sealed secret
   through ``sibyl.probe_credential_sealed(job_id)`` (the worker has no SELECT on ciphertext; the
   definer releases it only for a probe job whose lease it holds) and open it with the kernel DEK
   convention (B11; the worker holds the KEK, B7).
2. Outside any transaction: ``GET <base_url>/models`` (the OpenAI-compatible surface, D-decision)
   with the secret in the scheme's header, through ``net.GuardedTransport`` (connect-time IP
   re-check, no redirects, a deadline, a body cap). The secret is dropped right after.
3. The outcome, recorded by the runner in one fenced transaction:

   ======================  ==========  ===========================================  ==========
   upstream answer         job         audit                                        retry
   ======================  ==========  ===========================================  ==========
   2xx                     done        ``credential.verified`` (+ last_verified_at)  no
   401/403, other 4xx      done        ``credential.probe_failed`` (http_status)     no
   408/425/429/5xx, I/O    queued      ``credential.probe_failed`` when exhausted    yes
   not allowlisted / SSRF  failed      ``credential.probe_failed`` (0)               no
   gone/revoked/shredded   failed      ``credential.probe_failed`` (0)               no
   ======================  ==========  ===========================================  ==========

Never stored or logged: the secret, the auth header, the upstream body or error text.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from uuid import UUID

import httpx
from sibyl_schemas.values import JobKind

from ...core.audit import AuditRecord
from ...core.crypto.deks import ConnDekProvider, DekUnavailable, KeyShredded, kek_from_settings
from ...core.crypto.envelope import DecryptionError, EncryptedBlob
from ...core.crypto.sealed import open_credential
from ...core.problems import ProblemError
from .net import (
    GuardedBackend,
    GuardedTransport,
    guarded_get,
    is_ssrf_refusal,
    system_resolver,
)
from .runner import ClaimedJob, JobEnv, JobOutcome

RESOURCE = "provider_credential"
PROBE_PATH = "/models"
RETRYABLE_STATUS = frozenset({408, 425, 429})
_CRED_SQL = """
SELECT id, provider_id, base_url, allowlist_basis, auth_scheme, status, key_version,
       sibyl.is_allowlisted_base_url(base_url) AS allowlisted,
       sibyl.base_url_dev_hosts() AS dev_hosts
  FROM sibyl.provider_credential WHERE tenant_id = $1 AND id = $2
"""
# The worker cannot SELECT ciphertext; this definer returns it only for a probe job it holds.
_SEALED_SQL = "SELECT * FROM sibyl.probe_credential_sealed($1)"


class UnsupportedScheme(ValueError):
    pass


def auth_headers(scheme: str, secret: str) -> dict[str, str]:
    """The upstream auth header for ``provider_credential.auth_scheme``."""
    name = scheme.strip().lower().replace("_", "-")
    if name in ("bearer", "authorization"):
        return {"authorization": f"Bearer {secret}"}
    if name in ("x-api-key", "api-key-header"):
        return {"x-api-key": secret}
    if name in ("api-key", "azure"):
        return {"api-key": secret}
    raise UnsupportedScheme(name)


def probe_url(base_url: str) -> str:
    return base_url.rstrip("/") + PROBE_PATH


class CredentialProbe:
    kind = JobKind.CREDENTIAL_PROBE

    def __init__(self, env: JobEnv) -> None:
        self.env = env

    # --- audits --------------------------------------------------------------------------

    def _failed(self, job: ClaimedJob, http_status: int, error: str) -> AuditRecord:
        credential = job.subject_id or _credential_id(job.params)
        return AuditRecord(
            action="credential.probe_failed",
            actor_type="system",
            resource_type=RESOURCE,
            resource_id=credential,
            detail={
                "credential_id": credential,
                "http_status": http_status,
                "job_id": job.id,
                "error": error,
            },
        )

    def _verified(self, job: ClaimedJob, row: Mapping[str, Any], http_status: int) -> AuditRecord:
        return AuditRecord(
            action="credential.verified",
            actor_type="system",
            resource_type=RESOURCE,
            resource_id=row["id"],
            detail={
                "credential_id": row["id"],
                "provider_id": row["provider_id"],
                "base_url": row["base_url"],
                "allowlist_basis": row["allowlist_basis"],
                "key_version": int(row["key_version"]),
                "http_status": http_status,
                "job_id": job.id,
            },
        )

    def exhausted(self, job: ClaimedJob, last: JobOutcome | None) -> tuple[AuditRecord, ...]:
        status = int((last.result or {}).get("http_status", 0)) if last is not None else 0
        error = (last.error if last is not None else None) or "lease_expired"
        return (self._failed(job, status, error),)

    def _refuse(self, job: ClaimedJob, error: str, http_status: int = 0) -> JobOutcome:
        return JobOutcome.failed(
            error,
            {"outcome": "not_probed", "http_status": http_status},
            self._failed(job, http_status, error),
        )

    # --- run -----------------------------------------------------------------------------

    async def _load(self, job: ClaimedJob) -> tuple[Mapping[str, Any], str] | JobOutcome:
        credential = job.subject_id or _credential_id(job.params)
        if credential is None:
            return JobOutcome.failed("invalid_params")
        try:
            kek = kek_from_settings(self.env.settings)
        except ProblemError:
            return JobOutcome.retry("vault_unavailable")
        async with self.env.db.tenant_tx(job.tenant_id, readonly=True) as conn:
            row = await conn.fetchrow(_CRED_SQL, job.tenant_id, credential)
            if row is None:
                return JobOutcome.failed("credential_unavailable")
            if row["status"] not in ("active", "rotating"):
                return self._refuse(job, "credential_unavailable")
            if not row["allowlisted"]:
                return self._refuse(job, "base_url_refused")
            sealed = await conn.fetchrow(_SEALED_SQL, job.id)
            if sealed is None or sealed["credential_id"] != row["id"]:
                return self._refuse(job, "credential_unavailable")
            blob = EncryptedBlob(
                int(sealed["key_version"]), bytes(sealed["nonce"]), bytes(sealed["ciphertext"])
            )
            try:
                secret = await open_credential(
                    ConnDekProvider(conn, kek), job.tenant_id, row["id"], blob
                )
            except KeyShredded:
                return self._refuse(job, "credential_shredded")
            except (DekUnavailable, DecryptionError):
                return self._refuse(job, "credential_unopenable")
        return dict(row), secret.decode("utf-8")

    def _transport(self, dev_hosts: Any) -> httpx.AsyncBaseTransport:
        override = self.env.extras.get("probe_transport")
        if override is not None:
            transport: httpx.AsyncBaseTransport = override(dev_hosts)
            return transport
        backend = GuardedBackend(
            dev_hosts or (), resolver=self.env.extras.get("probe_resolver", system_resolver)
        )
        ca_file = getattr(self.env.settings, "upstream_ca_file", None)
        return GuardedTransport(backend, ca_file=ca_file)

    async def run(self, job: ClaimedJob) -> JobOutcome:
        loaded = await self._load(job)
        if isinstance(loaded, JobOutcome):
            return loaded
        row, secret = loaded
        try:
            headers = auth_headers(row["auth_scheme"], secret)
        except UnsupportedScheme:
            return self._refuse(job, "unsupported_auth_scheme")
        finally:
            del secret
        try:
            response = await guarded_get(
                probe_url(row["base_url"]),
                {**headers, "accept": "application/json", "user-agent": "sibyl-probe/1"},
                transport=self._transport(row["dev_hosts"]),
                timeout_s=float(self.env.extras.get("probe_timeout_s", 10.0)),
            )
        except (TimeoutError, httpx.TimeoutException):
            return JobOutcome.retry("probe_timeout", {"http_status": 0})
        except (httpx.HTTPError, OSError) as exc:
            if is_ssrf_refusal(exc):
                return self._refuse(job, "base_url_refused")
            return JobOutcome.retry("probe_unreachable", {"http_status": 0})
        finally:
            headers.clear()
        status = response.status
        result = {"http_status": status, "latency_ms": response.latency_ms}
        if 200 <= status < 300:
            tenant, credential = job.tenant_id, row["id"]

            async def mark(conn: Any) -> None:
                await conn.execute(
                    "UPDATE sibyl.provider_credential SET last_verified_at = now()"
                    " WHERE tenant_id = $1 AND id = $2",
                    tenant,
                    credential,
                )

            return JobOutcome.done(
                {"outcome": "verified", **result}, self._verified(job, row, status), apply=mark
            )
        if status in RETRYABLE_STATUS or status >= 500:
            return JobOutcome.retry("upstream_unavailable", result)
        return JobOutcome.done(
            {"outcome": "rejected", **result}, self._failed(job, status, "upstream_rejected")
        )


def _credential_id(params: Mapping[str, Any]) -> UUID | None:
    try:
        return UUID(str(params["credential_id"]))
    except (KeyError, ValueError):
        return None
