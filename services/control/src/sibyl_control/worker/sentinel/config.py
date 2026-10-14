"""The tenant's Sentinel configuration and its vaulted key (shared by the worker and the api).

The key is sealed with ``seal_credential`` under the tenant ``credential`` DEK, AAD bound to the
config's ``credential_id``. It is read back only through ``sibyl.sentinel_sealed_key()`` (the
worker has no SELECT on the ciphertext) and opened just before a call; callers drop it right
after building the client. It is never logged, audited or returned.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final
from uuid import UUID

import httpx
from sibyl_schemas.values import SentinelTask

from ...core.crypto.deks import ConnDekProvider, DekUnavailable
from ...core.crypto.envelope import DecryptionError, EncryptedBlob, KeyEncryptionKey
from ...core.crypto.sealed import open_credential, seal_credential
from ...core.llm import EgressPolicy, LlmClient, Price
from ...core.llm.egress import dev_hosts_of

CONFIG_COLUMNS: Final = (
    "tenant_id, enabled, provider, model, base_url, credential_id, key_hint, key_updated_at,"
    " key_version, daily_budget_usd, sampling_rate, tasks, price_in_usd_per_mtok,"
    " price_out_usd_per_mtok, version, updated_by_user_id, created_at, updated_at"
)
_CONFIG_SQL = f"SELECT {CONFIG_COLUMNS} FROM sibyl.sentinel_config WHERE tenant_id = $1"  # noqa: S608
_SEALED_SQL = "SELECT * FROM sibyl.sentinel_sealed_key()"
_DEV_HOSTS_SQL = "SELECT sibyl.base_url_dev_hosts()"

TransportFactory = Callable[[EgressPolicy], httpx.AsyncBaseTransport]


class KeyUnavailable(Exception):
    """No key is vaulted, or it cannot be opened (shredded tenant key, wrong AAD)."""


@dataclass(frozen=True)
class SentinelConfig:
    tenant_id: UUID
    enabled: bool
    provider: str
    model: str
    base_url: str | None
    credential_id: UUID
    has_key: bool
    key_hint: str | None
    daily_budget_usd: Decimal
    sampling_rate: Decimal
    tasks: frozenset[str]
    price: Price | None
    version: int
    row: Mapping[str, Any]

    def task_on(self, task: SentinelTask) -> bool:
        return self.enabled and task.value in self.tasks

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> SentinelConfig:
        price = None
        if row["price_in_usd_per_mtok"] is not None:
            price = Price(
                Decimal(row["price_in_usd_per_mtok"]), Decimal(row["price_out_usd_per_mtok"])
            )
        return cls(
            tenant_id=row["tenant_id"],
            enabled=bool(row["enabled"]),
            provider=str(row["provider"]),
            model=str(row["model"]),
            base_url=row["base_url"],
            credential_id=row["credential_id"],
            has_key=row["key_version"] is not None,
            key_hint=row["key_hint"],
            daily_budget_usd=Decimal(row["daily_budget_usd"]),
            sampling_rate=Decimal(row["sampling_rate"]),
            tasks=frozenset(row["tasks"] or ()),
            price=price,
            version=int(row["version"]),
            row=dict(row),
        )


async def load_config(conn: Any, tenant: UUID) -> SentinelConfig | None:
    row = await conn.fetchrow(_CONFIG_SQL, tenant)
    return None if row is None else SentinelConfig.from_row(row)


async def seal_key(
    conn: Any, kek: KeyEncryptionKey, tenant: UUID, credential_id: UUID, api_key: str
) -> tuple[EncryptedBlob, UUID]:
    sealed = await seal_credential(
        ConnDekProvider(conn, kek), tenant, credential_id, api_key.encode()
    )
    return sealed.blob, sealed.key_id


async def open_key(conn: Any, kek: KeyEncryptionKey, tenant: UUID) -> str:
    row = await conn.fetchrow(_SEALED_SQL)
    if row is None:
        raise KeyUnavailable("no Sentinel key is vaulted")
    blob = EncryptedBlob(int(row["key_version"]), bytes(row["nonce"]), bytes(row["ciphertext"]))
    try:
        secret = await open_credential(
            ConnDekProvider(conn, kek), tenant, row["credential_id"], blob
        )
    except (DekUnavailable, DecryptionError):
        raise KeyUnavailable("the Sentinel key cannot be opened") from None
    return secret.decode("utf-8")


async def egress_policy(conn: Any, settings: Any) -> EgressPolicy:
    dev = await conn.fetchval(_DEV_HOSTS_SQL)
    return EgressPolicy(
        dev_hosts=dev_hosts_of(dev), ca_file=getattr(settings, "upstream_ca_file", None)
    )


def build_client(
    cfg: SentinelConfig,
    api_key: str,
    policy: EgressPolicy,
    transport_factory: TransportFactory | None = None,
    **kw: Any,
) -> LlmClient:
    """The tenant's client; ``transport_factory`` substitutes the network (tests, demos)."""
    transport = transport_factory(policy) if transport_factory is not None else None
    return LlmClient(
        cfg.provider,
        api_key,
        cfg.model,
        base_url=cfg.base_url,
        transport=transport,
        policy=policy,
        **kw,
    )
