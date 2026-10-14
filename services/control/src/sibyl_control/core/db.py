"""asyncpg pool and the per-request tenant transaction (ADR-7, API.md §10.1).

Every tenant-scoped unit of work is ONE transaction whose FIRST statement is
``SELECT sibyl.set_tenant($1)`` (transaction-local ``app.tenant_id``; RLS fails closed without it).
Session-level ``SET`` is forbidden. ``pre_tenant()`` is the read-only escape hatch for the two
allowlisted pre-tenant reads (``api_key_lookup``, public signing keys).
"""

from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any, Protocol
from uuid import UUID

SET_TENANT_SQL = "SELECT sibyl.set_tenant($1::uuid)"

# 40P01 deadlock_detected, 40001 serialization_failure: the whole transaction may be re-run.
RETRYABLE_SQLSTATES: frozenset[str] = frozenset({"40P01", "40001"})
DEFAULT_TX_ATTEMPTS = 3
DEFAULT_RETRY_BASE_S = 0.02
DEFAULT_RETRY_MAX_S = 0.5


def is_retryable(exc: BaseException) -> bool:
    """True for errors after which re-running the whole transaction is safe."""
    return getattr(exc, "sqlstate", None) in RETRYABLE_SQLSTATES


async def retry_transient[T](
    op: Callable[[], Awaitable[T]],
    *,
    attempts: int = DEFAULT_TX_ATTEMPTS,
    base_delay_s: float = DEFAULT_RETRY_BASE_S,
    max_delay_s: float = DEFAULT_RETRY_MAX_S,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    rand: Callable[[], float] = random.random,
) -> T:
    """Run ``op`` up to ``attempts`` times, retrying only 40P01 / 40001 (code review H2).

    ``op`` must be a complete transaction with no effects outside it (an idempotent handler body):
    it is simply called again. Back-off doubles from ``base_delay_s`` up to ``max_delay_s`` with
    jitter in ``[50 %, 100 %]`` of the step, so two deadlocked peers do not collide again.
    """
    if attempts < 1:
        raise ValueError("attempts must be >= 1")
    for attempt in range(1, attempts + 1):
        try:
            return await op()
        except Exception as exc:
            if attempt == attempts or not is_retryable(exc):
                raise
            step = min(max_delay_s, base_delay_s * 2 ** (attempt - 1))
            await sleep(step * (0.5 + rand() / 2))
    raise AssertionError("unreachable")  # pragma: no cover


class Connection(Protocol):
    async def execute(self, query: str, *args: Any) -> Any: ...
    async def fetch(self, query: str, *args: Any) -> list[Any]: ...
    async def fetchrow(self, query: str, *args: Any) -> Any: ...
    async def fetchval(self, query: str, *args: Any) -> Any: ...


class _Pool(Protocol):
    def acquire(self) -> Any: ...
    async def close(self) -> None: ...


async def _init_connection(conn: Any) -> None:
    for name in ("json", "jsonb"):
        await conn.set_type_codec(name, encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


class Database:
    def __init__(self, pool: _Pool) -> None:
        self._pool = pool

    @classmethod
    async def connect(
        cls,
        dsn: str,
        *,
        min_size: int = 2,
        max_size: int = 10,
        application_name: str = "sibyl-control",
        command_timeout: float = 30.0,
    ) -> Database:
        import asyncpg

        pool = await asyncpg.create_pool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            command_timeout=command_timeout,
            init=_init_connection,
            # UTC everywhere: date casts and date_trunc follow the session time zone.
            server_settings={"application_name": application_name, "timezone": "UTC"},
        )
        return cls(pool)

    async def close(self) -> None:
        await self._pool.close()

    @asynccontextmanager
    async def tenant_tx(
        self,
        tenant_id: UUID,
        *,
        readonly: bool = False,
        statement_timeout_ms: int | None = None,
    ) -> AsyncIterator[Any]:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")
        async with self._pool.acquire() as conn, conn.transaction(readonly=readonly):
            await conn.execute(SET_TENANT_SQL, tenant_id)
            if statement_timeout_ms is not None:
                await conn.execute(f"SET LOCAL statement_timeout = {int(statement_timeout_ms)}")
            yield conn

    async def run_in_tenant_tx[T](
        self,
        tenant_id: UUID,
        body: Callable[[Any], Awaitable[T]],
        *,
        readonly: bool = False,
        statement_timeout_ms: int | None = None,
        attempts: int = DEFAULT_TX_ATTEMPTS,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> T:
        """``body(conn)`` in a fresh ``tenant_tx``, re-run on deadlock / serialization failure.

        Use it around idempotent handler transactions (audit + routing + outbox in one unit). The
        body is re-executed from scratch, so it must not keep state from a failed attempt.
        """

        async def attempt() -> T:
            async with self.tenant_tx(
                tenant_id, readonly=readonly, statement_timeout_ms=statement_timeout_ms
            ) as conn:
                return await body(conn)

        return await retry_transient(attempt, attempts=attempts, sleep=sleep)

    @asynccontextmanager
    async def pre_tenant(self) -> AsyncIterator[Any]:
        async with self._pool.acquire() as conn, conn.transaction(readonly=True):
            yield conn

    @asynccontextmanager
    async def system_tx(self) -> AsyncIterator[Any]:
        """A read-write transaction with no tenant set (RLS hides every tenant row).

        Only for the allowlisted global tables and the SECURITY DEFINER maintenance functions
        a login role is granted: ``signing_key_set`` issuance (B10), ``partition_ensure_ahead``,
        ``partition_retire_expired`` (lane U housekeeping)."""
        async with self._pool.acquire() as conn, conn.transaction():
            yield conn

    @asynccontextmanager
    async def listen_connection(self) -> AsyncIterator[Any]:
        """A dedicated pooled connection, outside any transaction, for LISTEN (worker wake-ups)."""
        async with self._pool.acquire() as conn:
            yield conn

    async def ping(self) -> bool:
        async with self.pre_tenant() as conn:
            return bool(await conn.fetchval("SELECT 1"))
