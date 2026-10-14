"""Outbound HTTP for worker jobs: SSRF-strict, connect-time IP re-check, bounded (B14, STRIDE T1).

A tenant-supplied ``base_url`` is fetched only from the worker (never inline in the api), and:

* the URL must pass ``sibyl.is_allowlisted_base_url()`` (checked by the caller in the DB: https,
  no private literal, dev doubles only through ``base_url_dev_host``);
* ``GuardedBackend`` resolves the host **at connect time**, refuses if any address is not public
  (loopback, RFC 1918, link-local, CGNAT, ULA, multicast, reserved, unspecified; IPv4-mapped
  IPv6 unwrapped) and connects to the vetted literal, so DNS rebinding cannot slip between the
  check and the connection; TLS still uses the URL host for SNI and certificate checks;
* hosts in ``base_url_dev_host`` (the compose sim doubles) skip the address check only;
* no redirects, no environment proxies, an overall deadline and a response body cap.

Mirrors ``sibyl_gateway.proxy.ssrf`` (control must not import the gateway).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import anyio
import httpcore
import httpx

DEFAULT_TIMEOUT_S = 10.0
CONNECT_TIMEOUT_S = 3.0
MAX_BODY_BYTES = 64 * 1024
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

Resolver = Callable[[str, int], Awaitable[list[str]]]


class SsrfBlocked(httpcore.ConnectError):
    """The upstream address is not allowed (never retried)."""


def is_ssrf_refusal(exc: BaseException) -> bool:
    """``httpx`` re-raises transport errors as ``httpx.ConnectError``; look through the chain."""
    seen: BaseException | None = exc
    while seen is not None:
        if isinstance(seen, SsrfBlocked):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def is_public_address(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT:
        return False
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified)


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Resolve, vet every address, connect to the vetted literal (rebinding-safe)."""

    def __init__(
        self,
        dev_hosts: Iterable[str] = (),
        *,
        resolver: Resolver = system_resolver,
        inner: httpcore.AsyncNetworkBackend | None = None,
    ) -> None:
        self._dev = frozenset(h.strip().lower() for h in dev_hosts if h.strip())
        self._resolve = resolver
        self._inner = inner or httpcore.AnyIOBackend()

    async def vet(self, host: str, port: int) -> str:
        bare = host.strip("[]").lower()
        if bare in self._dev:
            return host
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            pass
        else:
            if not is_public_address(bare):
                raise SsrfBlocked("upstream address is not public")
            return bare
        try:
            addresses = await self._resolve(bare, port)
        except (OSError, UnicodeError) as exc:
            raise httpcore.ConnectError(
                f"cannot resolve upstream host: {type(exc).__name__}"
            ) from None
        if not addresses or not all(is_public_address(a) for a in addresses):
            raise SsrfBlocked("upstream host resolves to a non-public address")
        return addresses[0].split("%", 1)[0]

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 (httpcore interface)
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        target = await self.vet(host, port)
        return await self._inner.connect_tcp(
            target,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 (httpcore interface)
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SsrfBlocked("unix sockets are never an upstream")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """``httpx`` transport whose pool connects only through ``GuardedBackend``."""

    def __init__(self, backend: GuardedBackend, *, ca_file: str | None = None) -> None:
        context = (
            ssl.create_default_context(cafile=ca_file) if ca_file else httpx.create_ssl_context()
        )
        super().__init__(verify=context, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=context,
            max_connections=4,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=backend,
        )


@dataclass(frozen=True)
class ProbeResponse:
    status: int
    latency_ms: int


async def guarded_get(
    url: str,
    headers: Mapping[str, str],
    *,
    transport: httpx.AsyncBaseTransport,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_body: int = MAX_BODY_BYTES,
) -> ProbeResponse:
    """One GET under an overall deadline; the body is read up to ``max_body`` and discarded."""
    started = time.monotonic()
    client = httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout_s, connect=min(CONNECT_TIMEOUT_S, timeout_s)),
        follow_redirects=False,
        trust_env=False,
    )
    async with client, asyncio.timeout(timeout_s):
        async with client.stream("GET", url, headers=dict(headers)) as response:
            seen = 0
            async for chunk in response.aiter_bytes():
                seen += len(chunk)
                if seen > max_body:
                    break
            status = response.status_code
    return ProbeResponse(status, int((time.monotonic() - started) * 1000))
