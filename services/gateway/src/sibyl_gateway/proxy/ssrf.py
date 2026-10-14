"""SSRF guard for upstream calls (STRIDE T1): the DB allowlist rule, plus a connect-time IP check.

``is_allowlisted_base_url`` is a line-for-line port of ``sibyl.is_allowlisted_base_url()``
(migration 0001): https only, no loopback / link-local / RFC 1918 / CGNAT / ULA literals, no
``localhost``/``*.localhost``/``*.internal``; hosts in ``SIBYL_DEV_HOSTS`` (the DB's
``sibyl.dev_hosts``) may use http. DNS names pass the static rule, so ``GuardedBackend``
resolves them at connect time, refuses if **any** address is private (rebinding), and connects
to the vetted address literal so the check and the connection cannot diverge. TLS still uses
the URL host for SNI and certificate checks. Redirects are never followed (see ``upstream``).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable
from typing import Any

import anyio
import httpcore

_URL = re.compile(r"^([a-z][a-z0-9+.-]*)://(\[[^\]]+\]|[^/:?#]+)(:[0-9]{1,5})?([/?#].*)?$")
_BLOCKED_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


class SsrfBlocked(httpcore.ConnectError):
    """The upstream address is not allowlisted (never retried against the same host)."""


def _blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified or ip.is_multicast:
        return True
    return any(ip.version == net.version and ip in net for net in _BLOCKED_NETS)


def is_allowlisted_base_url(url: str, dev_hosts: Iterable[str] = ()) -> bool:
    match = _URL.match(url or "")
    if match is None:
        return False
    scheme = match.group(1).lower()
    host = match.group(2).strip("[]").lower()
    if host in {h.strip().lower() for h in dev_hosts if h.strip()}:
        return scheme in ("http", "https")
    if scheme != "https":
        return False
    if host in ("localhost", "localhost.localdomain") or host.endswith((".localhost", ".internal")):
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True  # a DNS name: GuardedBackend re-checks the resolved addresses
    return not _blocked_ip(ip)


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Resolve, vet every address, connect to the vetted literal (rebinding-safe)."""

    def __init__(
        self, dev_hosts: Iterable[str] = (), inner: httpcore.AsyncNetworkBackend | None = None
    ) -> None:
        self._dev = frozenset(h.strip().lower() for h in dev_hosts if h.strip())
        self._inner = inner or httpcore.AnyIOBackend()

    async def _vet(self, host: str, port: int) -> str:
        try:
            literal = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            literal = None
        if literal is not None:
            if _blocked_ip(literal):
                raise SsrfBlocked("upstream address is not allowlisted")
            return str(literal)
        try:
            infos = await anyio.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise httpcore.ConnectError(f"cannot resolve upstream host: {exc}") from None
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
        if not addresses or any(_blocked_ip(ip) for ip in addresses):
            raise SsrfBlocked("upstream host resolves to a non-allowlisted address")
        return str(addresses[0])

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 (httpcore interface)
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        target = host if host.lower() in self._dev else await self._vet(host, port)
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
