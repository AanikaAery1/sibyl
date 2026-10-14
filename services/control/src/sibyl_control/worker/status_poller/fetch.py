"""Guarded fetch of a tenant-configured status feed URL (SSRF defence).

``provider.status_feed_url`` is tenant input and the worker sits inside the deployment network,
so every fetch is checked before a byte leaves:

* ``https`` only, no userinfo; ``http`` is allowed only for configured dev hosts (the
  ``sibyl-sim`` double, R55), which also skip the address check;
* every address the host resolves to must be public (no loopback, private, link-local, CGNAT,
  multicast, reserved or unspecified ranges; IP literals included);
* no redirects, a 5 s timeout and a 64 KB body cap; the body must be JSON.

Residual risk: DNS can change between the check and httpx's own resolution (rebinding). The
window is one lookup; pinning the connection to the checked address is a follow-up.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

MAX_BYTES = 64 * 1024
TIMEOUT_S = 5.0
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

Resolver = Callable[[str], Awaitable[list[str]]]


class FeedError(Exception):
    """The feed could not be fetched safely; the poller records it, never raises past a tick."""


async def system_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


@dataclass(frozen=True)
class FetchPolicy:
    resolve: Resolver = system_resolve
    dev_hosts: frozenset[str] = field(default_factory=frozenset)
    max_bytes: int = MAX_BYTES
    timeout_s: float = TIMEOUT_S


def _public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT)
    )


async def check_url(url: str, policy: FetchPolicy) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        raise FeedError("feed URL has no host")
    if parts.username or parts.password:
        raise FeedError("feed URL must not carry credentials")
    if host in policy.dev_hosts:
        if parts.scheme not in ("http", "https"):
            raise FeedError("feed URL must be https (or http for a dev host)")
        return
    if parts.scheme != "https":
        raise FeedError("feed URL must be https")
    try:
        addresses = [host] if _is_literal(host) else await policy.resolve(host)
    except OSError as exc:
        raise FeedError(f"cannot resolve {host}: {exc}") from exc
    if not addresses or not all(_public(a) for a in addresses):
        raise FeedError(f"feed host {host} resolves to a private or reserved address")


def _is_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def fetch_feed(url: str, client: httpx.AsyncClient, policy: FetchPolicy) -> Any:
    await check_url(url, policy)
    try:
        async with client.stream(
            "GET",
            url,
            follow_redirects=False,
            timeout=policy.timeout_s,
            headers={"accept": "application/json", "user-agent": "sibyl-status-poller/1"},
        ) as response:
            if response.status_code != 200:
                raise FeedError(f"feed answered HTTP {response.status_code}")
            body = bytearray()
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > policy.max_bytes:
                    raise FeedError("feed body too large")
    except httpx.HTTPError as exc:
        raise FeedError(f"feed request failed: {type(exc).__name__}") from exc
    try:
        return json.loads(bytes(body))
    except (ValueError, UnicodeDecodeError) as exc:
        raise FeedError("feed body is not JSON") from exc
