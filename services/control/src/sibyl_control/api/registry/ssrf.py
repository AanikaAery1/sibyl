"""Provider ``base_url`` checks at write time (security-auditor T1, API.md §5.5).

Two gates, both must pass: ``sibyl.is_allowlisted_base_url()`` (strict, https only, no private
literals; development doubles only through ``base_url_dev_host``, which no login role can write)
and a handler-side DNS resolution that refuses a name resolving to any non-public address. The
basis is recorded as ``allowlist_basis``: ``known_provider`` for the well-known vendor hosts
(no resolution needed), ``resolver_checked`` otherwise. Development doubles skip resolution
(they live on the compose network) and are recorded ``resolver_checked``; ``demo_host`` says so.
The gateway and the worker probe re-resolve at connect time (DNS rebinding is out of reach here).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ...core.problems import ProblemError

RESOLVE_TIMEOUT_S = 2.0
KNOWN_PROVIDER_HOSTS: frozenset[str] = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.cohere.com",
        "api.groq.com",
    }
)
KNOWN_PROVIDER_SUFFIXES: tuple[str, ...] = (
    ".openai.azure.com",
    ".amazonaws.com",
    "-aiplatform.googleapis.com",
)

Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), RESOLVE_TIMEOUT_S
    )
    return [str(info[4][0]) for info in infos]


_resolver: Resolver = system_resolver


def set_resolver(resolver: Resolver | None) -> None:
    """Swap the DNS resolver (tests); ``None`` restores the system resolver."""
    global _resolver
    _resolver = resolver or system_resolver


@dataclass(frozen=True)
class CheckedUrl:
    url: str
    host: str
    basis: str  # known_provider | resolver_checked
    dev_host: bool


def _refused(detail: str) -> ProblemError:
    return ProblemError("base_url_not_allowlisted", detail)


def _is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return bool(ip.is_global) and not ip.is_multicast


def is_known_provider(host: str) -> bool:
    return host in KNOWN_PROVIDER_HOSTS or host.endswith(KNOWN_PROVIDER_SUFFIXES)


async def check_base_url(conn: Any, url: str) -> CheckedUrl:
    """Raise 422 ``base_url_not_allowlisted`` unless ``url`` passes both gates."""
    if not await conn.fetchval("SELECT sibyl.is_allowlisted_base_url($1)", url):
        raise _refused("the base URL is not on the provider allowlist (https, public host)")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    dev_hosts = await conn.fetchval("SELECT sibyl.base_url_dev_hosts()")
    if host in set(dev_hosts or ()):
        return CheckedUrl(url, host, "resolver_checked", True)
    if is_known_provider(host):
        return CheckedUrl(url, host, "known_provider", False)
    try:
        addresses = await _resolver(host, parts.port or 443)
    except (OSError, TimeoutError, UnicodeError):
        raise _refused("the base URL host does not resolve") from None
    if not addresses or not all(_is_public(a) for a in addresses):
        raise _refused("the base URL host resolves to a non-public address")
    return CheckedUrl(url, host, "resolver_checked", False)
