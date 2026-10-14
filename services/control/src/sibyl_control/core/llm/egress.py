"""Outbound policy for LLM calls: a host allowlist per request, a public-address check at connect
time, TLS verification always on.

Two layers, both on every request:

1. ``AllowlistTransport`` refuses a URL whose host is not on the policy's allowlist (the three
   vendor API hosts plus the tenant's own vetted ``base_url`` host, if any), that carries
   userinfo, or that is not ``https`` (``http`` only for ``base_url_dev_host`` sim doubles).
   Redirects are never followed (the client sets ``follow_redirects=False``).
2. ``GuardedBackend`` (shared with the worker's credential probe) resolves the host when the
   connection is opened, refuses any non-public address and connects to the vetted literal, so
   DNS rebinding cannot slip between check and connect. TLS keeps the URL host for SNI and
   certificate checks; ``ssl.CERT_NONE`` is never used (a corporate CA bundle can be *added* via
   ``upstream_ca_file``).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

import httpx

from ...worker.jobs.net import GuardedBackend, GuardedTransport, Resolver, system_resolver
from .types import DEFAULT_BASE_URLS, EgressRefused

VENDOR_HOSTS: Final = frozenset(
    (urlsplit(url).hostname or "").lower() for url in DEFAULT_BASE_URLS.values()
)


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: frozenset[str] = VENDOR_HOSTS
    dev_hosts: frozenset[str] = field(default_factory=frozenset)
    resolver: Resolver = system_resolver
    ca_file: str | None = None

    def allowing(self, *hosts: str) -> EgressPolicy:
        extra = frozenset(h.lower().rstrip(".") for h in hosts if h)
        return EgressPolicy(self.allowed_hosts | extra, self.dev_hosts, self.resolver, self.ca_file)

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            raise EgressRefused("egress", "the URL has no host")
        if parts.username is not None or parts.password is not None:
            raise EgressRefused("egress", "credentials in a URL are refused")
        dev = host in self.dev_hosts
        if parts.scheme != "https" and not (dev and parts.scheme == "http"):
            raise EgressRefused("egress", "only https is allowed")
        if host not in self.allowed_hosts and not dev:
            raise EgressRefused("egress", f"host {host} is not on the egress allowlist")


class AllowlistTransport(httpx.AsyncBaseTransport):
    """Checks every outgoing request against the policy, then hands it to ``inner``."""

    def __init__(self, policy: EgressPolicy, inner: httpx.AsyncBaseTransport) -> None:
        self.policy = policy
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.policy.check(str(request.url))
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def guarded_transport(
    policy: EgressPolicy, inner: httpx.AsyncBaseTransport | None = None
) -> AllowlistTransport:
    """The production transport (``inner`` lets tests substitute a fake network)."""
    if inner is None:
        backend = GuardedBackend(policy.dev_hosts, resolver=policy.resolver)
        inner = GuardedTransport(backend, ca_file=policy.ca_file)
    return AllowlistTransport(policy, inner)


def dev_hosts_of(values: Iterable[str] | None) -> frozenset[str]:
    return frozenset(v.strip().lower() for v in values or () if v and v.strip())
