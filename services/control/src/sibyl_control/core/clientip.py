"""The real client address behind trusted reverse proxies (security review M4).

``SIBYL_TRUSTED_PROXIES`` lists the proxy networks (CIDRs or bare addresses, comma-separated),
e.g. the Caddy container network. ``X-Forwarded-For`` is read only when the TCP peer is one of
them, and then walked right to left: the first hop that is not a trusted proxy is the client.
Entries a client wrote itself sit to the left of that hop and are never used. Rate limits and
``ip_hash`` audit fields are keyed on this address.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
UNKNOWN = "unknown"


def parse_trusted_proxies(value: str) -> tuple[Network, ...]:
    """Parse a comma-separated list of CIDRs/addresses; raises ``ValueError`` on garbage."""
    nets: list[Network] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            nets.append(ipaddress.ip_network(item, strict=True))
    return tuple(nets)


def _address(text: str) -> Address | None:
    text = text.strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _trusted(address: Address, trusted: Sequence[Network]) -> bool:
    return any(address.version == net.version and address in net for net in trusted)


def client_ip(peer: str | None, forwarded_for: Iterable[str], trusted: Sequence[Network]) -> str:
    """The client address for a request from ``peer`` carrying ``X-Forwarded-For`` headers."""
    if not peer:
        return UNKNOWN
    peer_address = _address(peer)
    if peer_address is None or not _trusted(peer_address, trusted):
        return peer
    hops = [hop for header in forwarded_for for hop in header.split(",")]
    candidate: Address = peer_address
    for hop in reversed(hops):
        address = _address(hop)
        if address is None:
            break
        candidate = address
        if not _trusted(address, trusted):
            break
    return str(candidate)
