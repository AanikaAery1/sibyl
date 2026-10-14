"""Security M4: the real client behind trusted proxies (SIBYL_TRUSTED_PROXIES)."""

from __future__ import annotations

import pytest
from sibyl_control.core.clientip import client_ip, parse_trusted_proxies
from sibyl_control.core.settings import Settings

CADDY = parse_trusted_proxies("172.30.0.0/16, 127.0.0.1/32,::1/128")


def test_parse_accepts_cidrs_and_bare_addresses() -> None:
    nets = parse_trusted_proxies(" 10.0.0.0/8 ,192.168.1.7,  fd00::/8 ,")
    assert [str(n) for n in nets] == ["10.0.0.0/8", "192.168.1.7/32", "fd00::/8"]
    assert parse_trusted_proxies("") == ()


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "not-an-ip", "10.0.0.1/8"])
def test_parse_refuses_garbage(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_trusted_proxies(bad)


def test_settings_expose_trusted_networks(monkeypatch) -> None:
    monkeypatch.setenv("SIBYL_TRUSTED_PROXIES", "172.30.0.0/16")
    assert [str(n) for n in Settings().trusted_networks()] == ["172.30.0.0/16"]
    monkeypatch.delenv("SIBYL_TRUSTED_PROXIES")
    assert Settings().trusted_networks() == ()


def test_untrusted_peer_is_the_client_and_its_xff_is_ignored() -> None:
    assert client_ip("203.0.113.9", ["1.2.3.4"], CADDY) == "203.0.113.9"
    assert client_ip("203.0.113.9", [], ()) == "203.0.113.9"


def test_xff_is_honoured_only_from_a_trusted_proxy() -> None:
    assert client_ip("172.30.0.5", ["198.51.100.7"], CADDY) == "198.51.100.7"


def test_client_supplied_xff_entries_left_of_the_real_client_are_ignored() -> None:
    # attacker sends XFF: 1.1.1.1; Caddy appends the real address
    assert client_ip("172.30.0.5", ["1.1.1.1, 198.51.100.7"], CADDY) == "198.51.100.7"
    assert client_ip("172.30.0.5", ["1.1.1.1", "198.51.100.7"], CADDY) == "198.51.100.7"


def test_chains_of_trusted_proxies_are_walked_right_to_left() -> None:
    assert client_ip("127.0.0.1", ["198.51.100.7, 172.30.0.9"], CADDY) == "198.51.100.7"


def test_garbage_hops_stop_the_walk_at_the_last_trusted_hop() -> None:
    assert client_ip("172.30.0.5", ["198.51.100.7, garbage"], CADDY) == "172.30.0.5"
    assert client_ip("172.30.0.5", [""], CADDY) == "172.30.0.5"


def test_ipv6_and_bracketed_forms() -> None:
    assert client_ip("::1", ["[2001:db8::1]"], CADDY) == "2001:db8::1"
    assert client_ip("::1", ["2001:db8::2"], CADDY) == "2001:db8::2"


def test_missing_peer_is_unknown() -> None:
    assert client_ip(None, ["198.51.100.7"], CADDY) == "unknown"
