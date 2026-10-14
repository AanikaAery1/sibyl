"""SSRF guard: the DB allowlist rule ported, and the connect-time resolved-address check."""

from __future__ import annotations

import pytest
from sibyl_gateway.proxy.ssrf import GuardedBackend, SsrfBlocked, is_allowlisted_base_url


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://api.openai.com/v1", True),
        ("https://8.8.8.8/v1", True),
        ("http://api.openai.com/v1", False),
        ("https://localhost/v1", False),
        ("https://foo.localhost/v1", False),
        ("https://metadata.internal/v1", False),
        ("https://169.254.169.254/latest", False),
        ("https://10.0.0.5/v1", False),
        ("https://172.16.3.4/v1", False),
        ("https://192.168.1.1/v1", False),
        ("https://100.64.0.1/v1", False),
        ("https://127.0.0.1:8443/v1", False),
        ("https://[::1]/v1", False),
        ("https://[fd00::1]/v1", False),
        ("https://[fe80::1]/v1", False),
        ("https://0.0.0.0/v1", False),
        ("ftp://api.openai.com", False),
        ("not a url", False),
    ],
)
def test_static_rule_matches_the_database_function(url: str, ok: bool) -> None:
    assert is_allowlisted_base_url(url) is ok


def test_dev_hosts_may_use_http() -> None:
    assert is_allowlisted_base_url("http://127.0.0.1:18082/v1", ["127.0.0.1"])
    assert is_allowlisted_base_url("http://sim:8080/v1", ["sim"])
    assert not is_allowlisted_base_url("http://127.0.0.2:18082/v1", ["127.0.0.1"])


@pytest.mark.parametrize("host", ["127.0.0.1", "10.9.8.7", "::1", "::ffff:10.0.0.1", "localhost"])
async def test_connect_time_check_refuses_private_addresses(host: str) -> None:
    with pytest.raises(SsrfBlocked):
        await GuardedBackend().connect_tcp(host, 443, timeout=1)


async def test_dev_host_skips_the_address_check_but_still_connects() -> None:
    backend = GuardedBackend(["127.0.0.1"])
    with pytest.raises(Exception) as err:
        await backend.connect_tcp("127.0.0.1", 9, timeout=1)  # discard port: refused, not blocked
    assert not isinstance(err.value, SsrfBlocked)


async def test_unix_sockets_are_never_upstreams() -> None:
    with pytest.raises(SsrfBlocked):
        await GuardedBackend().connect_unix_socket("/var/run/docker.sock")
