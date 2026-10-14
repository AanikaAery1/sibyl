# ruff: noqa: RUF001 -- the Cyrillic host is the point of the test
"""Provider base-URL allowlist (security review H3): every reported bypass is refused, ordinary
public https endpoints are accepted, and development hosts come from a table that no login
role can write, never from a session-settable GUC."""

from __future__ import annotations

import asyncpg
import pytest

from .conftest import LOGIN_ROLES, Conn

REFUSED = [
    # userinfo: the host group used to swallow `x@169.254...` and fail the inet cast open
    "https://x@169.254.169.254/latest/meta-data",
    "https://api.openai.com\\@127.0.0.1/",
    "https://user:pass@api.openai.com/v1",
    "https://@api.openai.com/v1",
    # non-dotted / non-decimal IPv4 forms (inet_aton semantics)
    "https://2130706433/",
    "https://127.1/",
    "https://0x7f000001/",
    "https://0x7f.0.0.1/",
    "https://0177.0.0.1/",
    "https://017700000001/",
    "https://169.254.43518/",
    "https://10.1/",
    # trailing dot
    "https://localhost./",
    "https://metadata.google.internal./",
    "https://127.0.0.1./",
    # IPv6 forms
    "https://[::ffff:127.0.0.1]/",
    "https://[::ffff:a9fe:a9fe]/",
    "https://[::ffff:7f00:1]/",
    "https://[::]/",
    "https://[::1]/",
    "https://[64:ff9b::7f00:1]/",
    "https://[64:ff9b:1::a9fe:a9fe]/",
    "https://[::127.0.0.1]/",
    "https://[2002:7f00:1::]/",
    "https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/",
    "https://[fe80::1]/",
    "https://[fc00::1]/",
    "https://[ff02::1]/",
    "https://[2001:db8::1]/",
    "https://[fe80::1%25eth0]/",
    # private, loopback, link-local, CGNAT, multicast, reserved and documentation IPv4
    "https://127.0.0.1/",
    "https://10.0.0.5/v1",
    "https://172.16.0.1/",
    "https://192.168.1.1/",
    "https://169.254.169.254/",
    "https://100.64.0.1/",
    "https://0.0.0.0/",
    "https://224.0.0.1/",
    "https://239.255.255.250/",
    "https://240.0.0.1/",
    "https://255.255.255.255/",
    "https://198.18.0.1/",
    "https://192.0.0.8/",
    "https://192.0.2.1/",
    "https://198.51.100.7/",
    "https://203.0.113.9/",
    # internal names
    "https://localhost/",
    "https://LOCALHOST/",
    "https://foo.localhost/",
    "https://metadata.google.internal/",
    "https://printer.local/",
    "https://metadata/",
    # scheme, syntax and port
    "http://api.openai.com/v1",
    "ftp://api.openai.com/",
    "https:/api.openai.com",
    "https://api.openai.com:0/",
    "https://api.openai.com:99999/",
    "https://api..openai.com/",
    "https://-api.openai.com/",
    "https://api_openai.com/",
    "https://ap i.openai.com/",
    "https://api.openai.com/\n",
    "https://аpi.openai.com/",  # Cyrillic a: only punycode hosts
    "https:///v1",
    "",
]

ALLOWED = [
    "https://api.openai.com/v1",
    "https://API.OpenAI.com/v1",
    "https://api.anthropic.com",
    "https://api.anthropic.com:443/v1/messages?beta=true#x",
    "https://my-resource.openai.azure.com/openai/deployments/x",
    "https://bedrock-runtime.eu-west-1.amazonaws.com/",
    "https://xn--80ak6aa92e.com/",
    "https://8.8.8.8/",
    "https://1.1.1.1:8443/v1",
    "https://[2606:4700:4700::1111]/",
    "https://api.provider-one.example/v1/%2Fpath",
    None,
]


@pytest.mark.parametrize("url", REFUSED)
def test_bypass_is_refused(admin: Conn, url: str) -> None:
    assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url($1)", url) is False


@pytest.mark.parametrize("url", ALLOWED)
def test_public_https_endpoint_is_allowed(admin: Conn, url: str | None) -> None:
    assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url($1)", url) is True


@pytest.mark.parametrize("role", LOGIN_ROLES)
def test_login_roles_cannot_widen_the_allowlist(roles: dict[str, Conn], role: str) -> None:
    conn = roles[role]
    with conn.tx(rollback=True):
        conn.execute("SET LOCAL sibyl.dev_hosts = '169.254.169.254,metadata.google.internal'")
        assert (
            conn.fetchval(
                "SELECT sibyl.is_allowlisted_base_url('http://169.254.169.254/latest/meta-data/')"
            )
            is False
        )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        with conn.tx(rollback=True):
            conn.execute("INSERT INTO sibyl.base_url_dev_host (host) VALUES ('evil.example')")


def test_dev_hosts_come_from_the_migrate_owned_table(admin: Conn) -> None:
    url = "http://sibyl-sim:8080/v1"
    assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url($1)", url) is False
    with admin.tx(rollback=True):
        admin.execute("SET LOCAL ROLE sibyl_migrate")
        admin.execute("INSERT INTO sibyl.base_url_dev_host (host, note) VALUES ('sibyl-sim', 't')")
        assert admin.fetchval("SELECT sibyl.is_allowlisted_base_url($1)", url) is True
        # a dev host still cannot smuggle userinfo or another host
        assert (
            admin.fetchval(
                "SELECT sibyl.is_allowlisted_base_url('http://sibyl-sim@169.254.169.254/')"
            )
            is False
        )


def test_dev_host_rows_must_be_hostnames(admin: Conn) -> None:
    with pytest.raises(asyncpg.CheckViolationError):
        with admin.tx(rollback=True):
            admin.execute("INSERT INTO sibyl.base_url_dev_host (host) VALUES ('a b@c')")


def test_provider_check_uses_the_strict_function(admin: Conn) -> None:
    definition = admin.fetchval(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'ck_provider_base_url'"
    )
    assert "is_allowlisted_base_url" in definition
