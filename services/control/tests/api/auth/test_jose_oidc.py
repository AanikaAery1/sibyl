"""JWS verification, claim validation, the OIDC client and the sealed state cookie (no DB)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sibyl_control.api.auth.jose import (
    JoseError,
    b64url_encode,
    looks_like_jwt,
    parse_compact,
    validate_claims,
    verify_signature,
)
from sibyl_control.api.auth.oidc import OidcClient, OidcError
from sibyl_control.api.auth.state import (
    new_login_state,
    open_state,
    pkce_challenge,
    safe_return_to,
    seal_state,
)

from .fake_issuer import FakeIssuer

NOW = datetime.now(UTC)


@pytest.fixture(autouse=True)
def _fresh_now() -> None:
    """Tokens are minted at real time; pin NOW per test, not per module import (long CI runs)."""
    global NOW
    NOW = datetime.now(UTC)


@pytest.fixture(params=["RS256", "ES256"])
def issuer(request: pytest.FixtureRequest) -> FakeIssuer:
    return FakeIssuer(alg=request.param)


def jwks(issuer: FakeIssuer) -> dict:
    return {"keys": [issuer.jwk()]}


def test_valid_token_verifies(issuer: FakeIssuer) -> None:
    token = issuer.access_token("user-1")
    compact = parse_compact(token)
    verify_signature(compact, jwks(issuer))
    validate_claims(compact.claims, issuer=issuer.issuer, audience="sibyl-api", now=NOW)


def test_tampered_payload_fails(issuer: FakeIssuer) -> None:
    head, _, sig = issuer.access_token("user-1").split(".")
    forged = b64url_encode(json.dumps(issuer.claims("admin", aud="sibyl-api")).encode())
    with pytest.raises(JoseError, match="bad_signature"):
        verify_signature(parse_compact(f"{head}.{forged}.{sig}"), jwks(issuer))


def test_alg_none_and_hmac_are_refused(issuer: FakeIssuer) -> None:
    claims = b64url_encode(json.dumps(issuer.claims("u", aud="sibyl-api")).encode())
    for alg in ("none", "HS256"):
        head = b64url_encode(json.dumps({"alg": alg, "kid": issuer.kid}).encode())
        with pytest.raises(JoseError, match="alg_not_allowed"):
            verify_signature(parse_compact(f"{head}.{claims}.AAAA"), jwks(issuer))


def test_unknown_kid_is_refused(issuer: FakeIssuer) -> None:
    token = issuer.sign(issuer.claims("u", aud="sibyl-api"), header={"kid": "other"})
    with pytest.raises(JoseError, match="unknown_kid"):
        verify_signature(parse_compact(token), jwks(issuer))


def test_crit_header_is_refused(issuer: FakeIssuer) -> None:
    token = issuer.sign(issuer.claims("u", aud="sibyl-api"), header={"crit": ["exp"]})
    with pytest.raises(JoseError, match="unsupported_header"):
        parse_compact(token)


@pytest.mark.parametrize(
    ("change", "cause"),
    [
        ({"iss": "https://evil.test"}, "issuer_mismatch"),
        ({"aud": "someone-else"}, "audience_mismatch"),
        ({"aud": ["sibyl-api", "x"]}, "azp_required"),
        ({"exp": int(NOW.timestamp()) - 3600}, "expired"),
        ({"iat": int(NOW.timestamp()) + 3600}, "not_yet_valid"),
        ({"nbf": int(NOW.timestamp()) + 3600}, "not_yet_valid"),
        ({"sub": ""}, "missing_sub"),
        ({"exp": True}, "bad_exp"),
    ],
)
def test_claims_are_validated(change: dict, cause: str) -> None:
    claims = FakeIssuer().claims("u", aud="sibyl-api") | change
    with pytest.raises(JoseError, match=cause):
        validate_claims(claims, issuer="https://idp.test/dex", audience="sibyl-api", now=NOW)


def test_lifetime_and_nonce() -> None:
    issuer = FakeIssuer()
    long_lived = issuer.claims("u", aud="sibyl-api") | {"exp": int(NOW.timestamp()) + 7200}
    with pytest.raises(JoseError, match="lifetime_too_long"):
        validate_claims(
            long_lived, issuer=issuer.issuer, audience="sibyl-api", now=NOW, max_lifetime_s=3600
        )
    with pytest.raises(JoseError, match="nonce_mismatch"):
        validate_claims(
            issuer.claims("u", aud="a", nonce="n1"),
            issuer=issuer.issuer,
            audience="a",
            now=NOW,
            nonce="n2",
        )


def test_looks_like_jwt() -> None:
    assert looks_like_jwt("a.b.c")
    assert not looks_like_jwt("sbl_live_x.y.z")
    assert not looks_like_jwt("sibyl_sess_abc")


async def test_client_discovers_verifies_and_refreshes_on_rotation() -> None:
    issuer = FakeIssuer()
    client = OidcClient(httpx.AsyncClient(transport=issuer.transport()))
    claims = await client.verify(
        issuer.access_token("u1"), issuer_url=issuer.issuer, audience="sibyl-api", now=NOW
    )
    assert claims["sub"] == "u1"
    issuer.rotate("k2")
    claims = await client.verify(
        issuer.access_token("u2"), issuer_url=issuer.issuer, audience="sibyl-api", now=NOW
    )
    assert claims["sub"] == "u2"
    assert sum("/keys" in r for r in issuer.requests) == 2
    await client.aclose()


async def test_discovery_issuer_must_match_exactly() -> None:
    issuer = FakeIssuer()
    real = issuer.discovery

    def lying() -> dict:
        return real() | {"issuer": "https://other.test"}

    issuer.discovery = lying  # type: ignore[method-assign]
    client = OidcClient(httpx.AsyncClient(transport=issuer.transport()))
    with pytest.raises(OidcError, match="issuer_mismatch"):
        await client.metadata(issuer.issuer)


async def test_unreachable_issuer_is_an_oidc_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    client = OidcClient(httpx.AsyncClient(transport=httpx.MockTransport(boom)))
    with pytest.raises(OidcError, match="issuer_unreachable"):
        await client.metadata("https://idp.test/dex")


def test_state_cookie_round_trip_and_tamper() -> None:
    key = b"k" * 32
    state = new_login_state(tenant_id="t", issuer_id="i", return_to="/x", now=NOW)
    sealed = seal_state(key, state)
    assert open_state(key, sealed, now=NOW, ttl_s=600) == state
    assert open_state(b"j" * 32, sealed, now=NOW, ttl_s=600) is None
    flipped = sealed[:-2] + ("A" if sealed[-2] != "A" else "B") + sealed[-1]
    assert open_state(key, flipped, now=NOW, ttl_s=600) is None
    assert open_state(key, sealed, now=NOW + timedelta(minutes=11), ttl_s=600) is None
    assert open_state(key, None, now=NOW, ttl_s=600) is None


def test_pkce_s256_vector() -> None:
    # RFC 7636 appendix B
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("/console/agents?x=1", "/console/agents?x=1"),
        ("//evil.test/x", "/"),
        ("https://evil.test", "/"),
        ("/\\evil.test", "/"),
        ("/a\nb", "/"),
        (None, "/"),
    ],
)
def test_return_to_is_same_origin_only(value: str | None, expected: str) -> None:
    assert safe_return_to(value) == expected
