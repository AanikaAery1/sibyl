"""A local OIDC issuer for tests: discovery, JWKS, PKCE code flow, signed RS256/ES256 tokens.

Served through ``httpx.MockTransport`` so the real ``OidcClient`` code path runs unchanged.
``authorize(location)`` plays the browser + IdP login: it takes the redirect the api issued,
checks the PKCE challenge parameters and returns ``(code, state)`` for the callback.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _int_b64(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@dataclass
class _Grant:
    claims: dict[str, Any]
    challenge: str
    redirect_uri: str
    client_id: str
    nonce: str


@dataclass
class FakeIssuer:
    issuer: str = "https://idp.test/dex"
    client_id: str = "sibyl-console"
    client_secret: str = "console-secret"  # noqa: S105  (test fixture)
    kid: str = "k1"
    alg: str = "RS256"
    _key: Any = None
    grants: dict[str, _Grant] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)
    token_lifetime_s: int = 3600

    def __post_init__(self) -> None:
        self._key = self._new_key(self.alg)

    @staticmethod
    def _new_key(alg: str) -> Any:
        if alg == "ES256":
            return ec.generate_private_key(ec.SECP256R1())
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def rotate(self, kid: str) -> None:
        self.kid = kid
        self._key = self._new_key(self.alg)

    # ---- documents -------------------------------------------------------------------------
    def discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/auth",
            "token_endpoint": f"{self.issuer}/token",
            "jwks_uri": f"{self.issuer}/keys",
        }

    def jwk(self) -> dict[str, Any]:
        pub = self._key.public_key().public_numbers()
        if self.alg == "ES256":
            return {
                "kty": "EC",
                "crv": "P-256",
                "kid": self.kid,
                "use": "sig",
                "alg": "ES256",
                "x": b64u(pub.x.to_bytes(32, "big")),
                "y": b64u(pub.y.to_bytes(32, "big")),
            }
        return {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": _int_b64(pub.n),
            "e": _int_b64(pub.e),
        }

    # ---- signing ---------------------------------------------------------------------------
    def sign(self, claims: dict[str, Any], *, header: dict[str, Any] | None = None) -> str:
        head = {"alg": self.alg, "kid": self.kid, "typ": "JWT", **(header or {})}
        signing_input = f"{b64u(json.dumps(head).encode())}.{b64u(json.dumps(claims).encode())}"
        data = signing_input.encode()
        if self.alg == "ES256":
            der = self._key.sign(data, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            sig = self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{b64u(sig)}"

    def claims(self, sub: str, *, aud: str | list[str], **extra: Any) -> dict[str, Any]:
        now = int(time.time())
        return {
            "iss": self.issuer,
            "sub": sub,
            "aud": aud,
            "iat": now,
            "exp": now + self.token_lifetime_s,
            **extra,
        }

    def access_token(self, sub: str, *, aud: str = "sibyl-api", **extra: Any) -> str:
        return self.sign(self.claims(sub, aud=aud, azp="sibyl-cli", **extra))

    # ---- the browser + IdP half of the code flow ---------------------------------------------
    def authorize(self, location: str, *, sub: str, email: str, **extra: Any) -> tuple[str, str]:
        url = urlsplit(location)
        assert f"{url.scheme}://{url.netloc}{url.path}" == f"{self.issuer}/auth", location
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        assert q["response_type"] == "code"
        assert q["code_challenge_method"] == "S256"
        assert q["client_id"] == self.client_id
        code = secrets.token_urlsafe(16)
        claims = self.claims(
            sub,
            aud=self.client_id,
            email=email,
            email_verified=True,
            nonce=q["nonce"],
            auth_time=int(time.time()),
            **extra,
        )
        self.grants[code] = _Grant(
            claims, q["code_challenge"], q["redirect_uri"], q["client_id"], q["nonce"]
        )
        return code, q["state"]

    # ---- HTTP --------------------------------------------------------------------------------
    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(f"{request.method} {request.url}")
        path = str(request.url).split("?", 1)[0]
        if path == f"{self.issuer}/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery())
        if path == f"{self.issuer}/keys":
            return httpx.Response(200, json={"keys": [self.jwk()]})
        if path == f"{self.issuer}/token" and request.method == "POST":
            return self._token(request)
        return httpx.Response(404)

    def _token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        basic = request.headers.get("authorization", "")
        expected = (
            "Basic " + base64.b64encode(f"{self.client_id}:{self.client_secret}".encode()).decode()
        )
        if basic != expected:
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.grants.pop(form.get("code", ""), None)
        if grant is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        challenge = b64u(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
        if challenge != grant.challenge or form.get("redirect_uri") != grant.redirect_uri:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": "opaque",
                "token_type": "bearer",
                "id_token": self.sign(grant.claims),
            },
        )

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)
