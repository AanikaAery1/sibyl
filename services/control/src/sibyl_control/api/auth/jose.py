"""Minimal JWS (compact) verification for OIDC ID tokens and bearer access tokens.

Built on ``cryptography`` only (no JOSE dependency in the workspace; see the hand-back change
request). Allowlisted asymmetric algorithms only: ``none`` and every HMAC alg are refused, so a
public JWK can never be used as an HMAC secret (alg-confusion). The key is chosen by ``kid`` and
must match the alg's key type. Claims are validated strictly: exact ``iss``, ``aud`` containing
the expected audience, ``exp``/``nbf``/``iat`` with bounded leeway, optional ``nonce`` and a
maximum token lifetime.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

LEEWAY_S = 60
MAX_TOKEN_BYTES = 16 * 1024


class JoseError(Exception):
    """Any verification failure; ``cause`` is a short machine label for audit."""

    def __init__(self, cause: str) -> None:
        super().__init__(cause)
        self.cause = cause


@dataclass(frozen=True)
class _Alg:
    kty: str
    hash: hashes.HashAlgorithm | None
    kind: str  # pkcs1 | pss | ecdsa | eddsa
    curve: str | None = None
    coord_len: int = 0


ALGORITHMS: Mapping[str, _Alg] = {
    "RS256": _Alg("RSA", hashes.SHA256(), "pkcs1"),
    "RS384": _Alg("RSA", hashes.SHA384(), "pkcs1"),
    "RS512": _Alg("RSA", hashes.SHA512(), "pkcs1"),
    "PS256": _Alg("RSA", hashes.SHA256(), "pss"),
    "ES256": _Alg("EC", hashes.SHA256(), "ecdsa", "P-256", 32),
    "ES384": _Alg("EC", hashes.SHA384(), "ecdsa", "P-384", 48),
    "EdDSA": _Alg("OKP", None, "eddsa", "Ed25519"),
}
_CURVES = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or any(c in value for c in "=+/ \n"):
        raise JoseError("malformed")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        raise JoseError("malformed") from None


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise JoseError("malformed") from None
    if not isinstance(value, dict):
        raise JoseError("malformed")
    return value


@dataclass(frozen=True)
class Compact:
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and not token.startswith(("sbl_", "sibyl_sess_"))


def parse_compact(token: str) -> Compact:
    """Split and decode without verifying (callers must verify before trusting anything)."""
    if not token or len(token) > MAX_TOKEN_BYTES:
        raise JoseError("malformed")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("malformed")
    header = _json_object(b64url_decode(parts[0]))
    claims = _json_object(b64url_decode(parts[1]))
    signature = b64url_decode(parts[2])
    if header.get("crit"):
        raise JoseError("unsupported_header")
    return Compact(header, claims, f"{parts[0]}.{parts[1]}".encode("ascii"), signature)


def _int_from_b64(value: Any) -> int:
    return int.from_bytes(b64url_decode(value), "big")


def public_key(jwk: Mapping[str, Any]) -> Any:
    kty = jwk.get("kty")
    try:
        if kty == "RSA":
            return rsa.RSAPublicNumbers(
                _int_from_b64(jwk["e"]), _int_from_b64(jwk["n"])
            ).public_key()
        if kty == "EC":
            curve = _CURVES[jwk["crv"]]
            numbers = ec.EllipticCurvePublicNumbers(
                _int_from_b64(jwk["x"]), _int_from_b64(jwk["y"]), curve
            )
            return numbers.public_key()
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
    except (KeyError, ValueError, TypeError):
        raise JoseError("bad_jwk") from None
    raise JoseError("bad_jwk")


def _candidates(
    header: Mapping[str, Any], keys: Iterable[Mapping[str, Any]], alg: _Alg
) -> list[Mapping[str, Any]]:
    usable = [
        k
        for k in keys
        if k.get("kty") == alg.kty
        and k.get("use", "sig") == "sig"
        and (alg.curve is None or k.get("crv") == alg.curve)
        and (k.get("alg") in (None, header.get("alg")))
    ]
    kid = header.get("kid")
    if kid is not None:
        return [k for k in usable if k.get("kid") == kid]
    return usable if len(usable) == 1 else []


def _verify_one(key: Any, alg: _Alg, signing_input: bytes, signature: bytes) -> None:
    if alg.kind == "eddsa":
        key.verify(signature, signing_input)
        return
    digest = alg.hash
    if digest is None:  # only EdDSA hashes internally
        raise InvalidSignature
    if alg.kind == "pkcs1":
        key.verify(signature, signing_input, padding.PKCS1v15(), digest)
    elif alg.kind == "pss":
        pss = padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size)
        key.verify(signature, signing_input, pss, digest)
    else:
        if len(signature) != 2 * alg.coord_len:
            raise InvalidSignature
        r = int.from_bytes(signature[: alg.coord_len], "big")
        s = int.from_bytes(signature[alg.coord_len :], "big")
        key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(digest))


def has_key_for(compact: Compact, jwks: Mapping[str, Any]) -> bool:
    alg = ALGORITHMS.get(str(compact.header.get("alg")))
    return alg is not None and bool(_candidates(compact.header, jwks.get("keys", []), alg))


def verify_signature(compact: Compact, jwks: Mapping[str, Any]) -> None:
    alg = ALGORITHMS.get(str(compact.header.get("alg")))
    if alg is None:
        raise JoseError("alg_not_allowed")
    candidates = _candidates(compact.header, jwks.get("keys", []), alg)
    if not candidates:
        raise JoseError("unknown_kid")
    for jwk in candidates:
        try:
            _verify_one(public_key(jwk), alg, compact.signing_input, compact.signature)
            return
        except (InvalidSignature, ValueError, TypeError):
            continue
    raise JoseError("bad_signature")


def _numeric(claims: Mapping[str, Any], name: str, *, required: bool) -> int | None:
    value = claims.get(name)
    if value is None:
        if required:
            raise JoseError(f"missing_{name}")
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise JoseError(f"bad_{name}")
    return int(value)


def validate_claims(
    claims: Mapping[str, Any],
    *,
    issuer: str,
    audience: str,
    now: datetime,
    nonce: str | None = None,
    max_lifetime_s: int | None = None,
    leeway_s: int = LEEWAY_S,
) -> None:
    if claims.get("iss") != issuer:
        raise JoseError("issuer_mismatch")
    aud = claims.get("aud")
    audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
    if audience not in audiences:
        raise JoseError("audience_mismatch")
    if len(audiences) > 1 and claims.get("azp") is None:
        raise JoseError("azp_required")
    if not isinstance(claims.get("sub"), str) or not claims["sub"]:
        raise JoseError("missing_sub")
    ts = int(now.timestamp())
    exp = _numeric(claims, "exp", required=True)
    iat = _numeric(claims, "iat", required=True)
    nbf = _numeric(claims, "nbf", required=False)
    assert exp is not None and iat is not None
    if exp <= ts - leeway_s:
        raise JoseError("expired")
    if iat > ts + leeway_s or (nbf is not None and nbf > ts + leeway_s):
        raise JoseError("not_yet_valid")
    if max_lifetime_s is not None and exp - iat > max_lifetime_s:
        raise JoseError("lifetime_too_long")
    if nonce is not None:
        presented = claims.get("nonce")
        if not isinstance(presented, str) or not hmac.compare_digest(presented, nonce):
            raise JoseError("nonce_mismatch")
