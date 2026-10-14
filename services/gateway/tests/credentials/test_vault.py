"""sibyl-seal/1 and the memory-only credential vault (D11)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from sibyl_gateway.credentials.sealing import (
    SealError,
    b64url_decode,
    open_sealed,
    public_bytes,
    seal,
    seal_aad,
)
from sibyl_gateway.credentials.vault import CredentialVault
from sibyl_gateway.policy.view import CredentialRef

from ..support import TENANT, Clock

CRED = uuid4()


def wiped(handle: object) -> bool:
    """Zeroised: empty (contracts-v1.0) or raising on reveal (G0 fix, contracts-v1.1)."""
    try:
        return handle.reveal() == b""  # type: ignore[attr-defined]
    except RuntimeError:
        return True


def test_seal_roundtrip_and_aad_binding() -> None:
    key = X25519PrivateKey.generate()
    sealed = seal(public_bytes(key), b"sk-secret", seal_aad(TENANT, CRED, 2))
    assert open_sealed(key, sealed, seal_aad(TENANT, CRED, 2)) == b"sk-secret"
    for aad in (
        seal_aad(TENANT, CRED, 3),
        seal_aad(TENANT, uuid4(), 2),
        seal_aad(uuid4(), CRED, 2),
    ):
        with pytest.raises(SealError):
            open_sealed(key, sealed, aad)
    with pytest.raises(SealError):
        open_sealed(X25519PrivateKey.generate(), sealed, seal_aad(TENANT, CRED, 2))
    with pytest.raises(SealError):
        open_sealed(key, sealed[:20], seal_aad(TENANT, CRED, 2))
    with pytest.raises(SealError):
        seal(b"short", b"x", b"")
    with pytest.raises(SealError):
        b64url_decode("abc=")


def test_aad_is_length_prefixed() -> None:
    assert seal_aad("ab", "c", 1) != seal_aad("a", "bc", 1)


def _bundle(
    vault: CredentialVault, secret: bytes = b"sk-v", version: int = 1, ttl: int = 300
) -> dict:
    pub = b64url_decode(vault.seal_public_key)
    return {
        "expires_in_s": ttl,
        "items": {
            str(CRED): {
                "auth_scheme": "bearer",
                "secret": seal(pub, secret, seal_aad(TENANT, CRED, version)),
                "base_url": "https://api.example.com/v1",
                "key_version": version,
            },
            "not-a-uuid": {"secret": "x", "key_version": 1},
        },
    }


def test_vault_holds_at_most_ttl_and_zeroises() -> None:
    clock = Clock()
    vault = CredentialVault(clock=clock)
    assert vault.install_bundle(TENANT, _bundle(vault, ttl=9999)) == 1
    assert "sk-v" not in repr(vault)
    handle = vault.get(CredentialRef(CRED, 1))
    assert handle is not None and handle.reveal() == b"sk-v"
    assert vault.get(CredentialRef(CRED, 2)) is None
    assert vault.key_version(CRED) == 1 and vault.auth_scheme(CRED) == "bearer"
    clock.advance(301)  # capped at 300 s regardless of what the bundle says
    assert vault.get(CredentialRef(CRED, 1)) is None
    assert wiped(handle)  # zeroised on expiry


def test_replacement_zeroises_the_old_secret_and_clear_wipes_all() -> None:
    vault = CredentialVault()
    vault.install_bundle(TENANT, _bundle(vault, b"old", 1))
    old = vault.get(CredentialRef(CRED, 1))
    vault.install_bundle(TENANT, _bundle(vault, b"new", 2))
    assert old is not None and wiped(old)
    new = vault.get(CredentialRef(CRED, 2))
    assert new is not None and new.reveal() == b"new"
    vault.clear()
    assert vault.get(CredentialRef(CRED, 2)) is None


def test_items_sealed_for_another_tenant_or_key_are_refused() -> None:
    vault = CredentialVault()
    assert vault.install_bundle(uuid4(), _bundle(vault)) == 0
    other = CredentialVault()
    assert vault.install_bundle(TENANT, _bundle(other)) == 0
