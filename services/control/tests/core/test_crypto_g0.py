"""Security L6 / code review L5: strict signature decoding, SecretHandle hygiene, read-only
gateway contract tables (``sibyl_gateway.policy.view``, owned by the kernel lane)."""

from __future__ import annotations

import copy
import pickle

import pytest
from sibyl_control.core.crypto.signing import Ed25519Signer, b64url_decode, verify_document
from sibyl_gateway.policy.view import ERROR_MAP, FAIL_MODE_MATRIX, RETRY_AFTER_S, SecretHandle


@pytest.fixture(scope="module")
def signed():
    signer = Ed25519Signer.from_seed("k1", bytes(range(32)))
    doc = signer.sign_document({"a": 1})
    return signer, doc


def test_a_genuine_signature_verifies(signed) -> None:
    signer, doc = signed
    assert len(doc.signature) == 86
    assert verify_document(doc.body, doc.signature, signer.public_key_raw)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s + "==",  # padding
        lambda s: s[:40] + "!!" + s[42:],  # non-alphabet characters
        lambda s: s[:40] + "+/" + s[42:],  # standard, not url-safe, alphabet
        lambda s: s + "A",  # wrong length
        lambda s: " " + s,
        lambda s: s[:-1],
    ],
)
def test_non_canonical_signature_encodings_are_refused(signed, mutate) -> None:
    signer, doc = signed
    assert not verify_document(doc.body, mutate(doc.signature), signer.public_key_raw)


def test_b64url_decode_is_strict() -> None:
    assert b64url_decode("AAEC") == b"\x00\x01\x02"
    for bad in ("AA!C", "AAEC==", "A", "AA+C"):
        with pytest.raises(ValueError):
            b64url_decode(bad)


def test_secret_handle_refuses_reveal_after_zeroise() -> None:
    handle = SecretHandle(b"sk-provider-secret")
    assert handle.reveal() == b"sk-provider-secret"
    handle.zeroise()
    with pytest.raises(RuntimeError, match="zeroised"):
        handle.reveal()
    handle.zeroise()  # idempotent


@pytest.mark.parametrize("op", [pickle.dumps, copy.copy, copy.deepcopy])
def test_secret_handle_cannot_be_pickled_or_copied(op) -> None:
    with pytest.raises(TypeError):
        op(SecretHandle(b"secret"))


def test_secret_handle_never_prints_its_value() -> None:
    handle = SecretHandle(b"secret")
    assert "secret" not in repr(handle) and "secret" not in str(handle)


def test_gateway_contract_tables_are_read_only() -> None:
    for table in (ERROR_MAP, RETRY_AFTER_S, FAIL_MODE_MATRIX):
        with pytest.raises(TypeError):
            table["x"] = None  # type: ignore[index]
