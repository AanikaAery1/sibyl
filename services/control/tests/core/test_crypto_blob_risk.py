import base64
from datetime import date
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.blob.base import (
    BlobInfo,
    BlobNotFound,
    BlobStore,
    InvalidBlobKey,
    payload_key,
    validate_key,
)
from sibyl_control.core.canonical import canonicalize
from sibyl_control.core.crypto.envelope import (
    DataKey,
    DecryptionError,
    EnvelopeCipher,
    LocalKek,
    build_aad,
    generate_dek,
    open_sealed,
    seal,
)
from sibyl_control.core.crypto.signing import (
    Ed25519Signer,
    verify_document,
)
from sibyl_control.core.risk import RiskDocument

TENANT = UUID("01927000-0000-7000-8000-000000000001")


def test_seal_round_trip_and_aad_binding() -> None:
    key = generate_dek()
    aad = build_aad(TENANT, "payload", 1)
    sealed = seal(key, b"hello", aad)
    assert len(sealed.nonce) == 12
    assert open_sealed(key, sealed, aad) == b"hello"
    with pytest.raises(DecryptionError):
        open_sealed(key, sealed, build_aad(uuid4(), "payload", 1))
    with pytest.raises(DecryptionError):
        open_sealed(generate_dek(), sealed, aad)


def test_aad_is_unambiguous() -> None:
    assert build_aad("ab", "c") != build_aad("a", "bc")


def test_nonces_are_unique() -> None:
    key = generate_dek()
    assert seal(key, b"x", b"").nonce != seal(key, b"x", b"").nonce


def test_local_kek_wraps_and_hides_material() -> None:
    kek_material = generate_dek()
    kek = LocalKek("kek-1", kek_material)
    dek = generate_dek()
    wrapped = kek.wrap(dek, b"ctx")
    assert dek not in wrapped
    assert kek.unwrap(wrapped, b"ctx") == dek
    with pytest.raises(DecryptionError):
        kek.unwrap(wrapped, b"other")
    assert kek_material.hex() not in repr(kek)
    with pytest.raises(ValueError, match="32 bytes"):
        LocalKek("bad", b"short")


def test_local_kek_from_env_value() -> None:
    raw = generate_dek()
    kek = LocalKek.from_env("kek-env", base64.urlsafe_b64encode(raw).decode())
    assert kek.unwrap(kek.wrap(b"k" * 32, b""), b"") == b"k" * 32


class StaticDeks:
    def __init__(self) -> None:
        self.keys = {1: DataKey(uuid4(), "payload", 1, generate_dek())}

    async def active(self, tenant_id: UUID, purpose: str) -> DataKey:
        return self.keys[max(self.keys)]

    async def by_version(self, tenant_id: UUID, purpose: str, version: int) -> DataKey:
        return self.keys[version]


async def test_envelope_cipher_round_trip_and_key_version() -> None:
    deks = StaticDeks()
    cipher = EnvelopeCipher(deks)
    blob = await cipher.encrypt(TENANT, "payload", b"secret body", context=b"obj-1")
    assert blob.key_version == 1
    assert b"secret body" not in blob.ciphertext
    assert await cipher.decrypt(TENANT, "payload", blob, context=b"obj-1") == b"secret body"
    with pytest.raises(DecryptionError):
        await cipher.decrypt(TENANT, "payload", blob, context=b"obj-2")


def test_data_key_repr_hides_material() -> None:
    material = generate_dek()
    assert material.hex() not in repr(DataKey(uuid4(), "payload", 1, material))


def test_ed25519_sign_and_verify_canonical_document() -> None:
    signer = Ed25519Signer.from_seed("snap-2026-10-v1", b"\x07" * 32)
    doc = {"version": 3, "tenants": {"b": 1, "a": 2}}
    signed = signer.sign_document(doc)
    assert signed.kid == "snap-2026-10-v1"
    assert signed.body == canonicalize(doc)
    assert verify_document(signed.body, signed.signature, signer.public_key_raw)
    tampered = signed.body.replace(b'"version":3', b'"version":4')
    assert not verify_document(tampered, signed.signature, signer.public_key_raw)
    assert not verify_document(signed.body, "!!notb64", signer.public_key_raw)
    assert "=" not in signed.signature


def test_signatures_are_deterministic_for_the_same_seed() -> None:
    a = Ed25519Signer.from_seed("k", b"\x01" * 32).sign_document({"x": 1})
    b = Ed25519Signer.from_seed("k", b"\x01" * 32).sign_document({"x": 1})
    assert a.signature == b.signature


def test_blob_keys() -> None:
    oid = UUID("01927000-0000-7000-8000-0000000000ff")
    key = payload_key(TENANT, date(2026, 10, 10), "span_content", oid)
    assert key == f"tenant/{TENANT}/2026-10-10/span_content/{oid}.bin"
    assert validate_key(key) == key
    for bad in ("/abs", "a/../b", "a//b", "", "a\\b", "x" * 1025, "a/b c"):
        with pytest.raises(InvalidBlobKey):
            validate_key(bad)
    with pytest.raises(InvalidBlobKey):
        payload_key(TENANT, date(2026, 10, 10), "../etc", oid)


class MemoryBlobs:
    def __init__(self) -> None:
        self.items: dict[str, bytes] = {}

    async def put(self, key, data, *, content_type, if_absent=True):
        self.items[validate_key(key)] = data
        return BlobInfo(key, len(data), "0" * 64, content_type)

    async def get(self, key):
        try:
            return self.items[key]
        except KeyError:
            raise BlobNotFound(key) from None

    async def head(self, key):
        return None

    async def delete(self, key):
        return self.items.pop(key, None) is not None

    async def list_prefix(self, prefix, *, limit=1000):
        return sorted(k for k in self.items if k.startswith(prefix))[:limit]

    async def presigned_get(self, key, *, expires_s):
        return None


async def test_blob_store_protocol_is_runtime_checkable() -> None:
    store = MemoryBlobs()
    assert isinstance(store, BlobStore)
    await store.put("tenant/x/a.bin", b"1", content_type="application/json")
    with pytest.raises(BlobNotFound):
        await store.get("tenant/x/missing.bin")


def test_risk_document_contract() -> None:
    horizon = {"horizon_s": 900, "probability_band": "0.25", "confidence": "medium"}
    doc = RiskDocument.model_validate(
        {
            "agent_id": str(TENANT),
            "horizons": {
                "15m": horizon,
                "1h": horizon | {"horizon_s": 3600},
                "24h": horizon | {"horizon_s": 86400, "probability_band": "0.05"},
            },
            "recommended_action": "watch",
            "rules_source": "rules/v1",
        }
    )
    assert doc.horizons["15m"].probability is None
    with pytest.raises(ValueError):
        RiskDocument.model_validate({**doc.model_dump(mode="json"), "rules_source": "magic"})
    with pytest.raises(ValueError):
        RiskDocument.model_validate({**doc.model_dump(mode="json"), "horizons": {"15m": horizon}})
