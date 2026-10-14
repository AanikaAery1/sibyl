"""B11: one DEK-wrap convention and one sealed-object layout in ``core/crypto``.

Unit level: the wrap AAD is ``tenant ‖ purpose ‖ version`` (length-prefixed), object contexts
are pinned byte-for-byte, the sealed payload layout round-trips, and the connection-bound DEK
provider unwraps what ``wrap_dek`` wrapped and refuses shredded / foreign-KEK rows.
"""

from __future__ import annotations

import importlib
import struct
from typing import Any
from uuid import UUID, uuid4

import pytest
from sibyl_control.core.crypto import deks as core_deks
from sibyl_control.core.crypto import sealed as core_sealed
from sibyl_control.core.crypto.deks import (
    ConnDekProvider,
    DekUnavailable,
    KeyShredded,
    dek_wrap_aad,
    kek_from_settings,
    new_wrapped_dek,
    unwrap_dek,
    wrap_dek,
)
from sibyl_control.core.crypto.envelope import (
    DecryptionError,
    EncryptedBlob,
    LocalKek,
    build_aad,
    envelope_aad,
    generate_dek,
)
from sibyl_control.core.crypto.sealed import (
    MAGIC,
    SealedFormatError,
    credential_context,
    issuer_secret_context,
    open_compact,
    open_credential,
    open_payload_blob,
    pack,
    payload_context,
    seal_compact,
    seal_credential,
    seal_payload,
    unpack,
)
from sibyl_control.core.problems import ProblemError
from sibyl_control.core.settings import Settings

TENANT = UUID("01927000-0000-7000-8000-0000000000aa")
KEK = LocalKek("kek-b11", bytes(range(32)))


def _lp(*parts: str) -> bytes:
    return b"".join(struct.pack(">I", len(p.encode())) + p.encode() for p in parts)


def test_wrap_aad_is_tenant_purpose_version() -> None:
    assert dek_wrap_aad(TENANT, "payload", 3) == _lp(str(TENANT), "payload", "3")
    assert dek_wrap_aad(TENANT, "payload", 3) == build_aad(TENANT, "payload", 3)


def test_object_contexts_are_pinned() -> None:
    oid = uuid4()
    assert payload_context(oid) == _lp("payload_ref", str(oid))
    assert credential_context(oid) == _lp("provider_credential", str(oid))
    assert issuer_secret_context(oid) == _lp("oidc_issuer", str(oid), "client_secret")


def test_wrap_and_unwrap_round_trip_and_bind_every_field() -> None:
    dek = generate_dek()
    wrapped = wrap_dek(KEK, TENANT, "credential", 2, dek)
    assert unwrap_dek(KEK, TENANT, "credential", 2, wrapped) == dek
    for tenant, purpose, version in (
        (uuid4(), "credential", 2),
        (TENANT, "payload", 2),
        (TENANT, "credential", 3),
    ):
        with pytest.raises(DecryptionError):
            unwrap_dek(KEK, tenant, purpose, version, wrapped)


def test_new_wrapped_dek_refuses_unknown_purposes_and_hides_material() -> None:
    fresh = new_wrapped_dek(KEK, TENANT, "config", 1)
    assert unwrap_dek(KEK, TENANT, "config", 1, fresh.wrapped) == fresh.material
    assert fresh.material.hex() not in repr(fresh)
    with pytest.raises(ValueError, match="purpose"):
        new_wrapped_dek(KEK, TENANT, "snapshot", 1)


def test_kek_from_settings_is_a_503_when_unset() -> None:
    for settings in (None, Settings()):
        with pytest.raises(ProblemError) as err:
            kek_from_settings(settings)
        assert err.value.code == "service_unavailable"


def test_payload_layout_round_trips_and_rejects_foreign_bytes() -> None:
    blob = EncryptedBlob(7, b"n" * 12, b"ciphertext+tag")
    raw = pack(blob)
    assert raw.startswith(MAGIC) and unpack(raw) == blob
    with pytest.raises(SealedFormatError):
        unpack(b"SBL")
    with pytest.raises(SealedFormatError):
        unpack(b"XXXX" + raw[4:])


class FakeConn:
    """``tenant_key`` rows for ConnDekProvider (only the queries it issues)."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    async def fetchrow(self, sql: str, tenant_id: UUID, purpose: str, *args: Any) -> Any:
        for row in self.rows:
            if row["tenant_id"] != tenant_id or row["purpose"] != purpose:
                continue
            if "state = 'active'" in sql and row["state"] != "active":
                continue
            if "version = $3" in sql and row["version"] != args[0]:
                continue
            return row
        return None

    async def fetchval(self, sql: str, tenant_id: UUID, purpose: str) -> bool:
        return any(
            r["tenant_id"] == tenant_id and r["purpose"] == purpose and r["state"] == "shredded"
            for r in self.rows
        )


def _row(purpose: str, version: int, *, state: str = "active", kek: LocalKek = KEK) -> dict:
    wrapped = (
        None if state == "shredded" else wrap_dek(kek, TENANT, purpose, version, generate_dek())
    )
    return {
        "id": uuid4(),
        "tenant_id": TENANT,
        "purpose": purpose,
        "version": version,
        "state": state,
        "kek_id": kek.kek_id,
        "wrapped_dek": wrapped,
    }


async def test_conn_provider_seals_and_opens_credentials_and_payloads() -> None:
    deks = ConnDekProvider(FakeConn([_row("credential", 1), _row("payload", 1)]), KEK)
    cred = uuid4()
    sealed = await seal_credential(deks, TENANT, cred, b"sk-live-123")
    assert await open_credential(deks, TENANT, cred, sealed.blob) == b"sk-live-123"
    with pytest.raises(DecryptionError):
        await open_credential(deks, TENANT, uuid4(), sealed.blob)

    oid = uuid4()
    payload = await seal_payload(deks, TENANT, oid, b'{"a":1}')
    assert unpack(payload.packed).key_version == 1
    assert await open_payload_blob(deks, TENANT, oid, unpack(payload.packed)) == b'{"a":1}'
    assert payload.key_id == (await deks.active(TENANT, "payload")).key_id
    with pytest.raises(DecryptionError):
        await open_payload_blob(deks, TENANT, uuid4(), unpack(payload.packed))


async def test_compact_form_matches_the_envelope_aad() -> None:
    deks = ConnDekProvider(FakeConn([_row("config", 1)]), KEK)
    issuer = uuid4()
    ct, key_id, version = await seal_compact(
        deks, TENANT, "config", b"client-secret", issuer_secret_context(issuer)
    )
    assert version == 1
    plain = await open_compact(deks, TENANT, "config", 1, ct, issuer_secret_context(issuer))
    assert plain == b"client-secret"
    assert (await deks.by_version(TENANT, "config", 1)).key_id == key_id
    assert envelope_aad(TENANT, "config", 1, b"x") == build_aad(TENANT, "config", 1) + b"x"


async def test_conn_provider_reports_shredded_and_foreign_kek_keys() -> None:
    other = LocalKek("kek-other", generate_dek())
    deks = ConnDekProvider(
        FakeConn([_row("payload", 1, state="shredded"), _row("config", 1, kek=other)]), KEK
    )
    with pytest.raises(KeyShredded):
        await deks.active(TENANT, "payload")
    with pytest.raises(KeyShredded):
        await deks.by_version(TENANT, "payload", 1)
    with pytest.raises(DekUnavailable, match="another KEK"):
        await deks.active(TENANT, "config")
    with pytest.raises(DekUnavailable):
        await deks.active(TENANT, "credential")


def test_the_duplicates_are_gone() -> None:
    """B11: lanes import the convention from core; a name a lane module still exposes must be
    the core object itself (``ingest.deks`` is a pure re-export kept for in-flight lanes)."""
    core = {**vars(core_deks), **vars(core_sealed)}
    for module, names in (
        ("sibyl_control.api.credentials.vault", ("dek_wrap_aad", "wrap_dek", "ConnDekProvider")),
        ("sibyl_control.api.snapshot.credentials", ("PgDekProvider", "dek_aad")),
        ("sibyl_control.api.auth.dek", ("PgDekProvider", "wrap_aad", "new_wrapped_dek")),
        ("sibyl_control.api.reads.payloads", ("payload_context",)),
        ("sibyl_control.ingest.payloads", ("object_context", "pack", "unpack", "open_payload")),
    ):
        try:
            mod = importlib.import_module(module)
        except ModuleNotFoundError:
            continue
        for name in names:
            if hasattr(mod, name):
                assert getattr(mod, name) is core.get(name), (module, name)
    shim = importlib.import_module("sibyl_control.ingest.deks")  # re-export for lane U
    assert {n for n in vars(shim) if not n.startswith("_")} <= set(core) | {"annotations"}
    for name in ("PgDekProvider", "KeyShredded", "DekUnavailable", "wrap_dek", "dek_wrap_aad"):
        assert getattr(shim, name) is core[name]
