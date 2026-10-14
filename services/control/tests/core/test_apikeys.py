import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sibyl_control.core import apikeys
from sibyl_control.core.apikeys import (
    KEY_PATTERN,
    ApiKeyRejected,
    KeyRecord,
    RejectReason,
    generate_api_key,
    hash_secret,
    parse_api_key,
    pepper_from_env,
    reject_credentials_in_url,
    reject_key_from_browser,
    validate_expiry,
    validate_key_scopes,
    verify_api_key,
)
from sibyl_control.core.problems import ProblemError

PEPPER = b"p" * 32
NOW = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)


def record_for(plaintext: str, **overrides) -> KeyRecord:
    parsed = parse_api_key(plaintext)
    base = {
        "tenant_id": uuid4(),
        "id": uuid4(),
        "env": parsed.env,
        "secret_hash": hash_secret(parsed.secret, PEPPER),
        "scopes": frozenset({"ingest:write"}),
        "agent_id": None,
        "status": "active",
        "expires_at": NOW + timedelta(days=30),
        "rotation_grace_until": None,
    }
    base.update(overrides)
    return KeyRecord(**base)


def lookup_of(*records: tuple[str, KeyRecord]):
    table = {parse_api_key(k).prefix: r for k, r in records}

    async def lookup(prefix: str) -> KeyRecord | None:
        return table.get(prefix)

    return lookup


def test_generated_key_matches_published_regex_and_is_65_chars() -> None:
    generated = generate_api_key("live", PEPPER)
    assert re.fullmatch(KEY_PATTERN, generated.plaintext)
    assert len(generated.plaintext) == 65
    assert generated.secret_hash == hash_secret(parse_api_key(generated.plaintext).secret, PEPPER)
    assert generated.prefix == generated.plaintext[9:21]


def test_generated_keys_are_unique() -> None:
    assert generate_api_key("test", PEPPER).plaintext != generate_api_key("test", PEPPER).plaintext


def test_parse_rejects_malformed_and_hides_secret_in_repr() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    parsed = parse_api_key(plaintext)
    assert parsed.secret not in repr(parsed)
    for bad in ("", "sbl_prod_abcdefghijkl_" + "x" * 43, plaintext[:-1], "Bearer " + plaintext):
        with pytest.raises(ApiKeyRejected) as err:
            parse_api_key(bad)
        assert err.value.reason is RejectReason.MALFORMED


def test_hash_is_hmac_sha256_with_pepper() -> None:
    assert hash_secret("s", PEPPER) != hash_secret("s", b"q" * 32)
    assert len(hash_secret("s", PEPPER)) == 32


async def test_verify_accepts_a_valid_active_key() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    rec = record_for(plaintext)
    verified = await verify_api_key(plaintext, lookup_of((plaintext, rec)), PEPPER, now=NOW)
    assert verified.record is rec


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"status": "revoked"}, RejectReason.REVOKED),
        ({"status": "expired"}, RejectReason.EXPIRED),
        ({"expires_at": NOW - timedelta(seconds=1)}, RejectReason.EXPIRED),
        ({"status": "rotating", "rotation_grace_until": NOW}, RejectReason.GRACE_ELAPSED),
        ({"env": "test"}, RejectReason.ENV_MISMATCH),
    ],
)
async def test_verify_rejections(overrides, reason) -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    rec = record_for(plaintext, **overrides)
    with pytest.raises(ApiKeyRejected) as err:
        await verify_api_key(plaintext, lookup_of((plaintext, rec)), PEPPER, now=NOW)
    assert err.value.reason is reason


async def test_rotating_key_verifies_inside_grace() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    rec = record_for(plaintext, status="rotating", rotation_grace_until=NOW + timedelta(hours=1))
    await verify_api_key(plaintext, lookup_of((plaintext, rec)), PEPPER, now=NOW)


async def test_bad_secret_and_unknown_prefix_both_reject() -> None:
    real = generate_api_key("live", PEPPER).plaintext
    forged = real[:22] + ("A" if real[22] != "A" else "B") + real[23:]
    lookup = lookup_of((real, record_for(real)))
    with pytest.raises(ApiKeyRejected) as err:
        await verify_api_key(forged, lookup, PEPPER, now=NOW)
    assert err.value.reason is RejectReason.BAD_SECRET
    with pytest.raises(ApiKeyRejected) as err:
        await verify_api_key(generate_api_key("live", PEPPER).plaintext, lookup, PEPPER, now=NOW)
    assert err.value.reason is RejectReason.UNKNOWN


async def test_unknown_prefix_still_runs_a_constant_time_compare(monkeypatch) -> None:
    calls: list[int] = []
    real_compare = apikeys.hmac.compare_digest

    def spy(a, b):
        calls.append(1)
        return real_compare(a, b)

    monkeypatch.setattr(apikeys.hmac, "compare_digest", spy)

    async def nothing(prefix: str):
        return None

    with pytest.raises(ApiKeyRejected):
        await verify_api_key(generate_api_key("live", PEPPER).plaintext, nothing, PEPPER, now=NOW)
    assert calls == [1]


async def test_expected_env_is_enforced() -> None:
    plaintext = generate_api_key("test", PEPPER).plaintext
    with pytest.raises(ApiKeyRejected) as err:
        await verify_api_key(
            plaintext,
            lookup_of((plaintext, record_for(plaintext))),
            PEPPER,
            now=NOW,
            expected_env="live",
        )
    assert err.value.reason is RejectReason.ENV_MISMATCH


def test_rejection_message_never_contains_the_key() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    err = ApiKeyRejected(RejectReason.BAD_SECRET)
    assert plaintext not in str(err)
    assert err.problem().status == 401
    assert err.problem().code == "unauthenticated"


def test_scope_validation() -> None:
    assert validate_key_scopes(["ingest:write", "routing:read"], agent_id=None, env="live")
    with pytest.raises(ProblemError) as err:
        validate_key_scopes(["users:manage"], agent_id=None, env="live")
    assert err.value.code == "invalid_scope"
    for scopes, agent, env in (
        (["killswitch:pull", "agents:read"], None, "live"),
        (["killswitch:pull"], uuid4(), "live"),
        (["killswitch:pull"], None, "test"),
    ):
        with pytest.raises(ProblemError) as err:
            validate_key_scopes(scopes, agent_id=agent, env=env)
        assert err.value.code == "break_glass_scope_exclusive"
    assert validate_key_scopes(["killswitch:pull"], agent_id=None, env="live") == frozenset(
        {"killswitch:pull"}
    )


def test_expiry_defaults_to_365_days_and_caps_at_400() -> None:
    assert validate_expiry(None, now=NOW) == NOW + timedelta(days=365)
    assert validate_expiry(NOW + timedelta(days=400), now=NOW) == NOW + timedelta(days=400)
    for bad in (NOW + timedelta(days=401), NOW - timedelta(seconds=1)):
        with pytest.raises(ProblemError) as err:
            validate_expiry(bad, now=NOW)
        assert err.value.status == 422


def test_credentials_in_url_are_refused() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    reject_credentials_in_url([("limit", "5")])
    with pytest.raises(ProblemError) as err:
        reject_credentials_in_url([("api_key", plaintext)])
    assert err.value.code == "credential_in_url"
    assert plaintext not in (err.value.detail or "")


def test_keys_from_a_browser_origin_are_refused() -> None:
    plaintext = generate_api_key("live", PEPPER).plaintext
    reject_key_from_browser({"authorization": f"Bearer {plaintext}"})
    reject_key_from_browser({"origin": "https://console", "authorization": "Bearer jwt"})
    with pytest.raises(ProblemError) as err:
        reject_key_from_browser({"origin": "https://x", "authorization": f"Bearer {plaintext}"})
    assert err.value.code == "key_from_browser"


def test_pepper_from_env_requires_32_bytes() -> None:
    assert pepper_from_env("aa" * 32) == bytes.fromhex("aa" * 32)
    assert len(pepper_from_env("A" * 43)) == 32
    with pytest.raises(ValueError, match="32 bytes"):
        pepper_from_env("aa" * 8)


# --- test review F10 -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "grace", "reason"),
    [
        ("rotating", None, RejectReason.GRACE_ELAPSED),
        ("rotating", NOW, RejectReason.GRACE_ELAPSED),
        ("suspended", None, RejectReason.REVOKED),
        ("pending", None, RejectReason.REVOKED),
        ("", None, RejectReason.REVOKED),
        ("ACTIVE", None, RejectReason.REVOKED),
    ],
)
async def test_rotating_without_grace_and_unknown_statuses_are_refused(status, grace, reason):
    plaintext = generate_api_key("live", PEPPER).plaintext
    rec = record_for(plaintext, status=status, rotation_grace_until=grace)
    with pytest.raises(ApiKeyRejected) as err:
        await verify_api_key(plaintext, lookup_of((plaintext, rec)), PEPPER, now=NOW)
    assert err.value.reason is reason


async def test_flipping_any_secret_character_is_rejected() -> None:
    real = generate_api_key("live", PEPPER).plaintext
    lookup = lookup_of((real, record_for(real)))
    secret_start = len("sbl_live_") + 12 + 1
    for i in range(secret_start, len(real)):
        forged = real[:i] + ("A" if real[i] != "A" else "B") + real[i + 1 :]
        with pytest.raises(ApiKeyRejected) as err:
            await verify_api_key(forged, lookup, PEPPER, now=NOW)
        assert err.value.reason in (RejectReason.BAD_SECRET, RejectReason.MALFORMED), i
