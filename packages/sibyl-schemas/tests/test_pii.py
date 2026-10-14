"""The shared ``pii_standard`` detector registry (``sibyl_schemas.pii``).

Each detector has a positive corpus it must find (whole value) and a negative corpus it must
not fire on; the whole negative corpus is also run through every detector at once (0 false
positives). The detector ids match the DB's ``pii_standard`` redaction profile.
"""

from __future__ import annotations

import pytest
from sibyl_schemas import pii

POSITIVE: dict[str, list[str]] = {
    "email": ["jane.doe@example.com", "a+tag@sub.example.co.uk", "x_y%z@corp.io"],
    "phone": ["+1 415 555 0134", "+44 20 7946 0958", "(415) 555-0134", "+91 98765 43210"],
    "credit_card": ["4111 1111 1111 1111", "5555-5555-5555-4444", "378282246310005"],
    "iban": [
        "GB82 WEST 1234 5698 7654 32",
        "DE89370400440532013000",
        "FR1420041010050500013M02606",
    ],
    "ip_address": ["10.1.2.3", "192.168.0.254", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
    "national_id": [
        "123-45-6789",  # US SSN
        "AB 12 34 56 C",  # UK NINO
        "QQ123456A",  # UK NINO, compact
        "2345 6789 0124",  # India Aadhaar (Verhoeff)
        "ABCPE1234F",  # India PAN
    ],
    "postal_address": [
        "221 Baker Street",
        "1600 Pennsylvania Avenue",
        "10 Downing St",
        "SW1A 2AA",
        "EC1A 1BB",
    ],
}

NEGATIVE: list[str] = [
    "user@localhost",  # no TLD
    "4111 1111 1111 1112",  # Luhn fails
    "1234 5678 9012 3456",  # Luhn fails
    "GB82 WEST 1234 5698 7654 33",  # mod-97 fails
    "999.1.2.3",  # not an IP
    "000-12-3456",  # SSN area 000
    "666-12-3456",  # SSN area 666
    "123-00-4567",  # SSN group 00
    "2345 6789 0123",  # Aadhaar Verhoeff fails
    "1234 5678 9012",  # Aadhaar cannot start with 1
    "BG 12 34 56 C",  # NINO prefix BG is never issued
    "01927000-0000-7000-8000-00000000000a",  # uuid
    "2026-10-11T09:00:00.000Z",  # timestamp
    "version 1.2.3",
    "price 1499.00 USD",
    "build 20261011",
    "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "retry in 300 s",
    "Baker Street",  # no house number
]


def test_the_registry_lists_the_pii_standard_detectors() -> None:
    assert pii.PII_DETECTOR_IDS == (
        "email",
        "phone",
        "credit_card",
        "iban",
        "ip_address",
        "national_id",
        "postal_address",
    )
    assert set(pii.PII_DETECTORS) == set(pii.PII_DETECTOR_IDS)
    assert set(POSITIVE) == set(pii.PII_DETECTOR_IDS)


@pytest.mark.parametrize(
    ("detector", "value"), [(d, v) for d, values in POSITIVE.items() for v in values]
)
def test_each_detector_finds_its_positive_corpus(detector: str, value: str) -> None:
    hits = pii.find_pii(f"see {value} here", (detector,))
    assert [(h.detector, h.value) for h in hits] == [(detector, value)]


@pytest.mark.parametrize("value", NEGATIVE)
def test_no_detector_fires_on_the_negative_corpus(value: str) -> None:
    assert pii.find_pii(f"see {value} here") == []


def test_redact_replaces_every_hit_and_reports_rules_fired() -> None:
    text = "mail jane@example.com, card 4111 1111 1111 1111, ssn 123-45-6789 at 221 Baker Street"
    out, fired = pii.redact_pii(text, pii.PII_DETECTOR_IDS, lambda d, v: f"<{d}>")
    assert out == "mail <email>, card <credit_card>, ssn <national_id> at <postal_address>"
    assert fired == {"pii.email", "pii.credit_card", "pii.national_id", "pii.postal_address"}


def test_only_the_selected_detectors_run() -> None:
    out, fired = pii.redact_pii("jane@example.com 10.1.2.3", ("ip_address",), lambda d, v: "X")
    assert out == "jane@example.com X" and fired == {"pii.ip_address"}


def test_unknown_detector_ids_are_ignored_and_reported() -> None:
    assert pii.unknown_detectors(("email", "aws_access_key", "nope")) == ("aws_access_key", "nope")
    assert pii.find_pii("jane@example.com", ("nope",)) == []


def test_hits_carry_offsets_in_text_order() -> None:
    text = "10.1.2.3 then jane@example.com"
    hits = pii.find_pii(text)
    assert [h.detector for h in hits] == ["ip_address", "email"]
    assert all(text[h.start : h.end] == h.value for h in hits)


def test_validators() -> None:
    assert pii.luhn_ok("4111111111111111") and not pii.luhn_ok("4111111111111112")
    assert pii.iban_ok("GB82WEST12345698765432") and not pii.iban_ok("GB82WEST12345698765433")
    assert pii.verhoeff_ok("234567890124") and not pii.verhoeff_ok("234567890123")
