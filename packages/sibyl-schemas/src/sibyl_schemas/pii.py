"""The shared ``pii_standard`` detector registry (API.md §10.3, ``capture_mode = redacted``).

PII redaction is conditional on the redacted capture mode and sits on top of the unconditional
secrets floor (``sibyl_schemas.scrub``). The SDK, gateway and ingest import this one registry so
a value is redacted identically wherever it is captured. Detector ids equal the DB's
``pii_standard`` redaction profile (``0014_tenant_create.sql``):

    email           RFC 5321-ish local@domain.tld
    phone           international (+cc, 8-15 digits) or NANP (xxx) xxx-xxxx
    credit_card     13-19 digits, Luhn
    iban            ISO 13616, mod-97
    ip_address      IPv4 / full IPv6 (``ipaddress`` validated)
    national_id     US SSN (area/group/serial rules), UK NINO (prefix rules), India Aadhaar
                    (Verhoeff) and PAN
    postal_address  a numbered street line (``221 Baker Street``) or a UK postcode

    hits = find_pii(text, ("email", "phone"))
    clean, fired = redact_pii(text, PII_DETECTOR_IDS, lambda detector, value: "[PII]")

Overlapping hits resolve to the earliest start, then the detector listed first in
``PII_DETECTOR_IDS``. Patterns are linear-time friendly (bounded quantifiers, no nested
unbounded repetition).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

__all__ = [
    "PII_DETECTORS",
    "PII_DETECTOR_IDS",
    "PiiDetector",
    "PiiHit",
    "find_pii",
    "iban_ok",
    "luhn_ok",
    "redact_pii",
    "unknown_detectors",
    "verhoeff_ok",
]


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def iban_ok(compact: str) -> bool:
    raw = compact.upper()
    if not 15 <= len(raw) <= 34 or not raw.isalnum():
        return False
    number = "".join(str(int(ch, 36)) for ch in raw[4:] + raw[:4])
    return int(number) % 97 == 1


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(ch)]]
    return check == 0


def _digits(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def _card(value: str) -> bool:
    digits = _digits(value)
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


def _iban(value: str) -> bool:
    return iban_ok(value.replace(" ", ""))


def _ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _phone(value: str) -> bool:
    return 8 <= len(_digits(value)) <= 15


_NINO_BAD_PREFIXES = frozenset({"BG", "GB", "NK", "KN", "TN", "NT", "ZZ"})


def _national_id(value: str) -> bool:
    compact = value.replace(" ", "").replace("-", "")
    if re.fullmatch(r"\d{9}", compact):  # US SSN
        area, group, serial = compact[:3], compact[3:5], compact[5:]
        return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"
    if re.fullmatch(r"\d{12}", compact):  # Aadhaar
        return compact[0] not in "01" and verhoeff_ok(compact)
    if re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", compact):  # UK NINO
        return compact[:2] not in _NINO_BAD_PREFIXES
    return bool(re.fullmatch(r"[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]", compact))  # India PAN


_STREET_TYPES = (
    "Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl"
    "|Terrace|Close|Crescent|Square|Sq|Parkway|Highway|Hwy|Marg|Nagar"
)


@dataclass(frozen=True)
class PiiDetector:
    id: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    description: str = ""

    def matches(self, text: str) -> Iterable[re.Match[str]]:
        for match in self.pattern.finditer(text):
            if self.validator is None or self.validator(match.group(0)):
                yield match


_REGISTRY: tuple[PiiDetector, ...] = (
    PiiDetector(
        "email",
        re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"),
        description="local@domain.tld",
    ),
    PiiDetector(
        "phone",
        re.compile(
            r"(?<![\w+])(?:\+\d{1,3}[ .-]?\d{2,5}(?:[ .-]?\d{2,5}){1,3}"
            r"|\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}[ .-]\d{3}[ .-]\d{4})(?![\w])"
        ),
        _phone,
        "international +cc (8-15 digits) or NANP",
    ),
    PiiDetector(
        "credit_card",
        re.compile(r"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])"),
        _card,
        "13-19 digits, Luhn",
    ),
    PiiDetector(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
        _iban,
        "ISO 13616, mod-97",
    ),
    PiiDetector(
        "ip_address",
        re.compile(
            r"(?<![\w.:])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})"
            r"(?![\w.:])"
        ),
        _ip,
        "IPv4 / full IPv6",
    ),
    PiiDetector(
        "national_id",
        re.compile(
            r"(?<![\w-])(?:\d{3}-\d{2}-\d{4}"
            r"|[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]"
            r"|\d{4} \d{4} \d{4}|\d{12}"
            r"|[A-Z]{5}\d{4}[A-Z])(?![\w-])"
        ),
        _national_id,
        "US SSN, UK NINO, India Aadhaar (Verhoeff) and PAN",
    ),
    PiiDetector(
        "postal_address",
        re.compile(
            r"\b\d{1,5}[A-Za-z]? (?:[A-Z][a-z]{1,20} ){1,4}(?:" + _STREET_TYPES + r")\b\.?"
            r"|\b(?:[A-Z]{1,2}\d[A-Z\d]?|GIR) ?\d[ABD-HJLNP-UW-Z]{2}\b"
        ),
        description="numbered street line or UK postcode",
    ),
)

PII_DETECTOR_IDS: Final = tuple(d.id for d in _REGISTRY)
PII_DETECTORS: Final[Mapping[str, PiiDetector]] = MappingProxyType({d.id: d for d in _REGISTRY})
_PRIORITY: Final = {d.id: i for i, d in enumerate(_REGISTRY)}


@dataclass(frozen=True)
class PiiHit:
    detector: str
    start: int
    end: int
    value: str


def unknown_detectors(detector_ids: Iterable[str]) -> tuple[str, ...]:
    """Ids that are not PII detectors (e.g. the secrets detectors of the same profile)."""
    return tuple(d for d in detector_ids if d not in PII_DETECTORS)


def find_pii(text: str, detector_ids: Iterable[str] | None = None) -> list[PiiHit]:
    """Non-overlapping, validated hits in text order (all detectors when ``detector_ids`` is
    ``None``; unknown ids are ignored)."""
    wanted = PII_DETECTOR_IDS if detector_ids is None else tuple(detector_ids)
    hits = [
        PiiHit(d.id, m.start(), m.end(), m.group(0))
        for d in _REGISTRY
        if d.id in wanted
        for m in d.matches(text)
    ]
    hits.sort(key=lambda h: (h.start, _PRIORITY[h.detector], -h.end))
    out: list[PiiHit] = []
    for hit in hits:
        if out and hit.start < out[-1].end:
            continue
        out.append(hit)
    return out


def redact_pii(
    text: str, detector_ids: Iterable[str], replace: Callable[[str, str], str]
) -> tuple[str, set[str]]:
    """Replace every hit with ``replace(detector_id, value)``; returns the text and the rules
    fired (``pii.<detector_id>``)."""
    hits = find_pii(text, detector_ids)
    if not hits:
        return text, set()
    parts: list[str] = []
    cursor = 0
    for hit in hits:
        parts.append(text[cursor : hit.start])
        parts.append(replace(hit.detector, hit.value))
        cursor = hit.end
    parts.append(text[cursor:])
    return "".join(parts), {f"pii.{h.detector}" for h in hits}
