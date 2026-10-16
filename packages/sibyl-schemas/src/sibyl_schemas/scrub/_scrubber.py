"""The scrubbing engine: run the registry over every decoded view, resolve overlaps, replace
with salted tokens.

Pipeline (exported in `detectors.v1.json` as `pipeline` so other SDKs match it):
1. Refuse inputs over `max_chars` (`ScrubInputTooLarge`): never pass them through unscrubbed.
2. Build the decoded views (`_views.VIEW_CHAINS`: JSON unescape up to twice, percent-decode,
   format-character strip and fullwidth fold).
3. Run every detector on every view, in windows of `WINDOW_CHARS` with
   `WINDOW_OVERLAP_CHARS` overlap; a match is kept by the window it starts in.
4. Decode base64 runs (every view but the format view, and once more inside a decoded
   run); a run whose UTF-8 text holds a secret is replaced whole.
5. Map spans to the original text, trim existing `[KIND:hash8]` tokens out of candidates,
   resolve overlaps (higher priority, then longer), replace.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from bisect import bisect_right
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from typing import Any, Final

from sibyl_schemas.scrub._detectors import (
    DETECTORS,
    REPLACEMENT_FORMAT,
    REPLACEMENT_PATTERN,
    VALIDATORS,
    Detector,
    ScrubField,
)
from sibyl_schemas.scrub._views import View, decoded_views

MIN_SALT_BYTES: Final = 16
MAX_SCRUB_CHARS: Final = 16 * 1024 * 1024
"""Default per-string cap; larger inputs raise `ScrubInputTooLarge` (security H4)."""
WINDOW_CHARS: Final = 64 * 1024
WINDOW_OVERLAP_CHARS: Final = 16 * 1024
"""Longer than the longest bounded match (a PEM body is capped at 8 KiB)."""
BASE64_MIN_CHARS: Final = 24
BASE64_MAX_CHARS: Final = 64 * 1024
_BASE64_RUN: Final = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_KEEP_PIECE: Final = re.compile(r"[A-Za-z0-9]")
KEY_COLLISION_SEPARATOR: Final = "#"


class ScrubInputTooLarge(ValueError):
    """The string exceeds the scrubber's size cap; the caller must reject or truncate it."""


@dataclass(frozen=True, slots=True)
class Finding:
    """One replaced secret. Carries offsets and the token, never the secret itself."""

    detector_id: str
    kind: str
    start: int
    end: int
    replacement: str
    via: str = "raw"
    """Which decoded view found it: `raw`, `json`, `json+json`, `percent`, `format`, … or
    `base64` (a base64 run whose decoded text held a secret)."""


@dataclass(frozen=True, slots=True)
class ScrubResult:
    text: str
    findings: tuple[Finding, ...]

    @property
    def secrets_scrubbed(self) -> int:
        return len(self.findings)

    @property
    def rules_fired(self) -> tuple[str, ...]:
        """`redaction_profile.rules_fired` spelling: `secrets.<detector id>`."""
        return tuple(sorted({f"secrets.{f.detector_id}" for f in self.findings}))


@dataclass(frozen=True, slots=True)
class _Candidate:
    priority: int
    start: int
    end: int
    detector: Detector
    secret: str
    via: str


_Compiled = tuple[Detector, tuple[tuple[re.Pattern[str], int], ...], re.Pattern[str] | None]


@cache
def _compiled() -> tuple[_Compiled, ...]:
    table = []
    for detector in DETECTORS:
        patterns = tuple((p.compile(), p.group) for p in detector.patterns)
        requires = re.compile(detector.requires) if detector.requires else None
        table.append((detector, patterns, requires))
    return tuple(table)


def _windows(length: int) -> Iterator[tuple[int, int, int]]:
    """(scan_from, keep_before, scan_to): a match is kept by the window it starts in."""
    start = 0
    while True:
        keep = start + WINDOW_CHARS
        if keep >= length:
            yield start, length, length
            return
        yield start, keep, min(length, keep + WINDOW_OVERLAP_CHARS)
        start = keep


def _pattern_spans(text: str, pattern: re.Pattern[str], group: int) -> Iterator[tuple[int, int]]:
    for scan_from, keep_before, scan_to in _windows(len(text)):
        for match in pattern.finditer(text, scan_from, scan_to):
            if match.start() >= keep_before:
                break
            start, end = match.span(group)
            if start >= 0 and start != end:
                yield start, end


def _entry_spans(text: str, entry: _Compiled) -> list[tuple[int, int]]:
    detector, patterns, requires = entry
    if requires is not None and not requires.search(text):
        return []
    # Userinfo URL patterns MUST contain '@'. The DSN query-password
    # alternative needs one of its three literal key names followed by '='.
    # This fast rejection avoids running expensive URL regex scans over long
    # adversarial strings such as repeated "postgres://" fragments. Keep the
    # existing regex and validators for all possible positive cases.
    if detector.id in ("dsn", "basic_auth_url") and "@" not in text:
        if detector.id == "basic_auth_url" or not any(
            key in text.lower() for key in ("password=", "passwd=", "pwd=")
        ):
            return []
    check = VALIDATORS[detector.validator] if detector.validator else None
    spans: list[tuple[int, int]] = []
    for pattern, group in patterns:
        for start, end in _pattern_spans(text, pattern, group):
            if check is None or check(text[start:end]):
                spans.append((start, end))
    return spans


def detector_spans(text: str, detector: Detector) -> list[tuple[int, int]]:
    """Spans one detector accepts in `text` (no views, no field filter). For tests/tools."""
    entry = next(e for e in _compiled() if e[0] is detector or e[0].id == detector.id)
    return _entry_spans(text, entry)


def _view_candidates(view: View, field: ScrubField) -> list[_Candidate]:
    found: list[_Candidate] = []
    for priority, entry in enumerate(_compiled()):
        detector = entry[0]
        if detector.fields is not None and field not in detector.fields:
            continue
        for start, end in _entry_spans(view.text, entry):
            found.append(
                _Candidate(
                    priority,
                    view.to_original(start),
                    view.to_original(end),
                    detector,
                    view.text[start:end],
                    view.via,
                )
            )
    return found


def _decode_base64(run: str) -> str | None:
    body = run.rstrip("=")
    altchars = b"-_" if ("-" in body or "_" in body) else None
    if altchars is not None and ("+" in body or "/" in body):
        return None
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), altchars=altchars, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    printable = sum(ch.isprintable() or ch in "\t\r\n" for ch in text)
    return text if text and printable >= 0.9 * len(text) else None


def _base64_candidates(view: View, field: ScrubField, depth: int = 1) -> list[_Candidate]:
    found: list[_Candidate] = []
    for match in _BASE64_RUN.finditer(view.text):
        run = match.group()
        if len(run) > BASE64_MAX_CHARS:
            continue
        decoded = _decode_base64(run)
        if decoded is None:
            continue
        inner = _resolve(_text_candidates(decoded, field, depth + 1))
        if not inner:
            continue
        best = min(inner, key=lambda c: c.priority)
        found.append(
            _Candidate(
                best.priority,
                view.to_original(match.start()),
                view.to_original(match.end()),
                best.detector,
                run,
                "base64",
            )
        )
    return found


def _trim_tokens(
    cand: _Candidate, tokens: tuple[tuple[int, int], ...], text: str
) -> list[_Candidate]:
    """Existing `[KIND:hash8]` tokens are never rescanned (idempotency). A candidate that
    starts inside a token is dropped (a token's own `SECRET:` must not read as a key); one
    that starts before a token keeps its token-free pieces when they still look like secret
    material, so a lookalike token cannot shield the rest of a secret (L4)."""
    if any(t_start <= cand.start < t_end for t_start, t_end in tokens):
        return []
    pieces: list[_Candidate] = []
    cursor = cand.start
    for t_start, t_end in tokens:
        if t_end <= cand.start or t_start >= cand.end:
            continue
        pieces.append(_piece(cand, cursor, t_start, text))
        cursor = max(cursor, t_end)
    if cursor == cand.start:
        return [cand]
    pieces.append(_piece(cand, cursor, cand.end, text))
    return [p for p in pieces if p.end - p.start >= 4 and _KEEP_PIECE.search(p.secret)]


def _piece(cand: _Candidate, start: int, end: int, text: str) -> _Candidate:
    """A token-free piece, in original-text coordinates (hashed as it appears there)."""
    end = max(start, end)
    return _Candidate(cand.priority, start, end, cand.detector, text[start:end], cand.via)


def _resolve(
    candidates: list[_Candidate], tokens: tuple[tuple[int, int], ...] = (), text: str = ""
) -> list[_Candidate]:
    """Highest-priority detector wins an overlap; ties go to the longer match."""
    trimmed = (
        [p for cand in candidates for p in _trim_tokens(cand, tokens, text)]
        if tokens
        else candidates
    )
    # Accepted spans never overlap, so one bisect finds the only two neighbours to check:
    # O(k log k) instead of the quadratic all-pairs scan (many matches on adversarial text).
    starts: list[int] = []
    kept: list[_Candidate] = []
    for cand in sorted(trimmed, key=lambda c: (c.priority, c.start - c.end, c.start)):
        i = bisect_right(starts, cand.start)
        if i > 0 and kept[i - 1].end > cand.start:
            continue
        if i < len(kept) and kept[i].start < cand.end:
            continue
        starts.insert(i, cand.start)
        kept.insert(i, cand)
    return kept


BASE64_MAX_DEPTH: Final = 2
"""Base64 inside base64 (a secret manifest inside an encoded payload) is decoded once more."""


def _text_candidates(text: str, field: ScrubField, depth: int = 1) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    for view in decoded_views(text):
        candidates.extend(_view_candidates(view, field))
        if depth <= BASE64_MAX_DEPTH and "format" not in view.via:
            candidates.extend(_base64_candidates(view, field, depth))
    return candidates


class SecretsScrubber:
    """Unconditional secrets floor shared by SDK, gateway, ingest and api (D12).

    `salt` is the platform secret `SIBYL_SCRUB_SALT`: the same leaked key yields the same
    `[{kind}:{hash8}]` token across a tenant's traces (and across encodings, since the
    decoded secret is hashed) without being recoverable. The replacement is deliberately not
    length-preserving. Scrubbing is idempotent.
    """

    def __init__(self, salt: bytes, *, max_chars: int = MAX_SCRUB_CHARS) -> None:
        if len(salt) < MIN_SALT_BYTES:
            raise ValueError(f"scrub salt must be at least {MIN_SALT_BYTES} bytes")
        self._salt = salt
        self._max_chars = max_chars

    def token(self, kind: str, secret: str) -> str:
        data = secret.encode("utf-8", errors="surrogateescape")
        hash8 = hashlib.sha256(self._salt + data).hexdigest()[:8]
        return REPLACEMENT_FORMAT.format(kind=kind, hash8=hash8)

    def scrub(self, text: str, field: ScrubField | str = ScrubField.INPUT_MESSAGES) -> ScrubResult:
        if len(text) > self._max_chars:
            raise ScrubInputTooLarge(
                f"string of {len(text)} characters exceeds the {self._max_chars} scrub cap"
            )
        scrub_field = ScrubField(field)
        tokens = tuple(m.span() for m in REPLACEMENT_PATTERN.finditer(text))
        accepted = _resolve(_text_candidates(text, scrub_field), tokens, text)
        if not accepted:
            return ScrubResult(text, ())
        pieces: list[str] = []
        findings: list[Finding] = []
        cursor = 0
        for cand in accepted:
            secret = cand.secret or text[cand.start : cand.end]
            token = self.token(cand.detector.kind.value, secret)
            pieces.append(text[cursor : cand.start])
            pieces.append(token)
            findings.append(
                Finding(
                    cand.detector.id,
                    cand.detector.kind.value,
                    cand.start,
                    cand.end,
                    token,
                    cand.via,
                )
            )
            cursor = cand.end
        pieces.append(text[cursor:])
        return ScrubResult("".join(pieces), tuple(findings))

    def scrub_bytes(
        self, data: bytes, field: ScrubField | str = ScrubField.INPUT_MESSAGES
    ) -> bytes:
        """Scrub bytes as UTF-8; undecodable bytes round-trip unchanged (surrogateescape)."""
        return self._scrub_bytes(data, field, [])

    def _scrub_bytes(self, data: bytes, field: ScrubField | str, sink: list[Finding]) -> bytes:
        result = self.scrub(data.decode("utf-8", errors="surrogateescape"), field)
        if not result.findings:
            return data
        sink.extend(result.findings)
        return result.text.encode("utf-8", errors="surrogateescape")

    def scrub_json(
        self, value: Any, field: ScrubField | str = ScrubField.STATE
    ) -> tuple[Any, list[Finding]]:
        """Scrub every string leaf, string key, `bytes` and `bytearray` of a JSON-like value
        (security M7); returns a new value. A scrubbed key that collides with another key
        gets a `#2`, `#3`, … suffix so no member is lost."""
        findings: list[Finding] = []

        def text(node: str) -> str:
            result = self.scrub(node, field)
            findings.extend(result.findings)
            return result.text

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                return text(node)
            if isinstance(node, bytes | bytearray | memoryview):
                cleaned = self._scrub_bytes(bytes(node), field, findings)
                return bytearray(cleaned) if isinstance(node, bytearray) else cleaned
            if isinstance(node, Mapping):
                return _scrub_mapping(node, text, walk)
            if isinstance(node, list | tuple):
                return [walk(item) for item in node]
            return node

        return walk(value), findings


def _scrub_mapping(node: Mapping[Any, Any], text: Any, walk: Any) -> dict[Any, Any]:
    out: dict[Any, Any] = {}
    renamed: list[tuple[Any, Any]] = []
    for key, item in node.items():
        new_key = text(key) if isinstance(key, str) else key
        if new_key != key:
            renamed.append((new_key, walk(item)))
        else:
            out[key] = walk(item)
    for new_key, item in renamed:
        unique, n = new_key, 1
        while unique in out:
            n += 1
            unique = f"{new_key}{KEY_COLLISION_SEPARATOR}{n}"
        out[unique] = item
    return out
