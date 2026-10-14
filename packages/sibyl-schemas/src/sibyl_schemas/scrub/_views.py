"""Decoded views of a scrubbed string, with offsets back to the original (G0 tests F7).

A secret is often not literally present: it sits inside a JSON string that is itself a
JSON string value (tool-call `arguments`), behind percent-encoding (`password%3D…`), or is
split by zero-width or fullwidth characters. Each view decodes one such layer; detectors run
on every view and their spans are mapped back, so the original text is scrubbed in place.
Replacements always cover whole escape sequences, so JSON stays valid JSON.

Every decoder is a single left-to-right regex pass (linear). A view keeps sparse
breakpoints `(view_pos, parent_pos)`: between breakpoints the offset is constant.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

_JSON_ESCAPE: Final = re.compile(r"\\(?:u([0-9a-fA-F]{4})|([\"\\/bfnrt]))")
_JSON_SIMPLE: Final = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
_PERCENT_RUN: Final = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_FORMAT_CHARS: Final = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff]+"
)
_FULLWIDTH: Final = {cp: cp - 0xFEE0 for cp in range(0xFF01, 0xFF5F)}
"""Fullwidth ASCII variants map 1:1 onto ASCII (the NFKC result), so offsets are unchanged."""

VIEW_CHAINS: Final = (
    ("json",),
    ("json", "json"),
    ("json", "json", "json"),
    ("percent",),
    ("percent", "percent"),
    ("json", "percent"),
    ("percent", "json"),
    ("format",),
    ("json", "format"),
    ("percent", "format"),
)
"""Decoder chains tried after the raw text; a chain stops as soon as a step changes nothing."""


@dataclass(frozen=True, slots=True)
class View:
    text: str
    via: str
    vpos: tuple[int, ...] = (0,)
    ppos: tuple[int, ...] = (0,)
    parent: View | None = None

    def to_original(self, index: int) -> int:
        k = bisect_right(self.vpos, index) - 1
        mapped = self.ppos[k] + (index - self.vpos[k])
        return mapped if self.parent is None else self.parent.to_original(mapped)


def raw_view(text: str) -> View:
    return View(text, "raw")


def _json_piece(match: re.Match[str]) -> str:
    code, simple = match.groups()
    return chr(int(code, 16)) if code is not None else _JSON_SIMPLE[simple]


def _decode(
    parent: View, pattern: re.Pattern[str], piece: Callable[[re.Match[str]], str], via: str
) -> View | None:
    text = parent.text
    out: list[str] = []
    vpos, ppos = [0], [0]
    last = view_len = 0
    for match in pattern.finditer(text):
        start, end = match.span()
        replacement = piece(match)
        out.append(text[last:start])
        out.append(replacement)
        view_len += (start - last) + len(replacement)
        vpos.append(view_len)
        ppos.append(end)
        last = end
    if last == 0 and not out:
        return None
    out.append(text[last:])
    return View("".join(out), via, tuple(vpos), tuple(ppos), parent)


def _decode_percent(parent: View, via: str) -> View | None:
    """`%XX` runs decoded as UTF-8 (multi-byte characters included); undecodable bytes stay
    as lone surrogates, which no detector matches. One breakpoint per decoded character."""
    text = parent.text
    out: list[str] = []
    vpos, ppos = [0], [0]
    last = view_len = 0
    for match in _PERCENT_RUN.finditer(text):
        start, end = match.span()
        out.append(text[last:start])
        view_len += start - last
        decoded = bytes.fromhex(match.group().replace("%", "")).decode(
            "utf-8", errors="surrogateescape"
        )
        cursor = start
        for char in decoded:
            cursor += 3 * len(char.encode("utf-8", errors="surrogateescape"))
            view_len += 1
            vpos.append(view_len)
            ppos.append(cursor)
        out.append(decoded)
        last = end
    if not out:
        return None
    out.append(text[last:])
    return View("".join(out), via, tuple(vpos), tuple(ppos), parent)


def _decode_format(parent: View, via: str) -> View | None:
    text = parent.text
    if text.isascii():
        return None
    stripped = _decode(parent, _FORMAT_CHARS, lambda _m: "", via)
    base = stripped if stripped is not None else parent
    widened = base.text.translate(_FULLWIDTH)
    if stripped is None and widened == text:
        return None
    if stripped is None:
        return View(widened, via, parent=parent)
    return View(widened, via, stripped.vpos, stripped.ppos, parent)


def _step(parent: View, decoder: str) -> View | None:
    via = decoder if parent.via == "raw" else f"{parent.via}+{decoder}"
    if decoder == "json":
        return _decode(parent, _JSON_ESCAPE, _json_piece, via) if "\\" in parent.text else None
    if decoder == "percent":
        return _decode_percent(parent, via) if "%" in parent.text else None
    return _decode_format(parent, via)


def decoded_views(text: str) -> list[View]:
    """The raw view first, then every distinct decoded view (at most `len(VIEW_CHAINS)`)."""
    root = raw_view(text)
    views = [root]
    seen = {text}
    cache: dict[tuple[str, ...], View | None] = {(): root}
    for chain in VIEW_CHAINS:
        view = cache.get(chain[:-1])
        if view is None:
            continue
        if chain not in cache:
            cache[chain] = _step(view, chain[-1])
        decoded = cache[chain]
        if decoded is not None and decoded.text not in seen:
            seen.add(decoded.text)
            views.append(decoded)
    return views
