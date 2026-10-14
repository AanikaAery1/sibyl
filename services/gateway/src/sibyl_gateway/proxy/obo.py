"""``X-Sibyl-On-Behalf-Of``: who an agent acts for, passed into held actions (WAVE3 frozen).

Shape: ``{"kind":"user","id":<uuid>}`` or ``{"kind":"external","ref":<string ≤ 128>}``. The
header carries that JSON object, or the shorthand ``user:<uuid>`` / ``external:<ref>``. A
present but malformed header is a 400 on every surface (validated at the edge, never passed on
half-parsed). The value is metadata for approvers; it grants nothing.
"""

from __future__ import annotations

import json
from typing import Any, Final
from uuid import UUID

MAX_HEADER: Final = 512
MAX_REF: Final = 128


class OnBehalfOfInvalid(ValueError):
    pass


def parse_on_behalf_of(raw: str | None) -> dict[str, str] | None:
    if raw is None:
        return None
    text = raw.strip()
    if not text or len(text) > MAX_HEADER:
        raise OnBehalfOfInvalid("empty or oversized")
    if text.startswith("{"):
        try:
            doc: Any = json.loads(text)
        except ValueError:
            raise OnBehalfOfInvalid("not JSON") from None
        if not isinstance(doc, dict):
            raise OnBehalfOfInvalid("not an object")
        kind = doc.get("kind")
        expected = {"kind", "id"} if kind == "user" else {"kind", "ref"}
        if set(doc) != expected:
            raise OnBehalfOfInvalid("unexpected members")
        value = doc.get("id") if kind == "user" else doc.get("ref")
    else:
        kind, _, value = text.partition(":")
    if not isinstance(value, str):
        raise OnBehalfOfInvalid("value must be a string")
    if kind == "user":
        try:
            return {"kind": "user", "id": str(UUID(value))}
        except ValueError:
            raise OnBehalfOfInvalid("user id must be a uuid") from None
    if kind == "external":
        if not 0 < len(value) <= MAX_REF or not value.isprintable():
            raise OnBehalfOfInvalid("external ref must be 1-128 printable characters")
        return {"kind": "external", "ref": value}
    raise OnBehalfOfInvalid("kind must be user or external")
