"""`sibyl.on_behalf_of(...)`: who an agent acts for (WAVE3 frozen field `on_behalf_of`).

The value rides on every held-action request created inside the block (`on_behalf_of` body
member) and on every instrumented model call (`X-Sibyl-On-Behalf-Of` header for the gateway):

    with sibyl.on_behalf_of(user="0192...-uuid"):        # a Sibyl user
        agent.run(...)
    with sibyl.on_behalf_of(external="crm:contact/123"): # anyone else (≤ 128 chars)
        agent.run(...)

Context-local (threads and asyncio tasks each see their own value); nesting restores the
outer value on exit.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Final, Literal
from uuid import UUID

from sibyl._errors import SibylConfigError

MAX_EXTERNAL_REF: Final = 128
HEADER: Final = "X-Sibyl-On-Behalf-Of"
OnBehalfOf = dict[str, str]
_OBO: ContextVar[OnBehalfOf | None] = ContextVar("sibyl_on_behalf_of", default=None)
_default: OnBehalfOf | None = None


def parse(
    value: Any = None, *, user: str | UUID | None = None, external: str | None = None
) -> OnBehalfOf:
    """Validate into `{"kind":"user","id":<uuid>}` or `{"kind":"external","ref":<str>}`."""
    given = [v for v in (value, user, external) if v is not None]
    if len(given) != 1:
        raise SibylConfigError("on_behalf_of needs exactly one of value, user= or external=")
    if isinstance(value, dict):
        kind = value.get("kind")
        if kind == "user":
            return parse(user=value.get("id"))
        if kind == "external":
            return parse(external=value.get("ref"))
        raise SibylConfigError("on_behalf_of kind must be 'user' or 'external'")
    if value is not None:
        return parse(user=value) if isinstance(value, UUID) else parse(external=str(value))
    if user is not None:
        try:
            return {"kind": "user", "id": str(UUID(str(user)))}
        except ValueError:
            raise SibylConfigError("on_behalf_of user must be a Sibyl user uuid") from None
    ref = str(external).strip()
    if not ref or len(ref) > MAX_EXTERNAL_REF:
        raise SibylConfigError(f"on_behalf_of external ref must be 1-{MAX_EXTERNAL_REF} chars")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in ref):
        raise SibylConfigError("on_behalf_of external ref must not contain control characters")
    return {"kind": "external", "ref": ref}


def set_default(value: OnBehalfOf | None) -> None:
    """Process-wide fallback (`SIBYL_ON_BEHALF_OF` under `sibyl-run`); blocks override it."""
    global _default
    _default = dict(value) if value is not None else None


def current() -> OnBehalfOf | None:
    value = _OBO.get() or _default
    return dict(value) if value is not None else None


def header_value(value: OnBehalfOf | None = None) -> str | None:
    """`user:<uuid>` or `external:<ref>` (the gateway header form)."""
    obo = value if value is not None else current()
    if obo is None:
        return None
    kind: Literal["user", "external"] = obo["kind"]  # type: ignore[assignment]
    return f"user:{obo['id']}" if kind == "user" else f"external:{obo['ref']}"


@contextmanager
def on_behalf_of(
    value: Any = None, *, user: str | UUID | None = None, external: str | None = None
) -> Iterator[OnBehalfOf]:
    """Attribute every held action and model call in the block to a user or external party."""
    parsed = parse(value, user=user, external=external)
    token = _OBO.set(parsed)
    try:
        yield dict(parsed)
    finally:
        _OBO.reset(token)
