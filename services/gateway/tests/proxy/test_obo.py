"""``X-Sibyl-On-Behalf-Of`` (WAVE3 frozen): ``{"kind":"user","id":<uuid>}`` or
``{"kind":"external","ref":<string ≤ 128>}``, as JSON or the ``user:<uuid>`` /
``external:<ref>`` shorthand."""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter
from sibyl_gateway.proxy.obo import OnBehalfOfInvalid, parse_on_behalf_of
from sibyl_schemas.action_gate import OnBehalfOf

USER = "0192767f-0000-7000-8000-00000000d001"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        (f'{{"kind":"user","id":"{USER}"}}', {"kind": "user", "id": USER}),
        (f"user:{USER.upper()}", {"kind": "user", "id": USER}),
        ('{"kind":"external","ref":"crm:4711"}', {"kind": "external", "ref": "crm:4711"}),
        ("external:crm:4711", {"kind": "external", "ref": "crm:4711"}),
        ("  external:x  ", {"kind": "external", "ref": "x"}),
    ],
)
def test_valid_forms(raw: str | None, expected: dict[str, str] | None) -> None:
    parsed = parse_on_behalf_of(raw)
    assert parsed == expected
    if parsed is not None:
        # Cross-lane contract (B28): what the gateway forwards is AG-LIVE's frozen model.
        model = TypeAdapter(OnBehalfOf).validate_python(parsed)
        assert model.model_dump(mode="json") == parsed


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "user:not-a-uuid",
        "external:",
        "external:" + "x" * 129,
        "external:tab\there",
        "robot:1",
        '{"kind":"user"}',
        '{"kind":"user","id":"' + USER + '","extra":1}',
        '{"kind":"external","ref":7}',
        "[1]",
        "{not json",
        "x" * 600,
    ],
)
def test_invalid_forms_are_rejected(raw: str) -> None:
    with pytest.raises(OnBehalfOfInvalid):
        parse_on_behalf_of(raw)
