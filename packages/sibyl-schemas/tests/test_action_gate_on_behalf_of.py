"""Held-action ``on_behalf_of`` (lane AG-LIVE, WAVE3.md frozen shape): the person or external
principal an agent acted for. Four-eyes excludes a ``user`` on-behalf-of from approving."""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError
from sibyl_schemas import action_gate as ag

USER = "0192767f-0000-7000-8000-0000000ab001"


def _request(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "call_id": "call-obo-1",
        "agent_id": "0192767f-0000-7000-8000-00000000c011",
        "source": "gateway",
        "tool": "payments.transfer",
        "args": {"amount": 25000},
        "args_sha256": ag.args_digest({"amount": 25000}),
        "policy_id": None,
        "policy_version": None,
        "rule_id": None,
        "reason": "over limit",
        "hold_timeout_s": 900,
    }
    body.update(extra)
    return body


def test_on_behalf_of_is_optional_and_absent_from_the_dump() -> None:
    request = ag.HeldActionRequest.model_validate(_request())
    assert request.on_behalf_of is None or "on_behalf_of" not in request.model_dump()
    assert "on_behalf_of" not in request.model_dump(mode="json")
    assert ag.on_behalf_of_of(request) is None


def test_null_on_behalf_of_is_accepted_as_absent() -> None:
    request = ag.HeldActionRequest.model_validate(_request(on_behalf_of=None))
    assert ag.on_behalf_of_of(request) is None


def test_user_and_external_shapes() -> None:
    user = ag.HeldActionRequest.model_validate(_request(on_behalf_of={"kind": "user", "id": USER}))
    found = ag.on_behalf_of_of(user)
    assert isinstance(found, ag.OnBehalfOfUser) and found.id == USER
    assert user.model_dump(mode="json")["on_behalf_of"] == {"kind": "user", "id": USER}
    external = ag.HeldActionRequest.model_validate(
        _request(on_behalf_of={"kind": "external", "ref": "crm:customer/42"})
    )
    other = ag.on_behalf_of_of(external)
    assert isinstance(other, ag.OnBehalfOfExternal) and other.ref == "crm:customer/42"


@pytest.mark.parametrize(
    "value",
    [
        {"kind": "user"},
        {"kind": "user", "id": "not-a-uuid"},
        {"kind": "user", "id": USER, "ref": "x"},
        {"kind": "external", "ref": ""},
        {"kind": "external", "ref": "x" * 129},
        {"kind": "external", "ref": "line\nbreak"},
        {"kind": "external", "id": USER},
        {"kind": "robot", "id": USER},
        "user:" + USER,
        [],
    ],
)
def test_malformed_on_behalf_of_is_refused(value: Any) -> None:
    with pytest.raises(ValidationError):
        ag.HeldActionRequest.model_validate(_request(on_behalf_of=value))


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (f"user:{USER}", {"kind": "user", "id": USER}),
        (f"  user:{USER.upper()} ", {"kind": "user", "id": USER}),
        ("external:crm:customer/42", {"kind": "external", "ref": "crm:customer/42"}),
    ],
)
def test_the_gateway_header_form_parses_to_the_same_model(
    header: str, expected: dict[str, str]
) -> None:
    parsed = ag.on_behalf_of_from_header(header)
    assert parsed.model_dump(mode="json") == expected


@pytest.mark.parametrize(
    "header", ["", "user:", "user:nope", "external:", "robot:1", "external:" + "x" * 129, USER]
)
def test_a_malformed_header_is_refused(header: str) -> None:
    with pytest.raises(ValueError, match="on_behalf_of"):
        ag.on_behalf_of_from_header(header)


# --- B28: the header also accepts the frozen JSON shape, as strictly as the gateway ------------


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (f'{{"kind":"user","id":"{USER}"}}', {"kind": "user", "id": USER}),
        (f' {{"kind": "user", "id": "{USER.upper()}"}} ', {"kind": "user", "id": USER}),
        (
            '{"kind":"external","ref":"crm:customer/42"}',
            {"kind": "external", "ref": "crm:customer/42"},
        ),
        ('{"ref":"ticket 7","kind":"external"}', {"kind": "external", "ref": "ticket 7"}),
    ],
)
def test_the_json_header_form_parses_to_the_same_model(
    header: str, expected: dict[str, str]
) -> None:
    assert ag.on_behalf_of_from_header(header).model_dump(mode="json") == expected


@pytest.mark.parametrize(
    "header",
    [
        "{",
        "[]",
        '"user"',
        "{}",
        '{"kind":"user"}',
        '{"kind":"user","id":"nope"}',
        '{"kind":"user","id":7}',
        f'{{"kind":"user","id":"{USER}","ref":"x"}}',
        f'{{"kind":"user","id":"{USER}","id":"{USER}"}}',  # duplicate member
        '{"kind":"external","ref":""}',
        '{"kind":"external","ref":"' + "x" * 129 + '"}',
        '{"kind":"external","ref":"tab\\there"}',
        '{"kind":"external","id":"x"}',
        f'{{"kind":"robot","id":"{USER}"}}',
        '{"kind":"external","ref":"' + "x" * 600 + '"}',  # oversized header (gateway: 512)
    ],
)
def test_a_malformed_json_header_is_refused(header: str) -> None:
    with pytest.raises(ValueError, match="on_behalf_of"):
        ag.on_behalf_of_from_header(header)


@pytest.mark.parametrize(
    "ref",
    ["nbsp\u00a0here", "zero\u200bwidth", "bidi\u202eoverride", "line\u2028sep", "del\x7f"],
)
def test_external_refs_must_be_printable_like_the_gateway(ref: str) -> None:
    """The gateway refuses any ref with a non-printable character (``str.isprintable``); the
    schemas header parser is exactly as strict, in both header forms."""
    with pytest.raises(ValueError, match="on_behalf_of"):
        ag.on_behalf_of_from_header("external:" + ref)
    with pytest.raises(ValueError, match="on_behalf_of"):
        ag.on_behalf_of_from_header(json.dumps({"kind": "external", "ref": ref}))


def test_a_header_over_512_characters_is_refused() -> None:
    """Valid JSON padded past the gateway's 512-character header cap (after trimming)."""
    padded = '{"kind":"external",' + " " * 500 + '"ref":"x"}'
    assert len(padded.strip()) > ag.MAX_ON_BEHALF_OF_HEADER
    with pytest.raises(ValueError, match="on_behalf_of"):
        ag.on_behalf_of_from_header(padded)
