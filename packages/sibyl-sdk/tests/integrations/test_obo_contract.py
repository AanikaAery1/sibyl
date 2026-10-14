"""Cross-lane contract (integration of PLUG and AG-LIVE): what the SDK sends as `on_behalf_of`
(body) and `X-Sibyl-On-Behalf-Of` (header) is exactly what AG-LIVE's frozen model accepts."""

from __future__ import annotations

import uuid

import pytest
from sibyl import _obo
from sibyl_schemas.action_gate import (
    HeldActionRequest,
    OnBehalfOfExternal,
    OnBehalfOfUser,
    on_behalf_of_from_header,
    on_behalf_of_of,
)

USER = uuid.UUID("0192f0c4-1111-7222-8333-944445555666")


def _request(obo: dict[str, str]) -> HeldActionRequest:
    return HeldActionRequest.model_validate(
        {
            "call_id": "call-obo-contract",
            "agent_id": str(uuid.uuid4()),
            "source": "sdk",
            "tool": "refund",
            "args": {},
            "args_sha256": "0" * 64,
            "policy_id": None,
            "policy_version": None,
            "rule_id": None,
            "reason": "held",
            "hold_timeout_s": 900,
            "on_behalf_of": obo,
        }
    )


@pytest.mark.parametrize(
    ("obo", "expected"),
    [
        (_obo.parse(user=USER), OnBehalfOfUser(kind="user", id=str(USER))),
        (
            _obo.parse(external="crm:contact/123"),
            OnBehalfOfExternal(kind="external", ref="crm:contact/123"),
        ),
    ],
)
def test_sdk_body_and_header_match_the_action_gate_model(
    obo: dict[str, str], expected: OnBehalfOfUser | OnBehalfOfExternal
) -> None:
    # Arrange: the SDK's normalised value. Act: both wire forms. Assert: same frozen model.
    header = _obo.header_value(obo)
    assert header is not None
    assert on_behalf_of_of(_request(obo)) == expected
    assert on_behalf_of_from_header(header) == expected


def test_sdk_header_name_is_the_frozen_one() -> None:
    assert _obo.HEADER == "X-Sibyl-On-Behalf-Of"
