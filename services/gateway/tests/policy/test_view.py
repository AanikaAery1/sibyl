"""PolicyView (R62) seam between G-hot and G-policy, exercised with a fake implementation."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from uuid import UUID, uuid4

import pytest
from sibyl_gateway.policy.view import (
    ERROR_MAP,
    FAIL_MODE_MATRIX,
    AgentLimits,
    CredentialRef,
    DecisionRequest,
    KeyPrincipal,
    KeyRejected,
    ModelList,
    PolicyState,
    PolicyStatus,
    PolicyView,
    Refuse,
    SecretHandle,
    Serve,
    UpstreamTarget,
    apply_fail_mode,
)

TENANT = UUID("01927000-0000-7000-8000-000000000001")
AGENT = UUID("01927000-0000-7000-8000-0000000000a1")
STATUS = PolicyStatus(PolicyState.FRESH, version=7, kid="snap-1", age_s=3)
PRIMARY = UpstreamTarget(
    route="primary",
    provider_id=uuid4(),
    provider_slug="openai",
    dialect="openai_compatible",
    base_url="https://api.openai.com/v1",
    model="gpt-4.1-mini",
    credential="passthrough",
)


class FakePolicyView:
    """What G-hot tests use until G-policy lands: a fixed key and one agent."""

    def __init__(self, routing_state: str = "active", state: PolicyState = PolicyState.FRESH):
        self.routing_state = routing_state
        self._status = PolicyStatus(state, version=7, kid="snap-1", age_s=3)
        self.principal = KeyPrincipal(
            TENANT, uuid4(), "ABCDEFGHIJKL", "live", frozenset({"gateway:proxy"}), AGENT
        )

    def status(self) -> PolicyStatus:
        return self._status

    def authenticate(self, presented_key: str) -> KeyPrincipal | KeyRejected:
        if presented_key == "good":
            return self.principal
        return KeyRejected("sibyl_key_invalid")

    def decide(self, request: DecisionRequest) -> Serve | Refuse:
        refusal = apply_fail_mode(
            self._status.state,
            "closed",
            killed=self.routing_state == "killed",
            ever_loaded=True,
            agent_id=AGENT,
            policy=self._status,
        )
        if refusal is not None:
            return refusal
        return Serve(
            tenant_id=TENANT,
            agent_id=AGENT,
            routing_state="active",
            policy=self._status,
            targets=(PRIMARY,),
            fail_mode="closed",
            capture_mode="full",
            redaction_profile_hash="0" * 64,
            limits=AgentLimits(rps_limit=50),
        )

    def models(self, principal: KeyPrincipal, agent_header: str | None) -> ModelList | Refuse:
        return ModelList(("gpt-4.1-mini",))

    def credential(self, ref: CredentialRef) -> SecretHandle | None:
        return SecretHandle(b"sk-vaulted") if ref.key_version == 1 else None


def request(principal: KeyPrincipal) -> DecisionRequest:
    return DecisionRequest(
        principal=principal,
        operation="chat.completions",
        request_id="req-1",
        has_provider_credential=True,
    )


def test_fake_satisfies_the_protocol() -> None:
    assert isinstance(FakePolicyView(), PolicyView)


def test_decision_serves_with_ordered_targets() -> None:
    view = FakePolicyView()
    principal = view.authenticate("good")
    assert isinstance(principal, KeyPrincipal)
    decision = view.decide(request(principal))
    assert isinstance(decision, Serve)
    assert decision.targets[0].route == "primary"
    headers = decision.response_headers()
    assert headers["X-Sibyl-Policy-Version"] == "7"
    assert headers["X-Sibyl-Policy-State"] == "fresh"
    assert headers["X-Sibyl-Route"] == "primary"
    assert headers["X-Sibyl-Agent-Id"] == str(AGENT)
    assert str(TENANT) not in "".join(headers.values())


def test_killed_refuses_on_any_snapshot_state() -> None:
    for state in PolicyState:
        decision = FakePolicyView("killed", state).decide(request(FakePolicyView().principal))
        assert isinstance(decision, Refuse)
        assert (decision.http_status, decision.error_code) == (403, "sibyl_agent_killed")


def test_serve_requires_at_least_one_target() -> None:
    with pytest.raises(ValueError, match="target"):
        Serve(
            tenant_id=TENANT,
            agent_id=AGENT,
            routing_state="active",
            policy=STATUS,
            targets=(),
            fail_mode="open",
            capture_mode="full",
            redaction_profile_hash="0" * 64,
        )


def test_bad_key_is_rejected_uniformly() -> None:
    rejected = FakePolicyView().authenticate("bad")
    assert isinstance(rejected, KeyRejected)
    assert ERROR_MAP[rejected.code] == (401, "authentication_error")


def test_secret_handles_never_print_their_value() -> None:
    handle = FakePolicyView().credential(CredentialRef(uuid4(), 1))
    assert handle is not None
    assert "sk-vaulted" not in repr(handle) and "sk-vaulted" not in str(handle)
    assert handle.reveal() == b"sk-vaulted"
    handle.zeroise()
    with pytest.raises(RuntimeError):
        handle.reveal()  # use-after-zeroise must fail loudly (G0 review L5)


def test_decision_objects_are_frozen() -> None:
    with pytest.raises(FrozenInstanceError):
        PRIMARY.model = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("state", "fail_mode", "killed", "ever_loaded", "expected"),
    [
        (PolicyState.FRESH, "open", False, True, None),
        (PolicyState.FRESH, "closed", False, True, None),
        (PolicyState.STALE, "open", False, True, None),
        (PolicyState.STALE, "closed", False, True, None),
        (PolicyState.EXPIRED, "open", False, True, None),
        (PolicyState.EXPIRED, "closed", False, True, (503, "sibyl_policy_expired")),
        (PolicyState.UNAVAILABLE, "open", False, False, (503, "sibyl_no_snapshot")),
        (PolicyState.UNAVAILABLE, "closed", False, False, (503, "sibyl_no_snapshot")),
        (PolicyState.EXPIRED, "open", True, True, (403, "sibyl_agent_killed")),
        (PolicyState.FRESH, "closed", True, True, (403, "sibyl_agent_killed")),
    ],
)
def test_fail_mode_matrix_api_md_3_5(state, fail_mode, killed, ever_loaded, expected) -> None:
    out = apply_fail_mode(
        state, fail_mode, killed=killed, ever_loaded=ever_loaded, agent_id=AGENT, policy=STATUS
    )
    if expected is None:
        assert out is None
    else:
        assert isinstance(out, Refuse)
        assert (out.http_status, out.error_code) == expected


def test_matrix_is_total_and_audits_the_degraded_paths() -> None:
    for state in PolicyState:
        for mode in ("open", "closed"):
            assert (state, mode) in FAIL_MODE_MATRIX
    assert FAIL_MODE_MATRIX[(PolicyState.EXPIRED, "open")].audit == "policy.stale_bypass"
    assert FAIL_MODE_MATRIX[(PolicyState.EXPIRED, "closed")].audit == "policy.fail_closed_block"
    assert FAIL_MODE_MATRIX[(PolicyState.UNAVAILABLE, "open")].audit == (
        "policy.no_snapshot_refusal"
    )


def test_error_map_covers_api_md_3_5() -> None:
    for code in (
        "sibyl_header_not_allowed",
        "sibyl_agent_mismatch",
        "sibyl_agent_quarantined",
        "sibyl_policy_blocked",
        "sibyl_model_not_allowed",
        "sibyl_agent_unknown",
        "sibyl_rate_limited",
        "sibyl_inflight_limit",
        "sibyl_budget_exhausted",
        "upstream_error",
        "sibyl_agent_handed_off",
        "sibyl_agent_queued",
        "sibyl_breaker_open",
        "upstream_timeout",
    ):
        assert code in ERROR_MAP
    refusal = Refuse.of("sibyl_agent_handed_off", agent_id=AGENT, policy=STATUS)
    assert refusal.retry_after_s == 300
    assert refusal.error_type == "api_error"
