import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sibyl_control.core.problems import (
    PROBLEM_BASE,
    PROBLEM_CODES,
    SQLSTATE_MAP,
    install_problem_handlers,
    problem,
    problem_from_db_error,
)


class Body(BaseModel):
    name: str
    scopes: list[int]


def make_app() -> FastAPI:
    app = FastAPI()
    install_problem_handlers(app)

    @app.get("/boom/{code}")
    async def boom(code: str) -> None:
        raise problem(code, "specific detail", from_state="killed")

    @app.post("/body")
    async def body(b: Body) -> dict[str, str]:
        return {"ok": b.name}

    @app.get("/crash")
    async def crash() -> None:
        raise RuntimeError("secret internals sbl_live_x")

    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(make_app(), raise_server_exceptions=False)


def test_problem_body_shape(client: TestClient) -> None:
    resp = client.get("/boom/invalid_transition", headers={"X-Request-Id": "req-1"})
    assert resp.status_code == 409
    assert resp.headers["content-type"] == "application/problem+json"
    body = resp.json()
    assert body["type"] == f"{PROBLEM_BASE}invalid_transition"
    assert body["status"] == 409
    assert body["title"]
    assert body["detail"] == "specific detail"
    assert body["instance"] == "/boom/invalid_transition"
    assert body["request_id"] == "req-1"
    assert body["from_state"] == "killed"


def test_validation_errors_are_422_with_pointers(client: TestClient) -> None:
    resp = client.post("/body", json={"scopes": ["x"]})
    assert resp.status_code == 422
    body = resp.json()
    assert body["type"].endswith("/validation_failed")
    pointers = {e["pointer"] for e in body["errors"]}
    assert "/name" in pointers
    assert "/scopes/0" in pointers


def test_malformed_json_is_a_problem(client: TestClient) -> None:
    resp = client.post("/body", content=b"{", headers={"content-type": "application/json"})
    assert resp.status_code == 422
    assert resp.headers["content-type"] == "application/problem+json"


def test_unknown_route_is_a_problem(client: TestClient) -> None:
    resp = client.get("/nope")
    assert resp.status_code == 404
    assert resp.json()["type"].endswith("/not_found")


def test_unhandled_exceptions_never_leak(client: TestClient) -> None:
    resp = client.get("/crash")
    assert resp.status_code == 500
    assert "sbl_live" not in resp.text
    assert "RuntimeError" not in resp.text
    assert resp.json()["type"].endswith("/internal_error")


def test_rate_limit_problem_carries_retry_after() -> None:
    err = problem("rate_limited", retry_after_s=7)
    assert err.headers["Retry-After"] == "7"
    assert err.extensions["retry_after_s"] == 7


def test_unknown_code_is_a_programming_error() -> None:
    with pytest.raises(KeyError):
        problem("not_a_registered_code")


def test_codes_are_snake_case_and_statuses_are_errors() -> None:
    for code, spec in PROBLEM_CODES.items():
        assert code.replace("_", "").isalnum() and code == code.lower(), code
        assert 400 <= spec.status <= 599, code
        assert spec.title


class FakePgError(Exception):
    def __init__(self, sqlstate: str, message: str = "") -> None:
        super().__init__(message)
        self.sqlstate = sqlstate
        self.message = message


@pytest.mark.parametrize(
    ("sqlstate", "message", "code"),
    [
        (
            "SB011",
            "sibyl:stale_precondition: expected active, found degraded",
            "stale_precondition",
        ),
        ("SB012", "sibyl:operator_hold: until 2026-10-10", "operator_hold"),
        ("SB010", "sibyl:invalid_transition: routing killed -> active", "invalid_transition"),
        ("SB010", "", "invalid_transition"),
        ("SB032", "sibyl:legal_hold_active: shred refused", "hold_blocked"),
        ("SB034", "sibyl:erasure_blocked_by_chain: agent x", "erasure_blocked_by_chain"),
        ("SB020", "sibyl:audit_action_unknown: undeclared audit action x", "internal_error"),
        ("SB999", "sibyl:not_a_code: x", "internal_error"),
        ("SB999", "", "internal_error"),
        ("P0001", "some other raise", "internal_error"),
        ("P0001", "sibyl:self_approval: requester", "self_approval"),
        ("23505", "duplicate key", "conflict"),
        ("23514", "check", "validation_failed"),
        ("40001", "", "serialization_failure"),
    ],
)
def test_db_errors_map_to_problems(sqlstate: str, message: str, code: str) -> None:
    err = problem_from_db_error(FakePgError(sqlstate, message))
    assert err.code == code
    assert err.detail is None, "the database message is never echoed"


def test_sqlstate_map_targets_registered_codes() -> None:
    assert set(SQLSTATE_MAP.values()) <= set(PROBLEM_CODES)


def test_problem_error_is_json_serialisable() -> None:
    err = problem("precondition_failed", current={"etag": '"3"'})
    json.dumps(err.to_body(instance="/x", request_id="r"))
