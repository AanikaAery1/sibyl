"""Every OpenAPI operation is mounted in the app, and nothing else is."""

from __future__ import annotations

import importlib

import pytest
import sibyl_schemas
from sibyl_control.api.app import INFRA_PATHS, create_app
from sibyl_control.api.contract import operations
from sibyl_control.api.routers import iter_api_routes

from ._examples import concrete_path

API_OPS = [op for op in operations() if op.surface != "ingest"]
INGEST_OPS = [op for op in operations() if op.surface == "ingest"]


def _mounted(app) -> set[tuple[str, str]]:
    return set(iter_api_routes(app.routes))


@pytest.fixture(scope="module")
def mounted() -> set[tuple[str, str]]:
    return _mounted(create_app())


@pytest.mark.parametrize("op", API_OPS, ids=lambda o: o.operation_id)
def test_operation_is_mounted(op, mounted) -> None:
    assert (op.method, op.mount_path) in mounted


def test_app_mounts_nothing_outside_the_contract(mounted) -> None:
    contract = {(op.method, op.mount_path) for op in API_OPS}
    extra = {(m, p) for m, p in mounted if (m, p) not in contract and p not in INFRA_PATHS}
    assert extra == set()


def test_stubs_answer_501_problem_json(harness) -> None:
    # generateAgentBom stays a stub by ruling B14 (AI-BOM cut to Phase 1.5).
    resp = harness.client.post(
        "/api/v1/agents/00000000-0000-7000-8000-000000000001/versions/1/bom",
        headers={"Authorization": "Bearer owner-a", "Idempotency-Key": "stub-501"},
    )
    assert resp.status_code == 501
    assert resp.headers["content-type"] == "application/problem+json"
    body = resp.json()
    assert body["type"].endswith("/not_implemented")
    assert "generateAgentBom" in body["detail"]


def test_event_stream_is_not_shadowed_by_event_by_id(harness) -> None:
    # The stream is a real handler now (lane V). With no database in this harness it answers
    # 503 from the stream handler itself; the by-id route would answer 400/404 for "stream".
    resp = harness.client.get("/api/v1/events/stream", headers={"Authorization": "Bearer owner-a"})
    assert resp.status_code == 503, resp.text


def test_infra_endpoints_and_security_headers(harness) -> None:
    resp = harness.client.get("/healthz")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "no-referrer"
    assert resp.headers["Cache-Control"] == "no-store"
    assert resp.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert resp.headers["X-Sibyl-Api-Version"].startswith("v1.")
    assert resp.headers["X-Request-Id"]


def test_request_id_is_echoed_when_safe(harness) -> None:
    resp = harness.client.get("/healthz", headers={"X-Request-Id": "abc-123"})
    assert resp.headers["X-Request-Id"] == "abc-123"
    resp = harness.client.get("/healthz", headers={"X-Request-Id": "bad id\n"})
    assert resp.headers["X-Request-Id"] != "bad id\n"


def test_credentials_in_url_are_refused_globally(harness) -> None:
    key = "sbl_live_ABCDEFGHIJKL_" + "a" * 43
    resp = harness.client.get(f"/api/v1/agents?api_key={key}")
    assert resp.status_code == 400
    assert resp.json()["type"].endswith("/credential_in_url")
    assert key not in resp.text


def test_served_openapi_is_the_contract(harness) -> None:
    resp = harness.client.get("/api/v1/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["x-sibyl-contract-version"] == "1.1.0"
    assert resp.json()["info"]["version"].startswith("1.1.0")
    assert sibyl_schemas.CONTRACT_TAG == "contracts-v1.1.0"


@pytest.mark.parametrize("op", INGEST_OPS, ids=lambda o: o.operation_id)
def test_ingest_operation_is_mounted_by_the_ingest_app(op) -> None:
    module = importlib.import_module("sibyl_control.ingest.app")
    app = module.create_app()
    assert (op.method, op.mount_path) in _mounted(app)
    assert concrete_path(op).startswith("/v1/")
