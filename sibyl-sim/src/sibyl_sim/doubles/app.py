"""Two ASGI apps over one `SimState`.

- `doubles_app` (https, default port 18082): the OpenAI-compatible provider doubles. `/v1/*`
  is the default double (fixture base URL `https://127.0.0.1:18082/v1`), `/<double>/v1/*`
  addresses one double by name; `/sentinel-stub/...` is the Sentinel LLM double
  (`sentinel_stub`). Also serves the read-only status feeds.
- `control_app` (http, port 8300): `/healthz`, the status feeds, the dev CA at
  `/_sim/tls/ca.pem`, and the chaos admin API under `/_sim/*`. Admin never lives on a
  product port (R32); set `SIBYL_SIM_ADMIN_TOKEN` to require a bearer token.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

from sibyl_sim.doubles import responses, sentinel_stub
from sibyl_sim.doubles.engine import Double
from sibyl_sim.doubles.knobs import KnobError, Knobs
from sibyl_sim.doubles.sentinel_stub import SentinelStub
from sibyl_sim.doubles.state import SimState
from sibyl_sim.status_feed.routes import admin_routes, feed_routes


def _credential(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer ") and auth[7:].strip():
        return auth[7:].strip()
    return request.headers.get("x-api-key") or None


def _double(state: SimState, request: Request) -> Double | None:
    name = request.path_params.get("double", state.default_double)
    return state.doubles.get(str(name))


async def _json(request: Request) -> Any:
    try:
        return await request.json()
    except ValueError:
        return None


def _unauthorized() -> JSONResponse:
    return JSONResponse(responses.error_body(401, "invalid_api_key", "missing API key"), 401)


# ------------------------------------------------------------------ provider surface


def doubles_routes(state: SimState) -> list[Route]:
    async def chat(request: Request) -> Response:
        double = _double(state, request)
        if double is None:
            return JSONResponse(responses.error_body(404, "unknown_double"), 404)
        credential = _credential(request)
        if credential is None:
            return _unauthorized()
        body = await _json(request)
        if not isinstance(body, dict):
            return JSONResponse(responses.error_body(400, "invalid_json"), 400)
        model = str(body.get("model", ""))
        decision = double.decide(
            model=model, credential=credential, has_tools=bool(body.get("tools"))
        )
        await state.sleep(decision.latency_ms / 1000.0)
        headers = {
            **decision.headers,
            "x-sim-decision": f"{decision.seq}:{decision.behaviour}",
            "x-request-id": f"sim-{double.name}-{decision.seq}",
        }
        if decision.status != 200:
            return JSONResponse(
                responses.error_body(decision.status, decision.error_code or ""),
                decision.status,
                headers=headers,
            )
        payload = responses.completion(double.name, model, body, decision, int(state.clock()))
        usage = payload["usage"]
        cost = double.account(decision.knobs, usage["prompt_tokens"], usage["completion_tokens"])
        headers["x-sim-cost-usd"] = f"{cost:.8f}"
        if not body.get("stream"):
            return JSONResponse(payload, headers=headers)
        include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        gap = decision.knobs.inter_chunk_ms / 1000.0

        async def events() -> AsyncIterator[str]:
            for n, chunk in enumerate(responses.stream_chunks(payload, include_usage)):
                if n and gap:
                    await state.sleep(gap)
                yield f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream", headers=headers)

    async def embeddings(request: Request) -> Response:
        double = _double(state, request)
        if double is None:
            return JSONResponse(responses.error_body(404, "unknown_double"), 404)
        credential = _credential(request)
        if credential is None:
            return _unauthorized()
        body = await _json(request)
        if not isinstance(body, dict):
            return JSONResponse(responses.error_body(400, "invalid_json"), 400)
        model = str(body.get("model", ""))
        decision = double.decide(model=model, credential=credential, has_tools=False)
        await state.sleep(decision.latency_ms / 1000.0)
        if decision.status != 200:
            return JSONResponse(
                responses.error_body(decision.status, decision.error_code or ""),
                decision.status,
                headers=decision.headers,
            )
        payload = responses.embeddings(model, body, decision.knobs.token_multiplier)
        cost = double.account(decision.knobs, payload["usage"]["prompt_tokens"], 0)
        return JSONResponse(payload, headers={**decision.headers, "x-sim-cost-usd": f"{cost:.8f}"})

    async def models(request: Request) -> Response:
        double = _double(state, request)
        if double is None:
            return JSONResponse(responses.error_body(404, "unknown_double"), 404)
        if _credential(request) is None:
            return _unauthorized()
        if double.knobs.outage:
            return JSONResponse(responses.error_body(503, "service_unavailable"), 503)
        names = tuple(m for m in double.models if m not in double.knobs.missing_models)
        return JSONResponse(responses.models(double.provider, names, int(state.clock())))

    routes: list[Route] = []
    for prefix in ("", "/{double}"):
        routes += [
            Route(f"{prefix}/v1/chat/completions", chat, methods=["POST"]),
            Route(f"{prefix}/v1/embeddings", embeddings, methods=["POST"]),
            Route(f"{prefix}/v1/models", models, methods=["GET"]),
        ]
    return routes


async def _healthz(request: Request) -> Response:
    state: SimState = request.app.state.sim
    return JSONResponse(
        {
            "status": "ok",
            "doubles": sorted(state.doubles),
            "default_double": state.default_double,
            "ca_path": state.ca_path,
        }
    )


def _sentinel(state: SimState) -> SentinelStub:
    if state.sentinel is None:
        state.sentinel = SentinelStub(state.seed, state.clock)
    return state.sentinel


def doubles_app(state: SimState) -> Starlette:
    app = Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            *feed_routes(state.feeds),
            *sentinel_stub.provider_routes(lambda: _sentinel(state)),  # before /{double}/v1
            *doubles_routes(state),
        ]
    )
    app.state.sim = state
    return app


# ------------------------------------------------------------------ admin (sim port)


def _guard(state: SimState) -> Callable[[Request], Response | None]:
    def check(request: Request) -> Response | None:
        if state.admin_token is None:
            return None
        supplied = _credential(request) or ""
        if hmac.compare_digest(supplied.encode(), state.admin_token.encode()):
            return None
        return JSONResponse({"error": "admin token required"}, status_code=401)

    return check


def admin_double_routes(state: SimState) -> list[Route]:
    guard = _guard(state)

    def lookup(request: Request) -> Double | None:
        return state.doubles.get(str(request.path_params["double"]))

    async def list_doubles(request: Request) -> Response:
        return guard(request) or JSONResponse(
            {name: double.snapshot() for name, double in state.doubles.items()}
        )

    async def one(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        double = lookup(request)
        if double is None:
            return JSONResponse({"error": "unknown double"}, status_code=404)
        return JSONResponse(double.snapshot())

    async def knobs(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        double = lookup(request)
        if double is None:
            return JSONResponse({"error": "unknown double"}, status_code=404)
        patch = await _json(request)
        if not isinstance(patch, dict):
            return JSONResponse({"error": "JSON object expected"}, status_code=422)
        base = Knobs() if request.method == "PUT" else double.knobs
        try:
            new = base.merged(patch)
        except KnobError as exc:
            return JSONResponse({"error": str(exc)}, status_code=422)
        double.update(new, restart_ramp="ramp" in patch)
        return JSONResponse(double.snapshot())

    async def outage(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        double = lookup(request)
        body = await _json(request)
        if double is None:
            return JSONResponse({"error": "unknown double"}, status_code=404)
        if not isinstance(body, dict) or not isinstance(body.get("on"), bool):
            return JSONResponse({"error": 'body must be {"on": true|false}'}, status_code=422)
        double.update(double.knobs.merged({"outage": body["on"]}), restart_ramp=False)
        return JSONResponse(double.snapshot())

    async def reset(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        double = lookup(request)
        if double is None:
            return JSONResponse({"error": "unknown double"}, status_code=404)
        body = await _json(request) or {}
        seed = body.get("seed", state.seed) if isinstance(body, dict) else state.seed
        if not isinstance(seed, int) or isinstance(seed, bool):
            return JSONResponse({"error": "seed must be an integer"}, status_code=422)
        double.reset(seed)
        return JSONResponse(double.snapshot())

    async def log(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        double = lookup(request)
        if double is None:
            return JSONResponse({"error": "unknown double"}, status_code=404)
        return JSONResponse({"name": double.name, "decisions": list(double.log)})

    return [
        Route("/_sim/doubles", list_doubles, methods=["GET"]),
        Route("/_sim/doubles/{double}", one, methods=["GET"]),
        Route("/_sim/doubles/{double}/knobs", knobs, methods=["PUT", "PATCH"]),
        Route("/_sim/doubles/{double}/outage", outage, methods=["POST"]),
        Route("/_sim/doubles/{double}/reset", reset, methods=["POST"]),
        Route("/_sim/doubles/{double}/log", log, methods=["GET"]),
    ]


def control_app(state: SimState) -> Starlette:
    async def ca(request: Request) -> Response:
        if not state.ca_path:
            return JSONResponse({"error": "TLS not enabled"}, status_code=404)
        pem = await run_in_threadpool(Path(state.ca_path).read_text, "ascii")
        return PlainTextResponse(pem, media_type="application/x-pem-file")

    app = Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            Route("/_sim/tls/ca.pem", ca, methods=["GET"]),
            *feed_routes(state.feeds),
            *admin_routes(state.feeds, _guard(state)),
            *sentinel_stub.admin_routes(lambda: _sentinel(state), _guard(state)),
            *admin_double_routes(state),
        ]
    )
    app.state.sim = state
    return app
