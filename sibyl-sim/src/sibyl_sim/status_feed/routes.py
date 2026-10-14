"""Status-feed HTTP routes: the public Statuspage-shaped feed and its admin controls."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from sibyl_sim.status_feed.feed import FeedError, ProviderFeed

Feeds = Mapping[str, ProviderFeed]


def _feed(feeds: Feeds, request: Request) -> ProviderFeed | None:
    return feeds.get(str(request.path_params["provider"]))


def feed_routes(feeds: Feeds) -> list[Route]:
    """Read-only feed, safe to serve on both the sim port and the doubles' https port."""

    async def summary(request: Request) -> Response:
        feed = _feed(feeds, request)
        if feed is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        if feed.config.feed_down:
            return JSONResponse({"error": "status page unavailable"}, status_code=503)
        return JSONResponse(feed.summary())

    async def status(request: Request) -> Response:
        feed = _feed(feeds, request)
        if feed is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        if feed.config.feed_down:
            return JSONResponse({"error": "status page unavailable"}, status_code=503)
        doc = feed.summary()
        return JSONResponse({"page": doc["page"], "status": doc["status"]})

    return [
        Route("/status/{provider}/api/v2/summary.json", summary, methods=["GET"]),
        Route("/status/{provider}/api/v2/status.json", status, methods=["GET"]),
    ]


def admin_routes(feeds: Feeds, guard: Callable[[Request], Response | None]) -> list[Route]:
    """`/_sim/status/...` (sim port only, R32)."""

    async def body(request: Request) -> Any:
        try:
            return await request.json()
        except ValueError:
            return None

    async def get_or_update(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        feed = _feed(feeds, request)
        if feed is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        if request.method in ("PUT", "PATCH"):
            patch = await body(request)
            if not isinstance(patch, dict):
                return JSONResponse({"error": "JSON object expected"}, status_code=422)
            try:
                if request.method == "PUT":
                    feed.reset()
                feed.configure(patch, restart=request.method == "PUT")
            except FeedError as exc:
                return JSONResponse({"error": str(exc)}, status_code=422)
        return JSONResponse(feed.describe())

    async def add_incident(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        feed = _feed(feeds, request)
        if feed is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        raw = await body(request)
        if not isinstance(raw, dict):
            return JSONResponse({"error": "JSON object expected"}, status_code=422)
        try:
            incident = feed.add_incident(raw)
        except FeedError as exc:
            return JSONResponse({"error": str(exc)}, status_code=422)
        return JSONResponse(vars(incident), status_code=201)

    async def reset(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        feed = _feed(feeds, request)
        if feed is None:
            return JSONResponse({"error": "unknown provider"}, status_code=404)
        feed.reset()
        return JSONResponse(feed.describe())

    async def list_feeds(request: Request) -> Response:
        denied = guard(request)
        if denied is not None:
            return denied
        return JSONResponse({name: feed.describe() for name, feed in feeds.items()})

    return [
        Route("/_sim/status", list_feeds, methods=["GET"]),
        Route("/_sim/status/{provider}", get_or_update, methods=["GET", "PUT", "PATCH"]),
        Route("/_sim/status/{provider}/incidents", add_incident, methods=["POST"]),
        Route("/_sim/status/{provider}/reset", reset, methods=["POST"]),
    ]
