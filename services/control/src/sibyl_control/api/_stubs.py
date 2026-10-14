"""Register 501 stubs for every contract operation a module has not implemented yet.

Wave 0 ships every module as ``router = stub_router("<module>")``. A lane implements real
handlers on its own ``APIRouter`` (full paths, e.g. ``API_PREFIX + "/agents"``) and then calls
``stub_router("<module>", router)`` so the operations it has not reached yet stay mounted as 501.
"""

from __future__ import annotations

from collections.abc import Callable, Coroutine, Iterable, Iterator
from typing import Any, NoReturn

from fastapi import APIRouter
from fastapi.routing import APIRoute

from ..core.problems import ProblemError
from .contract import ContractOperation, operations


def iter_api_routes(routes: Iterable[Any], prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield ``(method, full_path)`` for every APIRoute, descending into included routers.

    FastAPI >= 0.14x keeps ``include_router`` lazily as wrapper objects instead of copying routes.
    """
    for route in routes:
        if isinstance(route, APIRoute):
            for method in route.methods or ():
                yield method.lower(), prefix + route.path
            continue
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            inner = prefix + (getattr(context, "prefix", "") or "")
            yield from iter_api_routes(original.routes, inner)


def _mounted(router: APIRouter) -> set[tuple[str, str]]:
    return set(iter_api_routes(router.routes))


def _endpoint(op: ContractOperation) -> Callable[[], Coroutine[Any, Any, NoReturn]]:
    async def not_implemented() -> NoReturn:
        raise ProblemError(
            "not_implemented",
            f"{op.operation_id} ({op.route_key}) is registered but not implemented yet",
            extensions={"operation_id": op.operation_id},
        )

    not_implemented.__name__ = f"stub_{op.operation_id}"
    return not_implemented


def stub_router(module: str, router: APIRouter | None = None) -> APIRouter:
    router = router or APIRouter()
    mounted = _mounted(router)
    for op in operations():
        if op.module != module or op.surface == "ingest":
            continue
        if (op.method, op.mount_path) in mounted:
            continue
        router.add_api_route(
            op.mount_path,
            _endpoint(op),
            methods=[op.method.upper()],
            operation_id=op.operation_id,
            name=op.operation_id,
            include_in_schema=False,
            response_model=None,
        )
    return router
