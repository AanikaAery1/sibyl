"""RFC 9457 problem details: the exception, the FastAPI handlers and the database error map.

The error-code registry itself (codes, statuses, titles) lives in ``sibyl_schemas.values``.

``type`` is ``https://sibyl.dev/problems/<code>``; ``<code>`` is the stable identifier used in the
OpenAPI ``x-sibyl-problems`` extension. ``detail`` must be safe: no secrets, no cross-tenant ids,
no upstream ``base_url``. Unhandled exceptions become a generic 500 with nothing from the exception.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sibyl_schemas import values as sv
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..migrate import errcodes

PROBLEM_BASE = sv.PROBLEM_TYPE_BASE
PROBLEM_MEDIA_TYPE = "application/problem+json"
REQUEST_ID_HEADER = "X-Request-Id"

log = logging.getLogger("sibyl.problems")


@dataclass(frozen=True)
class ProblemSpec:
    statuses: tuple[int, ...]
    title: str

    @property
    def status(self) -> int:
        return self.statuses[0]


PROBLEM_CODES: Mapping[str, ProblemSpec] = MappingProxyType(
    {
        code.value: ProblemSpec(sv.problem_statuses(code), sv.PROBLEM_TITLE[code])
        for code in sv.ProblemCode
    }
)
"""The registry is ``sibyl_schemas.values.ProblemCode`` (G0 single source); this is its view."""

# Postgres SQLSTATE -> problem code for errors the database raises on its own.
SQLSTATE_MAP: Mapping[str, str] = MappingProxyType(
    {
        "23505": "conflict",
        "23503": "reference_unknown",
        "23514": "validation_failed",
        "22P02": "validation_failed",
        "40001": "serialization_failure",
        "40P01": "serialization_failure",
        "57014": "database_timeout",
        "08006": "database_unavailable",
        "08001": "database_unavailable",
        "42501": "internal_error",
    }
)
SIBYL_RAISE_PREFIX = sv.DB_ERROR_PREFIX
SIBYL_SQLSTATE_CLASS = sv.DB_ERROR_SQLSTATE_CLASS


def _sibyl_db_code(sqlstate: str, message: str) -> str | None:
    """The ``sibyl:<code>`` of a Sibyl raise (chair ruling G0-1), from the message or SQLSTATE."""
    code = sv.parse_db_error_code(message)
    if code is None and sqlstate.startswith(SIBYL_SQLSTATE_CLASS):
        code = errcodes.code_for(sqlstate)
    return code


class ProblemError(Exception):
    """An error that renders as RFC 9457 problem details."""

    def __init__(
        self,
        code: str,
        detail: str | None = None,
        *,
        status: int | None = None,
        extensions: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        audit_denied: bool = False,
    ) -> None:
        spec = PROBLEM_CODES[code]
        self.code = code
        self.status = status if status is not None else spec.status
        if self.status not in spec.statuses:
            raise ValueError(f"{code} is not registered for status {self.status}")
        self.title = spec.title
        self.detail = detail
        self.extensions: dict[str, Any] = dict(extensions or {})
        self.headers: dict[str, str] = dict(headers or {})
        self.audit_denied = audit_denied
        super().__init__(f"{code}: {detail or spec.title}")

    def to_body(self, *, instance: str | None, request_id: str | None) -> dict[str, Any]:
        body: dict[str, Any] = {
            "type": PROBLEM_BASE + self.code,
            "title": self.title,
            "status": self.status,
        }
        if self.detail:
            body["detail"] = self.detail
        if instance:
            body["instance"] = instance
        if request_id:
            body["request_id"] = request_id
        for key, value in self.extensions.items():
            body.setdefault(key, value)
        return body


def problem(code: str, detail: str | None = None, **extensions: Any) -> ProblemError:
    """Build a registered problem; ``retry_after_s`` also sets the ``Retry-After`` header."""
    headers: dict[str, str] = {}
    if "retry_after_s" in extensions:
        headers["Retry-After"] = str(int(extensions["retry_after_s"]))
    status = extensions.pop("status", None)
    return ProblemError(code, detail, status=status, extensions=extensions, headers=headers)


def problem_from_db_error(exc: BaseException) -> ProblemError:
    """Map an asyncpg/Postgres error to a problem without echoing the database message.

    Sibyl raises use SQLSTATE class ``SB`` and a ``sibyl:<code>[: detail]`` message; the code is
    mapped through ``DB_ERROR_PROBLEM``. Unknown Sibyl codes are ``internal_error``.
    """
    sqlstate = str(getattr(exc, "sqlstate", None) or "")
    message = str(getattr(exc, "message", "") or exc)
    db_code = _sibyl_db_code(sqlstate, message)
    if db_code is not None:
        problem_code = sv.DB_ERROR_PROBLEM.get(db_code)
        if problem_code is None and db_code in PROBLEM_CODES:
            return ProblemError(db_code)
        return ProblemError(problem_code.value if problem_code else "internal_error")
    return ProblemError(SQLSTATE_MAP.get(sqlstate, "internal_error"))


def problem_response(
    err: ProblemError, *, instance: str | None, request_id: str | None
) -> JSONResponse:
    return JSONResponse(
        err.to_body(instance=instance, request_id=request_id),
        status_code=err.status,
        media_type=PROBLEM_MEDIA_TYPE,
        headers=err.headers or None,
    )


def _request_id(request: Request) -> str | None:
    state_id = getattr(request.state, "request_id", None)
    return state_id or request.headers.get(REQUEST_ID_HEADER)


def _pointer(loc: tuple[int | str, ...]) -> str:
    if not loc:
        return "/"
    where, *rest = loc
    path = "".join(f"/{part}" for part in rest)
    if where == "body":
        return path or "/"
    return f"{where}:{'/'.join(str(p) for p in rest)}"


def validation_problem(exc: RequestValidationError) -> ProblemError:
    errors = [
        {
            "pointer": _pointer(tuple(e.get("loc", ()))),
            "code": e.get("type", "invalid"),
            "message": e.get("msg", "invalid"),
        }
        for e in exc.errors()
    ]
    return ProblemError("validation_failed", extensions={"errors": errors})


_HTTP_CODES: Mapping[int, str] = MappingProxyType(
    {
        400: "validation_failed",
        401: "unauthenticated",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        413: "payload_too_large",
        415: "unsupported_media_type",
        422: "validation_failed",
        429: "rate_limited",
    }
)


def install_problem_handlers(app: FastAPI) -> None:
    """Make every error path of ``app`` answer with problem+json."""

    async def on_problem(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, ProblemError)
        return problem_response(exc, instance=request.url.path, request_id=_request_id(request))

    async def on_validation(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, RequestValidationError)
        err = validation_problem(exc)
        return problem_response(err, instance=request.url.path, request_id=_request_id(request))

    async def on_http(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, StarletteHTTPException)
        code = _HTTP_CODES.get(exc.status_code, "internal_error")
        status = exc.status_code if code != "internal_error" else 500
        if code == "validation_failed":
            status = 422
        err = ProblemError(code, status=status, headers=getattr(exc, "headers", None))
        return problem_response(err, instance=request.url.path, request_id=_request_id(request))

    async def on_unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error", extra={"path": request.url.path})
        err = ProblemError("internal_error")
        return problem_response(err, instance=request.url.path, request_id=_request_id(request))

    app.add_exception_handler(ProblemError, on_problem)
    app.add_exception_handler(RequestValidationError, on_validation)
    app.add_exception_handler(StarletteHTTPException, on_http)
    app.add_exception_handler(Exception, on_unhandled)
