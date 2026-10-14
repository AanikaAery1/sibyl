"""Enforcement-point bodies are AG-ENFORCE's strict wire models
(``sibyl_schemas.action_gate``); a body they refuse is a 422 like any request validation."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError

from ...core.problems import ProblemError


def parse_wire[M: BaseModel](model: type[M], payload: Any) -> M:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        errors = [
            {
                "pointer": "/" + "/".join(str(p) for p in err["loc"]),
                "code": err["type"],
                "message": err["msg"],
            }
            for err in exc.errors()[:20]
        ]
        raise ProblemError(
            "validation_failed", "request body is invalid", extensions={"errors": errors}
        ) from None
