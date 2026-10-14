"""Request building and response parsing shared by the sync and async monitor clients."""

from __future__ import annotations

import json
import os
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Final
from uuid import UUID, uuid4

import httpx
from sibyl_schemas.models.monitor import FindingSubmit

from sibyl._version import __version__

from ._errors import MonitorApiError, MonitorConfigError

API_PREFIX: Final = "/api/v1"
ENV_URL: Final = "SIBYL_API_URL"
ENV_KEY: Final = "SIBYL_MONITOR_KEY"
DEFAULT_TIMEOUT_S: Final = 10.0
MAX_PAGES: Final = 100
_KEY_RE = re.compile(r"^sbl_(live|test)_([A-Za-z0-9]{12})_[A-Za-z0-9_-]{43}$")
_RETRY_STATUSES = frozenset({429, 503})

Page = dict[str, Any]
JSON = dict[str, Any]


def normalise_base_url(url: str) -> str:
    """``https://host`` or ``https://host/api/v1`` -> ``https://host/api/v1`` (no trailing /)."""
    value = (url or "").strip().rstrip("/")
    if not value:
        raise MonitorConfigError(f"{ENV_URL} is not set")
    if not value.startswith(("https://", "http://")):
        raise MonitorConfigError(f"{ENV_URL} must be an http(s) URL")
    if not value.endswith(API_PREFIX):
        value += API_PREFIX
    return value


def key_hint(key: str) -> str:
    """The non-secret part of a key (``sbl_live_<prefix>_…``) for reprs and logs."""
    match = _KEY_RE.fullmatch(key)
    if match is None:
        return "sbl_…"
    return f"sbl_{match.group(1)}_{match.group(2)}_…"


def check_key(key: str) -> str:
    value = (key or "").strip()
    if not value:
        raise MonitorConfigError(f"{ENV_KEY} is not set")
    if _KEY_RE.fullmatch(value) is None:
        raise MonitorConfigError(
            "the monitor key must look like sbl_<env>_<prefix12>_<secret>"
            " (issued by POST /monitors/{id}/keys)"
        )
    return value


def from_env(environ: Mapping[str, str] | None = None) -> tuple[str, str]:
    env = os.environ if environ is None else environ
    return normalise_base_url(env.get(ENV_URL, "")), check_key(env.get(ENV_KEY, ""))


def tls_verify(ca_file: str | None) -> ssl.SSLContext | bool:
    """Verification is always on; ``ca_file`` adds a CA bundle (corporate TLS inspection)."""
    if ca_file:
        return ssl.create_default_context(cafile=ca_file)
    return True


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return str(value.value)
    return str(value)


def query(params: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Query pairs: ``None`` dropped, lists repeated (``state=a&state=b``)."""
    out: list[tuple[str, str]] = []
    for name, value in params.items():
        if value is None:
            continue
        if isinstance(value, list | tuple | set | frozenset):
            out.extend((name, _scalar(item)) for item in value)
        else:
            out.append((name, _scalar(value)))
    return out


def seg(value: UUID | str) -> str:
    """A path segment: must be a UUID (refuses path tricks from model-supplied ids)."""
    try:
        return str(UUID(str(value)))
    except ValueError:
        raise ValueError(f"not a UUID: {str(value)[:64]!r}") from None


@dataclass(frozen=True)
class Req:
    method: str
    path: str
    params: list[tuple[str, str]] = field(default_factory=list)
    body: JSON | None = None
    idempotency_key: str | None = None


def headers(key: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": f"sibyl-monitor/{__version__}",
    }


def build(req: Req) -> dict[str, Any]:
    kw: dict[str, Any] = {"params": req.params}
    extra: dict[str, str] = {}
    if req.body is not None:
        kw["content"] = json.dumps(req.body, separators=(",", ":")).encode()
        extra["Content-Type"] = "application/json"
    if req.idempotency_key is not None:
        extra["Idempotency-Key"] = req.idempotency_key
    if extra:
        kw["headers"] = extra
    return kw


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def parse(response: httpx.Response) -> Any:
    if 200 <= response.status_code < 300:
        if response.status_code == 204 or not response.content:
            return None
        return response.json()
    raise problem(response)


def problem(response: httpx.Response) -> MonitorApiError:
    doc: Any = None
    try:
        doc = response.json()
    except ValueError:
        doc = None
    if not isinstance(doc, dict):
        doc = {}
    code = doc.get("code")
    if not isinstance(code, str) or not code:
        type_uri = doc.get("type")
        code = type_uri.rstrip("/").rsplit("/", 1)[-1] if isinstance(type_uri, str) else ""
    if not code:
        code = f"http_{response.status_code}"
    known = {"type", "title", "status", "detail", "instance", "code"}
    return MonitorApiError(
        response.status_code,
        code,
        doc.get("title") if isinstance(doc.get("title"), str) else None,
        doc.get("detail") if isinstance(doc.get("detail"), str) else None,
        retry_after=_retry_after(response) if response.status_code in _RETRY_STATUSES else None,
        request_id=response.headers.get("x-request-id"),
        extensions={k: v for k, v in doc.items() if k not in known},
    )


# --- routes -------------------------------------------------------------------------------


def listing(path: str, limit: int | None, cursor: str | None, filters: Mapping[str, Any]) -> Req:
    return Req("GET", path, query({"limit": limit, "cursor": cursor, **filters}))


def finding_body(**fields: Any) -> JSON:
    """Validate a finding client-side (same model as the server) and return its JSON body."""
    model = FindingSubmit.model_validate({k: v for k, v in fields.items() if v is not None})
    body: JSON = model.model_dump(mode="json", exclude_none=True)
    if "body" not in fields or fields["body"] is None:
        body.pop("body", None)
    return body


def submit(body: JSON, idempotency_key: str | None) -> Req:
    return Req("POST", "/findings", body=body, idempotency_key=idempotency_key or str(uuid4()))


def recommendation_fields(
    held_action_id: UUID | str,
    advice: str,
    recommendation: str,
    summary: str | None,
    severity: str,
    extra: Mapping[str, Any],
) -> JSON:
    return {
        "kind": "held_action_review",
        "subject_kind": "held_action",
        "subject_id": seg(held_action_id),
        "advice": advice,
        "recommendation": recommendation,
        "summary": summary or f"Monitor advice on held action: {advice}",
        "severity": severity,
        **extra,
    }
