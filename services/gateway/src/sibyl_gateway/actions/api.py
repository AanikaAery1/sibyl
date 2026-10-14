"""Control-plane calls the gateway's Action Gate makes (ACTION-GATE.md §2.2, §3).

``POST /api/v1/held-actions`` (scope ``actions:hold``) and ``POST /api/v1/action-decisions``
(the cumulative check-and-increment), both idempotent per call id and authenticated with the
fronted tenant's gateway key (the same key that fetches that tenant's snapshot, R26). Every
failure returns ``None``: callers fail closed (no counter answer keeps ``on_exceed``; an
escalation that cannot be held is blocked). Bounded by a short timeout so a slow control plane
cannot stall a response for long.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any, Final
from uuid import UUID

import httpx
from sibyl_schemas.action_gate import ActionDecisionResult, HeldActionStatus

log = logging.getLogger("sibyl.gateway.actions")
HOLD_PATH: Final = "/api/v1/held-actions"
DECISION_PATH: Final = "/api/v1/action-decisions"
KeyFor = Callable[[UUID], str | None]


class ActionApi:
    def __init__(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        key_for: KeyFor,
        *,
        timeout_s: float = 2.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client = client
        self._key_for = key_for
        self._timeout = timeout_s

    async def hold(self, tenant: UUID, body: dict[str, Any]) -> HeldActionStatus | None:
        payload = await self._post(tenant, HOLD_PATH, body)
        try:
            return None if payload is None else HeldActionStatus.model_validate(payload)
        except ValueError:
            log.warning("held-action response malformed; blocking instead")
            return None

    async def decide(self, tenant: UUID, body: dict[str, Any]) -> ActionDecisionResult | None:
        payload = await self._post(tenant, DECISION_PATH, body)
        try:
            return None if payload is None else ActionDecisionResult.model_validate(payload)
        except ValueError:
            log.warning("action-decision response malformed; keeping on_exceed")
            return None

    async def _post(self, tenant: UUID, path: str, body: dict[str, Any]) -> Any:
        key = self._key_for(tenant)
        if key is None:
            log.warning("no gateway key fronts tenant %s; %s refused", tenant, path)
            return None
        try:
            response = await self._client.post(
                self._base + path,
                json=body,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Idempotency-Key": str(body.get("call_id", "")),
                },
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            log.warning("%s failed (%s); failing closed", path, type(exc).__name__)
            return None
        if response.status_code not in (200, 201):
            log.warning("%s answered HTTP %s; failing closed", path, response.status_code)
            return None
        try:
            return response.json()
        except ValueError:
            return None
