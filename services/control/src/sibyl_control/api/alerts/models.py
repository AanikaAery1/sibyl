"""Request body of ``POST /alerts/{id}/actions`` (OpenAPI ``AlertAction``, closed object).

``verdict`` is optional in the schema so a ``close`` without it reaches the handler, which
answers with the contract's own 422 ``verdict_required`` (D24) instead of a generic validation
error. ``verdict_note`` is held to 500 characters, the ``sibyl-label/1`` ``reason`` limit it is
stored under (the OpenAPI says 2000: recorded as a conflict for INT-1).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AlertActionName = Literal["ack", "silence", "close"]
Verdict = Literal["tp", "fp", "unsure"]
VERDICT_NOTE_MAX = 500


class AlertAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: AlertActionName
    reason: str | None = Field(default=None, max_length=2000)
    until: datetime | None = None
    verdict: Verdict | None = None
    verdict_note: str | None = Field(default=None, max_length=VERDICT_NOTE_MAX)
