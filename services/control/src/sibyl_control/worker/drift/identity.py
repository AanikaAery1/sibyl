"""Model identity drift (D51 part 1): the provider served something other than what the agent
asked for, or other than what it served during the baseline.

* ``served_model_mismatch``: ``response_model`` is not the requested model nor a dated snapshot
  of it (``gpt-4o`` -> ``gpt-4o-2024-08-06``, ``claude-sonnet-4`` -> ``claude-sonnet-4@2025…``)
  and the baseline never saw it either (an alias the baseline already served is not news).
* ``new_served_model``: a dated snapshot of the requested model the baseline never saw
  (a silent snapshot rollover).
* ``new_fingerprint``: ``attrs.system_fingerprint`` (PLUG lane, frozen field name) the baseline
  never saw; only when the baseline saw fingerprints at all (instrumentation that starts
  reporting them is not drift).

A value needs at least ``min_count`` calls in the window, so one stray response never alerts.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from sibyl_schemas.values import DriftIdentityChange

from .features import CallSample

MAX_VALUE = 128
_SNAPSHOT = re.compile(r"[-@:](\d{2,}[0-9.-]*|v\d+(\.\d+)*|latest)")


@dataclass(frozen=True)
class IdentityFinding:
    kind: DriftIdentityChange
    value: str
    count: int
    requested_model: str

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "count": self.count,
            "requested_model": self.requested_model,
        }


def _norm(model: str) -> str:
    return model.strip().lower().removeprefix("models/")


def served_matches(requested: str, served: str) -> bool:
    """``served`` is ``requested`` or a dated/pinned snapshot of it: the remainder must be a
    version tag (``-2024-08-06``, ``-0125``, ``-002``, ``@20250514``, ``:v2``, ``-latest``), so a
    sibling model sharing the prefix (``gpt-4o`` -> ``gpt-4o-mini``) is a mismatch."""
    r, s = _norm(requested), _norm(served)
    if not r or not s or not s.startswith(r):
        return False
    return s == r or _SNAPSHOT.fullmatch(s[len(r) :]) is not None


def top_values(values: Iterable[str | None], limit: int) -> list[str]:
    """The ``limit`` most frequent non-empty values (stable order), each capped in length."""
    counts = Counter(v[:MAX_VALUE] for v in values if v)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [v for v, _ in ranked[:limit]]


def changes(
    requested_model: str,
    calls: Sequence[CallSample],
    served_set: Iterable[str],
    fingerprint_set: Iterable[str],
    min_count: int,
) -> list[IdentityFinding]:
    """Identity findings of one window against the baseline's served and fingerprint sets."""
    served_known = set(served_set)
    fingerprints_known = set(fingerprint_set)
    out: list[IdentityFinding] = []
    served = Counter(c.response_model[:MAX_VALUE] for c in calls if c.response_model)
    for value, count in sorted(served.items()):
        if count < min_count or value in served_known:
            continue
        if not served_matches(requested_model, value):
            kind = DriftIdentityChange.SERVED_MODEL_MISMATCH
        elif served_known:
            kind = DriftIdentityChange.NEW_SERVED_MODEL
        else:
            continue  # the baseline saw no response_model at all: nothing to compare with
        out.append(IdentityFinding(kind, value, count, requested_model))
    if fingerprints_known:
        prints = Counter(c.fingerprint[:MAX_VALUE] for c in calls if c.fingerprint)
        for value, count in sorted(prints.items()):
            if count >= min_count and value not in fingerprints_known:
                out.append(
                    IdentityFinding(
                        DriftIdentityChange.NEW_FINGERPRINT, value, count, requested_model
                    )
                )
    return out
