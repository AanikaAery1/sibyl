"""Content references for audit ``detail``.

The kit's ``digest_ref`` hashes JCS bytes, which refuse floats; rule thresholds and step params
legitimately hold floats, so policy hashes a sorted, compact JSON rendering instead.
CHANGE REQUEST (kit): let ``digest_ref`` accept floats (it is a reference, not a chain input).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..registry._kit import jsonable


def content_ref(value: Any) -> str:
    text = json.dumps(jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
