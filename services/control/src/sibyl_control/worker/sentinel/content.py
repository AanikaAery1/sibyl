"""Opening captured (already scrubbed) payloads for Sentinel, only where capture mode allows.

The caller decides *whether* content may be sent (``gather`` checks the agent's effective capture
mode and the event's own); this module only opens a ``payload_refs`` row under the tenant's
payload DEK. Anything that goes wrong (swept, shredded, no blob store) is "no content".
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any
from uuid import UUID

from ...core.blob.base import BlobStore
from ...core.crypto.deks import ConnDekProvider
from ...core.crypto.envelope import KeyEncryptionKey
from ...core.crypto.sealed import open_payload
from .gather import ContentReader

log = logging.getLogger("sibyl.sentinel")
_REF_SQL = "SELECT uri, state FROM sibyl.payload_refs WHERE tenant_id = $1 AND id = $2"


def payload_reader(store: Callable[[], BlobStore], kek: KeyEncryptionKey) -> ContentReader:
    async def read(conn: Any, tenant: UUID, ref: UUID) -> Any:
        row = await conn.fetchrow(_REF_SQL, tenant, ref)
        if row is None or row["state"] != "stored":
            return None
        try:
            raw = await open_payload(store(), ConnDekProvider(conn, kek), tenant, row["uri"], ref)
            return json.loads(raw)
        except Exception:
            log.warning("sentinel could not open payload %s", ref)
            return None

    return read
