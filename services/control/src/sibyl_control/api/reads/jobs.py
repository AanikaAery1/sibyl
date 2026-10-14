"""``GET /jobs/{job_id}``: a job's state for the principal that requested it (B14, API §5.7).

Object rule ``job_owner``: only the requester sees the job (the human who asked, or the API key
that asked); anyone else, including other owners of the tenant, gets 404 (no existence oracle).
Job ``params`` are never echoed; ``result`` and ``error`` carry no secrets or upstream text.
"""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends

from ...core.jobs import Requester, job_view
from ...core.problems import ProblemError
from ..contract import API_PREFIX
from ..deps import AuthContext, guard
from ..registry._kit import Outcome, run_read

router = APIRouter()


@router.get(API_PREFIX + "/jobs/{job_id}")
async def get_job(job_id: UUID, ctx: Annotated[AuthContext, Depends(guard("getJob"))]) -> Any:
    principal = ctx.principal
    assert principal is not None
    me = Requester.of(principal)

    async def work(conn: Any) -> Outcome:
        row = await conn.fetchrow(
            "SELECT * FROM sibyl.job WHERE tenant_id = $1 AND id = $2", ctx.tenant_id, job_id
        )
        ctx.object_rule_checked("job_owner")
        if row is None or (row["requested_by_kind"], row["requested_by"]) != (me.kind, me.id):
            raise ProblemError("not_found", audit_denied=row is not None)
        return Outcome(job_view(row))

    return await run_read(ctx, work)
