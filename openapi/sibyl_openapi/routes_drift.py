"""D51 model drift routes (lane DRIFT): the fleet view, one agent's baselines and reports, one
report, and the audited baseline reset.

Every role reads drift with ``drift:read`` (watch-only health information); Admin and Security
admin reset an agent's baselines with ``drift:write`` (audited ``drift.baseline_reset``, reason
required). Drift never changes routing: it only raises watch-only alerts.

Wave 4 HARDEN: ``/drift/thresholds`` reads (``drift:read``) and replaces (``drift:write``,
If-Match, reason, audited ``drift.thresholds_updated``) the tenant's threshold overrides.
"""

from __future__ import annotations

from sibyl_schemas import values as sv

from .dsl import Op, Q, enum, integer, ref
from .params import AGENT_ID_Q

READ = "drift:read"
WRITE = "drift:write"

DRIFT_OPS: tuple[Op, ...] = (
    Op(
        "get",
        "/drift",
        "listDrift",
        "drift",
        "Fleet drift: every current baseline with its latest verdict",
        scope=READ,
        paged=True,
        query=(
            Q("verdict", enum(*(str(v.value) for v in sv.DriftVerdict))),
            Q("state", enum("collecting", "frozen")),
            AGENT_ID_Q,
        ),
        ok=((200, "DriftKeySummary", "Page of current drift baselines"),),
        page_extra=(("summary", ref("FleetDriftSummary")),),
        description="Model identity and behavioural drift per agent, provider and requested"
        " model (PSI / Jensen-Shannon against a frozen baseline). Watch-only.",
    ),
    Op(
        "get",
        "/drift/reports/{report_id}",
        "getDriftReport",
        "drift",
        "One drift report with every feature's numbers and the identity findings",
        scope=READ,
        ok=((200, "DriftReport", "Drift report"),),
    ),
    Op(
        "get",
        "/agents/{agent_id}/drift",
        "getAgentDrift",
        "drift",
        "One agent's drift baselines, latest reports, recent history and open drift alerts",
        scope=READ,
        query=(
            Q("since", ref("Timestamp"), description="history: reports evaluated at or after"),
            Q(
                "limit",
                integer(minimum=1, maximum=500, default=48),
                description="history: most recent reports to return (default 48, max 500)",
            ),
        ),
        ok=((200, "AgentDrift", "Agent drift"),),
        description="`since` and `limit` bound `history` only (newest first); baselines,"
        " latest reports and open alerts are always current.",
    ),
    Op(
        "post",
        "/agents/{agent_id}/drift/baseline",
        "resetDriftBaseline",
        "drift",
        "Reset (re-freeze) the agent's drift baselines; open drift alerts on them resolve",
        scope=WRITE,
        idem=True,
        audit=("drift.baseline_reset",),
        body="DriftBaselineReset",
        ok=((201, "DriftBaselineResetResult", "Baselines superseded; collecting again"),),
        problems={404: ("not_found",)},
    ),
    Op(
        "get",
        "/drift/thresholds",
        "getDriftThresholds",
        "drift",
        "The tenant's effective drift thresholds and window minimums, each with its source",
        scope=READ,
        ok=((200, "DriftThresholds", "Effective thresholds"),),
        etag_out=True,
        description='The ETag is "<version>", or "0" before the first save, so a client can'
        " always send it back as If-Match.",
    ),
    Op(
        "put",
        "/drift/thresholds",
        "putDriftThresholds",
        "drift",
        "Replace the tenant's drift threshold overrides (null or omitted = deployment default)",
        scope=WRITE,
        if_match="required_or_star",
        etag_out=True,
        audit=("drift.thresholds_updated",),
        body="DriftThresholdsPut",
        ok=((200, "DriftThresholds", "Saved"),),
        description=(
            "Watch-only: the values change when a report reads watch or drift and when a"
            " feature has enough samples, never routing. Ranges: PSI 0.01-2.0, JS two"
            " categories 0.0005-0.5, JS many categories 0.005-1.0, minimum samples 50-5000"
            " calls and 10-20000 tool calls; each statistic's effective watch must be below"
            ' its effective drift (422 validation_failed). If-Match is the ETag from GET ("0"'
            " before the first save; * is also accepted for the first write). Audited"
            " drift.thresholds_updated with the before and after overrides."
        ),
    ),
)
