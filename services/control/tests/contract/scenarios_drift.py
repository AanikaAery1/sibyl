"""Lane DRIFT scenarios (D51 model drift): a tenant-A agent (lane S's ``s_agent``) with a frozen
drift baseline and one report, written by direct SQL like the drift worker would."""

from __future__ import annotations

from uuid import UUID, uuid4

from ._world_kit import REASON, Req, Scenario, _etag
from .pg_world import ContractWorld
from .scenarios_lane_s import s_agent

FEATURES = {"refusal": {"kind": "categorical", "statistic": "js", "n": 600, "probs": {"no": 1.0}}}
REPORT_FEATURES = [
    {
        "feature": "output_tokens",
        "statistic": "psi",
        "status": "ok",
        "value": 0.41,
        "noise_floor": 0.05,
        "excess": 0.36,
        "watch": 0.1,
        "drift": 0.25,
        "verdict": "drift",
        "n_baseline": 600,
        "n_window": 250,
        "contributors": [{"label": "> 512", "baseline": 0.1, "window": 0.4}],
    }
]


def drift_agent(w: ContractWorld) -> tuple[UUID, UUID, UUID]:
    """(agent, baseline, report): a frozen baseline on openai/gpt-4o and one drift report."""
    agent = s_agent(w)
    baseline, report = uuid4(), uuid4()
    w.admin.execute(
        "INSERT INTO sibyl.drift_baseline (tenant_id, id, agent_id, provider, model, state,"
        " window_start, window_end, sample_count, features, served_models, fingerprints,"
        " frozen_at) VALUES ($1, $2, $3, 'openai', 'gpt-4o', 'frozen', now() - interval '8 hours',"
        " now() - interval '2 hours', 600, $4::jsonb, '{gpt-4o-2024-08-06}', '{fp_a}',"
        " now() - interval '2 hours')",
        w.a.id,
        baseline,
        agent,
        FEATURES,
    )
    w.admin.execute(
        "INSERT INTO sibyl.drift_report (tenant_id, id, baseline_id, agent_id, provider, model,"
        " window_start, window_end, sample_count, verdict, behaviour_evaluated, max_ratio,"
        " features) VALUES ($1, $2, $3, $4, 'openai', 'gpt-4o', now() - interval '1 hour', now(),"
        " 250, 'drift', true, 1.44, $5::jsonb)",
        w.a.id,
        report,
        baseline,
        agent,
        REPORT_FEATURES,
    )
    return agent, baseline, report


def _reset(w: ContractWorld) -> Req:
    agent, _, _ = drift_agent(w)
    return Req(f"/agents/{agent}/drift/baseline", {"reason": REASON}, agent_id=str(agent))


THRESHOLDS = "/drift/thresholds"


def _thresholds(w: ContractWorld) -> Req:
    """Tighten PSI drift for tenant A; If-Match is the current ETag ("0" before any save)."""
    return Req(THRESHOLDS, {"psi_drift": 0.3, "reason": REASON}, if_match=_etag(w, THRESHOLDS))


DRIFT: dict[str, Scenario] = {
    "listDrift": lambda w: (drift_agent(w), Req("/drift"))[1],
    "getDriftReport": lambda w: Req(f"/drift/reports/{drift_agent(w)[2]}"),
    "getAgentDrift": lambda w: (lambda a: Req(f"/agents/{a}/drift", agent_id=str(a)))(
        drift_agent(w)[0]
    ),
    "resetDriftBaseline": _reset,
    "getDriftThresholds": lambda w: Req(THRESHOLDS),
    "putDriftThresholds": _thresholds,
}
