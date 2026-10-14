"use client";
/**
 * Decision record for a `route.changed` row (ML §6.1): the transition, the health snapshot it
 * was based on with the score arithmetic, and how to reproduce it offline.
 */
import type { AuditEvent, Page, RoutingTransition } from "@/lib/api/types";
import type { HealthDocument } from "@/lib/api/documents";
import { useBff } from "@/hooks/useBff";
import { scoreArithmetic, splitFactors } from "@/lib/health/scoring";
import { ROUTING_LABEL } from "@/lib/labels";
import { FactorList } from "@/components/agent/HealthPanel";
import { BandPill } from "@/components/ui/StatePill";
import { Clock } from "@/components/ui/Time";

/** The demo embeds the snapshot; the live API carries only its id (no snapshot-by-id read yet). */
type TransitionX = RoutingTransition & { health_snapshot?: HealthDocument; health_snapshot_id?: string | null };

export function DecisionRecord({ event }: { event: AuditEvent }) {
  const detail = (event.detail ?? {}) as Record<string, unknown>;
  const transitionId = typeof detail.transition_id === "string" ? detail.transition_id : null;
  const { data } = useBff<Page<TransitionX>>(event.resource_id && transitionId ? `/agents/${event.resource_id}/routing/transitions?limit=200` : null);
  const tr = data?.data.find((t) => t.id === transitionId);
  const hs = tr?.health_snapshot;
  const rules = hs ? splitFactors(hs.factors).rules : [];
  if (!transitionId) return null;
  if (!tr) return <p className="muted">Loading the decision record…</p>;
  return (
    <section className="stack" data-testid="decision-record" style={{ gap: 12 }}>
      <h3 className="title-sm">Decision record</h3>
      <div className="inset" style={{ overflow: "hidden" }}>
        <dl className="kv">
          <div>
            <dt>Transition</dt>
            <dd>
              {tr.from_state ? ROUTING_LABEL[tr.from_state] : "—"} → {ROUTING_LABEL[tr.to_state]}
            </dd>
          </div>
          <div>
            <dt>Trigger · actor</dt>
            <dd>
              {tr.trigger.replaceAll("_", " ")} · {tr.actor_kind}
            </dd>
          </div>
          <div>
            <dt>Rules</dt>
            <dd className="mono">{(tr.rule_codes ?? []).join(", ") || "—"}</dd>
          </div>
          <div>
            <dt>Routing version</dt>
            <dd>{tr.routing_version}</dd>
          </div>
          <div>
            <dt>At</dt>
            <dd>
              <Clock at={tr.created_at} />
            </dd>
          </div>
        </dl>
      </div>
      {hs ? (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <BandPill band={hs.status} />
            <span className="caption">health snapshot {hs.health_snapshot_id.slice(0, 13)}… · rules/v1</span>
          </div>
          <div className="arith" data-testid="decision-arithmetic">
            {scoreArithmetic(rules, hs.score, hs.status)}
          </div>
          <div className="inset" style={{ overflow: "hidden" }}>
            <FactorList factors={rules} band={hs.status} />
          </div>
          {hs.feature_snapshot_ref ? (
            <div>
              <div className="caption" style={{ marginBottom: 6 }}>
                Reproduce offline
              </div>
              <pre className="code" tabIndex={0}>{`sibyl replay --snapshot ${hs.feature_snapshot_ref} --predictor rules/v1`}</pre>
            </div>
          ) : null}
        </>
      ) : tr.health_snapshot_id ? (
        <p className="caption">
          Decided on health snapshot <span className="mono">{tr.health_snapshot_id.slice(0, 13)}…</span>. Its factors are in the agent&apos;s health history.
        </p>
      ) : null}
    </section>
  );
}
