"use client";
/**
 * Incident view (B4–B7): the failover saga as a timeline with an RTO clock, the approval
 * card, routing transitions, handoff tasks, and the human actions (undo + 30-min hold,
 * clear hold, fail back, cancel, release, kill) available to this persona.
 */
import Link from "next/link";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { IncidentActionName } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { useNow } from "@/hooks/useNow";
import { formatDuration, formatStopwatch } from "@/lib/format";
import { KIND_LABEL, ROUTING_LABEL, SAGA_LABEL, STEP_LABEL, FIDELITY_LABEL, FAILURE_MODE_LABEL, label } from "@/lib/labels";
import { Timeline, type TimelineEntry } from "@/components/ui/Bits";
import { Pill, RoutingPill, TierBadge } from "@/components/ui/StatePill";
import { Clock } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { KillSwitchButton } from "@/components/shell/KillSwitch";
import { ApprovalCard } from "./ApprovalCard";
import { SentinelRecommendation } from "@/components/sentinel/SentinelRecommendation";
import type { IncidentView } from "./types";
import { DemoMark } from "@/components/ui/DemoMark";

const ACTION_COPY: Partial<Record<IncidentActionName, { label: string; title: string; body: string; primary?: boolean }>> = {
  undo: { label: "Undo", title: "Undo this move", body: "Puts the agent back where it was and pauses automation on it for 30 minutes (D21). Rules keep scoring; only people and the kill switch can move it during the hold." },
  clear_hold: { label: "Clear hold", title: "Clear the operator hold", body: "Lets rules and policies act on this agent again before the 30 minutes are up." },
  fail_back: { label: "Fail back", title: "Fail back to the primary", body: "Starts a canary on the primary at 10% and ramps to 100% while every window stays green." },
  cancel: { label: "Cancel", title: "Cancel the saga", body: "Stops the pending move before routing is written; the agent stays in degraded mode." },
  release: { label: "Release", title: "Release", body: "Returns the agent to active. Releasing a kill needs a fresh sign-in." },
};

export function IncidentDetail({ id, initial }: { id: string; initial: IncidentView | null }) {
  const s = useSession();
  const now = useNow(1000);
  const { data: inc } = useBff<IncidentView>(`/incidents/${id}`, initial);
  const [action, setAction] = useState<IncidentActionName | null>(null);

  if (!inc) {
    return (
      <div className="page">
        <div className="panel panel-pad">This incident does not exist in this tenant.</div>
      </div>
    );
  }
  const x = inc.x_console;
  const steps = x?.steps ?? [];
  const writeAt = steps.find((st) => st.step === "write_routing")?.at;
  const start = Date.parse(inc.created_at);
  const restoredAt = writeAt ? Date.parse(writeAt) : null;
  const elapsed = ((restoredAt ?? now) - start) / 1000;
  const rto = x?.rto_s ?? 900;
  const rtoPct = Math.min(1, elapsed / rto);
  const held = inc.operator_hold_until && Date.parse(inc.operator_hold_until) > now;

  const sagaItems: TimelineEntry[] = steps.map((st, i) => ({
    key: `${i}-${st.step}`,
    title: STEP_LABEL[st.step] ?? st.step,
    note: st.note,
    time: <Clock at={st.at} />,
    state: st.step === "waiting_approval" ? (inc.state === "waiting_approval" ? "active" : "done") : st.step === "write_routing" ? "moved" : "done",
  }));
  if (inc.state === "waiting_approval") sagaItems.push({ key: "next", title: "Write routing", note: "Runs as soon as a second person approves.", state: "pending" });

  const actions = (inc.available_actions ?? []).filter((a) => a !== "approve" && a !== "deny");

  return (
    <div className="page">
      <Link href="/incidents" className="btn btn-plain btn-sm" style={{ alignSelf: "flex-start", marginBottom: -12 }}>
        <Icon name="arrowLeft" size={14} /> Incidents
      </Link>
      <header className="page-head">
        <div>
          <div className="eyebrow">
            {KIND_LABEL[inc.kind]} · opened <Clock at={inc.created_at} /> by {inc.actor_kind === "rule" ? "rules/v1" : inc.actor_kind} <DemoMark paths={[`/incidents/${inc.id}`]} />
          </div>
          <h1 className="large-title">
            <Link href={`/agents/${inc.agent_id}`} style={{ color: "inherit" }}>
              {x?.agent_name ?? "Agent"}
            </Link>
          </h1>
          <p className="lede">{x?.reason}</p>
          <div style={{ display: "flex", gap: 6, marginTop: 10, flexWrap: "wrap", alignItems: "center" }}>
            <TierBadge tier={x?.tier ?? 3} />
            <Pill tone={inc.state === "done" ? "quiet" : inc.state === "waiting_approval" ? "human" : inc.state === "cancelled" ? "neutral" : "moved"} dot={inc.state !== "done"}>
              Saga · {SAGA_LABEL[inc.state]}
            </Pill>
            <RoutingPill state={inc.routing.state} holdUntil={inc.operator_hold_until} />
            {(inc.rule_codes ?? []).map((r) => (
              <span key={r} className="tag mono">
                {r}
              </span>
            ))}
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }} data-testid="incident-actions">
          {actions.map((a) => (
            <button key={a} type="button" className="btn" onClick={() => setAction(a)} data-testid={`action-${a}`}>
              <Icon name={a === "undo" ? "undo" : a === "fail_back" ? "replay" : a === "clear_hold" ? "play" : "x"} size={15} />
              {ACTION_COPY[a]?.label ?? a}
            </button>
          ))}
          {inc.routing.state !== "killed" ? <KillSwitchButton presetAgentId={inc.agent_id} compact /> : null}
        </div>
      </header>

      {held ? (
        <div className="banner" data-tone="human" role="status" data-testid="hold-banner">
          <Icon name="pause" size={16} />
          <span>
            <strong>Automation paused until <Clock at={inc.operator_hold_until} seconds={false} /></strong> (D21). {x?.hold_suppressed_count ? `${x.hold_suppressed_count} automatic moves suppressed while the outage continues.` : "Rules keep scoring but cannot move this agent."}
          </span>
        </div>
      ) : null}

      <div className="grid-split">
        <div className="stack">
          {inc.approval ? <ApprovalCard approval={inc.approval} incidentId={inc.id} /> : null}
          <SentinelRecommendation subjectKind="incident" subjectId={inc.id} canRead={s.can("sentinel:read")} canAsk={s.can("sentinel:admin")} />
          <section className="panel" aria-labelledby="saga-title">
            <div className="panel-head">
              <h3 id="saga-title">Failover saga</h3>
              <span className="caption">validate → check viability → write routing → hand off → done</span>
            </div>
            <Timeline items={sagaItems} label="Saga steps" />
          </section>
          <section className="panel" aria-labelledby="tr-title">
            <div className="panel-head">
              <h3 id="tr-title">Routing transitions</h3>
              <Link className="caption" href={`/audit?resource_id=${inc.id}`}>
                Decision records in the audit log
              </Link>
            </div>
            {(x?.transitions ?? []).length ? (
              (x?.transitions ?? []).map((t) => (
                <div className="row" key={t.id}>
                  <span className="num caption" style={{ width: 64 }}>
                    <Clock at={t.created_at} />
                  </span>
                  <div className="grow">
                    <div className="title-sm">
                      {t.from_state ? ROUTING_LABEL[t.from_state] : "—"} → {ROUTING_LABEL[t.to_state]}
                    </div>
                    <div className="muted">
                      {t.trigger.replaceAll("_", " ")} · {t.actor_kind} · v{t.routing_version}
                      {t.undone_by ? " · undone" : ""}
                      {t.inverse_of ? " · inverse of an automated move" : ""}
                    </div>
                  </div>
                  {t.audit_seq ? <span className="tag mono">seq {t.audit_seq}</span> : null}
                </div>
              ))
            ) : (
              <p className="row muted">Routing has not changed yet.</p>
            )}
          </section>
        </div>

        <div className="stack">
          <section className="panel panel-pad" aria-labelledby="rto-title" data-testid="rto-clock">
            <h3 id="rto-title" className="caption" style={{ fontWeight: 600 }}>
              {restoredAt ? "Service restored in" : "Time since detection"}
            </h3>
            <div className="rto" style={{ marginTop: 8 }}>
              <span className="big" suppressHydrationWarning>
                {formatStopwatch(elapsed)}
              </span>
              <span className="of">of {formatDuration(rto)} RTO</span>
            </div>
            <div className="meter" style={{ marginTop: 12 }} role="progressbar" aria-label="RTO used" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(rtoPct * 100)}>
              <span style={{ transform: `scaleX(${rtoPct})`, ["--meter" as string]: rtoPct > 0.8 ? "var(--failed-dot)" : rtoPct > 0.5 ? "var(--degraded-dot)" : "var(--healthy-dot)" } as React.CSSProperties} />
            </div>
            <dl className="kv" style={{ marginTop: 12, marginInline: "calc(var(--row-x) * -1)" }}>
              <div>
                <dt>RTO used</dt>
                <dd>{Math.round(rtoPct * 100)}%</dd>
              </div>
              <div>
                <dt>RPO at cut</dt>
                <dd>{x?.checkpoint_age_s !== null && x?.checkpoint_age_s !== undefined ? `${formatDuration(x.checkpoint_age_s)} of ${formatDuration(x.rpo_s)}` : "Request only"}</dd>
              </div>
              <div>
                <dt>Target</dt>
                <dd>{inc.chosen_step ? String((inc.chosen_step as Record<string, unknown>).provider ?? (inc.chosen_step as Record<string, unknown>).kind ?? "—") : "—"}</dd>
              </div>
            </dl>
          </section>

          <section className="panel" aria-labelledby="ho-title">
            <div className="panel-head">
              <h3 id="ho-title">Handoff tasks</h3>
              <Link className="caption" href="/queue">
                Operator queue
              </Link>
            </div>
            {(inc.handoff_tasks ?? []).length ? (
              (inc.handoff_tasks ?? []).map((t) => (
                <Link className="row" key={t.id} href={`/queue?task=${t.id}`}>
                  <Icon name="hand" size={16} />
                  <div className="grow">
                    <div className="title-sm truncate">{t.summary}</div>
                    <div className="muted">
                      {label(FAILURE_MODE_LABEL, t.failure_mode)} · {FIDELITY_LABEL[t.fidelity]} · {t.state}
                    </div>
                  </div>
                  <Icon name="chevronRight" size={14} />
                </Link>
              ))
            ) : (
              <p className="row muted">No in-flight work was handed to people.</p>
            )}
          </section>

          {!s.can("routing:override") && !s.can("approvals:decide") ? (
            <section className="panel panel-pad">
              <div className="title-sm">View only</div>
              <p className="muted" style={{ marginTop: 4 }}>Your role can read this incident and its evidence. Undo, hold and kill need an admin, engineer or duty officer.</p>
            </section>
          ) : null}
        </div>
      </div>

      {action ? <ActionDialog incidentId={inc.id} action={action} agentName={x?.agent_name ?? "agent"} onClose={() => setAction(null)} /> : null}
    </div>
  );
}

function ActionDialog({ incidentId, action, agentName, onClose }: { incidentId: string; action: IncidentActionName; agentName: string; onClose: () => void }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idem = useMemo(() => crypto.randomUUID(), []);
  const copy = ACTION_COPY[action];

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await s.withStepUp(() => bffSend(`/incidents/${incidentId}/actions`, { action, reason: reason.trim() }, { idempotencyKey: idem }));
      await mutate(() => true);
      toast.success(`${copy?.label ?? action} applied`, action === "undo" ? `${agentName} is back on its previous route; automation paused for 30 minutes.` : undefined);
      onClose();
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not applied.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Layer
      open
      onClose={onClose}
      title={copy?.title ?? action}
      description={copy?.body}
      testId="incident-action-dialog"
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={reason.trim().length < 10 || busy} onClick={() => void submit()} data-testid="incident-action-submit">
            {busy ? <span className="spinner" aria-hidden /> : null}
            {copy?.label ?? action}
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="field">
          <label htmlFor="ia-reason">Reason</label>
          <textarea id="ia-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why, in a sentence. It goes into the audit log." />
          <span className="hint">At least 10 characters.</span>
        </div>
        {error ? (
          <div className="banner" data-tone="failed" role="alert">
            <Icon name="incident" size={16} />
            {error}
          </div>
        ) : null}
      </div>
    </Layer>
  );
}
