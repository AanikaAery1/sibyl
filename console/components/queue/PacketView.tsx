"use client";
/**
 * Handoff packet (`sibyl-handoff/1`) for an operator: why it arrived, what the agent was
 * doing, what is left, and the next action. Agent-authored text sits inside the "untrusted
 * agent content" frame (STRIDE #8) and is rendered as plain text, never HTML.
 */
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { HandoffPacket } from "@/lib/api/documents";
import type { HandoffTask } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { FAILURE_MODE_LABEL, HANDOFF_LABEL, label } from "@/lib/labels";
import { formatDuration } from "@/lib/format";
import { ruleLabel } from "@/lib/health/scoring";
import { FidelityBadge, Pill } from "@/components/ui/StatePill";
import { Clock, Countdown } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { Timeline } from "@/components/ui/Bits";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { DemoMark } from "@/components/ui/DemoMark";

type Outcome = "resolved" | "escalated" | "abandoned";

export function PacketView({ taskId }: { taskId: string }) {
  const s = useSession();
  const { data: task } = useBff<HandoffTask>(`/handoff-tasks/${taskId}`);
  const { data: packet, error } = useBff<HandoffPacket>(s.can("packets:read") ? `/handoff-tasks/${taskId}/packet` : null);
  const [completing, setCompleting] = useState(false);
  const { mutate } = useSWRConfig();
  const toast = useToast();
  const idem = useMemo(() => ({ claim: crypto.randomUUID(), release_claim: crypto.randomUUID(), return: crypto.randomUUID() }), []);
  const [busy, setBusy] = useState<string | null>(null);

  if (!task) return <div className="panel panel-pad muted">Loading packet…</div>;
  const mine = task.claimed_by === s.userId;
  const canAct = s.can("queue:act");

  const act = async (action: "claim" | "release_claim" | "return"): Promise<void> => {
    setBusy(action);
    try {
      await bffSend(`/handoff-tasks/${taskId}/actions`, { action, ...(action === "return" ? { reason: "Primary is healthy again; returning to the agent." } : {}) }, { idempotencyKey: idem[action] });
      await mutate(() => true);
      toast.success(action === "claim" ? "Claimed. The task is locked to you for 30 minutes." : action === "return" ? "Returned to the agent" : "Claim released");
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(null);
    }
  };

  return (
    <article className="stack" aria-labelledby="packet-title" data-testid="packet">
      <section className="panel">
        <div className="panel-pad stack" style={{ gap: 10 }}>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
            <Pill tone={task.state === "claimed" ? "human" : task.state === "completed" ? "healthy" : "watch"} dot>
              {HANDOFF_LABEL[task.state]}
              {task.state === "claimed" ? (mine ? " by you" : " by someone else") : ""}
            </Pill>
            <FidelityBadge fidelity={task.fidelity} />
            <span className="tag">{label(FAILURE_MODE_LABEL, task.failure_mode)}</span>
            <DemoMark paths={[`/handoff-tasks/${taskId}`]} />
            <span className="tag">
              Due in&nbsp;<Countdown to={task.deadline_at} />
            </span>
          </div>
          <h2 id="packet-title" style={{ fontSize: "var(--fs-title2)", fontWeight: 700, letterSpacing: "var(--track-title)" }}>
            {packet?.goal ?? task.summary}
          </h2>
          {packet ? <p className="muted">Agent {packet.agent_name} · created <Clock at={packet.created_at} /> · {packet.accountability.line}</p> : null}
          {canAct ? (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 4 }}>
              {task.state === "queued" || task.state === "expired" ? (
                <button type="button" className="btn btn-primary" onClick={() => void act("claim")} disabled={busy !== null} data-testid="claim">
                  {busy === "claim" ? <span className="spinner" aria-hidden /> : <Icon name="hand" size={15} />} Claim
                </button>
              ) : null}
              {task.state === "claimed" && mine ? (
                <>
                  <button type="button" className="btn btn-primary" onClick={() => setCompleting(true)} data-testid="complete">
                    <Icon name="check" size={15} /> Complete
                  </button>
                  <button type="button" className="btn" onClick={() => void act("release_claim")} disabled={busy !== null}>
                    Release claim
                  </button>
                </>
              ) : null}
              {task.state === "queued" ? (
                <button type="button" className="btn" onClick={() => void act("return")} disabled={busy !== null} data-testid="return">
                  Return to agent
                </button>
              ) : null}
            </div>
          ) : (
            <p className="caption">Read-only for your role{s.roles.includes("auditor") ? "; opening the packet is audited as data.revealed" : ""}.</p>
          )}
        </div>
      </section>

      {error instanceof ProblemError ? <div className="banner" data-tone="failed">{error.problem.detail}</div> : null}
      {!packet ? null : (
        <>
          <section className="panel" aria-labelledby="why-title">
            <div className="panel-head">
              <h3 id="why-title">Why it is here</h3>
              <span className="caption mono">{packet.reason.trigger.kind}{packet.reason.trigger.rule_id ? ` · ${packet.reason.trigger.rule_id}` : ""}</span>
            </div>
            <div className="panel-pad stack" style={{ gap: 10 }}>
              <p style={{ lineHeight: "var(--lh-read)" }}>{packet.reason.plain_language}</p>
              {(packet.reason.trigger.factors ?? []).length ? (
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {(packet.reason.trigger.factors ?? []).map((f) => (
                    <span key={f.rule} className="tag">
                      {ruleLabel(f.rule)} −{f.penalty ?? 0}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          </section>

          <section className="panel" aria-labelledby="next-title" style={{ boxShadow: "0 0 0 1.5px var(--accent), var(--sh-panel)" }}>
            <div className="panel-pad">
              <h3 id="next-title" className="eyebrow" style={{ color: "var(--accent-text)" }}>
                Next action
              </h3>
              <p className="title-sm" style={{ marginTop: 6, lineHeight: "var(--lh-read)" }}>
                {packet.next_action}
              </p>
            </div>
          </section>

          <section className="panel" aria-labelledby="input-title">
            <div className="panel-head">
              <h3 id="input-title">Original input</h3>
              <span className="caption">capture {packet.redaction.capture_mode} · secrets scrubbed {packet.redaction.profile.secrets_scrubbed}</span>
            </div>
            <div className="panel-pad">
              <div className="untrusted" data-label="Untrusted agent content">
                {packet.original_input.preview ?? "(stored by reference)"}
              </div>
            </div>
          </section>

          <section className="panel" aria-labelledby="steps-title">
            <div className="panel-head">
              <h3 id="steps-title">Steps</h3>
              <span className="caption">
                {packet.fidelity === "checkpoint" ? `Checkpoint ${packet.provenance.checkpoint_seq ?? 0} · ${formatDuration(packet.provenance.checkpoint_age_s ?? 0)} old` : "Request-only: Sibyl saw the last request, not the agent's state"}
              </span>
            </div>
            {packet.completed_steps.length || packet.pending_steps.length ? (
              <Timeline
                label="Completed and pending steps"
                items={[
                  ...packet.completed_steps.map((st) => ({
                    key: `c${st.index}`,
                    state: "done" as const,
                    title: (
                      <>
                        {st.step.replaceAll("_", " ")}
                        {st.tool_name ? <span className="tag mono" style={{ marginLeft: 6 }}>{st.tool_name}</span> : null}
                        {st.assumed ? <span className="tag" style={{ marginLeft: 6 }}>assumed</span> : null}
                      </>
                    ),
                    note: st.output?.preview ? <span className="untrusted" data-label="Agent output" style={{ display: "block", marginTop: 12, fontSize: 13 }}>{st.output.preview}</span> : null,
                    time: <Clock at={st.ended_at} />,
                  })),
                  ...packet.pending_steps.map((st) => ({ key: `p${st.index}`, state: "pending" as const, title: st.step.replaceAll("_", " "), note: `${st.description ?? ""}${st.inputs_needed?.length ? ` · needs ${st.inputs_needed.join(", ")}` : ""}` })),
                ]}
              />
            ) : (
              <p className="row muted">No steps recorded. Start from the original input above.</p>
            )}
          </section>

          {(packet.side_effects ?? []).length ? (
            <section className="panel" aria-labelledby="se-title">
              <div className="panel-head">
                <h3 id="se-title">Side effects so far</h3>
              </div>
              {(packet.side_effects ?? []).map((se, i) => (
                <div className="row" key={i}>
                  <Icon name="external" size={15} />
                  <span className="grow">
                    {se.kind.replaceAll("_", " ")} · <span className="mono">{se.target}</span>
                  </span>
                  <Pill tone={se.reversible ? "quiet" : "degraded"}>{se.reversible ? "reversible" : "not reversible"}</Pill>
                </div>
              ))}
            </section>
          ) : null}

          <section className="panel" aria-labelledby="prov-title">
            <div className="panel-head">
              <h3 id="prov-title">Provenance</h3>
            </div>
            <dl className="kv">
              <div>
                <dt>Assembled by</dt>
                <dd>{packet.provenance.assembled_by.replaceAll("_", " ")}</dd>
              </div>
              <div>
                <dt>Trace</dt>
                <dd className="mono">{packet.provenance.trace_ids[0]?.slice(0, 16)}…</dd>
              </div>
              <div>
                <dt>Policy version</dt>
                <dd>{packet.provenance.policy_version}</dd>
              </div>
              <div>
                <dt>Cost so far</dt>
                <dd>${packet.sidecar?.cost_so_far_usd?.toFixed(4) ?? "—"}</dd>
              </div>
            </dl>
          </section>
        </>
      )}
      {completing ? <CompleteDialog taskId={taskId} onClose={() => setCompleting(false)} defaultNext={packet?.next_action ?? ""} /> : null}
    </article>
  );
}

function CompleteDialog({ taskId, onClose, defaultNext }: { taskId: string; onClose: () => void; defaultNext: string }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [outcome, setOutcome] = useState<Outcome>("resolved");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const idem = useMemo(() => crypto.randomUUID(), []);
  const submit = async (): Promise<void> => {
    setBusy(true);
    try {
      await bffSend(`/handoff-tasks/${taskId}/actions`, { action: "complete", outcome, outcome_note: note.trim() || undefined, next_action: defaultNext }, { idempotencyKey: idem });
      await mutate(() => true);
      toast.success("Task completed", outcome === "resolved" ? "Counted as a task completed despite the agent failure." : `Recorded as ${outcome}.`);
      onClose();
    } catch (err) {
      toast.error(err);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Layer
      open
      onClose={onClose}
      title="Complete the task"
      description="Your outcome becomes a label for the learning engine (D37)."
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void submit()} disabled={busy} data-testid="complete-submit">
            {busy ? <span className="spinner" aria-hidden /> : null}Complete
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="seg" role="radiogroup" aria-label="Outcome">
          {(["resolved", "escalated", "abandoned"] as const).map((o) => (
            <button key={o} type="button" role="radio" aria-checked={outcome === o} onClick={() => setOutcome(o)}>
              {o[0]?.toUpperCase()}
              {o.slice(1)}
            </button>
          ))}
        </div>
        <div className="field">
          <label htmlFor="outcome-note">What you did</label>
          <textarea id="outcome-note" className="textarea" value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Agreed the split pickup with Apex dispatch and booked both slots." />
        </div>
      </div>
    </Layer>
  );
}
