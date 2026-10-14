"use client";
/**
 * Human actions on an agent (POST /incidents): fail over, hand off, quarantine, kill.
 * Shown only to roles that hold the scope; everyone else sees why the panel is read-only.
 */
import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useSWRConfig } from "swr";
import type { FallbackChain, Incident, IncidentCreate } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { KillSwitchButton } from "@/components/shell/KillSwitch";

type ActionKind = "failover" | "handoff" | "quarantine";

interface ActionsPanelProps {
  agentId: string;
  agentName: string;
  tier: number;
  state: string;
  chain: FallbackChain | null;
}

export function ActionsPanel({ agentId, agentName, tier, state, chain }: ActionsPanelProps) {
  const s = useSession();
  const [open, setOpen] = useState<ActionKind | null>(null);
  const canOverride = s.can("routing:override");
  const canQuarantine = s.can("quarantine:act");
  const canKill = s.can("killswitch:pull");
  const movable = state === "active" || state === "degraded";

  if (!canOverride && !canQuarantine && !canKill) {
    return (
      <section className="panel panel-pad" aria-label="Actions">
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
          <Icon name="lock" size={18} style={{ color: "var(--text-3)", marginTop: 2 }} />
          <div>
            <div className="title-sm">View only</div>
            <p className="muted" style={{ marginTop: 4 }}>
              {s.roleLabels.join(" + ")} can read routing and health but cannot change them. Every change here is made by an engineer, admin or duty officer and lands in the audit log.
            </p>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" aria-labelledby="actions-title">
      <div className="panel-head">
        <h3 id="actions-title">Actions</h3>
        <span className="caption">Audited · reversible where possible</span>
      </div>
      <div className="panel-pad" style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {canOverride ? (
          <button type="button" className="btn btn-sm" disabled={!movable} onClick={() => setOpen("failover")} data-testid="action-failover">
            <Icon name="route" size={14} /> Fail over
          </button>
        ) : null}
        {canOverride ? (
          <button type="button" className="btn btn-sm" disabled={state === "killed"} onClick={() => setOpen("handoff")} data-testid="action-handoff">
            <Icon name="hand" size={14} /> Hand off to a person
          </button>
        ) : null}
        {canQuarantine ? (
          <button type="button" className="btn btn-sm" disabled={!["active", "degraded", "failed_over"].includes(state)} onClick={() => setOpen("quarantine")} data-testid="action-quarantine">
            <Icon name="shield" size={14} /> Quarantine
          </button>
        ) : null}
        <KillSwitchButton presetAgentId={agentId} compact />
      </div>
      {open ? <ActionDialog kind={open} onClose={() => setOpen(null)} agentId={agentId} agentName={agentName} tier={tier} chain={chain} /> : null}
    </section>
  );
}

const TITLES: Record<ActionKind, string> = { failover: "Fail over", handoff: "Hand off to a person", quarantine: "Quarantine" };

function ActionDialog({ kind, onClose, agentId, agentName, tier, chain }: { kind: ActionKind; onClose: () => void } & Omit<ActionsPanelProps, "state">) {
  const router = useRouter();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [target, setTarget] = useState<"auto" | "agent">("auto");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const idem = useMemo(() => crypto.randomUUID(), []);
  const hasBackup = Boolean(chain?.steps.some((x) => x.kind === "backup_agent"));
  const ok = reason.trim().length >= 10;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    const body: IncidentCreate = { agent_id: agentId, action: kind, reason: reason.trim(), ...(kind === "failover" && target === "agent" ? { target: { kind: "agent" } } : {}) };
    try {
      const inc = await bffSend<Incident>("/incidents", body, { idempotencyKey: idem });
      await mutate(() => true);
      toast.success(inc.state === "waiting_approval" ? "Sent for approval" : `${TITLES[kind]} applied`, inc.state === "waiting_approval" ? "A second person with approval rights must approve this tier-1 move." : `${agentName}: ${inc.routing.state.replaceAll("_", " ")}.`);
      onClose();
      router.push(`/incidents/${inc.id}`);
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
      title={`${TITLES[kind]} · ${agentName}`}
      description={kind === "failover" ? "Moves traffic to the next viable step of the approved chain now." : kind === "handoff" ? "Sends in-flight work to the operator queue with a handoff packet." : "The gateway refuses this agent's traffic until an operator releases it."}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!ok || busy} onClick={() => void submit()} data-testid="action-submit">
            {busy ? <span className="spinner" aria-hidden /> : null}
            {kind === "failover" && target === "agent" && tier === 1 ? "Request approval" : TITLES[kind]}
          </button>
        </>
      }
    >
      <div className="stack">
        {kind === "failover" ? (
          <fieldset className="inset" style={{ border: 0, padding: 0, margin: 0, overflow: "hidden" }}>
            <legend className="sr-only">Target</legend>
            <label className="choice">
              <input type="radio" name="target" checked={target === "auto"} onChange={() => setTarget("auto")} />
              <span>
                <span className="title-sm">Next viable step</span>
                <span className="muted" style={{ display: "block" }}>Alternate model or provider, skipping any provider that is down.</span>
              </span>
            </label>
            {hasBackup ? (
              <label className="choice">
                <input type="radio" name="target" checked={target === "agent"} onChange={() => setTarget("agent")} />
                <span>
                  <span className="title-sm">Backup agent</span>
                  <span className="muted" style={{ display: "block" }}>{tier === 1 ? "Tier 1: needs a second person to approve (four-eyes, D13)." : "Hands the task to the standby agent."}</span>
                </span>
              </label>
            ) : null}
          </fieldset>
        ) : null}
        <div className="field">
          <label htmlFor="action-reason">Reason</label>
          <textarea id="action-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="What you saw, and why this is the right move" />
          <span className="hint">At least 10 characters. Written to the audit log with your name.</span>
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
