"use client";
/**
 * Global kill switch (D20): scope, target, a reason ≥ 20 characters, typed confirmation for a
 * tenant-wide kill, then step-up. Irreversible without a step-up release, so it is the one
 * place the console asks for confirmation instead of offering undo.
 */
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentSummary, KillScopeKind, KillSwitch as KillSwitchT, Page, Provider } from "@/lib/api/types";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { ProblemError } from "@/lib/api/problem";
import { Layer } from "@/components/ui/Layer";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { PROVIDER_LABEL } from "@/lib/labels";
import { useSession } from "./Session";

const MIN_REASON = 20;

export function KillSwitchButton({ presetAgentId, compact = false }: { presetAgentId?: string; compact?: boolean }) {
  const s = useSession();
  const [open, setOpen] = useState(false);
  if (!s.can("killswitch:pull")) return null;
  return (
    <>
      <button type="button" className={compact ? "btn btn-sm btn-danger-quiet" : "glass-chip danger"} onClick={() => setOpen(true)} data-testid={presetAgentId ? "agent-kill" : "kill-switch"}>
        <Icon name="power" size={15} />
        <span className={compact ? "" : "hide-md"}>Kill switch</span>
      </button>
      {open ? <KillSwitchDialog open={open} onClose={() => setOpen(false)} presetAgentId={presetAgentId} /> : null}
    </>
  );
}

function KillSwitchDialog({ open, onClose, presetAgentId }: { open: boolean; onClose: () => void; presetAgentId?: string }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const { data: agents } = useBff<Page<AgentSummary & { x_console?: { provider: string } }>>("/agents?limit=200");
  const [scope, setScope] = useState<KillScopeKind>("agent");
  const [target, setTarget] = useState<string>(presetAgentId ?? "");
  const [reason, setReason] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<KillSwitchT | null>(null);
  const idem = useMemo(() => crypto.randomUUID(), []);

  const liveAgents = (agents?.data ?? []).filter((a) => a.routing.state !== "killed");
  const { data: providerPage } = useBff<Page<Provider>>("/providers");
  const providers = providerPage?.data ?? [];
  const providerSlug = providers.find((p) => p.id === target)?.slug;
  const reasonOk = reason.trim().length >= MIN_REASON;
  const targetOk = scope === "tenant" ? confirm.trim() === s.tenant : Boolean(target);
  // Live agents carry no provider; the API's blast radius names who a provider kill would stop.
  const hasExtras = (agents?.data ?? []).some((a) => Boolean(a.x_console));
  const { data: blast } = useBff<{ affected_agent_ids?: string[] }>(scope === "provider" && target && !hasExtras ? `/blast-radius/provider/${encodeURIComponent(target)}` : null);
  const providerCount = hasExtras ? liveAgents.filter((a) => a.x_console?.provider === providerSlug).length : blast ? liveAgents.filter((a) => blast.affected_agent_ids?.includes(a.id)).length : null;
  const affected = scope === "tenant" ? liveAgents.length : scope === "provider" ? providerCount : target ? 1 : 0;

  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      const ks = await s.withStepUp(() =>
        bffSend<KillSwitchT>("/kill-switches", { scope_kind: scope, ...(scope === "tenant" ? {} : { scope_id: target }), reason: reason.trim() }, { idempotencyKey: idem }),
      );
      setResult(ks);
      await mutate(() => true);
      toast.success("Kill switch pulled", `${ks.affected_agent_ids.length} agent${ks.affected_agent_ids.length === 1 ? "" : "s"} stopped; applied on ${ks.acks?.length ?? 0}/1 gateways.`);
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "The kill switch was not applied.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Layer
      open={open}
      onClose={onClose}
      title={result ? "Kill switch applied" : "Pull the kill switch"}
      description={result ? undefined : "Stops traffic immediately. It beats fail-open and stale snapshots, and only a re-authenticated human can release it."}
      testId="kill-dialog"
      footer={
        result ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button type="button" className="btn btn-danger" disabled={!reasonOk || !targetOk || busy || affected === 0} onClick={() => void submit()} data-testid="kill-confirm">
              {busy ? <span className="spinner" aria-hidden /> : <Icon name="power" size={15} />}
              {affected === null ? "Kill every agent on this provider" : `Kill ${affected} agent${affected === 1 ? "" : "s"}`}
            </button>
          </>
        )
      }
    >
      {result ? (
        <div className="inset" style={{ overflow: "hidden" }}>
          <dl className="kv">
            <div>
              <dt>Scope</dt>
              <dd>{result.scope_kind}</dd>
            </div>
            <div>
              <dt>Agents stopped</dt>
              <dd>{result.affected_agent_ids.length}</dd>
            </div>
            <div>
              <dt>Gateways acknowledged</dt>
              <dd>{result.acks?.length ?? 0} / 1</dd>
            </div>
            <div>
              <dt>Snapshot version</dt>
              <dd className="mono">{result.routing_version_at_pull}</dd>
            </div>
          </dl>
        </div>
      ) : (
        <div className="stack">
          <div className="seg" role="radiogroup" aria-label="Scope">
            {(["agent", "provider", "tenant"] as const).map((k) => (
              <button key={k} type="button" role="radio" aria-checked={scope === k} onClick={() => {
                  setScope(k);
                  setTarget(k === "agent" ? (presetAgentId ?? "") : "");
                }}>
                {k === "agent" ? "One agent" : k === "provider" ? "Provider" : "Whole tenant"}
              </button>
            ))}
          </div>
          {scope === "agent" ? (
            <div className="field">
              <label htmlFor="kill-agent">Agent</label>
              <select id="kill-agent" className="select" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Choose an agent…</option>
                {liveAgents.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name} · T{a.tier}
                  </option>
                ))}
              </select>
            </div>
          ) : scope === "provider" ? (
            <div className="field">
              <label htmlFor="kill-provider">Provider</label>
              <select id="kill-provider" className="select" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Choose a provider…</option>
                {providers.map((p) => (
                  <option key={p.id} value={p.id}>
                    {PROVIDER_LABEL[p.slug] ?? p.name}
                  </option>
                ))}
              </select>
            </div>
          ) : (
            <div className="field">
              <label htmlFor="kill-confirm-text">
                Type <span className="mono">{s.tenant}</span> to stop every agent
              </label>
              <input id="kill-confirm-text" className="input" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
            </div>
          )}
          <div className="field">
            <label htmlFor="kill-reason">Reason</label>
            <textarea id="kill-reason" className="textarea" value={reason} onChange={(e) => setReason(e.target.value)} aria-invalid={reason.length > 0 && !reasonOk} aria-describedby="kill-reason-hint" />
            <span id="kill-reason-hint" className={reason.length > 0 && !reasonOk ? "error" : "hint"}>
              {reasonOk ? "Written to the audit log as killswitch.pulled (critical)." : `At least ${MIN_REASON} characters (${reason.trim().length}/${MIN_REASON}).`}
            </span>
          </div>
          {error ? (
            <div className="banner" data-tone="failed" role="alert">
              <Icon name="incident" size={16} />
              {error}
            </div>
          ) : null}
        </div>
      )}
    </Layer>
  );
}
