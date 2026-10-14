"use client";
/**
 * One policy version: rules, simulate (server dry run), the signed JSON, versions, and the
 * approval flow. Approving a version with a tier-1 agent in scope (`approval_four_eyes`) needs a
 * second person: the author gets 409 self_approval inline.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { ActionPolicyRecord, ActionSimulate, ApiActionPolicy, SimulateResult } from "@/lib/api/action-gate";
import type { Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { FOUR_EYES_TITLE, SCOPE_KIND_LABEL, windowLabel } from "@/lib/action-gate/labels";
import { toPolicy } from "@/lib/action-gate/wire";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Clock } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { PolicyStatePill, personName } from "./Bits";
import { RuleList } from "./RuleList";
import { SimulatePanel } from "./SimulatePanel";

type Tab = "rules" | "simulate" | "json" | "versions";
const TABS: [Tab, string][] = [
  ["rules", "Rules"],
  ["simulate", "Simulate"],
  ["json", "JSON"],
  ["versions", "Versions"],
];

export function PolicyDetail({ id, initial }: { id: string; initial: ApiActionPolicy | null }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const tab = (TABS.find(([t]) => t === params.get("tab"))?.[0] ?? "rules") as Tab;
  const path = `/action-policies/${id}`;
  const { data } = useBff<ApiActionPolicy>(s.can("actions:read") ? path : null, initial);
  const rec = useMemo(() => (data ? toPolicy(data) : null), [data]);
  const { data: lineage } = useBff<Page<ApiActionPolicy>>(rec ? `/action-policies?policy_id=${rec.policy_id}&include_history=true&limit=50` : null);
  const versions = useMemo(() => (lineage?.data ?? []).map(toPolicy).sort((a, b) => b.version_no - a.version_no), [lineage]);

  if (!rec) {
    return (
      <div className="page">
        <div className="panel">
          <EmptyState icon="search" title="Policy not found" />
        </div>
      </div>
    );
  }
  const setTab = (t: Tab): void => router.replace(`/action-policies/${id}${t === "rules" ? "" : `?tab=${t}`}`, { scroll: false });
  const doc = rec.document;
  const simulate = (tool: string, args: Record<string, unknown>, counters: Record<string, number>): Promise<SimulateResult> => {
    const body: ActionSimulate = { tool, args, ...(Object.keys(counters).length ? { counters } : {}) };
    return bffSend<SimulateResult>(`/action-policies/${id}/simulate`, body);
  };

  return (
    <div className="page">
      <header className="page-head">
        <div style={{ minWidth: 0 }}>
          <Link href="/action-policies" className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
            <Icon name="arrowLeft" size={12} /> Action policies · {SCOPE_KIND_LABEL[rec.scope_kind]}: {rec.scope.label} <DemoMark paths={[path]} />
          </Link>
          <h1 className="large-title">{rec.name}</h1>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 8, alignItems: "center" }}>
            <span className="tag">v{rec.version_no}</span>
            <PolicyStatePill state={rec.state} onCanvas />
            {rec.approval_four_eyes ? (
              <span className="marker" title="A tier-1 agent is in scope: the author cannot approve this version">
                <Icon name="users" size={12} /> Four-eyes approval
              </span>
            ) : null}
            {rec.four_eyes ? (
              <span className="marker" title="Held actions under this policy need two distinct approvers">
                <Icon name="hand" size={12} /> Held actions need two approvers
              </span>
            ) : null}
            <span className="caption">
              Submitted by {personName(rec.created_by, s.userId)} · <Clock at={rec.created_at} seconds={false} />
            </span>
          </div>
        </div>
        {s.can("action_policies:write") && (rec.state === "approved" || rec.state === "draft") ? (
          <Link className="btn" href={`/action-policies/new?from=${rec.id}`} data-testid="policy-revise">
            <Icon name="plus" size={14} /> New version
          </Link>
        ) : null}
      </header>

      <PolicyDecision rec={rec} />

      <section className="section" aria-label="Sections">
        <div className="seg" role="group" aria-label="Section">
          {TABS.map(([t, l]) => (
            <button key={t} type="button" aria-pressed={tab === t} onClick={() => setTab(t)} data-testid={`policy-tab-${t}`}>
              {l}
            </button>
          ))}
        </div>
      </section>

      {tab === "rules" ? (
        <div className="grid-split">
          <section className="panel" aria-label="Rules">
            <div className="panel-head">
              <h3>Rules · first match wins</h3>
            </div>
            <RuleList doc={doc} />
          </section>
          <section className="panel" aria-label="Defaults">
            <div className="panel-head">
              <h3>Defaults</h3>
            </div>
            <dl className="kv">
              <div>
                <dt>No rule matches</dt>
                <dd>{doc.default_effect}</dd>
              </div>
              <div>
                <dt>Tool allowlist</dt>
                <dd className="mono">{doc.tool_allowlist_enforced ? (doc.tool_allowlist ?? []).join(", ") || "the agent's declared tools" : "not enforced"}</dd>
              </div>
              <div>
                <dt>Sensitive tools</dt>
                <dd className="mono">{doc.sensitive_tools.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt>External tools</dt>
                <dd className="mono">{doc.external_tools.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt>Hold for</dt>
                <dd>{windowLabel(doc.hold_timeout_s)}, then deny</dd>
              </div>
              <div>
                <dt>Document sha256</dt>
                <dd className="hash">{rec.document_sha256.slice(0, 16) || "—"}…</dd>
              </div>
            </dl>
          </section>
        </div>
      ) : tab === "simulate" ? (
        <SimulatePanel doc={doc} note={`Against v${rec.version_no} on the control plane; writes nothing`} run={simulate} />
      ) : tab === "json" ? (
        <section className="panel panel-pad" aria-label="Signed document">
          <pre className="code" tabIndex={0} data-testid="policy-json">
            {JSON.stringify(doc, null, 2)}
          </pre>
        </section>
      ) : (
        <section className="panel" aria-label="Versions">
          {versions.map((v) => (
            <Link key={v.id} href={`/action-policies/${v.id}`} className="row" aria-current={v.id === id ? "true" : undefined}>
              <span className="rule-index">v{v.version_no}</span>
              <span className="grow">
                {v.change_note ?? "—"}
                <span className="caption" style={{ display: "block" }}>
                  {personName(v.created_by, s.userId)}
                  {v.approved_by ? ` · approved by ${personName(v.approved_by, s.userId)}` : ""}
                </span>
              </span>
              <PolicyStatePill state={v.state} />
            </Link>
          ))}
        </section>
      )}
    </div>
  );
}

function PolicyDecision({ rec }: { rec: ActionPolicyRecord }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"approve" | "retire" | null>(null);
  const [error, setError] = useState<{ code: string; text: string } | null>(null);
  const idem = useMemo(() => ({ approve: crypto.randomUUID(), retire: crypto.randomUUID() }), []);
  const draft = rec.state === "draft";
  if (!s.can("action_policies:write") || (rec.state !== "draft" && rec.state !== "approved")) return null;

  const act = async (action: "approve" | "retire"): Promise<void> => {
    setBusy(action);
    setError(null);
    try {
      await bffSend(`/action-policies/${rec.id}/${action}`, { reason: reason.trim() }, { idempotencyKey: idem[action] });
      await mutate((k) => typeof k === "string" && (k.startsWith("/action-policies") || k.startsWith("/audit")));
      toast.success(action === "approve" ? `Version ${rec.version_no} approved` : `Version ${rec.version_no} retired`, action === "approve" ? "It goes out in the next signed snapshot." : undefined);
      setReason("");
    } catch (err) {
      if (err instanceof ProblemError) setError({ code: err.code, text: err.problem.detail ?? err.problem.title });
      else setError({ code: "error", text: "Not applied." });
    } finally {
      setBusy(null);
    }
  };

  const fourEyesError = error ? FOUR_EYES_TITLE[error.code] : undefined;
  return (
    <section className="panel" aria-labelledby="pdecide-title" data-testid="policy-decision" style={draft ? { boxShadow: "0 0 0 1.5px var(--human-dot), var(--sh-panel)" } : undefined}>
      <div className="panel-head">
        <h3 id="pdecide-title">{draft ? "Awaiting approval" : "Retire this version"}</h3>
        {draft && rec.approval_four_eyes ? <span className="caption">The author cannot approve it</span> : null}
      </div>
      <div className="panel-pad stack" style={{ gap: 10 }}>
        <div className="field">
          <label htmlFor="policy-reason">Reason</label>
          <input id="policy-reason" className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder={draft ? "e.g. Reviewed the rules and ran the simulate samples" : "e.g. Replaced by the finance-close group policy"} />
        </div>
        {error ? (
          <div className="banner" data-tone={fourEyesError ? "human" : "failed"} role="alert" data-testid="policy-error" data-code={error.code}>
            <Icon name={fourEyesError ? "users" : "incident"} size={16} />
            <span>
              {fourEyesError ? <strong>{fourEyesError}</strong> : null}
              {error.text}
            </span>
          </div>
        ) : null}
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          <button type="button" className="btn btn-danger-quiet" disabled={reason.trim().length < 10 || busy !== null} onClick={() => void act("retire")} data-testid="policy-retire">
            Retire
          </button>
          {draft ? (
            <button type="button" className="btn btn-primary" disabled={reason.trim().length < 10 || busy !== null} onClick={() => void act("approve")} data-testid="policy-approve">
              <Icon name="check" size={15} /> Approve
            </button>
          ) : null}
        </div>
      </div>
    </section>
  );
}
