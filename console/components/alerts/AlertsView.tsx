"use client";
/**
 * Alerts with the unverdicted queue (D24, D33): an alert is never closed without a verdict;
 * hysteresis-resolved alerts land here with verdict = null until a human labels them.
 * Member alerts of a provider incident collapse into one row.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentSummary, Alert, Page, Verdict } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { ruleLabel } from "@/lib/health/scoring";
import { VERDICT_LABEL } from "@/lib/labels";
import { EmptyState } from "@/components/ui/Bits";
import { Pill, SeverityPill } from "@/components/ui/StatePill";
import { Ago } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";

type View = "open" | "unverdicted" | "resolved";
type AlertX = Alert & { verdict_wanted?: boolean };

export function AlertsView({ initialAll, initialAgents }: { initialAll: Page<AlertX> | null; initialAgents: Page<AgentSummary> | null }) {
  const params = useSearchParams();
  const router = useRouter();
  const s = useSession();
  const view = (["open", "unverdicted", "resolved"].includes(params.get("view") ?? "") ? params.get("view") : "open") as View;
  const { data } = useBff<Page<AlertX>>("/alerts?limit=200&include_suppressed=true", initialAll);
  const { data: agents } = useBff<Page<AgentSummary>>("/agents?limit=200", initialAgents);
  const [closing, setClosing] = useState<AlertX | null>(null);
  const names = useMemo(() => new Map((agents?.data ?? []).map((a) => [a.id, a])), [agents]);
  const all = data?.data ?? [];
  const open = all.filter((a) => a.state !== "resolved");
  const unverdicted = all.filter((a) => a.state === "resolved" && a.verdict === null).sort((x, y) => Number(Boolean(y.verdict_wanted)) - Number(Boolean(x.verdict_wanted)));
  const resolved = all.filter((a) => a.state === "resolved" && a.verdict !== null);
  const list = view === "open" ? open : view === "unverdicted" ? unverdicted : resolved;
  const backlog = all.filter((a) => a.state === "resolved").length ? unverdicted.length / all.filter((a) => a.state === "resolved").length : 0;

  // Collapse provider-incident members into one group row.
  const groups = useMemo(() => {
    const out: { key: string; alerts: AlertX[] }[] = [];
    const byIncident = new Map<string, AlertX[]>();
    for (const a of list) {
      if (a.provider_incident_id && view === "open") byIncident.set(a.provider_incident_id, [...(byIncident.get(a.provider_incident_id) ?? []), a]);
      else out.push({ key: a.id, alerts: [a] });
    }
    for (const [k, v] of byIncident) out.unshift({ key: `pi-${k}`, alerts: v });
    return out;
  }, [list, view]);

  const setView = (v: View): void => router.replace(v === "open" ? "/alerts" : `/alerts?view=${v}`, { scroll: false });

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">Rules fire alerts · humans label them</div>
          <h1 className="large-title">Alerts</h1>
          <p className="lede num">
            {open.length} open. {unverdicted.length} resolved without a verdict — verdicts are the only labels the learning engine trains on.
          </p>
        </div>
        <div className="seg" role="tablist" aria-label="Alert views">
          {(
            [
              ["open", "Open", open.length],
              ["unverdicted", "Unverdicted", unverdicted.length],
              ["resolved", "Resolved", resolved.length],
            ] as const
          ).map(([v, l, n]) => (
            <button key={v} type="button" role="tab" aria-selected={view === v} onClick={() => setView(v)} data-testid={`alerts-${v}`}>
              {l} <span className="count">{n}</span>
            </button>
          ))}
        </div>
      </header>

      {view === "unverdicted" && backlog > 0.2 ? (
        <div className="banner" data-tone="watch" role="status">
          <Icon name="info" size={16} />
          <span>
            <strong>{Math.round(backlog * 100)}% of resolved alerts have no verdict</strong> (target under 20%). Alerts whose agent was moved automatically are listed first.
          </span>
        </div>
      ) : null}

      <section className="panel" aria-label={`${view} alerts`}>
        {groups.length === 0 ? (
          <EmptyState icon="check" title={view === "unverdicted" ? "Every resolved alert has a verdict" : view === "open" ? "No open alerts" : "Nothing resolved yet"} />
        ) : (
          groups.map((g) =>
            g.alerts.length > 1 ? (
              <details key={g.key} className="row" style={{ display: "block" }} data-testid="alert-group">
                <summary style={{ display: "flex", alignItems: "center", gap: 12, cursor: "pointer", listStyle: "none" }}>
                  <SeverityPill severity="critical" />
                  <div className="grow">
                    <div className="title-sm">One provider incident · {g.alerts.length} alerts collapsed</div>
                    <div className="muted">{ruleLabel(g.alerts[0]?.rule_code ?? "")} on {g.alerts.map((a) => names.get(a.agent_id ?? "")?.name).filter(Boolean).join(", ")}</div>
                  </div>
                  <span className="caption">
                    <Ago at={g.alerts[0]?.fired_at} />
                  </span>
                  <Icon name="chevronDown" size={14} />
                </summary>
                <div style={{ marginTop: 10 }}>
                  {g.alerts.map((a) => (
                    <AlertRow key={a.id} a={a} name={names.get(a.agent_id ?? "")?.name} onClose={() => setClosing(a)} canAct={s.can("alerts:act")} nested />
                  ))}
                </div>
              </details>
            ) : g.alerts[0] ? (
              <AlertRow key={g.key} a={g.alerts[0]} name={names.get(g.alerts[0].agent_id ?? "")?.name} onClose={() => setClosing(g.alerts[0] ?? null)} canAct={s.can("alerts:act")} />
            ) : null,
          )
        )}
      </section>
      {closing ? <VerdictDialog alert={closing} name={names.get(closing.agent_id ?? "")?.name} onClose={() => setClosing(null)} /> : null}
    </div>
  );
}

function AlertRow({ a, name, onClose, canAct, nested = false }: { a: AlertX; name?: string; onClose: () => void; canAct: boolean; nested?: boolean }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const ack = async (): Promise<void> => {
    try {
      await bffSend(`/alerts/${a.id}/actions`, { action: "ack" });
      await mutate(() => true);
      toast.success("Acknowledged");
    } catch (err) {
      toast.error(err);
    }
  };
  return (
    <div className="row" style={nested ? { paddingInline: 0 } : undefined} data-testid="alert-row" data-alert-id={a.id}>
      <SeverityPill severity={a.severity} />
      <div className="grow">
        <div className="title-sm truncate">
          {ruleLabel(a.rule_code)}
          {name ? <span className="subtle" style={{ fontWeight: 500 }}> · {a.agent_id ? <Link href={`/agents/${a.agent_id}`}>{name}</Link> : name}</span> : null}
        </div>
        <div className="muted truncate">
          {a.state === "resolved" ? (a.verdict ? `Closed · ${VERDICT_LABEL[a.verdict]}` : a.verdict_wanted ? "Resolved after an automatic move · verdict wanted" : "Resolved by hysteresis · no verdict") : a.state === "acked" ? "Acknowledged" : "Open"}
          {a.hold_suppressed_count ? ` · ${a.hold_suppressed_count} moves suppressed by a hold` : ""}
          {a.health_snapshot && typeof (a.health_snapshot as Record<string, unknown>).score === "number" ? ` · score ${(a.health_snapshot as Record<string, unknown>).score} at fire time` : ""}
        </div>
      </div>
      <span className="caption hide-sm">
        <Ago at={a.fired_at} />
      </span>
      {canAct && a.state === "open" ? (
        <button type="button" className="btn btn-sm" onClick={() => void ack()}>
          Ack
        </button>
      ) : null}
      {canAct && (a.state !== "resolved" || a.verdict === null) ? (
        <button type="button" className="btn btn-sm" onClick={onClose} data-testid="close-alert">
          {a.state === "resolved" ? "Add verdict" : "Close"}
        </button>
      ) : a.verdict ? (
        <Pill tone={a.verdict === "tp" ? "healthy" : a.verdict === "fp" ? "degraded" : "quiet"}>{a.verdict.toUpperCase()}</Pill>
      ) : null}
    </div>
  );
}

function VerdictDialog({ alert, name, onClose }: { alert: AlertX; name?: string; onClose: () => void }) {
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      await bffSend(`/alerts/${alert.id}/actions`, { action: "close", ...(verdict ? { verdict } : {}), ...(note.trim() ? { verdict_note: note.trim() } : {}) });
      await mutate(() => true);
      toast.success("Alert closed", verdict ? `Labelled ${(VERDICT_LABEL[verdict] ?? verdict).toLowerCase()}.` : undefined);
      onClose();
    } catch (err) {
      setError(err instanceof ProblemError ? (err.problem.detail ?? err.problem.title) : "Not closed.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <Layer
      open
      onClose={onClose}
      title={`Close · ${ruleLabel(alert.rule_code)}`}
      description={name ? `${name}. Was this alert right?` : "Was this alert right?"}
      testId="verdict-dialog"
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void submit()} disabled={busy} data-testid="verdict-submit">
            {busy ? <span className="spinner" aria-hidden /> : null}Close alert
          </button>
        </>
      }
    >
      <div className="stack">
        <div className="seg" role="radiogroup" aria-label="Verdict" style={{ alignSelf: "flex-start" }}>
          {(["tp", "fp", "unsure"] as const).map((v) => (
            <button key={v} type="button" role="radio" aria-checked={verdict === v} onClick={() => setVerdict(v)} data-testid={`verdict-${v}`}>
              {VERDICT_LABEL[v]}
            </button>
          ))}
        </div>
        <div className="field">
          <label htmlFor="verdict-note">Note (optional)</label>
          <textarea id="verdict-note" className="textarea" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder="What made it right or wrong" />
        </div>
        {error ? (
          <div className="banner" data-tone="failed" role="alert" data-testid="verdict-error">
            <Icon name="incident" size={16} />
            {error}
          </div>
        ) : null}
      </div>
    </Layer>
  );
}
