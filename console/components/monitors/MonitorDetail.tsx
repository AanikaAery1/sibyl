"use client";
/**
 * One external monitor (`GET /monitors/{id}`): what it watches, its keys (metadata only), its
 * signed webhooks with the last delivery, its recent findings and how to connect it. Admins
 * (`monitors:admin`) pause or resume it (PATCH with If-Match), issue keys, add webhooks, send a
 * test delivery and revoke it; everyone else with `sentinel:read` reads.
 */
import Link from "next/link";
import { useState } from "react";
import { useSWRConfig } from "swr";
import type { AgentGroup, Finding, Monitor, MonitorWebhook, WebhookTestResult } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { ProblemError } from "@/lib/api/problem";
import { bffSend, lastEtag, route } from "@/lib/client/bff";
import { useBff } from "@/hooks/useBff";
import { AGENT_GROUPS_PATH, EVENT_LABEL, FINDING_KIND_LABEL, MONITOR_ADVISORY_COPY, findingsFeedPath, monitorIfMatch, monitorPath, monitorProblemText, plainText, watchedLabel, webhookTestText } from "@/lib/monitors/view";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Pill } from "@/components/ui/StatePill";
import { Ago, DateTime } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { useToast } from "@/components/ui/Toast";
import { useSession } from "@/components/shell/Session";
import { SeverityTag } from "@/components/sentinel/Bits";
import { DeliveryPill, MonitorKindTag, MonitorStatePill, SetupSnippets } from "./Bits";
import { IssueKeyDialog, RevokeDialog, WebhookDialog } from "./Dialogs";

function problemText(err: unknown, fallback: string): string {
  if (err instanceof ProblemError) return monitorProblemText(err.status, err.code) ?? err.problem.detail ?? err.problem.title;
  return fallback;
}

function WebhookRow({ m, h, canAdmin }: { m: Monitor; h: MonitorWebhook; canAdmin: boolean }) {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const test = async (): Promise<void> => {
    setBusy(true);
    setResult(null);
    try {
      const r = await bffSend<WebhookTestResult>(route("/monitors/{monitor_id}/webhooks/{webhook_id}/test", { monitor_id: m.id, webhook_id: h.id }), {});
      setResult({ ok: r.ok, text: webhookTestText(r) });
    } catch (err) {
      setResult({ ok: false, text: problemText(err, "The test delivery could not be sent.") });
    } finally {
      setBusy(false);
    }
  };
  const live = h.state === "enabled" && m.state !== "revoked";
  return (
    <div className="row" style={{ alignItems: "flex-start", flexWrap: "wrap", cursor: "default" }} data-testid="webhook-row">
      <div className="grow stack" style={{ minWidth: 0, gap: 6 }}>
        <span className="mono" style={{ fontSize: "var(--fs-footnote)", overflowWrap: "anywhere" }} data-testid="webhook-url">
          {h.url}
        </span>
        <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
          {h.event_types.map((e) => (
            <span key={e} className="tag" title={e}>
              {EVENT_LABEL[e]}
            </span>
          ))}
        </div>
        <div className="caption" style={{ display: "flex", gap: "4px 12px", flexWrap: "wrap", alignItems: "center" }}>
          {h.state === "disabled" ? <Pill tone="quiet">Disabled</Pill> : <DeliveryPill status={h.last_delivery_status ?? "pending"} code={h.last_response_code} />}
          {h.last_delivery_at ? (
            <span>
              last delivery <Ago at={h.last_delivery_at} />
            </span>
          ) : null}
          {h.consecutive_failures ? <span className="num">{h.consecutive_failures} failures in a row</span> : null}
          {h.disabled_reason ? <span>{h.disabled_reason}</span> : null}
        </div>
        {result ? (
          <p className="caption" role="status" style={{ color: result.ok ? "var(--healthy)" : "var(--failed)" }} data-testid="webhook-test-result">
            {result.text}
          </p>
        ) : null}
      </div>
      {canAdmin && live ? (
        <button type="button" className="btn btn-sm" disabled={busy} onClick={() => void test()} data-testid="webhook-test">
          {busy ? <span className="spinner" aria-hidden /> : <Icon name="play" size={13} />} Send test
        </button>
      ) : null}
    </div>
  );
}

function RecentFindings({ monitorId }: { monitorId: string }) {
  const { data } = useBff<Page<Finding>>(findingsFeedPath({ source: "external", monitorId, limit: 10 }));
  const rows = data?.data ?? [];
  return (
    <section className="panel" aria-labelledby="mon-findings-title">
      <div className="panel-head">
        <h3 id="mon-findings-title">Recent findings</h3>
        <Link href="/sentinel?source=external" className="caption" style={{ textDecoration: "underline", textUnderlineOffset: 2 }}>
          All findings
        </Link>
      </div>
      {rows.length === 0 ? (
        <EmptyState icon="eye" title="No findings yet">
          Findings appear here when the monitor calls POST /findings with its key.
        </EmptyState>
      ) : (
        rows.map((f) => (
          <Link key={f.id} href={`/sentinel/${f.id}`} className="row" data-testid="monitor-finding" style={{ alignItems: "flex-start" }}>
            <div className="grow stack" style={{ minWidth: 0, gap: 4 }}>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
                <Pill tone="advisory">{FINDING_KIND_LABEL[f.kind]}</Pill>
                <SeverityTag severity={f.severity} />
              </div>
              <span style={{ overflowWrap: "anywhere" }}>{plainText(f.summary, 300)}</span>
            </div>
            <span className="caption" style={{ flex: "none" }}>
              <Ago at={f.created_at} />
            </span>
          </Link>
        ))
      )}
    </section>
  );
}

export function MonitorDetail({ id, initial }: { id: string; initial: Monitor | null }) {
  const s = useSession();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const canRead = s.can("monitors:admin") || s.can("sentinel:read");
  const canAdmin = s.can("monitors:admin");
  const path = monitorPath(id);
  const { data: m, error } = useBff<Monitor>(canRead ? path : null, initial);
  const { data: groups } = useBff<Page<AgentGroup>>(canRead ? AGENT_GROUPS_PATH : null);
  const [dialog, setDialog] = useState<"revoke" | "webhook" | "key" | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = async (): Promise<void> => {
    await mutate((key) => typeof key === "string" && (key.startsWith("/monitors") || key.startsWith("/findings")));
  };

  if (!m) {
    const forbidden = (error instanceof ProblemError && error.status === 403) || !canRead;
    return (
      <div className="page">
        <Link href="/monitors" className="caption">
          ← Monitors
        </Link>
        <div className="panel">
          <EmptyState icon={forbidden ? "lock" : "search"} title={forbidden ? "Not permitted" : "Monitor not found"} />
        </div>
      </div>
    );
  }

  const revoked = m.state === "revoked";
  const names = new Map((groups?.data ?? []).map((g) => [g.id, g.name]));

  const setState = async (next: "active" | "paused"): Promise<void> => {
    setBusy(true);
    setActionError(null);
    try {
      await bffSend<Monitor>(path, { state: next }, { method: "PATCH", ifMatch: monitorIfMatch(m, lastEtag(path)) });
      toast.success(next === "paused" ? "Monitor paused" : "Monitor resumed", next === "paused" ? "Its findings are refused (409) until you resume it; reads still work." : "It can submit findings again.");
      await refresh();
    } catch (err) {
      setActionError(problemText(err, "The monitor did not change."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page" style={{ maxWidth: 1100 }}>
      <header className="page-head">
        <div style={{ minWidth: 0 }}>
          <Link href="/monitors" className="eyebrow" style={{ textDecoration: "none", color: "var(--text-2)" }}>
            <Icon name="arrowLeft" size={12} /> Monitors <DemoMark paths={[path]} />
          </Link>
          <h1 className="large-title" style={{ overflowWrap: "anywhere" }} data-testid="monitor-name">
            {m.name}
          </h1>
          <div className="monitor-meta" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", marginTop: 6 }}>
            <MonitorKindTag kind={m.kind} />
            <MonitorStatePill state={m.state} />
            <span className="caption">
              registered <DateTime at={m.created_at} />
            </span>
          </div>
          {m.description ? (
            <p className="lede" style={{ overflowWrap: "anywhere" }}>
              {plainText(m.description, 2000)}
            </p>
          ) : null}
        </div>
        {canAdmin && !revoked ? (
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {m.state === "active" ? (
              <button type="button" className="btn" disabled={busy} onClick={() => void setState("paused")} data-testid="monitor-pause">
                {busy ? <span className="spinner" aria-hidden /> : <Icon name="pause" size={14} />} Pause
              </button>
            ) : (
              <button type="button" className="btn" disabled={busy} onClick={() => void setState("active")} data-testid="monitor-resume">
                {busy ? <span className="spinner" aria-hidden /> : <Icon name="play" size={14} />} Resume
              </button>
            )}
            <button type="button" className="btn" onClick={() => setDialog("key")} data-testid="monitor-issue-key">
              <Icon name="key" size={14} /> Issue key
            </button>
            <button type="button" className="btn btn-danger-quiet" onClick={() => setDialog("revoke")} data-testid="monitor-revoke-open">
              Revoke
            </button>
          </div>
        ) : null}
      </header>

      {actionError ? (
        <div className="banner" data-tone="failed" role="alert" data-testid="monitor-action-error">
          <Icon name="incident" size={16} />
          {actionError}
        </div>
      ) : null}

      {revoked ? (
        <div className="banner" data-tone="quiet" role="note" data-testid="monitor-revoked">
          <Icon name="lock" size={16} />
          <span>
            Revoked {m.revoked_at ? <DateTime at={m.revoked_at} /> : null}
            {m.revoke_reason ? `: ${plainText(m.revoke_reason, 2000)}` : "."} Its keys no longer work and its webhooks are disabled. Findings stay on record.
          </span>
        </div>
      ) : m.state === "paused" ? (
        <div className="banner" data-tone="watch" role="note" data-testid="monitor-paused">
          <Icon name="pause" size={16} />
          <span>Paused: it can still read, but Sibyl refuses its findings (409 not_active) until an admin resumes it.</span>
        </div>
      ) : (
        <div className="banner" data-tone="advisory" role="note">
          <Icon name="eye" size={16} />
          <span>{MONITOR_ADVISORY_COPY}</span>
        </div>
      )}

      <div className="grid-split">
        <div className="stack" style={{ minWidth: 0 }}>
          <section className="panel" aria-label="Overview">
            <dl className="kv">
              <div>
                <dt>Watches</dt>
                <dd data-testid="monitor-watches">{watchedLabel(m, names)}</dd>
              </div>
              <div>
                <dt>Key scopes</dt>
                <dd>
                  <span className="mono">monitor:read</span> · <span className="mono">findings:write</span>
                </dd>
              </div>
              <div>
                <dt>Rate limit</dt>
                <dd className="num">{m.rate_limit_per_min} findings per minute</dd>
              </div>
              <div>
                <dt>Findings, 24 h</dt>
                <dd className="num">
                  {m.findings_24h ?? 0}
                  {m.last_finding_at ? (
                    <span className="caption">
                      {" "}
                      · last <Ago at={m.last_finding_at} />
                    </span>
                  ) : null}
                </dd>
              </div>
            </dl>
          </section>

          <section className="panel" aria-labelledby="mon-keys-title">
            <div className="panel-head">
              <h3 id="mon-keys-title">Keys</h3>
              <span className="caption">Metadata only; rotate or revoke in Settings → API keys</span>
            </div>
            {m.keys.length === 0 ? (
              <EmptyState icon="key" title={revoked ? "Keys revoked" : "No active keys"} />
            ) : (
              <div className="table-wrap">
                <table className="table stack keys-table" data-testid="monitor-keys">
                  <thead>
                    <tr>
                      <th scope="col">Name</th>
                      <th scope="col">Status</th>
                      <th scope="col">Last used</th>
                      <th scope="col" className="hide-sm">
                        Expires
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {m.keys.map((k) => (
                      <tr key={k.id}>
                        <td>
                          <div style={{ fontWeight: 600 }}>{k.name}</div>
                          <div className="caption mono">
                            sbl_{k.env}_{k.prefix}_…
                          </div>
                        </td>
                        <td>
                          <Pill tone={k.status === "active" ? "healthy" : k.status === "rotating" ? "watch" : "neutral"} dot={k.status !== "revoked"}>
                            {k.status}
                          </Pill>
                        </td>
                        <td className="caption">{k.last_used_at ? <Ago at={k.last_used_at} /> : "Never"}</td>
                        <td className="caption hide-sm">
                          <DateTime at={k.expires_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="panel" aria-labelledby="mon-hooks-title">
            <div className="panel-head">
              <h3 id="mon-hooks-title">Webhooks</h3>
              {canAdmin && !revoked ? (
                <button type="button" className="btn btn-sm" onClick={() => setDialog("webhook")} data-testid="webhook-add-open">
                  <Icon name="plus" size={13} /> Add webhook
                </button>
              ) : null}
            </div>
            {m.webhooks.length === 0 ? (
              <EmptyState icon="link" title="No webhooks">
                {m.kind === "webhook" ? "Add the receiver Sibyl should push signed events to." : "Optional: push signed events to this monitor instead of polling."}
              </EmptyState>
            ) : (
              m.webhooks.map((h) => <WebhookRow key={h.id} m={m} h={h} canAdmin={canAdmin} />)
            )}
          </section>
        </div>

        <div className="stack" style={{ minWidth: 0 }}>
          <RecentFindings monitorId={m.id} />
          {canAdmin && !revoked ? (
            <section className="panel panel-pad stack" aria-labelledby="mon-connect-title" style={{ gap: 12 }}>
              <h3 id="mon-connect-title" className="title-sm">
                Connect
              </h3>
              <p className="caption">The key itself was shown once when it was issued. Issue another key if it was lost.</p>
              <SetupSnippets kind={m.kind} secret={null} />
            </section>
          ) : null}
        </div>
      </div>

      {canAdmin && !revoked ? (
        <>
          <RevokeDialog
            monitor={m}
            open={dialog === "revoke"}
            onClose={() => setDialog(null)}
            onDone={(next) => {
              setDialog(null);
              toast.success("Monitor revoked", `${next.name}'s keys stopped working and its webhooks are disabled.`);
              void refresh();
            }}
          />
          <WebhookDialog monitor={m} open={dialog === "webhook"} onClose={() => setDialog(null)} onDone={() => void refresh()} />
          <IssueKeyDialog monitor={m} open={dialog === "key"} onClose={() => setDialog(null)} onDone={() => void refresh()} />
        </>
      ) : null}
    </div>
  );
}
