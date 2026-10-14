"use client";
/**
 * Audit viewer (B8, the Compliance Auditor): the tenant's hash-chained events with prev→hash links, filters in
 * the URL, chain verification, export, and the decision record behind every routing change.
 */
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import type { AuditAnchor, AuditEvent, Page } from "@/lib/api/types";
import { PERSONAS } from "@/lib/auth/personas";
import { useBff } from "@/hooks/useBff";
import { latestAnchor, matchesFamily, newestFirst, sinceHours } from "@/lib/audit-query";
import { useNow } from "@/hooks/useNow";
import { shortHash } from "@/lib/format";
import { EmptyState } from "@/components/ui/Bits";
import { Pill } from "@/components/ui/StatePill";
import { Clock, DateTime } from "@/components/ui/Time";
import { Icon } from "@/components/ui/Icon";
import { Layer } from "@/components/ui/Layer";
import { useSession } from "@/components/shell/Session";
import { ChainTools } from "./ChainTools";
import { DecisionRecord } from "./DecisionRecord";
import { ActionRecord } from "./ActionRecord";

const ACTIONS: [string, string][] = [
  ["", "All actions"],
  ["route.changed", "Routing changes"],
  ["failover", "Failover"],
  ["approval", "Approvals"],
  ["handoff", "Handoffs"],
  ["alert", "Alerts"],
  ["killswitch", "Kill switch"],
  ["access", "Access"],
  ["api_key", "API keys"],
  ["capture", "Capture policy"],
  ["action", "Action Gate (all)"],
  ["action.blocked", "Blocked actions"],
  ["action.escalated", "Held for a person"],
  ["action.approved", "Held actions approved"],
  ["action.denied", "Held actions denied"],
  ["action.expired", "Held actions expired"],
  ["action_policy", "Action policies"],
];

function actorName(e: AuditEvent): string {
  if (e.actor_type === "human") return PERSONAS.find((p) => p.userId === e.actor_id)?.fullName ?? "Human";
  if (e.actor_type === "rule") return "rules/v1";
  if (e.actor_type === "api_key") return "API key";
  if (e.actor_type === "policy") return "Action Gate";
  return e.actor_type;
}

export function AuditView({ initial, initialAnchors, query, family }: { initial: Page<AuditEvent> | null; initialAnchors: Page<AuditAnchor> | null; query: string; family: string | null }) {
  const s = useSession();
  const router = useRouter();
  const params = useSearchParams();
  // Newest first (order=desc), 200 at a time; step back through older events with the cursor.
  const [position, setPosition] = useState<{ query: string; cursor: string } | null>(null);
  const cursor = position?.query === query ? position.cursor : null;
  const setCursor = (c: string | null): void => setPosition(c ? { query, cursor: c } : null);
  const now = useNow(60_000);
  const { data, error } = useBff<Page<AuditEvent>>(`/audit/events?limit=200${query ? `&${query}` : ""}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`, cursor ? null : initial);
  const { data: anchors } = useBff<Page<AuditAnchor>>("/audit/anchors?limit=200", initialAnchors);
  const [open, setOpen] = useState<AuditEvent | null>(null);
  const rows = newestFirst((data?.data ?? []).filter((e) => matchesFamily(e.action, family)));
  const lastAnchor = latestAnchor(anchors?.data ?? []);
  const pager = s.mode === "live" && (cursor || (data?.has_more && data.next_cursor));

  const setParams = (changes: Record<string, string>): void => {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    router.replace(`/audit${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };
  const setParam = (k: string, v: string): void => setParams({ [k]: v });

  if (!s.can("audit:read")) {
    return (
      <div className="page">
        <header>
          <h1 className="large-title">Audit</h1>
        </header>
        <div className="panel">
          <EmptyState icon="lock" title="Audit is restricted">
            Your role ({s.roleLabels.join(" + ") || "none"}) cannot read the audit log. Auditors, admins, workspace admins and security admins can.
          </EmptyState>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">Tamper-evident · sha256 chain · Ed25519 anchors</div>
          <h1 className="large-title">Audit log</h1>
          <p className="lede num">
            {rows.length} events shown{lastAnchor ? <>, last anchor at seq {lastAnchor.seq_to} (<DateTime at={lastAnchor.anchored_at} />)</> : null}. Every automated decision, approval and human override is here.
          </p>
        </div>
        <ChainTools headSeq={rows[0]?.seq ?? 1} />
      </header>
      {pager ? (
        <div className="banner" data-tone="info" role="status" data-testid="audit-pager">
          <Icon name="info" size={16} />
          <span className="grow">{cursor ? "Older events." : "The newest 200 events."} {data?.has_more ? "Older events follow." : "This reaches the first event that matches."}</span>
          {cursor ? (
            <button type="button" className="btn btn-sm" onClick={() => setCursor(null)}>
              Newest
            </button>
          ) : null}
          {data?.has_more && data.next_cursor ? (
            <button type="button" className="btn btn-sm" onClick={() => setCursor(data.next_cursor ?? null)} data-testid="audit-older">
              Older events <Icon name="arrowRight" size={13} />
            </button>
          ) : null}
        </div>
      ) : null}

      <section className="section" aria-label="Filters">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <label className="sr-only" htmlFor="audit-action">
            Action
          </label>
          <select id="audit-action" className="select" style={{ width: "auto", minHeight: 34, borderRadius: 999 }} value={params.get("action") ?? ""} onChange={(e) => setParam("action", e.target.value)}>
            {ACTIONS.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <div className="seg" role="group" aria-label="Actor">
            {[
              ["", "Anyone"],
              ["human", "People"],
              ["rule", "Rules"],
              ["system", "System"],
            ].map(([v, l]) => (
              <button key={v} type="button" aria-pressed={(params.get("actor_type") ?? "") === v} onClick={() => setParam("actor_type", v ?? "")}>
                {l}
              </button>
            ))}
          </div>
          <label className="sr-only" htmlFor="audit-since">
            When
          </label>
          <select
            id="audit-since"
            className="select"
            style={{ width: "auto", minHeight: 34, borderRadius: 999 }}
            value={params.get("occurred_after") ? "custom" : ""}
            onChange={(e) => {
              const hours = Number(e.target.value);
              setParams({ occurred_after: hours ? sinceHours(now, hours) : "", occurred_before: "" });
            }}
            data-testid="audit-since"
          >
            <option value="">Any time</option>
            {params.get("occurred_after") ? <option value="custom">Since {params.get("occurred_after")?.slice(0, 16).replace("T", " ")}</option> : null}
            <option value="1">Last hour</option>
            <option value="24">Last 24 hours</option>
            <option value="168">Last 7 days</option>
          </select>
          {params.get("agent_id") ? (
            <button type="button" className="tag" style={{ height: 30, border: 0, cursor: "pointer" }} onClick={() => setParam("agent_id", "")} data-testid="audit-agent-chip">
              Agent {params.get("agent_id")?.slice(-6)} <Icon name="x" size={12} />
            </button>
          ) : null}
          {params.get("resource_id") ? (
            <button type="button" className="tag" style={{ height: 30, border: 0, cursor: "pointer" }} onClick={() => setParam("resource_id", "")}>
              Resource {params.get("resource_id")?.slice(-6)} <Icon name="x" size={12} />
            </button>
          ) : null}
        </div>
      </section>

      <section className="panel table-wrap" aria-label="Audit events">
        {error ? (
          <EmptyState icon="lock" title="Not permitted" />
        ) : rows.length === 0 ? (
          <EmptyState icon="search" title="No events match" />
        ) : (
          <table className="table stack">
            <thead>
              <tr>
                <th scope="col">Seq</th>
                <th scope="col">Time</th>
                <th scope="col">Action</th>
                <th scope="col" className="hide-sm">Actor</th>
                <th scope="col" className="hide-sm">Resource</th>
                <th scope="col" className="hide-sm">prev → hash</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.seq} onClick={() => setOpen(e)} style={{ cursor: "pointer" }} data-testid="audit-row">
                  <td className="num mono">{e.seq}</td>
                  <td className="num">
                    <Clock at={e.recorded_at} />
                  </td>
                  <td>
                    <button type="button" className="btn-plain" style={{ border: 0, background: "none", padding: 0, font: "inherit", fontWeight: 600, color: "var(--text)", cursor: "pointer" }} onClick={() => setOpen(e)}>
                      {e.action}
                    </button>
                    {e.severity && e.severity !== "info" ? (
                      <span style={{ marginLeft: 6 }}>
                        <Pill tone={e.severity === "critical" ? "failed" : "degraded"}>{e.severity}</Pill>
                      </span>
                    ) : null}
                  </td>
                  <td className="hide-sm">{actorName(e)}</td>
                  <td className="hide-sm">
                    <span className="mono caption">{e.resource_ref ?? e.resource_type}</span>
                  </td>
                  <td className="hide-sm">
                    <span className="hash">
                      {shortHash(e.prev_hash, 6)} <span className="link-glyph">→</span> {shortHash(e.hash, 8)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <Layer open={Boolean(open)} onClose={() => setOpen(null)} title={open ? `${open.action} · seq ${open.seq}` : "Event"} description={open ? <Clock at={open.recorded_at} /> : undefined} variant="sheet" testId="audit-sheet">
        {open ? (
          <div className="stack">
            <div className="inset" style={{ overflow: "hidden" }}>
              <dl className="kv">
                <div>
                  <dt>Actor</dt>
                  <dd>{actorName(open)}</dd>
                </div>
                <div>
                  <dt>Resource</dt>
                  <dd className="mono">{open.resource_ref ?? open.resource_type}</dd>
                </div>
                <div>
                  <dt>Reason</dt>
                  <dd style={{ textAlign: "right" }}>{open.reason ?? "—"}</dd>
                </div>
                <div>
                  <dt>prev_hash</dt>
                  <dd className="hash">{shortHash(open.prev_hash, 16)}</dd>
                </div>
                <div>
                  <dt>hash</dt>
                  <dd className="hash">{shortHash(open.hash, 16)}</dd>
                </div>
              </dl>
            </div>
            {open.action === "route.changed" ? <DecisionRecord event={open} /> : null}
            {open.action.startsWith("action.") ? <ActionRecord event={open} /> : null}
            <div>
              <div className="caption" style={{ marginBottom: 6 }}>
                Detail (refs and stats only; content is never written to the audit log)
              </div>
              <pre className="code" tabIndex={0}>{JSON.stringify(open.detail ?? {}, null, 2)}</pre>
            </div>
          </div>
        ) : null}
      </Layer>
    </div>
  );
}
