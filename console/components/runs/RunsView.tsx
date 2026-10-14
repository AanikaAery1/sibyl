"use client";
/**
 * Runs (D50): agent runs newest first from `GET /runs`, top-level by default (`root_only`), with
 * the API's filters (agent, status, event-time window; the API defaults to the last 24 hours and
 * allows 31 days) and keyset paging. Filters live in the URL; each row opens the run tree.
 */
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import type { RunStatus, RunSummary } from "@/lib/api/monitor";
import type { AgentSummary, Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { useNow } from "@/hooks/useNow";
import { sinceHours } from "@/lib/audit-query";
import { RUN_STATUS_LABEL, runPath, runsPath, runsQueryOf } from "@/lib/runs/tree";
import { EmptyState } from "@/components/ui/Bits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";
import { DemoMark } from "@/components/ui/DemoMark";
import { RunStatusPill, runDuration } from "./RunBits";

const SELECT_STYLE = { width: "auto", minHeight: 34, borderRadius: 999 } as const;

export function RunsView({ initial }: { initial: Page<RunSummary> | null }) {
  const router = useRouter();
  const params = useSearchParams();
  const now = useNow(60_000);
  const q = runsQueryOf((k) => params.get(k));
  const path = runsPath(q);
  const { data, error } = useBff<Page<RunSummary>>(path, initial);
  const { data: agentsPage } = useBff<Page<AgentSummary>>("/agents?limit=200");
  const agents = new Map((agentsPage?.data ?? []).map((a) => [a.id, a]));
  const runs = data?.data ?? [];

  const setParams = (changes: Record<string, string>): void => {
    const next = new URLSearchParams(params.toString());
    for (const [k, v] of Object.entries(changes)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("cursor" in changes)) next.delete("cursor");
    router.replace(`/runs${next.toString() ? `?${next}` : ""}`, { scroll: false });
  };

  const agentName = q.agentId ? (agents.get(q.agentId)?.name ?? `Agent ${q.agentId.slice(-6)}`) : null;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <div className="eyebrow">
            Run trees from the SDK <DemoMark paths={[path]} />
          </div>
          <h1 className="large-title">Runs</h1>
          <p className="lede">{q.rootOnly ? "Top-level runs" : "Every run, child runs included"}, newest first. Metadata only: models, tools, handoffs and gate outcomes, never content.</p>
        </div>
      </header>

      <section className="section" aria-label="Filters">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <div className="seg" role="group" aria-label="Which runs">
            {(
              [
                ["", "Top-level"],
                ["all", "All runs"],
              ] as const
            ).map(([v, l]) => (
              <button key={v} type="button" aria-pressed={(params.get("scope") ?? "") === v} onClick={() => setParams({ scope: v })} data-testid={`runs-scope-${v || "top"}`}>
                {l}
              </button>
            ))}
          </div>
          <label className="sr-only" htmlFor="runs-status">
            Status
          </label>
          <select id="runs-status" className="select" style={SELECT_STYLE} value={q.status ?? ""} onChange={(e) => setParams({ status: e.target.value })} data-testid="runs-status">
            <option value="">Any status</option>
            {(Object.keys(RUN_STATUS_LABEL) as RunStatus[]).map((st) => (
              <option key={st} value={st}>
                {RUN_STATUS_LABEL[st]}
              </option>
            ))}
          </select>
          <label className="sr-only" htmlFor="runs-since">
            When
          </label>
          <select
            id="runs-since"
            className="select"
            style={SELECT_STYLE}
            value={q.since ? "custom" : ""}
            onChange={(e) => {
              const hours = Number(e.target.value);
              setParams({ since: hours ? sinceHours(now, hours) : "", until: "" });
            }}
            data-testid="runs-since"
          >
            <option value="">Last 24 hours</option>
            {q.since ? <option value="custom">Since {q.since.slice(0, 16).replace("T", " ")}</option> : null}
            <option value="1">Last hour</option>
            <option value="168">Last 7 days</option>
            <option value="720">Last 30 days</option>
          </select>
          {q.agentId ? (
            <button type="button" className="tag" style={{ height: 30, border: 0, cursor: "pointer" }} onClick={() => setParams({ agent_id: "" })} data-testid="runs-agent-chip">
              {agentName} <Icon name="x" size={12} />
              <span className="sr-only">Clear the agent filter</span>
            </button>
          ) : null}
        </div>
      </section>

      <section className="panel" aria-label="Runs" data-testid="runs-list">
        {error ? (
          <EmptyState icon="lock" title="Runs are not available" />
        ) : runs.length === 0 ? (
          <EmptyState icon="branch" title={data ? "No runs in this window" : "Loading runs…"}>
            {data ? "Runs appear once an SDK-instrumented agent reports a run tree." : undefined}
          </EmptyState>
        ) : (
          runs.map((r) => (
            <Link key={r.run_id} href={runPath(r.run_id)} className="row" data-testid="runs-row">
              <Icon name="branch" size={16} />
              <span className="grow" style={{ minWidth: 0, display: "flex", flexDirection: "column", gap: 2 }}>
                <span className="title-sm">{r.agent_name ?? "Run"}</span>
                <span className="caption truncate">
                  {r.agent_id && agents.get(r.agent_id)?.name !== r.agent_name ? `${agents.get(r.agent_id)?.name ?? "Agent"} · ` : ""}
                  {r.model_calls ?? 0} model · {r.tool_calls ?? 0} tool calls
                  {r.handoff_to_agent ? ` · handed off to ${r.handoff_to_agent}` : ""}
                  {r.parent_run_id ? " · child run" : ""}
                </span>
              </span>
              <span className="caption num hide-sm">{runDuration(r.duration_ms)}</span>
              <RunStatusPill status={r.status} />
              <span className="caption">{r.started_at ? <Ago at={r.started_at} /> : null}</span>
              <Icon name="chevronRight" size={14} />
            </Link>
          ))
        )}
      </section>

      {q.cursor || data?.has_more ? (
        <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
          {q.cursor ? (
            <button type="button" className="btn btn-sm" onClick={() => setParams({ cursor: "" })}>
              Newest
            </button>
          ) : null}
          {data?.has_more && data.next_cursor ? (
            <button type="button" className="btn btn-sm" onClick={() => setParams({ cursor: data.next_cursor ?? "" })} data-testid="runs-older">
              Older runs <Icon name="arrowRight" size={13} />
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
