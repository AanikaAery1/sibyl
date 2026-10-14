"use client";
/** An agent's recent top-level runs (`GET /runs?agent_id=…&root_only=true`), each linking to its run tree. */
import Link from "next/link";
import type { RunSummary } from "@/lib/api/monitor";
import type { Page } from "@/lib/api/types";
import { useBff } from "@/hooks/useBff";
import { recentRunsPath, runPath } from "@/lib/runs/tree";
import { RunStatusPill, runDuration } from "./RunBits";
import { Icon } from "@/components/ui/Icon";
import { Ago } from "@/components/ui/Time";

export function RecentRuns({ agentId }: { agentId: string }) {
  const { data, error } = useBff<Page<RunSummary>>(recentRunsPath(agentId));
  const runs = data?.data ?? [];
  if (error || runs.length === 0) return null;
  return (
    <section className="section" aria-labelledby="runs-title" data-testid="recent-runs">
      <div className="section-title">
        <h2 id="runs-title">Recent runs</h2>
        <span className="meta">
          <Link href={`/runs?agent_id=${agentId}`} data-testid="all-runs">
            All runs
          </Link>
        </span>
      </div>
      <div className="panel">
        {runs.map((r) => (
          <Link key={r.run_id} href={runPath(r.run_id)} className="row" data-testid="run-row">
            <Icon name="branch" size={16} />
            <span className="grow title-sm" style={{ fontWeight: 550 }}>
              {r.agent_name ?? "Run"}
            </span>
            <span className="caption num hide-sm">{runDuration(r.duration_ms)}</span>
            <RunStatusPill status={r.status} />
            <span className="caption">{r.started_at ? <Ago at={r.started_at} /> : null}</span>
            <Icon name="chevronRight" size={14} />
          </Link>
        ))}
      </div>
    </section>
  );
}
