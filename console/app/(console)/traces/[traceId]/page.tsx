import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";
import type { Trace } from "@/lib/api/monitor";
import { serverGet } from "@/lib/bff/server";
import { rootRunsOf, runPath } from "@/lib/runs/tree";
import { EmptyState } from "@/components/ui/Bits";

export const metadata: Metadata = { title: "Trace" };

/**
 * A trace link (e.g. a discovered agent's `first_trace_id`) lands on the run tree of the trace's
 * top-level run. The trace read only resolves the run id; the tree itself comes from `/runs`.
 */
export default async function TracePage({ params }: { params: Promise<{ traceId: string }> }) {
  const { traceId } = await params;
  const res = await serverGet<Trace>(`/traces/${encodeURIComponent(traceId)}`);
  const roots = rootRunsOf(res.data?.spans ?? []);
  if (roots.length === 1 && roots[0]) redirect(runPath(roots[0]));
  return (
    <div className="page">
      <header className="page-head">
        <div style={{ minWidth: 0 }}>
          <h1 className="large-title">Trace</h1>
          <p className="caption mono" style={{ overflowWrap: "anywhere" }}>
            trace {traceId}
          </p>
        </div>
      </header>
      <section className="panel" aria-label="Runs in this trace">
        {roots.length === 0 ? (
          <EmptyState icon="search" title="No runs in this trace">
            {res.status === 403 ? "Your role cannot read this trace." : "No run telemetry for this trace in your workspace (it may be past retention)."}
          </EmptyState>
        ) : (
          roots.map((id) => (
            <Link key={id} href={runPath(id)} className="row" data-testid="trace-run">
              <span className="grow mono">run {id}</span>
            </Link>
          ))
        )}
      </section>
    </div>
  );
}
