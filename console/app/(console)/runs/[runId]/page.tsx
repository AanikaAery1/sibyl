import type { Metadata } from "next";
import type { RunDetail } from "@/lib/api/monitor";
import { serverGet } from "@/lib/bff/server";
import { runPath } from "@/lib/runs/tree";
import { RunTreeView } from "@/components/runs/RunTreeView";

export const metadata: Metadata = { title: "Run tree" };

export default async function RunTreePage({ params }: { params: Promise<{ runId: string }> }) {
  const { runId } = await params;
  const res = await serverGet<RunDetail>(runPath(encodeURIComponent(runId)));
  return <RunTreeView runId={runId} initial={res.data} />;
}
