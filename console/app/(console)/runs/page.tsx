import type { Metadata } from "next";
import type { RunSummary } from "@/lib/api/monitor";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { runsPath, runsQueryOf } from "@/lib/runs/tree";
import { RunsView } from "@/components/runs/RunsView";

export const metadata: Metadata = { title: "Runs" };

export default async function RunsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const one = (k: string): string | null => (typeof sp[k] === "string" ? (sp[k] as string) : null);
  const res = await serverGet<Page<RunSummary>>(runsPath(runsQueryOf(one)));
  return <RunsView initial={res.data} />;
}
