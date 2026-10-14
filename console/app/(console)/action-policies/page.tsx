import type { Metadata } from "next";
import type { ApiActionPolicy } from "@/lib/api/action-gate";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { policyListPath } from "@/lib/action-gate/paths";
import { PoliciesView } from "@/components/actions/PoliciesView";

export const metadata: Metadata = { title: "Action policies" };

export default async function ActionPoliciesPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const view = (await searchParams).view === "all" ? "all" : "current";
  const res = await serverGet<Page<ApiActionPolicy>>(policyListPath(view));
  return <PoliciesView initial={res.data} view={view} />;
}
