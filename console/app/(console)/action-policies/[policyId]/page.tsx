import type { Metadata } from "next";
import type { ApiActionPolicy } from "@/lib/api/action-gate";
import { serverGet } from "@/lib/bff/server";
import { PolicyDetail } from "@/components/actions/PolicyDetail";

export const metadata: Metadata = { title: "Action policy" };

export default async function ActionPolicyPage({ params }: { params: Promise<{ policyId: string }> }) {
  const { policyId } = await params;
  const res = await serverGet<ApiActionPolicy>(`/action-policies/${encodeURIComponent(policyId)}`);
  return <PolicyDetail id={policyId} initial={res.data} />;
}
