import type { Metadata } from "next";
import type { ApiActionPolicy } from "@/lib/api/action-gate";
import { serverGet } from "@/lib/bff/server";
import { toPolicy } from "@/lib/action-gate/wire";
import { PolicyEditor } from "@/components/actions/PolicyEditor";

export const metadata: Metadata = { title: "Edit action policy" };

export default async function NewActionPolicyPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const from = (await searchParams).from;
  const res = typeof from === "string" ? await serverGet<ApiActionPolicy>(`/action-policies/${encodeURIComponent(from)}`) : null;
  return <PolicyEditor key={typeof from === "string" ? from : "new"} from={res?.data ? toPolicy(res.data) : null} />;
}
