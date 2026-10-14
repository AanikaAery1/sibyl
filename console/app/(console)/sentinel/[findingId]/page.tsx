import type { Metadata } from "next";
import type { Finding } from "@/lib/api/external-monitors";
import { serverGet } from "@/lib/bff/server";
import { findingPath } from "@/lib/monitors/view";
import { FindingDetail } from "@/components/sentinel/FindingDetail";

export const metadata: Metadata = { title: "Finding" };

export default async function FindingPage({ params }: { params: Promise<{ findingId: string }> }) {
  const { findingId } = await params;
  const res = await serverGet<Finding>(findingPath(findingId));
  return <FindingDetail id={findingId} initial={res.data} />;
}
