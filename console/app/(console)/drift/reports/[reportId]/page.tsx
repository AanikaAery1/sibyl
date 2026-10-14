import type { Metadata } from "next";
import type { DriftReport } from "@/lib/api/monitor";
import { serverGet } from "@/lib/bff/server";
import { DriftReportView } from "@/components/drift/DriftReportView";

export const metadata: Metadata = { title: "Drift report" };

export default async function DriftReportPage({ params }: { params: Promise<{ reportId: string }> }) {
  const { reportId } = await params;
  const res = await serverGet<DriftReport>(`/drift/reports/${encodeURIComponent(reportId)}`);
  return <DriftReportView id={reportId} initial={res.data} />;
}
