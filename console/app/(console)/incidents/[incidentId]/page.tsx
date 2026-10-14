import type { Metadata } from "next";
import { serverGet } from "@/lib/bff/server";
import { IncidentDetail } from "@/components/incident/IncidentDetail";
import type { IncidentView } from "@/components/incident/types";

export const metadata: Metadata = { title: "Incident" };

export default async function IncidentPage({ params }: { params: Promise<{ incidentId: string }> }) {
  const { incidentId } = await params;
  const res = await serverGet<IncidentView>(`/incidents/${encodeURIComponent(incidentId)}`);
  return <IncidentDetail id={incidentId} initial={res.data} />;
}
