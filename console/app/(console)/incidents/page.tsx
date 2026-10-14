import type { Metadata } from "next";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { IncidentList } from "@/components/incident/IncidentList";
import type { IncidentView } from "@/components/incident/types";

export const metadata: Metadata = { title: "Incidents" };

export default async function IncidentsPage() {
  const res = await serverGet<Page<IncidentView>>("/incidents?limit=100");
  return <IncidentList initial={res.data} />;
}
