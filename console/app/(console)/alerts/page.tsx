import type { Metadata } from "next";
import type { AgentSummary, Alert, Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { AlertsView } from "@/components/alerts/AlertsView";

export const metadata: Metadata = { title: "Alerts" };

export default async function AlertsPage() {
  const [alerts, agents] = await Promise.all([serverGet<Page<Alert>>("/alerts?limit=200&include_suppressed=true"), serverGet<Page<AgentSummary>>("/agents?limit=200")]);
  return <AlertsView initialAll={alerts.data} initialAgents={agents.data} />;
}
