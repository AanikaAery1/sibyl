import type { Metadata } from "next";
import type { FleetHealth, Page, Provider } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { FleetView } from "@/components/fleet/FleetView";
import type { FleetAgent } from "@/components/fleet/types";

export const metadata: Metadata = { title: "Fleet" };

export default async function FleetPage() {
  const [agents, fleet, providers] = await Promise.all([
    serverGet<Page<FleetAgent>>("/agents?limit=200"),
    serverGet<FleetHealth>("/fleet/health"),
    serverGet<Page<Provider>>("/providers"),
  ]);
  return <FleetView initialAgents={agents.data} initialFleet={fleet.data} initialProviders={providers.data} />;
}
