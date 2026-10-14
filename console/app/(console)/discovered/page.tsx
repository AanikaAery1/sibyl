import type { Metadata } from "next";
import type { AgentSummary, Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { DISCOVERED_PATH } from "@/lib/onboarding/instrument";
import { DiscoveredAgents } from "@/components/onboarding/DiscoveredAgents";

export const metadata: Metadata = { title: "Discovered agents" };

export default async function DiscoveredPage() {
  const res = await serverGet<Page<AgentSummary>>(DISCOVERED_PATH);
  return (
    <div className="page" style={{ maxWidth: 980 }}>
      <header>
        <div className="eyebrow">Set up · auto-discovery</div>
        <h1 className="large-title">Discovered agents</h1>
        <p className="lede">Agents Sibyl found in telemetry. Confirm the ones you own; until then they are watched and policy-checked, but never routed or failed over.</p>
      </header>
      <DiscoveredAgents initial={res.data} />
    </div>
  );
}
