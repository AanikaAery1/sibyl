import type { Metadata } from "next";
import { agentPaths } from "@/lib/agent-data";
import { consoleMode, wallClock } from "@/lib/bff/mode";
import { serverGet } from "@/lib/bff/server";
import { AgentDetail, type AgentInitial } from "@/components/agent/AgentDetail";

export const metadata: Metadata = { title: "Agent" };

export default async function AgentPage({ params }: { params: Promise<{ agentId: string }> }) {
  const { agentId } = await params;
  const p = agentPaths(agentId, consoleMode(), wallClock());
  const [agent, health, routing, plan, chains, metrics, history, transitions, alerts, incidents, providers] = await Promise.all([
    serverGet<AgentInitial["agent"]>(p.base),
    serverGet<AgentInitial["health"]>(p.health),
    serverGet<AgentInitial["routing"]>(p.routing),
    serverGet<AgentInitial["plan"]>(p.plan),
    serverGet<AgentInitial["chains"]>(p.chains),
    serverGet<AgentInitial["metrics"]>(p.metrics),
    serverGet<AgentInitial["history"]>(p.history),
    serverGet<AgentInitial["transitions"]>(p.transitions),
    serverGet<AgentInitial["alerts"]>(p.alerts),
    serverGet<AgentInitial["incidents"]>(p.incidents),
    serverGet<AgentInitial["providers"]>("/providers?limit=200"),
  ]);
  const initial: AgentInitial = {
    agent: agent.data,
    health: health.data,
    routing: routing.data,
    plan: plan.data,
    chains: chains.data,
    metrics: metrics.data,
    history: history.data,
    transitions: transitions.data,
    alerts: alerts.data,
    incidents: incidents.data,
    providers: providers.data,
  };
  return <AgentDetail id={agentId} initial={initial} />;
}
