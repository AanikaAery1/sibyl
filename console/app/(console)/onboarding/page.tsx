import type { Metadata } from "next";
import type { AgentSummary, CapturePolicy, Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { OnboardingView } from "@/components/settings/OnboardingView";

export const metadata: Metadata = { title: "Onboarding" };

export default async function OnboardingPage() {
  const [policies, agents] = await Promise.all([serverGet<Page<CapturePolicy>>("/capture-policies"), serverGet<Page<AgentSummary>>("/agents?limit=50")]);
  return <OnboardingView initialPolicies={policies.data} initialAgents={agents.data} />;
}
