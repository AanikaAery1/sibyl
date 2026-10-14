import type { Metadata } from "next";
import type { AuditAnchor, AuditEvent, Page } from "@/lib/api/types";
import { auditQuery } from "@/lib/audit-query";
import { serverGet } from "@/lib/bff/server";
import { AuditView } from "@/components/audit/AuditView";

export const metadata: Metadata = { title: "Audit" };

const one = (v: string | string[] | undefined): string | null => (typeof v === "string" ? v : null);

export default async function AuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const { api, family } = auditQuery({
    action: one(sp.action),
    actor_type: one(sp.actor_type),
    resource_id: one(sp.resource_id),
    agent_id: one(sp.agent_id),
    occurred_after: one(sp.occurred_after),
    occurred_before: one(sp.occurred_before),
  });
  const [events, anchors] = await Promise.all([serverGet<Page<AuditEvent>>(`/audit/events?limit=200&${api}`), serverGet<Page<AuditAnchor>>("/audit/anchors?limit=200")]);
  return <AuditView initial={events.data} initialAnchors={anchors.data} query={api} family={family} />;
}
