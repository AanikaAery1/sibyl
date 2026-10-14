import type { Metadata } from "next";
import type { Monitor } from "@/lib/api/external-monitors";
import { serverGet } from "@/lib/bff/server";
import { monitorPath } from "@/lib/monitors/view";
import { MonitorDetail } from "@/components/monitors/MonitorDetail";

export const metadata: Metadata = { title: "Monitor" };

export default async function MonitorPage({ params }: { params: Promise<{ monitorId: string }> }) {
  const { monitorId } = await params;
  const res = await serverGet<Monitor>(monitorPath(monitorId));
  return <MonitorDetail id={monitorId} initial={res.data} />;
}
