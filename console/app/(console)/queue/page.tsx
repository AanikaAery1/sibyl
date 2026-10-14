import type { Metadata } from "next";
import type { HandoffTaskSummary, Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { QueueView } from "@/components/queue/QueueView";

export const metadata: Metadata = { title: "Operator queue" };

export default async function QueuePage() {
  const res = await serverGet<Page<HandoffTaskSummary> & { x_console?: { completed_despite_failure: number } }>("/queue?limit=100");
  return <QueueView initial={res.data} />;
}
