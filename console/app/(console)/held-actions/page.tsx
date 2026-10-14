import type { Metadata } from "next";
import type { ApiHeldAction } from "@/lib/api/action-gate";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { heldListPath } from "@/lib/action-gate/paths";
import { HeldActionsView } from "@/components/actions/HeldActionsView";

export const metadata: Metadata = { title: "Held actions" };

export default async function HeldActionsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const view = sp.view === "decided" || sp.view === "all" ? sp.view : "waiting";
  const res = await serverGet<Page<ApiHeldAction>>(heldListPath(view));
  return <HeldActionsView initial={res.data} view={view} />;
}
