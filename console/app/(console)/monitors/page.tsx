import type { Metadata } from "next";
import type { Monitor } from "@/lib/api/external-monitors";
import type { Page } from "@/lib/api/types";
import { serverGet } from "@/lib/bff/server";
import { MONITORS_PATH, type StateFilter } from "@/lib/monitors/view";
import { MonitorsView } from "@/components/monitors/MonitorsView";

export const metadata: Metadata = { title: "Monitors" };

const STATES: readonly StateFilter[] = ["active", "paused", "revoked"];

export default async function MonitorsPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const state = STATES.find((x) => x === sp.state) ?? "all";
  const res = await serverGet<Page<Monitor>>(MONITORS_PATH);
  return <MonitorsView initial={res.data} state={state} />;
}
