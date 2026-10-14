import type { Metadata } from "next";
import type { SentinelConfig } from "@/lib/api/monitor";
import { serverGet } from "@/lib/bff/server";
import { SentinelSettings } from "@/components/sentinel/SentinelSettings";

export const metadata: Metadata = { title: "Sentinel setup" };

export default async function SentinelSettingsPage() {
  const res = await serverGet<SentinelConfig>("/sentinel/config");
  return <SentinelSettings initial={res.data} />;
}
