"use client";
/** Client providers for the console: SWR, toasts, session, live events, timezone, clock seed. */
import { useState, type ReactNode } from "react";
import { SWRConfig } from "swr";
import type { FleetHealth } from "@/lib/api/types";
import { seedServerNow } from "@/lib/client/sources";
import { LiveProvider } from "@/components/live/LiveProvider";
import { TzProvider } from "@/components/ui/Time";
import { ToastProvider } from "@/components/ui/Toast";
import { AppShell } from "./AppShell";
import { SessionProvider, type SessionInfo } from "./Session";

interface ClientRootProps {
  session: SessionInfo;
  fleet: FleetHealth | null;
  tz: string;
  serverNow: number;
  paused: boolean;
  children: ReactNode;
}

export function ClientRoot({ session, fleet, tz, serverNow, paused, children }: ClientRootProps) {
  // Seed the shared clock once, during the first render, so relative times hydrate close.
  useState(() => {
    seedServerNow(serverNow, paused);
    return true;
  });
  return (
    <SWRConfig value={{ errorRetryCount: 2 }}>
      <TzProvider tz={tz}>
        <ToastProvider>
          <SessionProvider info={session}>
            <LiveProvider tenant={session.tenant}>
              <AppShell fleet={fleet}>{children}</AppShell>
            </LiveProvider>
          </SessionProvider>
        </ToastProvider>
      </TzProvider>
    </SWRConfig>
  );
}
