"use client";
/**
 * Live mode only: a small purple "Demo data" ribbon on a panel whose data the API cannot serve
 * yet (501, or forced with SIBYL_DEMO_ROUTES). Demo mode does not need it: the toolbar chip
 * already says every screen is demo data.
 */
import { useDemoFallback } from "@/lib/client/sources";
import { useSession } from "@/components/shell/Session";

export function DemoMark({ paths }: { paths: readonly (string | null | undefined)[] }) {
  const s = useSession();
  const on = useDemoFallback(paths);
  if (s.mode !== "live" || !on) return null;
  return (
    <span className="demo-ribbon" title="The control plane does not serve this yet; this panel shows demo data." data-testid="demo-mark">
      Demo data
    </span>
  );
}
