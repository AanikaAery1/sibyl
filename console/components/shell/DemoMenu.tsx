"use client";
/**
 * "Demo data" chip: makes the data mode unmistakable and drives the scripted scenario
 * (replay, pause/resume). In live mode it lists routes still served by the demo fallback.
 */
import useSWR from "swr";
import { usePopover } from "@/hooks/usePopover";
import { consolePost } from "@/lib/client/bff";
import { setClockPaused, useFallbackRoutes } from "@/lib/client/sources";
import { formatStopwatch } from "@/lib/format";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { useSWRConfig } from "swr";
import { useSession } from "./Session";

interface DemoStatus {
  mode: "demo" | "live";
  elapsed_s?: number;
  paused?: boolean;
  now?: string;
  beats?: { id: string; at_s: number; label: string; done: boolean }[];
}

const fetchStatus = async (): Promise<DemoStatus> => (await fetch("/api/bff/demo", { cache: "no-store" })).json() as Promise<DemoStatus>;

export function DemoMenu() {
  const s = useSession();
  const { open: popOpen, toggle: popToggle, rootRef, triggerRef } = usePopover();
  const toast = useToast();
  const { mutate } = useSWRConfig();
  const fallbacks = useFallbackRoutes();
  const { data, mutate: refresh } = useSWR<DemoStatus>("demo-status", fetchStatus, { refreshInterval: popOpen ? 1000 : 10_000 });

  if (s.mode === "live") {
    return (
      <span className="glass-chip" title={fallbacks.length ? `Demo fallback: ${fallbacks.join(", ")}` : "All routes served by the API"}>
        <Icon name="link" size={15} />
        Live API{fallbacks.length ? ` · ${fallbacks.length} on demo` : ""}
      </span>
    );
  }

  const control = async (body: Record<string, unknown>, msg: string): Promise<void> => {
    try {
      const next = await consolePost<DemoStatus>("/demo", body);
      setClockPaused(next.paused && next.now ? Date.parse(next.now) : null);
      await refresh(next, { revalidate: false });
      await mutate(() => true);
      toast.success(msg);
    } catch (err) {
      toast.error(err);
    }
  };

  const next = data?.beats?.find((b) => !b.done);
  return (
    <div ref={rootRef} style={{ position: "relative" }}>
      <button ref={triggerRef} type="button" className="glass-chip" aria-haspopup="dialog" aria-expanded={popOpen} onClick={popToggle} data-testid="demo-chip">
        <span className="demo-ribbon">Demo data</span>
        <span className="num hide-md" suppressHydrationWarning>
          {data?.elapsed_s !== undefined ? formatStopwatch(data.elapsed_s) : "—"}
        </span>
      </button>
      <div className="popover" data-open={popOpen} role="dialog" aria-label="Demo scenario" style={{ right: 0, top: "calc(100% + 8px)", width: 360 }}>
        <div style={{ padding: "8px 10px 6px" }}>
          <div className="title-sm">Scripted scenario · Meridian</div>
          <p className="muted" style={{ marginTop: 4 }}>
            Fixtures follow the frozen OpenAPI contract. Nothing here touches a real provider. {data?.paused ? "Paused." : next ? `Next: ${next.label}.` : "All beats played."}
          </p>
        </div>
        <ol style={{ maxHeight: 280, overflowY: "auto", padding: "4px 4px 6px" }}>
          {(data?.beats ?? []).map((b) => (
            <li key={b.id} className="menu-item" style={{ minHeight: 34, cursor: "default", color: b.done ? "var(--text)" : "var(--text-3)" }}>
              <span className="num caption" style={{ width: 40 }}>
                {formatStopwatch(b.at_s)}
              </span>
              <span className="grow" style={{ fontSize: 13 }}>
                {b.label}
              </span>
              {b.done ? <Icon name="check" size={14} style={{ color: "var(--healthy-dot)" }} /> : null}
            </li>
          ))}
        </ol>
        <div className="menu-sep" />
        <div style={{ display: "flex", gap: 8, padding: "6px 8px 8px" }}>
          <button type="button" className="btn btn-sm" onClick={() => void control({ action: "reset" }, "Scenario restarted")} data-testid="demo-replay">
            <Icon name="replay" size={14} /> Replay
          </button>
          {data?.paused ? (
            <button type="button" className="btn btn-sm" onClick={() => void control({ action: "resume" }, "Scenario resumed")}>
              <Icon name="play" size={14} /> Resume
            </button>
          ) : (
            <button type="button" className="btn btn-sm" onClick={() => void control({ action: "pause" }, "Scenario paused")}>
              <Icon name="pause" size={14} /> Pause
            </button>
          )}
          <button type="button" className="btn btn-sm" onClick={() => void control({ action: "seek", t: 70 }, "Jumped to the failover")}>
            Skip to failover
          </button>
        </div>
      </div>
    </div>
  );
}
