/**
 * Demo scenario control (demo mode only): status, reset, pause/resume and seek.
 * Used by the "Demo data" popover and by the Playwright suites for deterministic states.
 */
import type { NextRequest } from "next/server";
import { ProblemError } from "@/lib/api/problem";
import { assertCsrf, json, problem, readJson } from "@/lib/bff/http";
import { consoleMode } from "@/lib/bff/mode";
import { pauseDemo, resetDemo, resumeDemo, scenarioStatus, seekDemo } from "@/lib/demo/store";

export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  if (consoleMode() !== "demo") return json({ mode: consoleMode() });
  return json({ mode: "demo", ...scenarioStatus() });
}

interface DemoBody {
  action?: "reset" | "pause" | "resume" | "seek";
  t?: number;
  pause?: boolean;
}

export async function POST(req: NextRequest): Promise<Response> {
  try {
    assertCsrf(req);
    if (consoleMode() !== "demo") throw new ProblemError(409, "live_mode", "Demo controls are off", "The console is in live mode.");
    const body = ((await readJson(req)) ?? {}) as DemoBody;
    switch (body.action) {
      case "reset":
        resetDemo();
        break;
      case "pause":
        pauseDemo();
        break;
      case "resume":
        resumeDemo();
        break;
      case "seek":
        if (typeof body.t !== "number" || body.t < 0 || body.t > 7200) throw new ProblemError(422, "validation_failed", "Bad seek", "t is seconds from the scenario start, 0–7200.");
        seekDemo(body.t, body.pause ?? false);
        break;
      default:
        throw new ProblemError(422, "validation_failed", "Unknown action", "Use reset, pause, resume or seek.");
    }
    return json({ mode: "demo", ...scenarioStatus() });
  } catch (err) {
    if (err instanceof ProblemError) return problem(err);
    throw err;
  }
}
