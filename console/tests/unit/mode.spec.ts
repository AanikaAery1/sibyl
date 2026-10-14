/** Console mode fails closed in production (lib/bff/mode.ts). */
import { expect, test } from "@playwright/test";
import { consoleMode } from "@/lib/bff/mode";

function withEnv(env: Record<string, string | undefined>, fn: () => void): void {
  const saved = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  const set = (k: string, v: string | undefined): void => {
    if (v === undefined) delete process.env[k];
    else (process.env as Record<string, string>)[k] = v;
  };
  try {
    for (const [k, v] of Object.entries(env)) set(k, v);
    fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) set(k, v);
  }
}

test("explicit modes win", () => {
  withEnv({ SIBYL_CONSOLE_MODE: "demo", NODE_ENV: "production" }, () => expect(consoleMode()).toBe("demo"));
  withEnv({ SIBYL_CONSOLE_MODE: "LIVE", NODE_ENV: "development" }, () => expect(consoleMode()).toBe("live"));
});

test("missing or misspelled: live in production, demo in development", () => {
  withEnv({ SIBYL_CONSOLE_MODE: undefined, NODE_ENV: "production" }, () => expect(consoleMode()).toBe("live"));
  withEnv({ SIBYL_CONSOLE_MODE: "lvie", NODE_ENV: "production" }, () => expect(consoleMode()).toBe("live"));
  withEnv({ SIBYL_CONSOLE_MODE: undefined, NODE_ENV: "development" }, () => expect(consoleMode()).toBe("demo"));
});
