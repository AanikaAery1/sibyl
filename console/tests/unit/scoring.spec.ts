/** Live sibyl-health/1 factor lists carry worker bookkeeping (`_hysteresis`, `_clamp`). */
import { expect, test } from "@playwright/test";
import type { HealthFactor } from "@/lib/api/documents";
import { scoreArithmetic, scoreChecks, splitFactors } from "@/lib/health/scoring";

const f = (rule: string, penalty: number): HealthFactor => ({ rule, penalty, weight: 0.5, value: 1, threshold: 0, direction: "above", explanation: rule });

test("bookkeeping rows and zero penalties are not listed as rules", () => {
  const { rules, clamp } = splitFactors([f("error_rate", 12), f("p95_latency", 0), f("_hysteresis", 0), f("provider_status", 30)]);
  expect(rules.map((r) => r.rule)).toEqual(["provider_status", "error_rate"]);
  expect(clamp).toBe(0);
});

test("the live identity 100 − Σ + clamp = score holds with a stored clamp", () => {
  const { rules, clamp } = splitFactors([f("provider_status", 60), f("error_rate", 50), f("_clamp", 10)]);
  expect(clamp).toBe(10);
  expect(scoreChecks(rules, clamp, 0)).toBe(true);
  expect(scoreChecks(rules, clamp, 5)).toBe(false);
});

test("demo documents (no stored clamp) still check, clamped or not", () => {
  expect(scoreChecks([f("error_rate", 30), f("p95_latency", 12)], 0, 58)).toBe(true);
  expect(scoreChecks([f("error_rate", 60), f("provider_status", 60)], 0, 0)).toBe(true);
});

test("arithmetic text ignores bookkeeping", () => {
  expect(scoreArithmetic([f("error_rate", 30), f("_clamp", 0), f("p95_latency", 12)], 58, "degraded")).toBe("100 − (30 + 12) = 58 → degraded");
});
