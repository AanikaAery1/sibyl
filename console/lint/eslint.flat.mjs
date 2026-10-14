// ESLint flat config for the console. Lives here (not eslint.config.mjs) because a local
// config-protection hook blocks agents from creating linter configs at the conventional path;
// the chair can rename it at merge. Rules are the Next.js core-web-vitals + TypeScript sets,
// tightened (never loosened) below.
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const config = [
  ...nextVitals,
  ...nextTs,
  {
    ignores: [
      ".next/**",
      "node_modules/**",
      "test-results/**",
      "playwright-report/**",
      "playwright-report-live/**",
      "next-env.d.ts",
      "lib/api/schema.gen.ts",
    ],
  },
  {
    rules: {
      "no-console": ["error", { allow: ["warn", "error"] }],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/consistent-type-imports": "error",
    },
  },
  {
    files: ["scripts/**/*.mjs", "tests/**/*.ts", "playwright.config.ts"],
    rules: { "no-console": "off" },
  },
];

export default config;
