/**
 * Plug-and-play onboarding snippets (D50): one line (`sibyl.instrument()`), zero code
 * (`sibyl-run app.py`), and the gateway base-URL option for the three native model protocols.
 * Pure and unit-tested; the snippets mirror packages/sibyl-sdk/README.md.
 */

export type FrameworkId = "openai" | "anthropic" | "gemini" | "langchain" | "openai-agents" | "crewai";
export type InstrumentMode = "one-line" | "zero-code" | "gateway";

export interface Framework {
  id: FrameworkId;
  label: string;
  extra: string;
  /** The gateway speaks this protocol natively (B25: same-protocol only). */
  gateway: boolean;
  usage: string;
  note: string;
}

export const FRAMEWORKS: readonly Framework[] = [
  { id: "openai", label: "OpenAI", extra: "openai", gateway: true, usage: 'client = openai.OpenAI()\nclient.chat.completions.create(model="gpt-5-mini", messages=[...])', note: "Captures the served model, system_fingerprint, refusals and proposed tool calls." },
  { id: "anthropic", label: "Anthropic", extra: "anthropic", gateway: true, usage: 'anthropic.Anthropic().messages.create(model="claude-sonnet-4-5", max_tokens=512, messages=[...])', note: "Captures stop_reason (including refusal) and tool_use blocks, sync, async and streaming." },
  { id: "gemini", label: "Gemini", extra: "google", gateway: true, usage: 'genai.Client().models.generate_content(model="gemini-2.5-flash", contents="...")', note: "Safety blocks are recorded as refusals; MAX_TOKENS as the length finish reason." },
  { id: "langchain", label: "LangChain / LangGraph", extra: "langchain", gateway: false, usage: 'graph.invoke({"messages": [...]})  # no callbacks= needed', note: "The outer graph is a run, each node a child run; transfer_to_<agent> tools record handoffs." },
  { id: "openai-agents", label: "OpenAI Agents SDK", extra: "openai-agents", gateway: false, usage: "from agents import Agent, Runner, function_tool  # after instrument()", note: "Each agent is a child run, function spans are tool calls, handoff spans record the target agent." },
  { id: "crewai", label: "CrewAI", extra: "crewai", gateway: false, usage: "crew.kickoff()", note: "The crew is a run, each agent a child run; delegation tools record the coworker as the handoff." },
];

const IMPORTS: Readonly<Record<FrameworkId, string>> = {
  openai: "import sibyl, openai",
  anthropic: "import sibyl, anthropic",
  gemini: "import sibyl\nfrom google import genai",
  langchain: "import sibyl",
  "openai-agents": "import sibyl",
  crewai: "import sibyl",
};

export interface SnippetEnv {
  /** Ingest endpoint (SIBYL_ENDPOINT). */
  endpoint: string;
  /** Gateway origin, e.g. https://sibyl.example:8444 */
  gateway: string;
  /** Shown key prefix only; secrets are never rendered back. */
  keyHint: string;
  agent: string;
}

export function frameworkById(id: string | null | undefined): Framework {
  return FRAMEWORKS.find((f) => f.id === id) ?? (FRAMEWORKS[0] as Framework);
}

/** Modes a framework offers: frameworks ride on a model client, so no gateway tab. */
export function modesFor(f: Framework): InstrumentMode[] {
  return f.gateway ? ["one-line", "zero-code", "gateway"] : ["one-line", "zero-code"];
}

function envBlock(env: SnippetEnv): string {
  return [`export SIBYL_API_KEY="${env.keyHint}"`, `export SIBYL_ENDPOINT="${env.endpoint}"`, `export SIBYL_AGENT_ID="${env.agent}"`].join("\n");
}

function gatewaySnippet(id: FrameworkId, env: SnippetEnv): string {
  const header = `{"X-Sibyl-Agent": "${env.agent}"}`;
  if (id === "anthropic") {
    return `import anthropic\n\nclient = anthropic.Anthropic(\n    base_url="${env.gateway}",        # the Sibyl gateway (native Messages API)\n    api_key="${env.keyHint}",          # your Sibyl key, not the provider key\n    default_headers=${header},\n)`;
  }
  if (id === "gemini") {
    return `from google import genai\n\nclient = genai.Client(\n    api_key="${env.keyHint}",          # your Sibyl key, not the provider key\n    http_options={"base_url": "${env.gateway}", "headers": ${header}},\n)`;
  }
  return `from openai import OpenAI\n\nclient = OpenAI(\n    base_url="${env.gateway}/v1",     # the Sibyl gateway\n    api_key="${env.keyHint}",          # your Sibyl key, not the provider key\n    default_headers=${header},\n)`;
}

export function snippetFor(id: FrameworkId, mode: InstrumentMode, env: SnippetEnv): { install: string; code: string; language: "python" | "shell" } {
  const f = frameworkById(id);
  const install = `pip install "sibyl-sdk[${f.extra}]"`;
  if (mode === "gateway") {
    if (!f.gateway) throw new Error(`${f.label} has no gateway option; instrument the model client instead`);
    return { install: "# no install: change the base URL, the key and one header", code: gatewaySnippet(id, env), language: "python" };
  }
  if (mode === "zero-code") {
    return { install, code: `${envBlock(env)}\n\nsibyl-run app.py --your --args      # your app, unchanged`, language: "shell" };
  }
  return { install, code: `${IMPORTS[id]}\n\nsibyl.instrument()  # reads SIBYL_*, instruments every installed client and framework\n\n${f.usage}`, language: "python" };
}

/** Discovered agents (lifecycle `discovered`); callers filter too, so a stale or unfiltered page cannot leak others. */
export const DISCOVERED_PATH = "/agents?lifecycle=discovered&limit=200";

export function discoveredOnly<T extends { lifecycle: string }>(rows: readonly T[]): T[] {
  return rows.filter((a) => a.lifecycle === "discovered");
}
