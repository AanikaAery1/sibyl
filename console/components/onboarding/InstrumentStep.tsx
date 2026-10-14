"use client";
/**
 * "Instrument your agents" (D50): one line (`sibyl.instrument()`), zero code (`sibyl-run app.py`)
 * or, for the three native model protocols, the gateway base URL. Tabs per framework; the
 * selection lives in the URL so a link to a snippet is shareable.
 */
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";
import { FRAMEWORKS, frameworkById, modesFor, snippetFor, type InstrumentMode } from "@/lib/onboarding/instrument";
import { Icon } from "@/components/ui/Icon";

const MODE_LABEL: Readonly<Record<InstrumentMode, string>> = { "one-line": "One line", "zero-code": "Zero code", gateway: "Gateway" };
const MODE_HELP: Readonly<Record<InstrumentMode, string>> = {
  "one-line": "Add one call at the top of your entry point. Every installed client and framework is instrumented; libraries that are not installed are skipped.",
  "zero-code": "Run the app unchanged under sibyl-run. A configuration problem is printed to stderr (never the key) and the app still starts.",
  gateway: "No SDK: point the client at the Sibyl gateway. It speaks this provider's native protocol; fallbacks stay on the same protocol.",
};

export function InstrumentStep({ keyHint, gateway, endpoint }: { keyHint: string; gateway: string; endpoint: string }) {
  const router = useRouter();
  const params = useSearchParams();
  const framework = frameworkById(params.get("framework"));
  const modes = modesFor(framework);
  const want = params.get("mode") as InstrumentMode | null;
  const mode: InstrumentMode = want && modes.includes(want) ? want : "one-line";
  const [copied, setCopied] = useState(false);
  const snip = snippetFor(framework.id, mode, { endpoint, gateway, keyHint, agent: "quote-worker" });

  const setParam = (k: string, v: string): void => {
    const next = new URLSearchParams(params.toString());
    next.set(k, v);
    router.replace(`${window.location.pathname}?${next}`, { scroll: false });
  };

  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(snip.code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="stack" style={{ gap: 14 }} data-testid="instrument">
      <p className="muted">Multi-agent systems report a run tree: parent runs, handoffs between agents and every step. Agents Sibyl has not seen register as discovered and are never routed or failed over until you confirm them (the Action Gate and kill switch still apply).</p>
      <div className="seg" role="tablist" aria-label="Framework">
        {FRAMEWORKS.map((f) => (
          <button key={f.id} type="button" role="tab" aria-selected={framework.id === f.id} onClick={() => setParam("framework", f.id)} data-testid={`fw-${f.id}`}>
            {f.label}
          </button>
        ))}
      </div>
      <div className="snippet-tabs">
        <div className="seg" role="tablist" aria-label="How">
          {modes.map((m) => (
            <button key={m} type="button" role="tab" aria-selected={mode === m} onClick={() => setParam("mode", m)} data-testid={`mode-${m}`}>
              <Icon name={m === "gateway" ? "route" : m === "zero-code" ? "terminal" : "sparkle"} size={13} /> {MODE_LABEL[m]}
            </button>
          ))}
        </div>
        <span className="caption">{MODE_HELP[mode]}</span>
      </div>
      <pre className="code" tabIndex={0} aria-label="Install command">
        {snip.install}
      </pre>
      <div className="snippet">
        <pre className="code" tabIndex={0} aria-label={`${framework.label} ${MODE_LABEL[mode]} snippet`} data-testid="instrument-snippet">
          {snip.code}
        </pre>
        <button type="button" className="btn btn-sm copy" onClick={() => void copy()} aria-live="polite">
          <Icon name={copied ? "check" : "copy"} size={13} /> {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <p className="caption">{framework.note} Prompts and outputs leave the process only in full or redacted capture, after the secrets scrub; metadata-only sends hashes.</p>
    </div>
  );
}
