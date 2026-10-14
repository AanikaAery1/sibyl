"use client";
/** Verify the hash chain (POST /audit/verifications) and export it with an anchor (POST /audit/exports). */
import { useEffect, useState } from "react";
import type { AuditExport, VerificationResult } from "@/lib/api/types";
import { bffGet, bffSend } from "@/lib/client/bff";
import { useSession } from "@/components/shell/Session";
import { Icon } from "@/components/ui/Icon";
import { useToast } from "@/components/ui/Toast";
import { shortHash } from "@/lib/format";

export function ChainTools({ headSeq }: { headSeq: number }) {
  const s = useSession();
  const toast = useToast();
  const [result, setResult] = useState<(VerificationResult & { tampered?: boolean; tampered_seq?: number }) | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [exp, setExp] = useState<AuditExport | null>(null);
  const [job, setJob] = useState<string | null>(null);

  useEffect(() => {
    if (!exp || exp.state === "done" || exp.state === "failed") return;
    const id = window.setInterval(() => {
      void bffGet<AuditExport>(`/audit/exports/${exp.id}`).then(setExp).catch(() => undefined);
    }, 900);
    return () => window.clearInterval(id);
  }, [exp]);

  const verify = async (): Promise<void> => {
    setVerifying(true);
    try {
      // Up to 100,000 rows verify inline (200); longer chains run as a job (202 {job_id}).
      const out = await bffSend<VerificationResult | { job_id: string }>("/audit/verifications", {});
      if ("job_id" in out) {
        setResult(null);
        setJob(out.job_id);
      } else {
        setJob(null);
        setResult(out);
      }
    } catch (err) {
      toast.error(err);
    } finally {
      setVerifying(false);
    }
  };
  const tamper = async (): Promise<void> => {
    try {
      const res = await fetch("/api/bff/demo/tamper", { cache: "no-store" });
      const body = (await res.json()) as VerificationResult & { tampered_seq: number };
      setResult({ ...body, tampered: true });
    } catch (err) {
      toast.error(err);
    }
  };
  const startExport = async (): Promise<void> => {
    try {
      setExp(await bffSend<AuditExport>("/audit/exports", { from_seq: 1, to_seq: headSeq, format: "jsonl", include_anchors: true }, { idempotencyKey: crypto.randomUUID() }));
    } catch (err) {
      toast.error(err);
    }
  };

  return (
    <div className="stack">
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {s.can("audit:verify") ? (
          <button type="button" className="btn btn-primary" onClick={() => void verify()} disabled={verifying} data-testid="verify-chain">
            {verifying ? <span className="spinner" aria-hidden /> : <Icon name="shield" size={15} />} Verify chain
          </button>
        ) : null}
        {s.can("audit:export") ? (
          <button type="button" className="btn" onClick={() => void startExport()} disabled={Boolean(exp && exp.state !== "done")} data-testid="export">
            <Icon name="download" size={15} /> Export evidence
          </button>
        ) : null}
      </div>

      {job ? (
        <div className="panel" data-testid="verify-job" aria-live="polite">
          <div className="row">
            <Icon name="clock" size={18} />
            <div className="grow">
              <div style={{ fontWeight: 650 }}>Verification running as a background job</div>
              <div style={{ fontSize: 13 }} className="mono">job {job.slice(0, 8)} · the chain is longer than 100,000 rows</div>
            </div>
          </div>
        </div>
      ) : null}

      {result ? (
        <div className="panel" data-testid="verify-result" aria-live="polite">
          <div className="row" style={{ background: result.ok ? "var(--healthy-tint)" : "var(--failed-tint)", color: result.ok ? "var(--healthy)" : "var(--failed)" }}>
            <Icon name={result.ok ? "check" : "incident"} size={18} />
            <div className="grow">
              <div style={{ fontWeight: 650 }}>{result.ok ? "Chain intact" : `Break at seq ${result.first_break_seq}`}</div>
              <div style={{ fontSize: 13 }} className="num">
                {result.tampered ? `A copy with one byte changed at seq ${result.tampered_seq} was verified: the hash no longer matches, so every later row is untrusted.` : `${result.rows} rows recomputed · ${result.anchors_checked} signed anchors match · no gaps`}
              </div>
            </div>
          </div>
          {s.mode === "demo" && !result.tampered && result.ok ? (
            <div className="row">
              <span className="muted grow">See what tampering looks like: verify a copy with one edited byte.</span>
              <button type="button" className="btn btn-sm" onClick={() => void tamper()} data-testid="tamper">
                Verify a tampered copy
              </button>
            </div>
          ) : null}
        </div>
      ) : null}

      {exp ? (
        <div className="panel" data-testid="export-job">
          <div className="row">
            <Icon name={exp.state === "done" ? "check" : "clock"} size={16} />
            <div className="grow">
              <div className="title-sm">{exp.state === "done" ? "Export ready" : exp.state === "failed" ? "Export failed" : exp.state === "running" ? "Writing export anchor, then the file…" : "Queued"}</div>
              <div className="muted num">
                seq {exp.from_seq}–{exp.to_seq} · JSONL{exp.export_sha256 ? ` · sha256 ${shortHash(exp.export_sha256, 12)}` : ""}
              </div>
            </div>
            {exp.state === "done" && exp.download_url ? (
              <a className="btn btn-sm btn-primary" href={`/api/bff/audit/exports/${encodeURIComponent(exp.id)}/download`} download data-testid="download">
                <Icon name="download" size={14} /> Download
              </a>
            ) : exp.state === "failed" ? null : (
              <span className="spinner" aria-label="Working" style={{ color: "var(--text-3)" }} />
            )}
          </div>
          {exp.state === "done" ? (
            <div className="panel-pad" style={{ paddingTop: 0 }}>
              <div className="caption" style={{ marginBottom: 6 }}>
                Verify offline, without trusting the database
              </div>
              <pre className="code" tabIndex={0}>{`sibyl audit verify sibyl-audit-${s.tenant}-${exp.from_seq}-${exp.to_seq}.jsonl \\
  --anchor anchor.json --public-key sibyl-audit.pub
# chain ok: ${exp.to_seq - exp.from_seq + 1} events, export anchor ${exp.anchor_id?.slice(0, 8) ?? "…"}, signature valid, no gaps`}</pre>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
