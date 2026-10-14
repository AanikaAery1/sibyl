/**
 * A console-side subset of the PII and secret detectors (`sibyl_schemas.pii`, `sibyl_schemas.scrub`)
 * for the Action Gate's data-class rules in demo mode and in the editor's draft preview. The
 * patterns follow the Python registry; validators are simplified (Luhn kept, IBAN mod-97 and
 * Aadhaar Verhoeff omitted). The control plane remains the authority for real decisions.
 */
import type { PiiId } from "@/lib/api/action-gate";

const PATTERNS: Readonly<Record<PiiId, RegExp>> = {
  email: /(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b/g,
  phone: /(?<![\w+])(?:\+\d{1,3}[ .-]?\d{2,5}(?:[ .-]?\d{2,5}){1,3}|\(\d{3}\)[ .-]?\d{3}[ .-]\d{4}|\d{3}[ .-]\d{3}[ .-]\d{4})(?!\w)/g,
  credit_card: /(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d-])/g,
  iban: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
  ip_address: /(?<![\w.:])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})(?![\w.:])/g,
  national_id: /(?<![\w-])(?:\d{3}-\d{2}-\d{4}|[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]|\d{4} \d{4} \d{4}|\d{12}|[A-Z]{5}\d{4}[A-Z])(?![\w-])/g,
  postal_address: /\b\d{1,5}[A-Za-z]? (?:[A-Z][a-z]{1,20} ){1,4}(?:Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Drive|Dr|Marg|Nagar)\b\.?|\b(?:[A-Z]{1,2}\d[A-Z\d]?|GIR) ?\d[ABD-HJLNP-UW-Z]{2}\b/g,
};

function luhn(text: string): boolean {
  const digits = text.replace(/\D/g, "");
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

function phoneOk(text: string): boolean {
  const n = text.replace(/\D/g, "").length;
  return n >= 8 && n <= 15;
}

function ipOk(text: string): boolean {
  if (text.includes(":")) return true;
  return text.split(".").every((o) => Number(o) <= 255);
}

const VALIDATORS: Partial<Record<PiiId, (s: string) => boolean>> = { credit_card: luhn, phone: phoneOk, ip_address: ipOk };

export interface PiiHit {
  detector: PiiId;
  value: string;
}

export function findPii(text: string, detectors: readonly PiiId[]): PiiHit[] {
  const out: PiiHit[] = [];
  for (const id of detectors) {
    for (const m of text.matchAll(PATTERNS[id])) {
      const ok = VALIDATORS[id];
      if (!ok || ok(m[0])) out.push({ detector: id, value: m[0] });
    }
  }
  return out;
}

/** `[KIND:hash8]`, the scrubber's replacement (`REPLACEMENT_FORMAT`). */
export const SCRUBBED_RE = /\[(?:SECRET|TOKEN|PRIVATE_KEY|ENTROPY):[0-9a-f]{8}\]/g;

const SECRET_RES: readonly RegExp[] = [
  /\[(?:SECRET|TOKEN|PRIVATE_KEY|ENTROPY):[0-9a-f]{8}\]/,
  /\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /\bsibyl_(?:live|test)_[A-Za-z0-9]{20,}/,
];

/** A value the scrubber would treat as a secret (or that it already replaced). */
export function looksSecret(text: string): boolean {
  return SECRET_RES.some((re) => re.test(text));
}
