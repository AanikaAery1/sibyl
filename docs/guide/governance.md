# Governance: audit, export, erasure and holds

**Who this is for:**

- Auditors, the Compliance Auditor persona.
- Admins who handle erasure requests and legal holds.

The routes are under `https://localhost:8443/api/v1`. Every `POST` needs an `Idempotency-Key`.

## The audit chain

Every action in a tenant appends one row to that tenant's audit chain. This covers human actions, API-key actions, rule and policy decisions, and worker steps. A row records:

- `seq`, the position in the chain;
- the action, for example `routing.transition`, `failover.undone`, `killswitch.pulled`, `erasure.approved` or `data.revealed`;
- the actor type (`human`, `api_key`, `rule`, `policy`, `system` or `agent`) and the actor's id, key id and session id;
- the resource;
- the reason;
- a `detail` object.

Rows never hold captured content. The database refuses `detail` keys that could carry it.

Each row is chained to the one before it:

```
hash = sha256(prev_hash ‖ sha256(JCS(envelope)) ‖ sha256(JCS(detail)))
```

JCS is RFC 8785 canonical JSON. The first row's `prev_hash` is 32 zero bytes. Rows are appended under a per-tenant lock and cannot be updated or deleted. Audit data is kept for at least 400 days, and contracts can extend that to 7 years (D27).

```bash
curl -s "$SIBYL/api/v1/audit/events?action=failover.undone&from=2026-10-11T00:00:00Z" -H "Authorization: Bearer $SESSION"
curl -s "$SIBYL/api/v1/audit/events/1042" -H "Authorization: Bearer $SESSION"
```

Filters:

| Filter | Matches |
|---|---|
| `from_seq`, `to_seq` | A sequence range |
| `action` | One action name |
| `actor_type`, `actor_id` | Who acted |
| `resource_type`, `resource_id` | What was acted on |
| `is_evidence` | Evidence-grade rows only |
| `from`, `to` | Recorded time |

An Engineer limited to some agent groups sees only rows about agents in those groups.

## Anchors

An anchor is a signed checkpoint of the chain head. The worker signs it with the audit-anchor Ed25519 key, whose private half is held outside the database. Each anchor is also copied to the BlobStore at `anchors/<tenant>/<id>.json`.

| Kind | When it is written |
|---|---|
| `hourly` | At least every hour, when the chain has grown |
| `export` | At the end of every audit export, before the export file is written |
| `erasure` | When keys are shredded, and when an erasure completes |
| `break_glass` | After a break-glass kill |
| `rekey`, `partition_boundary` | Key rotation and partition retirement |

```bash
curl -s "$SIBYL/api/v1/audit/anchors?kind=hourly" -H "Authorization: Bearer $SESSION"
curl -s "$SIBYL/api/v1/audit/signing-keys" -H "Authorization: Bearer $SESSION"   # public keys, every state
```

The anchors loop runs hourly and at worker start. It also serves export, verification and break-glass requests. Until it wakes on database notifications, those requests wait for its next run. <!-- verify: NOTIFY wake-up for the anchors loop is a change request to INT-1 -->

## Verifying on the server

```bash
curl -s -X POST "$SIBYL/api/v1/audit/verifications" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{"from_seq": 0}'
# {"ok": true, "rows": 2817, "anchors_checked": 3, "first_break_seq": null, "kind": null}
```

The server walks the chain in Postgres and checks the anchor signatures. A range of up to 100,000 rows is verified in the request. A larger range returns `202 {"job_id": ...}`, and the anchors loop runs the same check. Either way the result is recorded as `audit.verified` or `audit.verify_failed`. Verification needs `audit:verify`.

## Exporting and verifying offline

Exporting needs `audit:export`. It is always audited, as `audit.exported` when requested and `audit.export_completed` when done.

```bash
# 1. request a range (at most 1,000,000 rows; format jsonl or csv)
EXPORT=$(curl -s -X POST "$SIBYL/api/v1/audit/exports" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"from_seq": 0, "to_seq": 2816, "format": "jsonl"}' | jq -r .id)

# 2. poll: queued -> done (or failed)
curl -s "$SIBYL/api/v1/audit/exports/$EXPORT" -H "Authorization: Bearer $SESSION" \
  | jq '{state, anchor_id, export_sha256, download_url}'

# 3. download (an auditor's read is audited and needs a reason)
curl -s "$(curl -s "$SIBYL/api/v1/audit/exports/$EXPORT" -H "Authorization: Bearer $SESSION" | jq -r .download_url)" \
  -H "Authorization: Bearer $SESSION" -H "X-Sibyl-Reveal-Reason: Q4 ISO 42001 evidence" -o audit-export.jsonl

# 4. verify with no server access
uv run sibyl audit verify audit-export.jsonl --public-key deploy/compose/env/public/anchor_signing.pem
```

**How an export is written.** The worker first writes an `export` anchor at `to_seq`, or reuses one already there. It then writes the export, sealed under the tenant's payload key. A request that fails three times becomes `state: failed`.

**Formats:**

- `jsonl` is `sibyl.audit_export/1`: a header line, the event rows and the anchor lines. It verifies offline.
- `csv` holds the same columns for spreadsheets. It carries no anchors and cannot be verified.

**What `sibyl audit verify` checks:**

1. Every row recomputes to its stored digests and hash.
2. The rows are contiguous.
3. Each `prev_hash` is the previous row's `hash`.
4. Every anchor is signed by a key in the key set, names this tenant, and matches the row hash at its `seq_to`.
5. The export ends at an anchor.

Exit `0` means the chain verifies. Exit `1` means a break, reported with its `seq` and kind (`gap`, `prev_mismatch`, `content_mismatch`, `hash_mismatch`, `anchor_signature`, `anchor_tenant`, `anchor_mismatch`, `unanchored_tail` or `no_anchor`). Exit `2` means the input could not be read.

A key marked `compromised` never verifies anything.

The anchor public key is written by `deploy/compose/init-env.sh` to `deploy/compose/env/public/anchor_signing.pem`. Keep a copy wherever exports are verified. `GET /audit/signing-keys` returns the same keys as JSON, and the CLI accepts that file directly.

Data exports (`POST /exports`, for payloads rather than the audit log) are cut to Phase 1.5 and answer `501`.

## Retention

| Data | Default | Range |
|---|---|---|
| Payloads (prompts, outputs, checkpoint state, packets) | 30 days | Up to 365 days per tenant, set on the capture policy (D28) |
| Audit chain | 400 days | Up to 7 years by contract (D27) |
| Backups | 7 days | `SIBYL_BACKUP_RETENTION_DAYS`; stated on erasure certificates (D26) |

The retention loop runs hourly. It sweeps expired payloads, except those under an active legal hold, and records one `retention.objects_swept` row for each batch.

When a payload cannot be read, the response says why:

| Response | Cause |
|---|---|
| `404 payload_swept` | Retention removed it |
| `410 payload_shredded` | It was erased |

## Legal holds

A hold freezes retention and blocks erasure for its scope. Placing or releasing one needs `holds:manage` (Admin or Security admin), a fresh step-up and a reason. Both are evidence-grade audit rows (`hold.placed`, `hold.released`). A hold never widens anyone's read access.

```bash
curl -s -X POST "$SIBYL/api/v1/legal-holds" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{
    "scope_kind": "agent", "scope_ref": "'"$AGENT"'",
    "window_from": "2026-09-01T00:00:00Z", "expires_at": "2027-03-31T00:00:00Z",
    "reason": "Litigation hold, matter 2026-114."}'
curl -s "$SIBYL/api/v1/legal-holds?state=active" -H "Authorization: Bearer $SESSION"
curl -s -X POST "$SIBYL/api/v1/legal-holds/$HOLD/release" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{"reason": "Matter 2026-114 settled."}'
```

| `scope_kind` | Needs |
|---|---|
| `tenant` | No `scope_ref` and no `agent_ids` |
| `agent` | `scope_ref` set to the agent id |
| `incident` | `provider_incident_id`. Affected agents come from the incident. The hold may be open-ended and ends with the incident. |
| `subject` | `scope_ref` set to the subject identifier, which is hashed with `SIBYL_SUBJECT_SALT` and never stored, plus the `agent_ids` the operator resolved |

Every hold except an incident hold needs `expires_at` within two years. A mismatched scope is refused with `422 scope_mismatch`. Releasing a hold reopens the erasure requests it blocked; the response lists them in `reopened_erasure_ids`.

## Erasure (crypto-shred, D17)

```bash
# Request (erasure:request: Admin, Workspace admin or Security admin)
curl -s -X POST "$SIBYL/api/v1/erasure-requests" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{
    "scope_kind": "agent", "scope_ref": "'"$AGENT"'",
    "legal_basis": "gdpr_art17", "reason": "Data subject request DSR-0193 covering this agent."}'

# Approve: a different person, erasure:approve (Admin or Security admin), fresh step-up
curl -s -X POST "$SIBYL/api/v1/erasure-requests/$REQ/actions" -H "Authorization: Bearer $OTHER_SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"action": "approve", "reason": "Verified DSR-0193 identity and scope."}'

# Follow it, then fetch the certificate
curl -s "$SIBYL/api/v1/erasure-requests/$REQ" -H "Authorization: Bearer $SESSION" | jq '{state, blocking_hold_ids}'
curl -s "$SIBYL/api/v1/erasure-requests/$REQ/certificate" -H "Authorization: Bearer $SESSION"
```

**Scopes:**

| Scope | Erases |
|---|---|
| `tenant` | The whole tenant |
| `agent` | One agent, named by `scope_ref` |
| `subject` | One data subject, resolved by the operator as `agent_ids` plus a time window |

`legal_basis` is one of `gdpr_art17`, `dpdp_s12`, `contract_end`, `tenant_offboarding`, `other`.

**Safety rules.** The database enforces these as well as the API:

- **Two people.** The approver must not be the requester (`409 self_approval`). Approve and reject need step-up.
- **Tenant scope needs Admins.** Only an Admin may file or approve it, and a second active Admin must exist (`409 second_owner_required`).
- **Holds block.** A request blocked by a hold enters `hold_blocked`, with `blocking_hold_ids`. Approval checks the holds again (`409 hold_blocked`).
- **One request per scope** may be in progress at a time (`409 erasure_in_progress`).
- **Backup agents.** An agent that is the backup in another agent's approved chain cannot be erased until that chain is retired (`409 erasure_blocked_by_chain`).
- **Cancelling.** The requester or an Admin can `cancel` before execution. A second person can `reject`.

**How it runs.** The worker executes an approved request one step at a time, and resumes after a crash:

```
approved → executing → keys_shredded (tenant scope) → objects_deleted → derived_purged → verified → completed
```

The `verified` step requires zero residue: no rows, no objects, and every payload key shredded for a tenant. Completion then happens in this order:

1. A **signed erasure-ledger entry** is written on the worker-only volume.
2. An `erasure` anchor is written.
3. The certificate is stored, with its SHA-256 and the anchor id.

The certificate states when pre-erasure backups expire (`backups_expire_at`, D26). A restore of an older backup replays every ledger entry before the restored database can be opened; see the [backup and restore runbook](../../ops/runbooks/backup-restore.md).

While a tenant-scope erasure runs, ingest answers `429 tenant_erasing`.

Runbook: [erasure request](../../ops/runbooks/erasure-request.md).
