# Runbook: erasure request

**Use when:** a data subject, a customer or a contract end requires data to be erased (D17). Sibyl erases by crypto-shredding: it destroys the keys, deletes the objects and purges the derived rows. It then proves the erasure with a signed ledger entry, an anchor and a certificate.

**Roles:** two different people, both with a fresh step-up.

| Step | Who |
|---|---|
| File the request | An Admin, Workspace admin or Security admin (`erasure:request`) |
| Approve it | A **different** Admin or Security admin (`erasure:approve`) |
| Tenant scope | Only Admins may file or approve, and the tenant must have a second active Admin |

**Sources:** D17, D26, G0-7, R63; [governance guide](../../docs/guide/governance.md#erasure-crypto-shred-d17).

## 1. Check the request before filing

1. **Identity and legal basis.** Record the requester's identity check and the basis: `gdpr_art17`, `dpdp_s12`, `contract_end`, `tenant_offboarding` or `other`. Put the external reference in the reason.
2. **Scope.**
    - `agent` takes the agent id.
    - `subject` takes the subject identifier plus the `agent_ids` and time window that may hold that subject's data. Sibyl hashes the identifier with `SIBYL_SUBJECT_SALT` and never stores or echoes it. Resolving which agents saw the subject is your job in Phase 1.
    - `tenant` erases the whole tenant.
3. **Holds.** Check for legal holds:
   ```bash
   curl -s --cacert "$CA" "$SIBYL/api/v1/legal-holds?state=active" -H "Authorization: Bearer $SESSION" | jq '.data[] | {id, scope_kind, scope_ref, expires_at}'
   ```
   A matching hold blocks the erasure. Do not release a hold to let an erasure through without legal sign-off.
4. **Fallback chains.** An agent that is the backup in another agent's approved fallback chain cannot be erased (`409 erasure_blocked_by_chain`). Retire or replace that chain first.

## 2. File it

```bash
REQ=$(curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/erasure-requests" -H "Authorization: Bearer $SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" -d '{
    "scope_kind": "subject",
    "scope_ref": "customer-48812@example.com",
    "agent_ids": ["'"$AGENT_A"'", "'"$AGENT_B"'"],
    "window_from": "2026-01-01T00:00:00Z",
    "legal_basis": "gdpr_art17",
    "reason": "DSR-0193: verified erasure request, ticket SUP-7781."}' | jq -r .id)
curl -s --cacert "$CA" "$SIBYL/api/v1/erasure-requests/$REQ" -H "Authorization: Bearer $SESSION" | jq '{state, blocking_hold_ids}'
```

The state is `requested`, or `hold_blocked` if a hold applies. Only one request per scope may be live at a time (`409 erasure_in_progress`). Filing is limited to 5 per day per tenant.

## 3. Second person approves

The approver signs in, steps up in the console, and runs:

```bash
curl -s --cacert "$CA" -X POST "$SIBYL/api/v1/erasure-requests/$REQ/actions" -H "Authorization: Bearer $APPROVER_SESSION" \
  -H "Idempotency-Key: $(uuidgen)" -H "Content-Type: application/json" \
  -d '{"action": "approve", "reason": "Checked DSR-0193 identity, scope and holds."}'
```

**If it is refused:**

| Response | Cause |
|---|---|
| `409 self_approval` | The approver is the requester |
| `409 hold_blocked` | A hold appeared, with `blocking_hold_ids` |
| `403 step_up_required` | The approver needs to step up |

To stop before execution:

- Another person can `reject` the request.
- The requester or an Admin can `cancel` it.

## 4. Execution (the worker, about every 10 seconds)

```
approved → executing → keys_shredded (tenant only) → objects_deleted → derived_purged → verified → completed
```

Each step is its own transaction, so a crash resumes where it stopped. Holds are checked again in every phase. A step that fails records `error` on the request and is retried; nothing is skipped.

Follow the progress:

```bash
watch -n 10 "curl -s --cacert $CA $SIBYL/api/v1/erasure-requests/$REQ -H 'Authorization: Bearer $SESSION' | jq '{state, error}'"
```

During a tenant-scope erasure, ingest refuses that tenant's telemetry with `429 tenant_erasing`.

**If it is stuck with an error:**

| Error | Fix |
|---|---|
| A new hold | Resolve the hold with legal |
| Residue found at `verified` | Collect the worker logs (`dc logs worker \| grep -i erasure`) and do not edit rows by hand |
| A chain blocker | Retire the chain |

## 5. Completion

```bash
curl -s --cacert "$CA" "$SIBYL/api/v1/erasure-requests/$REQ/certificate" -H "Authorization: Bearer $SESSION" > erasure-certificate-$REQ.json
jq '{certificate_sha256, anchor_id, backups_expire_at}' erasure-certificate-$REQ.json
```

- Send the certificate to the requester.
- `backups_expire_at` is when pre-erasure backups age out (7-day retention, D26). Until then, the erased data exists only inside encrypted backups. A restore replays every erasure from the signed ledger before the restored database opens ([backup-restore.md](backup-restore.md)).
- Payloads that were erased answer `410 payload_shredded`.

## 6. Keep the ledger safe

The erasure ledger lives on the worker-only volume `erasure_ledger`. Copy it to the backup host after every erasure:

```bash
dc cp worker:/var/lib/sibyl/ledger/erasure-ledger.jsonl ./erasure-ledger.jsonl
```

Losing it means an old backup could restore erased data. The restore refuses to proceed without a ledger head it can verify.
