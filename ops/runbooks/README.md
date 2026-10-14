# Runbooks

Phase 1 has one operator, working in a business-hours window (D18). These runbooks assume that person is on the machine running the compose stack.

| Runbook | Use it when |
|---|---|
| [incident-response.md](incident-response.md) | Anything looks wrong and you do not know where to start |
| [provider-outage.md](provider-outage.md) | A model provider is down or degraded |
| [snapshot-stale.md](snapshot-stale.md) | The gateway reports a `stale` or `expired` snapshot, or refuses with `sibyl_policy_expired` or `sibyl_no_snapshot` |
| [sse-outbox-stalled.md](sse-outbox-stalled.md) | The console stops updating, or health scores, exports or anchors stop advancing |
| [erasure-request.md](erasure-request.md) | You received a right-to-erasure request |
| [rotate-keys.md](rotate-keys.md) | You need to rotate API keys, tenant data keys or signing keys |
| [backup-restore.md](backup-restore.md) | Backups, restores and the restore drill (owned by the infrastructure lane) |

Every runbook uses this shorthand, run from the repository root:

```bash
dc() { docker compose -f deploy/compose/docker-compose.yml --env-file deploy/compose/.env --profile sim "$@"; }
psql_sibyl() { dc exec -T postgres psql -U postgres -d sibyl "$@"; }
export SIBYL=https://localhost:8443 CA="$PWD/sibyl-local-root.crt"
```

API calls use a console session token: `Authorization: Bearer sibyl_sess_<cookie>` (see [API conventions](../../docs/guide/api.md#authentication)). Write down every action you take, with its time, in the incident log. The audit chain records what Sibyl did; the incident log records why you did it.
