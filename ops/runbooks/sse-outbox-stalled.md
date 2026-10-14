# Runbook: SSE or outbox stalled (the commit-horizon caveat)

**Symptoms (any of these):**

- The console stops updating while the API answers normally.
- Event streams send only `: ping` heartbeats.
- Health scores freeze, and new alerts stop appearing, although traffic flows.
- Audit exports stay `queued`, or anchors stop advancing, after the anchors loop has run.

**Sources:** R58, R60; `services/control/migrations/0001_foundation.sql` (`sibyl.commit_horizon`) and `0012_outbox.sql` (`sibyl.outbox_read`).

## Why this happens

Every ordered reader of the outbox and of the events table reads only rows **below the commit horizon**:

```sql
sibyl.commit_horizon() = pg_snapshot_xmin(pg_current_snapshot())
```

The commit horizon is the oldest transaction id still running anywhere on the Postgres cluster. Reading below it means a transaction that commits late is never skipped. That guarantees order and completeness.

The price: **one long-running write transaction holds every reader back until it ends.** That covers anything with an assigned transaction id: an `idle in transaction` session, a long migration, or a hand-run `psql` session with an open `BEGIN`. It applies even if that transaction is in a different database on the same cluster.

| Reader | Effect of a stuck horizon |
|---|---|
| `GET /api/v1/events/stream` (console, SSE clients) | No new events |
| Worker `rollup` (consumer group `rollup`) | No new metrics, so scoring goes blind and detection stops |
| Worker `anchors` (consumer group `housekeeping.anchors`) | Exports, verifications and break-glass anchors wait |

**Read-only transactions do not hold the horizon back.** They have no transaction id. A lost `NOTIFY` is not the cause either: streams poll every 2 seconds regardless of notifications.

## Diagnose

### 1. Find the oldest transaction that holds a transaction id

```bash
psql_sibyl -c "
SELECT pid, datname, usename, application_name, state,
       now() - xact_start AS xact_age, backend_xid, left(query, 80) AS query
  FROM pg_stat_activity
 WHERE backend_xid IS NOT NULL
 ORDER BY xact_start
 LIMIT 10;"
psql_sibyl -c "SELECT gid, prepared, owner, database FROM pg_prepared_xacts;"
```

A transaction older than about 30 seconds with `state = 'idle in transaction'` is almost certainly the cause. A forgotten prepared transaction (`pg_prepared_xacts`) has the same effect, and survives restarts.

### 2. Confirm the readers are behind

```bash
psql_sibyl -c "
SELECT consumer_group, topic, count(*) AS tenants, min(last_created_at) AS oldest_position
  FROM sibyl.consumer_offsets GROUP BY 1, 2;"
psql_sibyl -c "SELECT sibyl.commit_horizon() AS horizon,
  (SELECT xid FROM sibyl.outbox ORDER BY xid DESC LIMIT 1) AS newest_outbox_xid;"
```

If `newest_outbox_xid` is at or above `horizon` and stays there, rows are waiting behind the horizon.

### 3. Rule out the other causes

| Check | Command | Meaning |
|---|---|---|
| Worker loops failing | `dc exec -T worker python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:8002/healthz').read().decode())" \| jq '.loops.rollup, .loops.anchors'` | A failing loop is a different problem. Read `last_error` and the worker logs. |
| SSE hub connection | `dc logs --since 15m api \| grep -i 'sse hub'` | The hub reconnects on its own. While it reconnects, streams fall back to polling. |
| Slow consumer | The client got `event: reset` with `"reason":"slow_consumer"` | The client's buffer of 1,000 frames filled. It should reconnect with `Last-Event-ID`. |
| Expired cursor | The client got `event: reset` with `"reason":"cursor_expired"` | Back-fill from the list routes, then reconnect without `Last-Event-ID`. |
| Stream cap | `429 stream_limit` | A session may hold 20 streams and an API key 5. Close the extra tabs or clients. |

## Fix

1. **End the blocking transaction.** If it is a human session or a stuck client, terminate it:
   ```bash
   psql_sibyl -c "SELECT pg_terminate_backend(<pid>);"
   ```
   For a forgotten prepared transaction, run `ROLLBACK PREPARED '<gid>';` once you are sure nobody needs it.

   If it is the worker in a long phase, let it finish. Examples are a bulk erasure step or a large verification; the worker's pool allows statements up to 900 seconds.

   Never terminate `migrate` while it is running. Wait, or stop and restore per [backup-restore.md](backup-restore.md).
2. **Readers catch up by themselves.** They resume from their saved cursors once the horizon moves. Nothing is lost or reordered. Health scoring recomputes the minutes it missed.
3. **Clients reconnect.** The console reconnects on its own. Other SSE clients should reconnect with their last `id:` as `Last-Event-ID`.

## Prevent it

- Never leave an interactive `psql` session open inside `BEGIN` against the production cluster. On the dev cluster on port 5433, test databases from other work count too, because transaction ids are cluster-wide.
- Set a cluster-wide guard against forgotten sessions:
  ```sql
  ALTER SYSTEM SET idle_in_transaction_session_timeout = '60s';  -- then: SELECT pg_reload_conf();
  ```
  <!-- verify: idle_in_transaction_session_timeout is not set by the compose postgres configuration today -->
- Do not use prepared transactions (`max_prepared_transactions` stays at its default of 0).
- Watch the rollup lag (`consumer_offsets.last_created_at` for `rollup`). Alert when it is more than 2 minutes behind during traffic.
