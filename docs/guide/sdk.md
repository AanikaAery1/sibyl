# Python SDK reference

Package `sibyl-sdk`, imported as `sibyl`. It needs Python 3.13 or later and is licensed Apache-2.0. It depends on `sibyl-schemas`, `httpx` and `cryptography`. It does not route traffic: routing and inline fallback are the gateway's job. The SDK sends telemetry, checkpoints, handoff packets and labels to ingest, and polls the signed policy snapshot so it can honour the kill switch.

This page documents the public surface in `packages/sibyl-sdk/src/sibyl/__init__.py`.

## Install

The package is not on PyPI yet; name reservation is an open founder item (D46). Use it from the workspace:

```bash
uv sync --all-packages                 # the SDK is a workspace member
uv run python -c "import sibyl; print(sibyl.__version__)"
```

To install it into another environment:

```bash
pip install ./packages/sibyl-schemas ./packages/sibyl-sdk
```

`openai` and `anthropic` are optional. The SDK instruments them when they are importable.

## Three guarantees

1. **It never blocks your thread.** Calls append to bounded in-memory queues, and one daemon thread batches, gzips and sends.
2. **It never raises into your code**, with three exceptions:
    - `SibylConfigError` from `init()`.
    - `SibylKilled` when the agent is killed.
    - `SibylPolicyUnavailable`, for fail-closed agents only.
3. **Secrets are scrubbed before anything leaves the process**, whatever the capture mode.

## Configure: `sibyl.init()`

```python
sibyl.init(
    api_key: str | None = None,
    *,
    endpoint: str | None = None,
    agent_id: str | UUID | None = None,
    capture_mode: Literal["full", "redacted", "metadata"] | None = None,
    env: Literal["live", "test"] | None = None,
    instrument: Sequence[Literal["openai", "anthropic", "mcp", "httpx"]] | Literal["auto"] = "auto",
    scrub: ScrubHook | Sequence[ScrubHook] | None = None,
    exporter: ExporterConfig | None = None,
    policy: PolicyConfig | None = None,
    resource_attributes: Mapping[str, str] | None = None,
    tracer_provider: Any | None = None,        # accepted, ignored in Phase 1
    fail_mode: Literal["open", "closed"] | None = None,
    transport: httpx.BaseTransport | None = None,
) -> Client
```

Explicit arguments win over environment variables. Calling `init()` again replaces the previous client and flushes it.

| Argument | Environment variable | Default | Notes |
|---|---|---|---|
| `api_key` | `SIBYL_API_KEY` | required | Form `sbl_<live\|test>_<prefix12>_<secret>`. Keys with `gateway:proxy` or `killswitch:pull` are refused. Use an agent-bound key with `ingest:write`, `routing:read` and `handoff:write`. |
| `endpoint` | `SIBYL_ENDPOINT` | required | The ingest base URL, for example `https://localhost:8445`. Plain `http` is allowed but logs a warning unless the host is loopback. |
| `policy.endpoint` | `SIBYL_API_URL` | the ingest endpoint | The API base URL used for the snapshot poll. |
| `agent_id` | `SIBYL_AGENT_ID` | none | A slug or UUID. A bound key implies it. |
| `capture_mode` | `SIBYL_CAPTURE_MODE` | `full` | The registry can only make it stricter (D12). |
| `env` | `SIBYL_ENV` | the key's env | Must match the key. |
| `fail_mode` | none | `open` | Local override used only until the first snapshot arrives. After that the registry's value wins. |
| none | `SIBYL_SCRUB_SALT` | per-key salt | Set it to the platform salt (16 bytes or more) so scrub tokens match the gateway's. |
| `transport` | none | none | An `httpx` transport for the SDK's own HTTP clients. Use it in tests, or to supply a custom TLS context. |

**`ExporterConfig`** has these keyword-only fields. All sizes are hard caps:

| Field | Default |
|---|---|
| `max_queue_spans` | 10,000 |
| `max_queue_bytes` | 32 MiB |
| `batch_size` | 512 |
| `schedule_delay` | 2 s |
| `export_timeout` | 10 s |
| `spool_dir` | `None` (off) |
| `spool_max_bytes` | 256 MiB |
| `spool_max_age` | 7 days |
| `critical_lane` | `True` |
| `shutdown_flush_timeout` | 2 s |
| `heartbeat_interval` | 10 s |
| `buffer_report_interval` | 60 s |

Checkpoints, handoffs and task ends travel in a separate critical lane, so ordinary telemetry cannot crowd them out. A 429 or 503 from ingest pauses both lanes for the `Retry-After` interval. A timeout keeps the batch, under the same batch id, so ingest can de-duplicate it on replay.

**`PolicyConfig`** has these fields:

| Field | Default |
|---|---|
| `poll_interval` | 20 s |
| `max_stale` | 15 min |
| `public_key` | `None`, meaning trust on first use, then follow the signed rotation chain |
| `cache_dir` | `~/.sibyl/policy` |
| `enforce_kill_switch` | `True` |
| `endpoint` | `None` |
| `enabled` | `True` |

<!-- verify after INT-2: the snapshot poll GETs /api/v1/policy/snapshot on SIBYL_API_URL, which Caddy answers 404 on the public :8443 origin; until that is routed, the SDK has no snapshot and runs fail-open (the gateway still enforces kills), and agent and tenant ids in SDK documents fall back to the key binding resolved by ingest -->

## Task boundaries: `sibyl.agent()`

```python
with sibyl.agent(goal="Quote order A-1") as run:          # or: async with
    ...
    run.outcome("success")
```

```python
sibyl.agent(name=None, *, agent_id=None, task_id=None, goal=None,
            conversation_id=None, attributes=None) -> AgentRun
```

Entering a task emits `agent.invoke` with `phase=start`. Leaving it ends the `invoke_agent` span with status `ok`, `error`, `handed_off` or `cancelled`. Nested runs share the trace and record `parent_task_id`. Exceptions always propagate unchanged.

**`AgentRun`** members:

| Member | Meaning |
|---|---|
| `outcome(outcome, *, reason=None, rework=None)` | Emits `task.outcome`. `outcome` is `success`, `partial`, `failure`, `abandoned` or `handed_off`. |
| `handoff(packet) -> UUID` | Sends the packet and marks the run `handed_off`. |
| `cancel(reason=None)` | Marks the run `cancelled`. |
| `set_goal(goal)` | Sets the run's goal. |
| `task_id`, `trace_id`, `span_id`, `steps`, `tool_calls`, `model_calls`, `latest_checkpoint` | Read-only state. |

`sibyl.current_run()` returns the innermost open run, or `None`.

## Checkpoints: `sibyl.checkpoint()`

```python
sibyl.checkpoint(
    state: Mapping[str, Any] | Any,
    *,
    step: str | None = None,
    step_index: int | None = None,
    completed: Sequence[Step | str] = (),
    pending: Sequence[Step | str] = (),
    side_effects: Sequence[SideEffect] = (),
    state_schema: str | None = None,     # default "app:unspecified/v1"
    run: AgentRun | None = None,
) -> UUID
```

A checkpoint records resumable state as a `sibyl-checkpoint/1` document in the critical lane. The state is scrubbed and validated on the exporter thread. Up to 64 KB of state is stored inline. Larger state is stored by reference, up to the 4 MiB inline payload limit. Beyond that the checkpoint is dropped with a warning. Checkpoints chain through `prev_checkpoint_id`.

Checkpoint after each side effect and before each long step. Outside `init()` or `sibyl.agent()` the call is ignored with a one-time warning.

`Step(step, *, index=None, description=None, output=None, inputs_needed=(), blocked_on=None, tool_name=None)` describes a step. `SideEffect(kind, *, target=None, idempotency_key=None, reversible=None)` describes an effect already caused. `kind` is one of `external_write`, `message_sent`, `payment`, `file_written`, `db_write`, `ticket_created`, `api_call`, `unknown`.

## Handoff: `sibyl.handoff`

```python
packet = sibyl.handoff.packet(
    *, reason: str, failure_mode: FailureMode, next_action: str,
    goal: str | None = None, pending: Sequence[Step | str] | None = None,
    deadline: datetime | None = None, run: AgentRun | None = None,
    from_checkpoint: UUID | Literal["latest"] | None = "latest",
) -> HandoffPacket
run.handoff(packet)                 # or sibyl.handoff.request(packet, run=run)
```

`packet()` builds a validated `sibyl-handoff/1` packet. When a checkpoint exists, it copies the completed steps, pending steps and side effects from it, and fidelity is `checkpoint`. Otherwise fidelity is `request_only`.

Text that is too short is padded and text that is too long is truncated, so the call never raises. `reason` is 20–1000 characters and `next_action` is 5–300.

`failure_mode` is one of:

- `provider_outage`, `latency_degradation`, `quality_collapse`
- `prompt_injection`, `policy_violation`
- `tool_failure`, `data_source_failure`
- `infinite_loop`, `cost_runaway`
- `permission_error`, `model_deprecation`, `silent_drift`

Sending a packet needs `handoff:write`. Without it, the packet is not sent and a warning is logged once. The worker turns packets into handoff tasks in the operator queue within about 30 seconds.

## Labels: `sibyl.outcome()` and `sibyl.feedback()`

```python
sibyl.outcome(outcome, *, reason=None, rework=None, run=None) -> None
sibyl.feedback(score: float, *, scale="thumbs", target="task", target_id=None,
               rater="end_user", comment=None, tags=()) -> UUID
```

`feedback` clamps `score` to the range [-1, 1] and keeps the original value as `raw_value`. `target` is `trace`, `task`, `call` or `packet`, and defaults to the current run. Comments are scrubbed, and then stored or dropped according to the capture mode.

## Tools: `@sibyl.tool`

```python
@sibyl.tool(side_effect="read")
def lookup_order(order_id: str) -> dict: ...

@sibyl.tool(name="send_email", side_effect="external", tool_type="function",
            capture_args=None, capture_result=None, mcp_server=None)
def send_email(to: str, body: str) -> None: ...
```

The decorator wraps sync, async and generator functions in an `execute_tool` span. Arguments and results are captured as scrubbed content unless capture is off.

- `side_effect` is one of `none`, `read`, `write`, `external`, `unknown`.
- `tool_type` is one of `function`, `mcp`, `a2a`, `http`, `retrieval`, `code`, `extension`, `datastore`.

## Model clients

With `instrument="auto"`, which is the default, `init()` patches the importable `openai` and `anthropic` client classes. To wrap one instance explicitly:

```python
client = sibyl.instrument(openai.OpenAI(...), capture_mode=None)
```

Each wrapped call does four things:

1. Runs `sibyl.policy.check()`, which may raise `SibylKilled`.
2. Opens a `gen_ai.*` client span (OpenTelemetry GenAI semantic conventions 1.37).
3. Adds `X-Sibyl-Agent`, `X-Sibyl-Task-Id`, `X-Sibyl-Call-Id`, `X-Sibyl-Policy-Version` and `traceparent` through `extra_headers`.
4. Records usage, finish reasons and content according to the capture mode.

Streams are proxied: the span ends when the stream is exhausted or closed.

To route through the gateway as well, point the client at it and add your gateway key yourself:

```python
client = openai.OpenAI(base_url="https://localhost:8444/v1", api_key=PROVIDER_KEY,
                       default_headers={"X-Sibyl-Key": GATEWAY_KEY})
```

## Policy and the kill switch: `sibyl.policy`

| Call | Returns |
|---|---|
| `sibyl.policy.current(agent_id=None)` | `PolicySnapshot \| None`, this agent's slice of the verified snapshot |
| `sibyl.policy.check(agent_id=None)` | Raises `SibylKilled` if the agent is killed, whatever the snapshot's freshness. Raises `SibylPolicyUnavailable` only for fail-closed agents with no usable snapshot. |
| `sibyl.policy.on_change(callback)` | An unsubscribe function |

`PolicySnapshot` fields:

| Field | Type or values |
|---|---|
| `agent_id`, `tenant_id` | UUID |
| `slug` | str |
| `policy_version` | int |
| `issued_at` | datetime |
| `ttl_s`, `grace_s`, `max_stale_s` | numbers |
| `state` | one of the seven routing states |
| `fail_mode` | `open` or `closed` |
| `capture_mode` | `full`, `redacted` or `metadata` |
| `tier` | 1–3 |
| `primary` | the primary provider and model |
| `fallback_chain` | the chain steps |
| `kill_reason` | str or `None` |
| `key_scopes` | the key's scopes |

`freshness_at(now)` returns `fresh`, `stale`, `expired` or `unavailable`.

Snapshots are verified with Ed25519 over the raw bytes, cached on disk, and never accepted at a lower version. A cached `killed` state persists through staleness until a fresh snapshot says otherwise.

## Lifecycle

| Call | Effect |
|---|---|
| `sibyl.flush(timeout=None) -> bool` | Waits for queued data to be sent |
| `sibyl.shutdown(timeout=None)` | Flushes within the bound and stops the threads |
| `sibyl.get_client() -> Client` | The process-wide client. Raises `SibylConfigError` before `init()`. |
| `client.stats()` | `ExporterStats`: `queued_spans`, `queued_bytes`, `dropped_spans`, `dropped_by_reason`, `spooled_bytes`, `exported_batches`, `rejected_events`, `last_export_at`, `last_error`, `backpressure_until` |

The SDK re-creates its threads after `fork()`.

## Custom scrubbing

```python
def drop_account_numbers(text: str, ctx: sibyl.ScrubContext) -> str:
    return ACCOUNT_RE.sub("[ACCOUNT]", text)

sibyl.init(scrub=drop_account_numbers)
```

The pipeline for each content part runs in this order:

1. The built-in secrets floor. It cannot be turned off or reordered.
2. Your hooks, in order.
3. The capture-mode gate.

If a hook raises, that part is downgraded to `metadata`. Unscrubbed content is never sent. `ScrubContext` carries `part` (`input_messages`, `output_messages`, `system_instructions`, `tool_definitions`, `tool_args`, `tool_result`, `state` or `comment`), `agent_id`, `task_id` and `call_id`.

## Testing your agent

`sibyl.testing` provides a recording in-memory ingest, a signed-snapshot stub, an advanceable clock and `TEST_KEY`, which is a well-formed fake key. It has no pytest dependency and makes no network calls. The runnable example in `packages/sibyl-sdk/examples/quickstart.py` uses a loopback stub by default:

```bash
uv run python packages/sibyl-sdk/examples/quickstart.py           # offline
SIBYL_API_KEY=sbl_test_... SIBYL_ENDPOINT=https://localhost:8445 SIBYL_API_URL=https://localhost:8443 \
  uv run python packages/sibyl-sdk/examples/quickstart.py --live
```

## The `sibyl` command line

```bash
uv run sibyl audit verify EXPORT.jsonl --public-key KEY [--public-key KEY ...] [--anchor ANCHOR.json ...] [--quiet]
```

It verifies an exported audit chain offline. `KEY` can be:

- a PEM public key,
- a raw or base64url 32-byte key,
- the JSON from `GET /api/v1/audit/signing-keys`,
- or a JWKS-style key set.

`--anchor` takes anchor JSON in any of these forms: an object, a list, `{data: [...]}` or JSONL. By default the anchors inside the export are used.

Exit codes: `0` the chain verifies, `1` a break (reported with its `seq` and kind), `2` the input cannot be read. Break kinds are `gap`, `prev_mismatch`, `content_mismatch`, `hash_mismatch`, `anchor_signature`, `anchor_tenant`, `anchor_mismatch`, `unanchored_tail` and `no_anchor`.

## TypeScript

A TypeScript SDK is an interface sketch only in Phase 1 (D35). Node agents use the gateway path: an OpenAI client with `baseURL` set to the gateway and `defaultHeaders: {"X-Sibyl-Key": ..., "X-Sibyl-Agent": ...}`. That gives monitoring and failover. Handoff packets are `request_only`.
