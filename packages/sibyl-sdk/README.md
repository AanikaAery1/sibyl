# sibyl-sdk

Python SDK for **Sibyl**, the AI governance and agent reliability platform (Apache-2.0).
It reports what your agents do (model calls, tool calls, runs and handoffs), enforces the
kill switch and the Action Gate before risky tool calls run, and never ships secrets: an
unconditional secrets scrub runs on every piece of content, and `capture_mode` decides
whether content leaves the process at all.

## Install

```bash
pip install sibyl-sdk                      # core
pip install "sibyl-sdk[openai]"            # plus one integration
pip install "sibyl-sdk[all]"               # every integration below
```

Extras: `openai`, `anthropic`, `google`, `langchain`, `openai-agents`, `crewai`, `all`.
They only pull in the library being instrumented; Sibyl itself needs none of them.

## Configure

| variable                | meaning                                                         |
|-------------------------|-----------------------------------------------------------------|
| `SIBYL_API_KEY`         | ingest key `sbl_<env>_<prefix>_<secret>` (required)             |
| `SIBYL_ENDPOINT`        | ingest URL (required)                                           |
| `SIBYL_API_URL`         | control-plane URL for snapshots and the Action Gate (default: the endpoint) |
| `SIBYL_AGENT_ID`        | agent slug or uuid this process reports as                      |
| `SIBYL_ENV`             | `live` or `test` (must match the key)                           |
| `SIBYL_CAPTURE_MODE`    | `full`, `redacted` or `metadata` (the registry may tighten it)  |
| `SIBYL_INSTRUMENT`      | `auto` (default), `none`, or a list such as `openai,langchain`  |
| `SIBYL_SENSITIVE_TOOLS` | tool-name globs that fail closed without a fresh policy, e.g. `payments.*,send_email` |
| `SIBYL_ON_BEHALF_OF`    | `user:<uuid>` or `external:<ref>` (sibyl-run, whole process)    |
| `SIBYL_DISABLED`        | `1`: sibyl-run starts the target without Sibyl                  |

## Plug and play

**One line.** At the top of your entry point:

```python
import sibyl

sibyl.instrument()  # reads SIBYL_*, then instruments every installed client and framework
```

**Zero code.** Run the app unchanged:

```bash
sibyl-run app.py --your --args
sibyl-run -m my_service.main
python -m sibyl.run app.py          # same, without the console script
```

`sibyl-run` never stops your app from starting: a configuration problem is printed to
stderr (never the key) and the app runs without monitoring.

`sibyl.instrument()` returns the names it instrumented, e.g. `["openai", "langchain"]`.
Libraries that are not installed are skipped. Calling it twice is harmless.

### What is captured

Every model call records the provider, the requested model, the **served** model, the
provider fingerprint (`system_fingerprint`), input and output tokens, latency and
time-to-first-token, finish reasons, refusals and the tool calls the model proposed. That
metadata is always sent; it is what model drift detection compares. Prompts and outputs
are sent only in `full` or `redacted` capture mode, after the secrets scrub; in
`metadata` mode only their SHA-256 hashes leave the process.

Multi-agent systems report a **run tree**: each run, model call and tool call carries
`parent_run_id` (the run that contains it) and `step_index` (its order in that run), and
a run that hands work to another agent records `handoff_to_agent`. An agent first seen as
a handoff target is registered in Sibyl as `discovered`: it is visible in the console and still checked by the Action Gate and kill switch, but never routed or failed over until an admin confirms it.

## Integrations

### OpenAI

```python
import sibyl, openai

sibyl.instrument()
client = openai.OpenAI()
client.chat.completions.create(model="gpt-5-mini", messages=[...])  # sync, async, stream=True
client.responses.create(model="gpt-5", input="...")  # Responses API
```

Zero code: `sibyl-run app.py`. Captures `system_fingerprint`, refusals (`message.refusal`)
and proposed `tool_calls`. Embeddings record usage only.

### Anthropic

```python
import sibyl, anthropic

sibyl.instrument()
anthropic.Anthropic().messages.create(model="claude-...", max_tokens=512, messages=[...])
```

Zero code: `sibyl-run app.py`. Captures `stop_reason` (including `refusal`) and `tool_use`
blocks, sync, async and `stream=True`.

### Google Gen AI (Gemini)

```python
import sibyl
from google import genai

sibyl.instrument()
genai.Client().models.generate_content(model="gemini-2.5-flash", contents="...")
```

Zero code: `sibyl-run app.py`. Covers `generate_content` and `generate_content_stream`,
sync (`client.models`) and async (`client.aio.models`). Safety blocks are recorded as
refusals; `MAX_TOKENS` is reported as the `length` finish reason. Sibyl's headers are added
to `config.http_options` when `config` is a dict (a typed config object is left untouched).

### LangChain and LangGraph

```python
import sibyl

sibyl.instrument()  # registers a global callback handler; no callbacks= needed
graph.invoke({"messages": [...]})
```

Zero code: `sibyl-run app.py`. The outermost chain or graph is a run; each LangGraph node
is a child run (its `step_index` is the graph step); tools are tool calls; a
`transfer_to_<agent>` tool or a `Command(goto=..., graph=Command.PARENT)` records a
handoff. Models called through an instrumented OpenAI or Anthropic client are recorded
once, by the client integration; other providers are recorded from LangChain's results.
Where configure hooks are disabled, pass `sibyl.integrations.langchain.handler()` in
`callbacks=`.

### OpenAI Agents SDK

```python
import sibyl

sibyl.instrument()  # before you define tools
from agents import Agent, Runner, function_tool
```

Zero code: `sibyl-run app.py`. A tracing processor maps the workflow (trace) to a run,
each agent to a child run, function spans to tool calls and handoff spans to
`handoff_to_agent`. Tools created after `instrument()` are gated; gate an earlier tool
with `sibyl.integrations.openai_agents.gate_tool(tool)`.

### CrewAI

```python
import sibyl

sibyl.instrument()
crew.kickoff()
```

Zero code: `sibyl-run app.py`. The crew is a run, each agent (by role) a child run, tool
usages are tool calls, and the delegation tools ("Delegate work to coworker", "Ask
question to coworker") record the coworker as the handoff target.

## Action Gate for framework tools

Tools that LangChain, the OpenAI Agents SDK or CrewAI execute go through the same
pre-execution check as `@sibyl.tool`: the agent's action policies, cumulative caps, and
holds for a person. A blocked, denied or held call raises `SibylActionBlocked`,
`SibylActionDenied` or `SibylActionHeld` before the tool's code runs. A tool listed as
sensitive (by a policy, by `sibyl.instrument(sensitive_tools=[...])` or by
`SIBYL_SENSITIVE_TOOLS`) is blocked when no fresh policy snapshot is held (fail closed).

## Acting on behalf of someone

```python
with sibyl.on_behalf_of(user="0192...-uuid"):  # a Sibyl user
    agent.run(task)
with sibyl.on_behalf_of(external="crm:contact/123"):  # anyone else, up to 128 chars
    agent.run(task)
```

The value is attached to every held action created in the block (so the approver sees who
the agent acts for) and sent to the gateway as `X-Sibyl-On-Behalf-Of`.

## Explicit API

`sibyl.init(...)`, `sibyl.agent(...)`, `@sibyl.tool`, `sibyl.check_action(...)`,
`sibyl.checkpoint(...)`, `sibyl.handoff(...)`, `sibyl.instrument(client)` for a single client
instance, and `sibyl.flush()` / `sibyl.shutdown()` remain available; see the module
docstrings.
