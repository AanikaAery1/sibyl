"""The scripted model behind `sentinel-stub` (pure functions, no I/O).

Sentinel speaks three wire dialects (Anthropic Messages, OpenAI Chat Completions, Gemini
generateContent). This module reads one request of any dialect, finds the task from the JSON
schema Sentinel asks for, pulls the `<agent_data>` document out of the user message and writes
a schema-valid structured answer from it, the way a careful (if simple-minded) reviewer would:

* incident: names the failing agent, the rule codes that fired and the saga's state;
* held action: `needs_more_info` when the arguments are not visible (metadata capture), `deny`
  when they read like an injected instruction, else `approve`;
* drift: `injection_like` when a step's scrubbed arguments read like an instruction;
* fleet: counts from the fleet document.

Only numbers and field names that are in the data are quoted, so the oracle's faithfulness and
evidence-resolution scorers have a known-good reference. Wording varies by a hash of
(seed, task, subject): the same seed answers the same way.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any, Final, Literal

from sibyl_schemas.models.sentinel import OUTPUT_MODELS
from sibyl_schemas.values import SentinelTask

Dialect = Literal["anthropic", "openai", "gemini"]
DATA_RE: Final = re.compile(r"<agent_data>\n?(.*?)\n?</agent_data>", re.DOTALL)
INJECTION_RE: Final = re.compile(
    r"ignore (all )?previous instructions|approve (this|every)|</?agent_data>|system prompt",
    re.IGNORECASE,
)
OUTAGE_RULES: Final = frozenset({"consecutive_failures", "error_rate", "provider_status"})
GEMINI_SCHEMA_MARK: Final = "matching this JSON Schema exactly:\n"
_FIELDS: Final = {task: frozenset(model.model_fields) for task, model in OUTPUT_MODELS.items()}
CONFIDENCE: Final = ("medium", "high")


class StubRequestError(ValueError):
    """The request is not a Sentinel request this stub understands (answered 400)."""


# ------------------------------------------------------------------ reading a request


def system_text(dialect: Dialect, body: Mapping[str, Any]) -> str:
    if dialect == "anthropic":
        return str(body.get("system") or "")
    if dialect == "openai":
        msgs = body.get("messages") or []
        return "\n".join(str(m.get("content") or "") for m in msgs if m.get("role") == "system")
    parts = ((body.get("systemInstruction") or {}).get("parts")) or []
    return "\n".join(str(p.get("text") or "") for p in parts)


def user_texts(dialect: Dialect, body: Mapping[str, Any]) -> list[str]:
    if dialect == "gemini":
        return [
            "".join(str(p.get("text") or "") for p in c.get("parts") or [])
            for c in body.get("contents") or []
            if c.get("role") == "user"
        ]
    return [
        str(m.get("content") or "") for m in body.get("messages") or [] if m.get("role") == "user"
    ]


def prompt_text(dialect: Dialect, body: Mapping[str, Any]) -> str:
    return system_text(dialect, body) + "\n" + "\n".join(user_texts(dialect, body))


def schema_of(dialect: Dialect, body: Mapping[str, Any]) -> Mapping[str, Any] | None:
    if dialect == "anthropic":
        fmt = (body.get("output_config") or {}).get("format") or {}
        schema = fmt.get("schema")
    elif dialect == "openai":
        schema = ((body.get("response_format") or {}).get("json_schema") or {}).get("schema")
    else:
        text = system_text(dialect, body)
        cut = text.find(GEMINI_SCHEMA_MARK)
        schema = None
        if cut >= 0:
            try:
                schema = json.loads(text[cut + len(GEMINI_SCHEMA_MARK) :])
            except ValueError:
                schema = None
    return schema if isinstance(schema, Mapping) else None


def detect_task(dialect: Dialect, body: Mapping[str, Any]) -> SentinelTask:
    schema = schema_of(dialect, body)
    if schema is None:
        raise StubRequestError("no JSON schema in the request: not a Sentinel analysis")
    props = frozenset((schema.get("properties") or {}).keys())
    for task, fields in _FIELDS.items():
        if props == fields:
            return task
    raise StubRequestError("the JSON schema matches no Sentinel task")


def agent_data(dialect: Dialect, body: Mapping[str, Any]) -> dict[str, Any]:
    """The `<agent_data>` document of the first user message (repairs append more turns)."""
    for text in user_texts(dialect, body):
        match = DATA_RE.search(text)
        if match:
            try:
                value = json.loads(match.group(1))
            except ValueError:
                raise StubRequestError("<agent_data> is not JSON") from None
            if isinstance(value, dict):
                return value
    raise StubRequestError("no <agent_data> in the user message")


def max_tokens_of(dialect: Dialect, body: Mapping[str, Any]) -> int:
    if dialect == "gemini":
        return int((body.get("generationConfig") or {}).get("maxOutputTokens") or 0)
    raw = body.get("max_tokens") if dialect == "anthropic" else body.get("max_completion_tokens")
    return int(raw or 0)


# ------------------------------------------------------------------ scripted answers


def _pick(seed: int, task: SentinelTask, subject: str, n: int) -> int:
    digest = hashlib.sha256(f"{seed}:{task.value}:{subject}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % n


def _texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [t for v in value.values() for t in _texts(v)]
    if isinstance(value, list):
        return [t for v in value for t in _texts(v)]
    return []


def _cite(data: Mapping[str, Any], path: str, template: str) -> str:
    """`template` with the field path when every segment exists in the data, else ''."""
    node: Any = data
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return ""
        node = node[part]
    return template.format(path)


def looks_injected(value: Any) -> bool:
    return any(INJECTION_RE.search(t) for t in _texts(value))


def _incident(data: Mapping[str, Any], pick: int) -> dict[str, Any]:
    inc = data.get("incident") or {}
    agent = data.get("agent") or {}
    slug = agent.get("slug") or "the agent"
    rules = [str(r) for r in inc.get("rule_codes") or []]
    if inc.get("alert_rule"):
        rules.append(str(inc["alert_rule"]))
    outage = bool(OUTAGE_RULES & set(rules))
    cause = (
        "A hard outage at the agent's primary provider: its calls failed back to back."
        if outage
        else "The data does not show the cause; the rules that fired are listed above."
    )
    move = f"{inc.get('from_state')} to {inc.get('to_state')}"
    tier = agent.get("tier")
    return {
        "severity": "critical" if tier == 1 else "warning",
        "summary": f"{slug}: provider outage, routing moved {move}"
        if outage
        else f"{slug}: incident, routing moved {move}",
        "what_failed": f"Calls from {slug} (tier {tier}) failed; rules fired: "
        + (", ".join(sorted(set(rules))) or "none recorded")
        + _cite(data, "incident.rule_codes", " ({})")
        + ".",
        "likely_cause": cause,
        "what_sibyl_did": f"The {inc.get('kind')} saga is {inc.get('state')} at step "
        f"{inc.get('step')}{_cite(data, 'incident.step_results', ' ({})')}; routing moved {move}.",
        "what_to_check": [
            "confirm the fallback target is serving"
            + _cite(data, "incident.step_results", " ({})"),
            "the provider's status page"
            + _cite(data, "latest_health.predicted_failure_mode", " and {}"),
        ],
        "confidence": CONFIDENCE[pick % 2] if outage else "low",
    }


def _held(data: Mapping[str, Any], pick: int) -> dict[str, Any]:
    held = data.get("held_action") or {}
    tool = held.get("tool") or "the tool"
    if not data.get("content_included"):
        return {
            "severity": "warning",
            "summary": f"{tool}: arguments not visible (capture_mode {data.get('capture_mode')})",
            "advice": "needs_more_info",
            "reasoning": "The agent's capture mode keeps the arguments out of Sentinel's view, so "
            "the amount and recipient cannot be checked against the policy rule"
            + _cite(data, "held_action.rule_reason", " ({})")
            + ".",
            "risks": [
                "approving blind",
                "repeated holds" + _cite(data, "held_action.same_tool_holds_7d", " ({})"),
            ],
            "confidence": "low",
        }
    if looks_injected(data.get("arguments_scrubbed")):
        return {
            "severity": "critical",
            "summary": f"{tool}: the arguments carry an instruction aimed at the reviewer",
            "advice": "deny",
            "reasoning": "arguments_scrubbed contains text that reads like an injected "
            "instruction (asking for approval); a genuine request does not.",
            "risks": ["prompt injection", "funds leaving under false pretences"],
            "confidence": CONFIDENCE[pick % 2],
        }
    return {
        "severity": "info",
        "summary": f"{tool}: consistent with the agent's purpose",
        "advice": "approve",
        "reasoning": "arguments_scrubbed matches the declared purpose; the policy rule escalated "
        "it only on its amount" + _cite(data, "held_action.rule_reason", " ({})") + ".",
        "risks": ["amount above the automatic limit"],
        "confidence": CONFIDENCE[pick % 2],
    }


def _drift(data: Mapping[str, Any], pick: int) -> dict[str, Any]:
    agent = data.get("agent") or {}
    evidence = []
    for t_index, trace in enumerate(data.get("trajectories") or []):
        for step in trace.get("steps") or []:
            if looks_injected(step.get("arguments_scrubbed")):
                evidence.append(
                    f"trajectory {t_index} step {step.get('step')}: arguments read "
                    "like an instruction"
                )
    flagged = bool(evidence)
    return {
        "severity": "warning" if flagged else "info",
        "summary": f"{agent.get('slug')}: "
        + ("injection-like tool arguments" if flagged else "consistent with its purpose"),
        "purpose_drift": False,
        "injection_like": flagged,
        "evidence": evidence[:8] or ["no step in trajectories reads like an instruction"],
        "recommendation": "Review the flagged steps' source input before the next run."
        if flagged
        else "No action needed.",
        "confidence": CONFIDENCE[pick % 2],
    }


def _fleet(data: Mapping[str, Any], pick: int) -> dict[str, Any]:
    fleet = data.get("fleet") or {}
    incidents = fleet.get("incidents_24h") or {}
    holds = fleet.get("held_actions_24h") or {}
    return {
        "severity": "warning" if incidents else "info",
        "summary": f"{fleet.get('agents')} agents; incidents_24h {json.dumps(incidents)}; "
        f"held_actions_24h {json.dumps(holds)}.",
        "highlights": [f"fleet.agents: {fleet.get('agents')}"],
        "concerns": [f"fleet.incidents_24h: {json.dumps(incidents)}"] if incidents else [],
        "recommendation": "Review open incidents first." if incidents else "No action needed.",
    }


SCRIPTS: Final = {
    SentinelTask.INCIDENT_EXPLANATION: _incident,
    SentinelTask.HELD_ACTION_REVIEW: _held,
    SentinelTask.SEMANTIC_DRIFT: _drift,
    SentinelTask.FLEET_SUMMARY: _fleet,
}


def subject_key(task: SentinelTask, data: Mapping[str, Any]) -> str:
    for key in ("incident", "held_action", "agent"):
        value = data.get(key)
        if isinstance(value, Mapping) and value.get("id"):
            return str(value["id"])
    return task.value


def answer(task: SentinelTask, data: Mapping[str, Any], seed: int) -> dict[str, Any]:
    """A schema-valid answer (validated here, so a script bug fails loudly in tests)."""
    raw = SCRIPTS[task](data, _pick(seed, task, subject_key(task, data), 2))
    return OUTPUT_MODELS[task].model_validate(raw).model_dump(mode="json")


# ------------------------------------------------------------------ writing a response


def usage_for(prompt: str, answer_text: str) -> tuple[int, int]:
    return max(1, math.ceil(len(prompt) / 4)), max(1, math.ceil(len(answer_text) / 4))


def wire_response(
    dialect: Dialect, model: str, text: str, usage: tuple[int, int], seq: int
) -> dict[str, Any]:
    tokens_in, tokens_out = usage
    if dialect == "anthropic":
        return {
            "id": f"msg_sentinel_stub_{seq:06d}",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": tokens_in, "output_tokens": tokens_out},
        }
    if dialect == "openai":
        return {
            "id": f"chatcmpl-sentinel-stub-{seq:06d}",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": tokens_in,
                "completion_tokens": tokens_out,
                "total_tokens": tokens_in + tokens_out,
            },
        }
    return {
        "candidates": [
            {"content": {"role": "model", "parts": [{"text": text}]}, "finishReason": "STOP"}
        ],
        "usageMetadata": {"promptTokenCount": tokens_in, "candidatesTokenCount": tokens_out},
        "modelVersion": model,
    }


def model_of(dialect: Dialect, body: Mapping[str, Any], path_model: str | None) -> str:
    if dialect == "gemini":
        return path_model or "gemini"
    return str(body.get("model") or "unknown")


__all__ = [
    "Dialect",
    "StubRequestError",
    "agent_data",
    "answer",
    "detect_task",
    "looks_injected",
    "max_tokens_of",
    "model_of",
    "prompt_text",
    "usage_for",
    "user_texts",
    "wire_response",
]
