"""OTel GenAI semconv v1.37.0 spans → wire-shaped ``sibyl-event/1`` candidates (§4.5 steps 2-4).

Classification is by ``gen_ai.operation.name`` after the legacy map (``gen_ai.system``,
OpenLLMetry ``gen_ai.prompt.N.*`` / ``gen_ai.completion.N.*`` and ``gen_ai.usage.*_tokens``,
OpenInference ``llm.*``). Spans Sibyl does not understand are raw-only (``dead_letter``), not
rejections; GenAI spans missing a required attribute are rejected ``missing_required``.
Content attributes never reach ``attrs``: they become the candidate's ``Content`` body.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from sibyl_schemas.values import ToolActionEffect

from ..ids import deterministic_uuid7, span_event_id
from ..otlp.model import STATUS_ERROR, Scope, Span
from .candidate import Candidate, Content
from .fields import (
    CAPTURE_MODES,
    POLICY_STATES,
    as_bool,
    as_float,
    as_hash,
    as_int,
    as_str,
    as_str_list,
    as_uuid,
    compact,
    dumps,
    json_value,
    not_nil,
    rfc3339_ns,
)

GENAI_OPERATIONS = ("chat", "text_completion", "embeddings", "generate_content")
TOOL_TYPES = ("function", "mcp", "a2a", "http", "retrieval", "code", "extension", "datastore")
SIDE_EFFECTS = ("none", "read", "write", "external", "unknown")
OUTPUT_TYPES = ("text", "json", "image", "speech")
GENAI_CONTENT_TYPE = "application/vnd.sibyl.genai-content+json"
TOOL_CONTENT_TYPE = "application/vnd.sibyl.tool-content+json"

# sibyl.* attributes the normaliser reads (API.md §4.6); other sibyl.* keys are dropped and counted.
KNOWN_SIBYL = re.compile(
    r"^sibyl\.(tenant_id|agent_id|task_id|call_id|source|emitter_id|seq|env|capture\.mode"
    r"|redaction\.(profile|version|rules|secrets_scrubbed|profile_hash|emitter_profile_hash|late_hits)"
    r"|policy\.(state|version|fail_mode|snapshot_age_s)"
    r"|route\.(decision|reason|transition_id|from\.(provider|model)|to\.(provider|model))"
    r"|retry\.(attempt|inline_fallback_used|breaker_state)"
    r"|ratelimit\.(limit|remaining|reset)_(requests|tokens)"
    r"|ttfb_ms|streamed|model\.context_limit|checkpoint\.[a-z_]+|tool\.side_effect_class|mcp\.server"
    r"|prompt\.version|task\.outcome|feedback\.(score|scale)|eval\.sample|payload\.(truncated|bytes_original)"
    r"|sdk\.version|schema\.version|semconv\.version|latency_ms"
    r"|content_hash\.(input|output|system|args|result)|output_chars|parent_task_id"
    r"|parent_run_id|step_index|handoff_to_agent|system_fingerprint|refusal|tool_calls\.(names|ids)"
    r"|action\.(effect|rule_id|held_action_id)"
    r"|invoke\.(status|steps|tool_calls|model_calls|cancel_reason))$"
)
ACTION_EFFECTS = tuple(str(e.value) for e in ToolActionEffect)
MAX_ACTION_RULE_ID = 128
MAX_FINGERPRINT = 128
MAX_AGENT_REF = 256
MAX_TOOL_CALLS = 32
REFUSAL = "refusal"
_LEGACY_MSG = re.compile(
    r"^(gen_ai\.(prompt|completion)|llm\.(input|output)_messages)\.(\d+)\.(.+)$"
)


def _run_tree(attrs: dict[str, Any], *, handoff: bool) -> dict[str, Any]:
    """D50 frozen run-tree attrs: ``parent_run_id``, ``step_index``, ``handoff_to_agent``."""
    out: dict[str, Any] = {
        "parent_run_id": as_uuid(attrs.get("sibyl.parent_run_id")),
        "step_index": as_int(attrs.get("sibyl.step_index"), minimum=0),
    }
    if handoff:
        ref = as_str(attrs.get("sibyl.handoff_to_agent"))
        out["handoff_to_agent"] = (ref.strip()[:MAX_AGENT_REF] or None) if ref else None
    return out


def _action_outcome(attrs: dict[str, Any]) -> dict[str, Any]:
    """Action Gate outcome the SDK stamps on a tool span (``sibyl.action.*``); an unknown
    effect or a malformed held-action id is dropped, a long rule id clipped."""
    rule = as_str(attrs.get("sibyl.action.rule_id"))
    return {
        "action_effect": _enum(attrs.get("sibyl.action.effect"), ACTION_EFFECTS),
        "action_rule_id": rule[:MAX_ACTION_RULE_ID] if rule else None,
        "held_action_id": as_uuid(attrs.get("sibyl.action.held_action_id")),
    }


def _fingerprint(attrs: dict[str, Any]) -> str | None:
    value = as_str(attrs.get("sibyl.system_fingerprint")) or as_str(
        attrs.get("gen_ai.openai.response.system_fingerprint")
    )
    return value[:MAX_FINGERPRINT] if value else None


def _tool_calls(attrs: dict[str, Any]) -> list[dict[str, Any]] | None:
    names = as_str_list(attrs.get("sibyl.tool_calls.names")) or []
    ids = as_str_list(attrs.get("sibyl.tool_calls.ids")) or []
    calls = []
    for i, name in enumerate(names[:MAX_TOOL_CALLS]):
        call: dict[str, Any] = {"name": name[:MAX_AGENT_REF]}
        if i < len(ids) and ids[i]:
            call["id"] = ids[i][:MAX_AGENT_REF]
        calls.append(call)
    return calls or None


def _finish_reasons(attrs: dict[str, Any]) -> list[str] | None:
    reasons = as_str_list(attrs.get("gen_ai.response.finish_reasons"))
    if as_bool(attrs.get("sibyl.refusal")) and REFUSAL not in (reasons or []):
        reasons = [*(reasons or []), REFUSAL]
    return reasons


def _status(span: Span, attrs: dict[str, Any]) -> tuple[str, str | None]:
    error_type = as_str(attrs.get("error.type"))
    if span.status_code == STATUS_ERROR or error_type:
        return "error", error_type or (span.status_message[:200] or "error")
    return "ok", None


def _legacy_messages(attrs: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, dict[int, dict[str, Any]]] = {"input_messages": {}, "output_messages": {}}
    for key, value in attrs.items():
        match = _LEGACY_MSG.match(key)
        if match is None:
            continue
        side = "input_messages" if match.group(2) in ("prompt", "input") else "output_messages"
        field = match.group(5).removeprefix("message.")
        found[side].setdefault(int(match.group(4)), {})[field] = json_value(value)
    return {side: [msgs[i] for i in sorted(msgs)] for side, msgs in found.items() if msgs}


def _genai_content(span: Span, attrs: dict[str, Any], warnings: list[str]) -> Content | None:
    body: dict[str, Any] = {}
    for part, key in (
        ("input_messages", "gen_ai.input.messages"),
        ("output_messages", "gen_ai.output.messages"),
        ("system_instructions", "gen_ai.system_instructions"),
        ("tool_definitions", "gen_ai.tool.definitions"),
    ):
        if key in attrs:
            body[part] = json_value(attrs[key])
    legacy = _legacy_messages(attrs)
    for event in span.events:
        if event.name in ("gen_ai.content.prompt", "gen_ai.content.completion"):
            side = "input_messages" if event.name.endswith("prompt") else "output_messages"
            value = event.attributes.get("gen_ai.prompt", event.attributes.get("gen_ai.completion"))
            legacy.setdefault(side, []).append({"content": json_value(value)})
    if legacy:
        warnings.append("legacy content attributes mapped to gen_ai.*.messages")
        for side, messages in legacy.items():
            body.setdefault(side, messages)
    if not body:
        return None
    return Content(dumps(body), GENAI_CONTENT_TYPE, tuple(sorted(body)))


def _usage(attrs: dict[str, Any], warnings: list[str]) -> dict[str, Any] | None:
    def first(*keys: str) -> int | None:
        for key in keys:
            if key in attrs:
                if not key.startswith("gen_ai.usage.input") and not key.startswith(
                    "gen_ai.usage.output"
                ):
                    warnings.append(f"legacy attribute {key} mapped to gen_ai.usage.*")
                return as_int(attrs[key], minimum=0)
        return None

    usage = compact(
        {
            "input_tokens": first(
                "gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens", "llm.token_count.prompt"
            ),
            "output_tokens": first(
                "gen_ai.usage.output_tokens",
                "gen_ai.usage.completion_tokens",
                "llm.token_count.completion",
            ),
            "cached_input_tokens": as_int(
                attrs.get("gen_ai.usage.cache_read.input_tokens"), minimum=0
            ),
            "reasoning_tokens": as_int(
                attrs.get("gen_ai.usage.reasoning.output_tokens"), minimum=0
            ),
        }
    )
    return {**usage, "source": "provider"} if usage else None


def _target(attrs: dict[str, Any], side: str) -> dict[str, Any] | None:
    return (
        compact(
            {
                "provider": as_str(attrs.get(f"sibyl.route.{side}.provider")),
                "model": as_str(attrs.get(f"sibyl.route.{side}.model")),
            }
        )
        or None
    )


def _genai_attrs(
    span: Span, attrs: dict[str, Any], source: str, warnings: list[str]
) -> dict[str, Any]:
    status, error_type = _status(span, attrs)
    op = as_str(attrs.get("gen_ai.operation.name"))
    headroom_inputs = {
        f"{k}_{u}": as_int(attrs.get(f"sibyl.ratelimit.{k}_{u}"))
        for k in ("limit", "remaining", "reset")
        for u in ("requests", "tokens")
    }
    ratelimit = compact(
        {
            "limit_requests": headroom_inputs["limit_requests"],
            "remaining_requests": headroom_inputs["remaining_requests"],
            "reset_requests_ms": headroom_inputs["reset_requests"],
            "limit_tokens": headroom_inputs["limit_tokens"],
            "remaining_tokens": headroom_inputs["remaining_tokens"],
            "reset_tokens_ms": headroom_inputs["reset_tokens"],
        }
    )
    attempt = as_int(attrs.get("sibyl.retry.attempt"), minimum=1)
    decision = as_str(attrs.get("sibyl.route.decision"))
    output_type = as_str(attrs.get("gen_ai.output.type"))
    return compact(
        {
            "operation": op,
            "provider": _provider(attrs),
            "request_model": _model(attrs),
            "response_model": as_str(attrs.get("gen_ai.response.model")),
            "response_id": as_str(attrs.get("gen_ai.response.id")),
            "status": status,
            "error_type": error_type,
            "http_status": _http_status(attrs),
            "latency_ms": max(0.0, (span.end_ns - span.start_ns) / 1e6),
            "ttfb_ms": as_float(attrs.get("sibyl.ttfb_ms"), minimum=0),
            "streamed": as_bool(attrs.get("sibyl.streamed")),
            "usage": _usage(attrs, warnings),
            "finish_reasons": _finish_reasons(attrs),
            "tool_calls_requested": _tool_calls(attrs),
            "system_fingerprint": _fingerprint(attrs),
            **_run_tree(attrs, handoff=False),
            "request": {
                "temperature": as_float(attrs.get("gen_ai.request.temperature")),
                "top_p": as_float(attrs.get("gen_ai.request.top_p")),
                "top_k": as_int(attrs.get("gen_ai.request.top_k")),
                "max_tokens": as_int(attrs.get("gen_ai.request.max_tokens")),
                "seed": as_int(attrs.get("gen_ai.request.seed")),
                "stop_sequences": as_str_list(attrs.get("gen_ai.request.stop_sequences")),
                "frequency_penalty": as_float(attrs.get("gen_ai.request.frequency_penalty")),
                "presence_penalty": as_float(attrs.get("gen_ai.request.presence_penalty")),
                "choice_count": as_int(attrs.get("gen_ai.request.choice.count")),
                "output_type": output_type if output_type in OUTPUT_TYPES else None,
                "service_tier": as_str(attrs.get("gen_ai.openai.request.service_tier")),
            },
            "context": {
                "model_context_limit": as_int(attrs.get("sibyl.model.context_limit"), minimum=1)
            },
            "ratelimit": ratelimit,
            "retry": compact(
                {
                    "attempt": attempt,
                    "inline_fallback_used": as_bool(attrs.get("sibyl.retry.inline_fallback_used")),
                    "breaker_state": _enum(
                        attrs.get("sibyl.retry.breaker_state"), ("closed", "open", "half_open")
                    ),
                }
            )
            if attempt
            else None,
            "route": compact(
                {
                    "decision": decision,
                    "reason": as_str(attrs.get("sibyl.route.reason")),
                    "from": _target(attrs, "from"),
                    "to": _target(attrs, "to"),
                    "transition_id": as_uuid(attrs.get("sibyl.route.transition_id")),
                }
            )
            if decision in ("primary", "failover", "inline_fallback", "canary", "stale_primary")
            else None,
            "server": {
                "address": as_str(attrs.get("server.address")),
                "port": as_int(attrs.get("server.port")),
            },
            "conversation_id": as_str(attrs.get("gen_ai.conversation.id")),
            "prompt_version": as_str(attrs.get("sibyl.prompt.version")),
            "eval_sample": as_bool(attrs.get("sibyl.eval.sample")),
            "content_hashes": {
                key: as_hash(attrs.get(f"sibyl.content_hash.{key}"))
                for key in ("input", "output", "system")
            },
            "output_chars": as_int(attrs.get("sibyl.output_chars"), minimum=0),
            "contributions": [source],
            "merge_state": "partial",
        }
    )


def _enum(value: Any, allowed: tuple[str, ...]) -> str | None:
    return value if isinstance(value, str) and value in allowed else None


def _provider(attrs: dict[str, Any]) -> str | None:
    for key in ("gen_ai.provider.name", "gen_ai.system", "llm.provider", "llm.system"):
        value = as_str(attrs.get(key))
        if value:
            return value.lower()
    return None


def _model(attrs: dict[str, Any]) -> str | None:
    return as_str(attrs.get("gen_ai.request.model")) or as_str(attrs.get("llm.model_name"))


def _http_status(attrs: dict[str, Any]) -> int | None:
    value = as_int(attrs.get("http.response.status_code"))
    return value if value is not None and 100 <= value <= 599 else None


def _tool_attrs(span: Span, attrs: dict[str, Any]) -> dict[str, Any]:
    status, error_type = _status(span, attrs)
    mcp = as_str(attrs.get("sibyl.mcp.server"))
    tool_type = _enum(attrs.get("gen_ai.tool.type"), TOOL_TYPES) or ("mcp" if mcp else "function")
    return compact(
        {
            "tool_name": as_str(attrs.get("gen_ai.tool.name")),
            "tool_type": tool_type,
            "tool_call_id": as_str(attrs.get("gen_ai.tool.call.id")),
            "mcp_server": mcp,
            "status": status,
            "error_type": error_type,
            "latency_ms": max(0.0, (span.end_ns - span.start_ns) / 1e6),
            "side_effect_class": _enum(attrs.get("sibyl.tool.side_effect_class"), SIDE_EFFECTS)
            or "unknown",
            **_run_tree(attrs, handoff=True),
            **_action_outcome(attrs),
        }
    )


def _tool_content(attrs: dict[str, Any]) -> Content | None:
    body = {}
    for part, key in (
        ("tool_args", "gen_ai.tool.call.arguments"),
        ("tool_result", "gen_ai.tool.call.result"),
    ):
        if key in attrs:
            body[part] = json_value(attrs[key])
    return Content(dumps(body), TOOL_CONTENT_TYPE, tuple(sorted(body))) if body else None


INVOKE_STATUSES = ("ok", "error", "handed_off", "cancelled")


def _invoke_attrs(span: Span, attrs: dict[str, Any]) -> dict[str, Any]:
    """``invoke_agent`` spans are complete invocations: ``agent.invoke(phase=end)``."""
    status, error_type = _status(span, attrs)
    declared = _enum(attrs.get("sibyl.invoke.status"), INVOKE_STATUSES)
    if declared is not None:
        status = declared
    if status == "cancelled" and error_type is None:
        error_type = as_str(attrs.get("sibyl.invoke.cancel_reason"))
    return compact(
        {
            "phase": "end",
            "agent_name": as_str(attrs.get("gen_ai.agent.name")) or span.name,
            "parent_task_id": as_uuid(attrs.get("sibyl.parent_task_id")),
            "status": status,
            "error_type": error_type,
            "duration_ms": max(0.0, (span.end_ns - span.start_ns) / 1e6),
            "steps": as_int(attrs.get("sibyl.invoke.steps"), minimum=0),
            "tool_calls": as_int(attrs.get("sibyl.invoke.tool_calls"), minimum=0),
            "model_calls": as_int(attrs.get("sibyl.invoke.model_calls"), minimum=0),
            **_run_tree(attrs, handoff=True),
        }
    )


def _classify(span: Span, attrs: dict[str, Any], warnings: list[str]) -> str | None:
    op = as_str(attrs.get("gen_ai.operation.name"))
    if op is None:
        kind = as_str(attrs.get("openinference.span.kind"))
        if kind == "LLM" or (
            op is None and ("llm.model_name" in attrs or "gen_ai.system" in attrs)
        ):
            attrs["gen_ai.operation.name"] = "chat"
            warnings.append("legacy span without gen_ai.operation.name classified as chat")
            return "gen_ai.request"
        if kind == "TOOL":
            attrs["gen_ai.operation.name"] = "execute_tool"
            attrs.setdefault("gen_ai.tool.name", attrs.get("tool.name", span.name))
            return "tool.call"
    if op in GENAI_OPERATIONS:
        return "gen_ai.request"
    if op == "execute_tool":
        return "tool.call"
    if op == "invoke_agent":
        return "agent.invoke"
    if span.name == "sibyl.task.outcome":
        return "task.outcome"
    if span.name == "sibyl.feedback":
        return "feedback"
    return None


def _missing(event_type: str, span: Span, attrs: dict[str, Any]) -> list[str]:
    missing = []
    if len(span.trace_id) != 16 or not any(span.trace_id):
        missing.append("trace_id")
    if len(span.span_id) != 8 or not any(span.span_id):
        missing.append("span_id")
    if not span.start_ns or not span.end_ns or span.end_ns < span.start_ns:
        missing.append("start/end time")
    if event_type == "gen_ai.request":
        if not attrs.get("provider"):
            missing.append("gen_ai.provider.name")
        if not attrs.get("request_model"):
            missing.append("gen_ai.request.model")
    elif event_type == "tool.call" and not attrs.get("tool_name"):
        missing.append("gen_ai.tool.name")
    elif event_type == "task.outcome" and not attrs.get("outcome"):
        missing.append("sibyl.task.outcome")
    elif event_type == "feedback" and attrs.get("score") is None:
        missing.append("sibyl.feedback.score")
    return missing


def _envelope(
    tenant_id: UUID,
    span: Span,
    attrs: dict[str, Any],
    resource: dict[str, Any],
    event_type: str,
    source: str,
) -> dict[str, Any]:
    service = as_str(resource.get("service.name")) or "unknown"
    instance = as_str(resource.get("service.instance.id")) or "0"
    emitter = as_str(attrs.get("sibyl.emitter_id")) or f"otel:{service}:{instance}"
    rules = as_str_list(attrs.get("sibyl.redaction.rules")) or []
    state = as_str(attrs.get("sibyl.policy.state"))
    fail_mode = as_str(attrs.get("sibyl.policy.fail_mode"))
    capture = as_str(attrs.get("sibyl.capture.mode"))
    return {
        "schema": "sibyl-event/1",
        "event_id": str(span_event_id(tenant_id, span.trace_id, span.span_id, source, span.end_ns)),
        "type": event_type,
        "tenant_id": str(tenant_id),
        "agent_id": None,
        "task_id": as_uuid(attrs.get("sibyl.task_id")),
        "call_id": as_uuid(attrs.get("sibyl.call_id")),
        "trace_id": span.trace_id.hex(),
        "span_id": span.span_id.hex(),
        **({"parent_span_id": span.parent_span_id.hex()} if len(span.parent_span_id) == 8 else {}),
        "ts": rfc3339_ns(span.end_ns),
        "source": source,
        "emitter_id": emitter,  # truncated after scrubbing (pipeline)
        "seq": as_int(attrs.get("sibyl.seq"), minimum=0) or 0,
        "capture_mode": capture if capture in CAPTURE_MODES else "full",
        "redaction_profile": compact(
            {
                "id": as_str(attrs.get("sibyl.redaction.profile")) or "secrets_only",
                "version": as_int(attrs.get("sibyl.redaction.version"), minimum=1) or 1,
                "rules_fired": rules,
                "secrets_scrubbed": as_int(attrs.get("sibyl.redaction.secrets_scrubbed"), minimum=0)
                or 0,
                "profile_hash": as_hash(attrs.get("sibyl.redaction.profile_hash")),
                "emitter_profile_hash": as_hash(attrs.get("sibyl.redaction.emitter_profile_hash")),
            }
        )
        | {"rules_fired": rules},
        "policy_state": compact(
            {
                "state": state if state in POLICY_STATES else "not_applicable",
                "policy_version": as_int(attrs.get("sibyl.policy.version"), minimum=0),
                "fail_mode": fail_mode if fail_mode in ("open", "closed") else None,
                "snapshot_age_s": as_float(attrs.get("sibyl.policy.snapshot_age_s"), minimum=0),
            }
        ),
    }


def span_candidate(
    index: int, tenant_id: UUID, span: Span, scope: Scope, resource: dict[str, Any], schema_url: str
) -> Candidate:
    attrs = dict(span.attributes)
    cand = Candidate(
        index=index, event=None, trace_hex=span.trace_id.hex(), span_hex=span.span_id.hex()
    )
    cand.env = as_str(resource.get("sibyl.env")) or as_str(attrs.get("sibyl.env"))
    cand.instrumentor = f"{scope.name}/{scope.version}" if scope.name else None
    cand.sdk_version = as_str(attrs.get("sibyl.sdk.version")) or as_str(
        resource.get("sibyl.sdk.version")
    )
    unknown = [k for k in attrs if k.startswith("sibyl.") and not KNOWN_SIBYL.match(k)]
    if unknown:
        cand.warnings.append(f"{len(unknown)} unknown sibyl.* attributes dropped")
    event_type = _classify(span, attrs, cand.warnings)
    if event_type is None:
        cand.dead_letter = "unclassified span"
        return cand
    raw_source = as_str(attrs.get("sibyl.source"))
    source = raw_source if raw_source in ("sdk", "gateway") else "sdk"
    contribution = raw_source if raw_source in ("sdk", "gateway") else "otel"
    if event_type == "gen_ai.request":
        body = _genai_attrs(span, attrs, contribution, cand.warnings)
        cand.content = _genai_content(span, attrs, cand.warnings)
    elif event_type == "tool.call":
        body = _tool_attrs(span, attrs)
        cand.content = _tool_content(attrs)
    elif event_type == "agent.invoke":
        body = _invoke_attrs(span, attrs)
    elif event_type == "task.outcome":
        outcome = _enum(
            attrs.get("sibyl.task.outcome"),
            ("success", "partial", "failure", "abandoned", "handed_off"),
        )
        body = compact({"outcome": outcome, "declared_by": "sdk"})
    else:
        score = as_float(attrs.get("sibyl.feedback.score"), minimum=-1, maximum=1)
        body = compact(
            {
                "feedback_id": str(
                    deterministic_uuid7(
                        span.end_ns // 1_000_000, tenant_id, span.span_id, "feedback"
                    )
                ),
                "target": {"kind": "trace", "id": span.trace_id.hex()},
                "score": score,
                "scale": as_str(attrs.get("sibyl.feedback.scale")) or "thumbs",
                "rater": "end_user",
            }
        )
    missing = _missing(event_type, span, body)
    if missing:
        cand.fail("missing_required", "missing " + ", ".join(missing))
        return cand
    event = _envelope(tenant_id, span, attrs, resource, event_type, source)
    if event_type == "gen_ai.request" and event["call_id"] is None:
        event["call_id"] = str(
            deterministic_uuid7(
                span.end_ns // 1_000_000, tenant_id, span.trace_id, span.span_id, "call"
            )
        )
    event["attrs"] = body
    for name in ("gen_ai.response.model", "gen_ai.usage.output_tokens"):
        if event_type == "gen_ai.request" and name not in attrs:
            cand.warnings.append(f"semconv: span missing {name}")
    cand.event = event
    cand.agent_ref = not_nil(
        as_str(attrs.get("sibyl.agent_id")) or as_str(attrs.get("gen_ai.agent.id"))
    )
    if schema_url and "1.37" not in schema_url:
        cand.warnings.append(f"semconv schema {schema_url.rsplit('/', 1)[-1]} mapped to 1.37.0")
    return cand
