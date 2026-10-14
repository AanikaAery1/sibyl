"""Provider response extraction (D50/D51 inputs): served model, provider fingerprint, usage,
finish reasons, refusals and the tool calls a model proposed, for every supported API.

APIs: `openai.chat` (Chat Completions), `openai.responses` (Responses), `openai.embeddings`,
`anthropic.messages`, `google.generate_content`. Streams are reassembled by `Accumulator`
into a response-shaped dict so one `extract()` serves both paths. Pure functions over
pydantic objects or dicts; nothing here reads content unless asked for the output body.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

MAX_TOOL_CALLS: Final = 32
MAX_NAME: Final = 128
REFUSAL: Final = "refusal"
GOOGLE_REFUSALS: Final = frozenset(
    {"safety", "prohibited_content", "blocklist", "spii", "image_safety", "recitation"}
)
_FINISH_ALIASES: Final = {"max_tokens": "length", "max_output_tokens": "length"}


def get(obj: Any, *path: str | int) -> Any:
    """Attribute or key access through pydantic objects, dicts and lists; None if absent."""
    for step in path:
        if obj is None:
            return None
        if isinstance(step, int):
            try:
                obj = obj[step]
            except (IndexError, KeyError, TypeError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(step)
        else:
            obj = getattr(obj, step, None)
    return obj


def plain(obj: Any) -> Any:
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            return dump(mode="json", exclude_none=True)
        except Exception:  # a provider model that cannot dump must not break the call
            return str(obj)
    if isinstance(obj, (list, tuple)):
        return [plain(item) for item in obj]
    if isinstance(obj, dict):
        return {key: plain(value) for key, value in obj.items()}
    return obj


def _enum_text(value: Any) -> str | None:
    """Provider enums (google `FinishReason.STOP`) and strings as lower-case text."""
    if value is None:
        return None
    name = getattr(value, "name", None)
    text = str(name if isinstance(name, str) else getattr(value, "value", value))
    text = text.rsplit(".", 1)[-1].strip().lower()
    return text or None


def _finish(value: Any) -> str | None:
    text = _enum_text(value)
    return _FINISH_ALIASES.get(text, text) if text else None


@dataclass
class Extracted:
    response_id: str | None = None
    response_model: str | None = None
    system_fingerprint: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    finish_reasons: list[str] = field(default_factory=list)
    refusal: bool = False
    tool_calls: list[tuple[str | None, str]] = field(default_factory=list)
    output: list[dict[str, Any]] | None = None

    def add_tool(self, call_id: Any, name: Any) -> None:
        if name and len(self.tool_calls) < MAX_TOOL_CALLS:
            ident = str(call_id)[:MAX_NAME] if call_id else None
            self.tool_calls.append((ident, str(name)[:MAX_NAME]))

    def span_attributes(self) -> dict[str, Any]:
        attrs: dict[str, Any] = {
            "gen_ai.response.id": self.response_id,
            "gen_ai.response.model": self.response_model,
            "gen_ai.usage.input_tokens": self.input_tokens,
            "gen_ai.usage.output_tokens": self.output_tokens,
        }
        if self.system_fingerprint:
            attrs["sibyl.system_fingerprint"] = self.system_fingerprint[:MAX_NAME]
        if self.finish_reasons:
            attrs["gen_ai.response.finish_reasons"] = list(self.finish_reasons)
        if self.refusal:
            attrs["sibyl.refusal"] = True
        if self.tool_calls:
            attrs["sibyl.tool_calls.names"] = [name for _, name in self.tool_calls]
            attrs["sibyl.tool_calls.ids"] = [ident or "" for ident, _ in self.tool_calls]
        return attrs


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


# ----------------------------------------------------------------------------- per API


def _openai_chat(response: Any, out: Extracted) -> None:
    usage = get(response, "usage")
    out.input_tokens = _int(get(usage, "prompt_tokens")) or _int(get(usage, "input_tokens"))
    out.output_tokens = _int(get(usage, "completion_tokens")) or _int(get(usage, "output_tokens"))
    out.system_fingerprint = get(response, "system_fingerprint") or None
    messages: list[dict[str, Any]] = []
    for choice in get(response, "choices") or []:
        reason = _finish(get(choice, "finish_reason"))
        if reason:
            out.finish_reasons.append(reason)
        message = get(choice, "message")
        if get(message, "refusal"):
            out.refusal = True
        for call in get(message, "tool_calls") or []:
            out.add_tool(get(call, "id"), get(call, "function", "name") or get(call, "name"))
        body = plain(message) or {}
        messages.append(body if isinstance(body, dict) else {"content": body})
    out.output = messages


def _openai_responses(response: Any, out: Extracted) -> None:
    usage = get(response, "usage")
    out.input_tokens = _int(get(usage, "input_tokens"))
    out.output_tokens = _int(get(usage, "output_tokens"))
    items = get(response, "output") or []
    called = False
    for item in items:
        kind = get(item, "type")
        if kind == "function_call":
            called = True
            out.add_tool(get(item, "call_id") or get(item, "id"), get(item, "name"))
        elif kind == "message":
            for part in get(item, "content") or []:
                if get(part, "type") == "refusal":
                    out.refusal = True
    status = _enum_text(get(response, "status"))
    if status == "incomplete":
        reason = _finish(get(response, "incomplete_details", "reason")) or "incomplete"
        out.finish_reasons.append(reason)
    elif status == "completed":
        out.finish_reasons.append("tool_calls" if called else "stop")
    elif status in ("failed", "cancelled"):
        out.finish_reasons.append(status)
    out.output = [{"role": "assistant", "content": plain(items)}]


def _anthropic(response: Any, out: Extracted) -> None:
    usage = get(response, "usage")
    out.input_tokens = _int(get(usage, "input_tokens"))
    out.output_tokens = _int(get(usage, "output_tokens"))
    reason = _finish(get(response, "stop_reason"))
    if reason:
        out.finish_reasons.append(reason)
        out.refusal = reason == REFUSAL
    content = get(response, "content") or []
    for block in content:
        if get(block, "type") == "tool_use":
            out.add_tool(get(block, "id"), get(block, "name"))
    out.output = [{"role": "assistant", "content": plain(content) or []}]


def _google(response: Any, out: Extracted) -> None:
    usage = get(response, "usage_metadata")
    out.input_tokens = _int(get(usage, "prompt_token_count"))
    out.output_tokens = _int(get(usage, "candidates_token_count"))
    out.response_model = get(response, "model_version") or out.response_model
    out.response_id = get(response, "response_id") or out.response_id
    if get(response, "prompt_feedback", "block_reason"):
        out.refusal = True
    messages: list[dict[str, Any]] = []
    for candidate in get(response, "candidates") or []:
        reason = _finish(get(candidate, "finish_reason"))
        if reason:
            out.finish_reasons.append(reason)
            if reason in GOOGLE_REFUSALS:
                out.refusal = True
        parts = get(candidate, "content", "parts") or []
        for part in parts:
            call = get(part, "function_call")
            if call is not None:
                out.add_tool(get(call, "id"), get(call, "name"))
        messages.append({"role": "model", "content": plain(parts) or []})
    out.output = messages


def extract(api: str, response: Any) -> Extracted:
    out = Extracted(
        response_id=_str(get(response, "id")),
        response_model=_str(get(response, "model")),
    )
    if api == "openai.chat":
        _openai_chat(response, out)
    elif api == "openai.responses":
        _openai_responses(response, out)
    elif api == "anthropic.messages":
        _anthropic(response, out)
    elif api == "google.generate_content":
        _google(response, out)
    else:  # embeddings: usage only
        usage = get(response, "usage")
        out.input_tokens = _int(get(usage, "prompt_tokens")) or _int(get(usage, "input_tokens"))
    return out


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


# ----------------------------------------------------------------------------- streams


class Accumulator:
    """Reassembles streamed chunks/events into a response-shaped dict for `extract()`."""

    def __init__(self, api: str) -> None:
        self.api = api
        self.text: list[str] = []
        self.data: dict[str, Any] = {"usage": {}}
        self.finish: str | None = None
        self.refusal: list[str] = []
        self.tools: dict[int, dict[str, Any]] = {}
        self.final: Any = None

    def add(self, chunk: Any) -> None:
        if self.api == "anthropic.messages":
            self._anthropic(chunk)
        elif self.api == "openai.responses":
            self._responses(chunk)
        elif self.api == "google.generate_content":
            self._google(chunk)
        else:
            self._openai(chunk)

    def _openai(self, chunk: Any) -> None:
        for key in ("id", "model", "system_fingerprint"):
            if get(chunk, key):
                self.data[key] = get(chunk, key)
        if get(chunk, "usage") is not None:
            self.data["usage"] = plain(get(chunk, "usage"))
        delta = get(chunk, "choices", 0, "delta")
        if get(delta, "content"):
            self.text.append(str(get(delta, "content")))
        if get(delta, "refusal"):
            self.refusal.append(str(get(delta, "refusal")))
        for call in get(delta, "tool_calls") or []:
            index = get(call, "index")
            slot = self.tools.setdefault(index if isinstance(index, int) else len(self.tools), {})
            if get(call, "id"):
                slot["id"] = get(call, "id")
            if get(call, "function", "name"):
                slot["name"] = get(call, "function", "name")
        reason = get(chunk, "choices", 0, "finish_reason")
        if reason:
            self.finish = str(reason)

    def _anthropic(self, event: Any) -> None:
        kind = get(event, "type")
        if kind == "message_start":
            self.data["id"] = get(event, "message", "id")
            self.data["model"] = get(event, "message", "model")
            self.data["usage"]["input_tokens"] = get(event, "message", "usage", "input_tokens")
        elif kind == "content_block_start" and get(event, "content_block", "type") == "tool_use":
            block = get(event, "content_block")
            self.tools[len(self.tools)] = {"id": get(block, "id"), "name": get(block, "name")}
        elif kind == "content_block_delta" and get(event, "delta", "text"):
            self.text.append(str(get(event, "delta", "text")))
        elif kind == "message_delta":
            self.finish = get(event, "delta", "stop_reason") or self.finish
            self.data["usage"]["output_tokens"] = get(event, "usage", "output_tokens")

    def _responses(self, event: Any) -> None:
        response = get(event, "response")
        if response is not None and get(event, "type") in (
            "response.completed",
            "response.incomplete",
            "response.failed",
        ):
            self.final = response
        elif response is not None and self.final is None:
            self.data["id"] = get(response, "id")
            self.data["model"] = get(response, "model")
        delta = get(event, "delta")
        if get(event, "type") == "response.output_text.delta" and isinstance(delta, str):
            self.text.append(delta)

    def _google(self, chunk: Any) -> None:
        for key in ("model_version", "response_id"):
            if get(chunk, key):
                self.data[key] = get(chunk, key)
        if get(chunk, "usage_metadata") is not None:
            self.data["usage_metadata"] = plain(get(chunk, "usage_metadata"))
        if get(chunk, "prompt_feedback", "block_reason"):
            self.data["prompt_feedback"] = plain(get(chunk, "prompt_feedback"))
        candidate = get(chunk, "candidates", 0)
        for part in get(candidate, "content", "parts") or []:
            if get(part, "text"):
                self.text.append(str(get(part, "text")))
            call = get(part, "function_call")
            if call is not None:
                self.tools[len(self.tools)] = {"id": get(call, "id"), "name": get(call, "name")}
        if get(candidate, "finish_reason") is not None:
            self.finish = _enum_text(get(candidate, "finish_reason"))

    def response(self) -> Any:
        text = "".join(self.text)
        tools = [self.tools[i] for i in sorted(self.tools)]
        if self.api == "openai.responses":
            if self.final is not None:
                return self.final
            return {**self.data, "status": "incomplete", "output": []}
        if self.api == "anthropic.messages":
            blocks: list[dict[str, Any]] = [{"type": "text", "text": text}]
            blocks += [{"type": "tool_use", **t} for t in tools]
            return {**self.data, "stop_reason": self.finish, "content": blocks}
        if self.api == "google.generate_content":
            parts: list[dict[str, Any]] = [{"text": text}] if text else []
            parts += [{"function_call": t} for t in tools]
            return {
                **self.data,
                "candidates": [{"finish_reason": self.finish, "content": {"parts": parts}}],
            }
        message: dict[str, Any] = {"role": "assistant", "content": text}
        if self.refusal:
            message["refusal"] = "".join(self.refusal)
        if tools:
            message["tool_calls"] = [
                {"id": t.get("id"), "function": {"name": t.get("name")}} for t in tools
            ]
        return {**self.data, "choices": [{"finish_reason": self.finish, "message": message}]}
