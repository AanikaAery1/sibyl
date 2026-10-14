"""Chaos knobs for one provider double (ML §8.1: chaos lives at the double, never in the
product). Knobs are immutable; every admin update builds a new validated `Knobs`."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field, fields, replace
from typing import Any, Literal, cast

LatencyDist = Literal["fixed", "uniform", "normal", "lognormal"]
_DISTS = ("fixed", "uniform", "normal", "lognormal")


class KnobError(ValueError):
    """An invalid knob value; the admin API answers 422 with this message."""


def _rate(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise KnobError(f"{name} must be a number in [0, 1]")
    return float(value)


def _non_negative(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise KnobError(f"{name} must be a non-negative number")
    return float(value)


@dataclass(frozen=True)
class Latency:
    """Time to first byte. `fixed` uses `ms`; `uniform` `min_ms..max_ms`; `normal`
    `mean_ms ± stddev_ms` (clipped at 0); `lognormal` `median_ms` and `sigma`."""

    dist: LatencyDist = "fixed"
    ms: float = 0.0
    min_ms: float = 0.0
    max_ms: float = 0.0
    mean_ms: float = 0.0
    stddev_ms: float = 0.0
    median_ms: float = 0.0
    sigma: float = 0.0

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> Latency:
        dist = raw.get("dist", "fixed")
        if dist not in _DISTS:
            raise KnobError(f"latency.dist must be one of {_DISTS}")
        values = {k: _non_negative(f"latency.{k}", raw[k]) for k in raw if k != "dist"}
        unknown = set(values) - {f.name for f in fields(cls)}
        if unknown:
            raise KnobError(f"unknown latency keys {sorted(unknown)}")
        latency = cls(dist=cast(LatencyDist, dist), **values)
        if latency.dist == "uniform" and latency.max_ms < latency.min_ms:
            raise KnobError("latency.max_ms must be >= latency.min_ms")
        return latency


@dataclass(frozen=True)
class Ramp:
    """Rate-limit headroom ramps linearly from `start_headroom` to `end_headroom` over
    `ramp_s` seconds after the knob is set; afterwards 429 if `then_429` (S-02/S-03)."""

    start_headroom: float = 1.0
    end_headroom: float = 0.02
    ramp_s: float = 720.0
    then_429: bool = True
    retry_after_s: int = 20

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> Ramp:
        ramp = cls(
            start_headroom=_rate("ramp.start_headroom", raw.get("start_headroom", 1.0)),
            end_headroom=_rate("ramp.end_headroom", raw.get("end_headroom", 0.02)),
            ramp_s=_non_negative("ramp.ramp_s", raw.get("ramp_s", 720.0)),
            then_429=bool(raw.get("then_429", True)),
            retry_after_s=int(_non_negative("ramp.retry_after_s", raw.get("retry_after_s", 20))),
        )
        return ramp


@dataclass(frozen=True)
class ToolLoop:
    """Answer with a tool call at `rate` (when the request offers tools). `arguments` (A-5)
    is a list of argument objects; each request gets one picked by a hash of its prompt, so the
    same seed proposes the same actions."""

    rate: float = 0.0
    tool_name: str | None = None
    arguments: tuple[str, ...] = ()


@dataclass(frozen=True)
class Override:
    """First match wins: requests with this credential and/or model get `patch` applied
    on top of the base knobs (S-22: fail only one tenant's credential)."""

    credential: str | None = None
    model: str | None = None
    patch: Mapping[str, Any] = field(default_factory=dict)

    def matches(self, credential: str | None, model: str) -> bool:
        if self.credential is not None and self.credential != credential:
            return False
        return not (self.model is not None and self.model != model)


@dataclass(frozen=True)
class Knobs:
    error_rate: float = 0.0
    error_statuses: tuple[int, ...] = (500, 502, 503)
    latency: Latency = field(default_factory=Latency)
    inter_chunk_ms: float = 0.0
    limit_requests: int = 10_000
    limit_tokens: int = 2_000_000
    ramp: Ramp | None = None
    refusal_rate: float = 0.0
    truncation_rate: float = 0.0
    truncation_fraction: float = 0.3
    schema_failure_rate: float = 0.0
    tool_loop: ToolLoop = field(default_factory=ToolLoop)
    token_multiplier: float = 1.0
    cost_per_input_token_usd: float = 0.0
    cost_per_output_token_usd: float = 0.0
    outage: bool = False
    missing_models: tuple[str, ...] = ()
    served_model: str | None = None  # silent model swap: the `model` the response reports
    system_fingerprint: str | None = None
    overrides: tuple[Override, ...] = ()

    # ---------------------------------------------------------------- parse / merge

    def merged(self, patch: Mapping[str, Any]) -> Knobs:
        """A new `Knobs` with `patch` applied; unknown keys and bad values raise."""
        known = {f.name for f in fields(self)}
        unknown = set(patch) - known
        if unknown:
            raise KnobError(f"unknown knobs {sorted(unknown)}")
        changes: dict[str, Any] = {}
        for key, value in patch.items():
            changes[key] = _PARSERS[key](value)
        return replace(self, **changes)

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> Knobs:
        return cls().merged(raw)

    def for_request(self, credential: str | None, model: str) -> Knobs:
        for override in self.overrides:
            if override.matches(credential, model):
                return replace(self, overrides=()).merged(override.patch)
        return self

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(json.dumps(asdict(self)))
        data["overrides"] = [
            {
                "match": {
                    k: v
                    for k, v in (
                        ("credential", "***" if o.credential else None),
                        ("model", o.model),
                    )
                    if v is not None
                },
                "knobs": dict(o.patch),
            }
            for o in self.overrides
        ]
        return data


def _statuses(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise KnobError("error_statuses must be a non-empty list of HTTP status codes")
    for status in value:
        if not isinstance(status, int) or isinstance(status, bool) or not 400 <= status <= 599:
            raise KnobError("error_statuses entries must be integers in 400..599")
    return tuple(value)


def _models(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise KnobError("missing_models must be a list of model names")
    return tuple(value)


def _tool_loop(value: Any) -> ToolLoop:
    if not isinstance(value, Mapping):
        raise KnobError("tool_loop must be an object {rate, tool_name}")
    name = value.get("tool_name")
    if name is not None and not isinstance(name, str):
        raise KnobError("tool_loop.tool_name must be a string")
    raw_args = value.get("arguments") or []
    if not isinstance(raw_args, list) or not all(isinstance(a, Mapping) for a in raw_args):
        raise KnobError("tool_loop.arguments must be a list of objects")
    return ToolLoop(
        rate=_rate("tool_loop.rate", value.get("rate", 0.0)),
        tool_name=name,
        arguments=tuple(json.dumps(dict(a), sort_keys=True) for a in raw_args),
    )


def _opt_str(name: str, limit: int) -> Any:
    def parse(value: Any) -> str | None:
        if value is not None and (not isinstance(value, str) or not 0 < len(value) <= limit):
            raise KnobError(f"{name} must be null or a string of 1..{limit} characters")
        return value

    return parse


def _overrides(value: Any) -> tuple[Override, ...]:
    if not isinstance(value, list):
        raise KnobError("overrides must be a list of {match, knobs}")
    parsed = []
    for item in value:
        match = item.get("match", {}) if isinstance(item, Mapping) else None
        patch = item.get("knobs", {}) if isinstance(item, Mapping) else None
        if not isinstance(match, Mapping) or not isinstance(patch, Mapping) or not match:
            raise KnobError("each override needs a non-empty match and a knobs object")
        if "overrides" in patch:
            raise KnobError("overrides cannot nest")
        Knobs().merged(patch)  # validate eagerly
        parsed.append(
            Override(
                credential=match.get("credential"), model=match.get("model"), patch=dict(patch)
            )
        )
    return tuple(parsed)


def _positive_int(name: str) -> Any:
    def parse(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise KnobError(f"{name} must be a positive integer")
        return value

    return parse


def _bool(name: str) -> Any:
    def parse(value: Any) -> bool:
        if not isinstance(value, bool):
            raise KnobError(f"{name} must be true or false")
        return value

    return parse


_PARSERS: dict[str, Any] = {
    "error_rate": lambda v: _rate("error_rate", v),
    "error_statuses": _statuses,
    "latency": lambda v: Latency.parse(v if isinstance(v, Mapping) else {"_": v}),
    "inter_chunk_ms": lambda v: _non_negative("inter_chunk_ms", v),
    "limit_requests": _positive_int("limit_requests"),
    "limit_tokens": _positive_int("limit_tokens"),
    "ramp": lambda v: None if v is None else Ramp.parse(v),
    "refusal_rate": lambda v: _rate("refusal_rate", v),
    "truncation_rate": lambda v: _rate("truncation_rate", v),
    "truncation_fraction": lambda v: _rate("truncation_fraction", v),
    "schema_failure_rate": lambda v: _rate("schema_failure_rate", v),
    "tool_loop": _tool_loop,
    "token_multiplier": lambda v: _non_negative("token_multiplier", v),
    "cost_per_input_token_usd": lambda v: _non_negative("cost_per_input_token_usd", v),
    "cost_per_output_token_usd": lambda v: _non_negative("cost_per_output_token_usd", v),
    "outage": _bool("outage"),
    "missing_models": _models,
    "served_model": _opt_str("served_model", 128),
    "system_fingerprint": _opt_str("system_fingerprint", 128),
    "overrides": _overrides,
}
