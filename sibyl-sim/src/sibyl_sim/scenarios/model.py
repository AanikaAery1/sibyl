"""The scenario DSL (YAML, one file per scenario; qa-expert §1.4, ML §8.2).

Everything the oracle needs is in the file; nothing is implied by code:

    id, title, seed, duration_s, smoke, phase, requires   identity and gating
    tenants      per tenant: default traffic profile and per-agent profiles
    profiles     traffic shapes (rps, path through gateway or SDK, tools, task length)
    chaos        timeline of knob changes at the doubles, the status feeds, ingest, actors
    labels       ground truth (onset / peak / recovery / precursor) per agent
    expect       one predicate per entry: {<predicate>: {args}, requires?, severity?}
    personas     scripted persona actions (the Admin, the Operator, the Auditor)
    budgets      per-agent monthly budgets the admin sets through the API before t=0
    cadences     per-agent expected traffic cadence (s) declared the same way (R9, S-18)

`requires` names the wave-2 lanes a scenario or an expectation depends on: S (saga,
approvals, kill switch, queue), P (prediction, alert loop), U (audit, governance). Missing lanes
skip with an allowlisted reason, never a fake (WAVE2 rules).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Final

LANES: Final = ("S", "P", "U")
MONEY: Final = re.compile(r"[0-9]+\.[0-9]{4}")  # the API's money string (MONEY_PATTERN)
TENANTS: Final = ("meridian", "northstar", "sandbox")
DEFAULT_TENANT: Final = "meridian"
DOUBLES: Final = ("openai-stub", "anthropic-stub", "ollama-stub")
FEEDS: Final = ("openai", "anthropic", "ollama")
LABEL_KINDS: Final = ("precursor", "onset", "peak", "recovery")
SEVERITIES: Final = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
DEFAULT_SEED: Final = 20261011
PERSONAS: Final = ("admin", "operator", "auditor")


@dataclass(frozen=True)
class PredicateSpec:
    severity: str
    lanes: tuple[str, ...] = ()


PREDICATES: Final[Mapping[str, PredicateSpec]] = MappingProxyType(
    {
        # wave-1 surfaces: health engine, alerts via SSE, gateway, ingest, reads
        "detect": PredicateSpec("MEDIUM"),
        "no_alert": PredicateSpec("HIGH"),
        "quiet": PredicateSpec("HIGH"),
        "isolated": PredicateSpec("CRITICAL"),
        "observed": PredicateSpec("CRITICAL"),
        "explainable": PredicateSpec("CRITICAL"),
        "health": PredicateSpec("MEDIUM"),
        "band_episodes": PredicateSpec("MEDIUM"),
        "provider_incident": PredicateSpec("MEDIUM"),
        "recommended_action": PredicateSpec("MEDIUM"),
        "failure_mode": PredicateSpec("MEDIUM"),
        "gateway_route": PredicateSpec("MEDIUM"),
        "event_seen": PredicateSpec("MEDIUM"),
        "no_duplicates": PredicateSpec("HIGH"),
        "scores_at_least": PredicateSpec("HIGH"),
        "contract": PredicateSpec("HIGH"),
        # wave-2 lanes
        "action": PredicateSpec("HIGH", ("S",)),
        "no_action": PredicateSpec("HIGH", ("S",)),
        "single_failover": PredicateSpec("HIGH", ("S",)),
        "tier_gate": PredicateSpec("CRITICAL", ("S",)),
        "rto": PredicateSpec("HIGH", ("S",)),
        "handoff": PredicateSpec("HIGH", ("S",)),
        "gateway_refused": PredicateSpec("CRITICAL", ("S",)),
        "predict": PredicateSpec("MEDIUM", ("P",)),
        "verdict_loop": PredicateSpec("MEDIUM", ("P",)),
        "audit_has": PredicateSpec("HIGH", ("U",)),
        # Action Gate (A-5): the gate is zero unauthorised actions executed
        "actions": PredicateSpec("CRITICAL"),
        # Sibyl Sentinel (S-33, oracle/sentinel.py): advisory only, budgeted, capture-gated
        "sentinel_findings": PredicateSpec("HIGH"),
        "sentinel_advisory": PredicateSpec("CRITICAL"),
        "sentinel_budget": PredicateSpec("HIGH"),
        "sentinel_capture": PredicateSpec("CRITICAL"),
        "sentinel_quality": PredicateSpec("LOW"),
    }
)

PERSONA_VERBS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "close_alert": ("P",),
        "close_without_verdict": ("P",),
        "drain_unverdicted": ("P",),
        "approve": ("S",),
        "deny": ("S",),
        "self_approve": ("S",),
        "undo": ("S",),
        "clear_hold": ("S",),
        "fail_back": ("S",),
        "pull_kill": ("S",),
        "release_kill": ("S",),
        "claim_task": ("S",),
        "complete_task": ("S",),
        "edit_rule": (),
        "revoke_credential": (),
        "draft_chain": (),
        "open_incident": ("S",),
        "approve_chain": (),
        "audit_check": ("U",),
        "label_write_attempt": ("P",),
        "install_action_policy": (),
        "approve_action_policy": (),
        "decide_held": (),
        # Sibyl Sentinel (S-33)
        "configure_sentinel": (),
        "set_capture_mode": (),
    }
)


class ScenarioError(ValueError):
    """A scenario file that cannot run; the message names the field."""


@dataclass(frozen=True, order=True)
class AgentRef:
    tenant: str
    slug: str

    @classmethod
    def parse(cls, raw: Any) -> AgentRef:
        if not isinstance(raw, str) or not raw:
            raise ScenarioError(f"agent reference must be a string, got {raw!r}")
        parts = raw.split("/")
        if len(parts) == 1:
            return cls(DEFAULT_TENANT, parts[0])
        if len(parts) == 2 and all(parts):
            return cls(parts[0], parts[1])
        raise ScenarioError(f"agent reference {raw!r} must be <slug> or <tenant>/<slug>")

    def __str__(self) -> str:
        return f"{self.tenant}/{self.slug}"


@dataclass(frozen=True)
class Profile:
    """A traffic shape. `via`: gateway (OpenAI-compatible surface) or sdk (instrumented
    calls straight to the double, plus tool spans, tasks and outcomes)."""

    name: str
    rps: float = 0.1
    via: str = "gateway"
    tools: bool = False
    tool_calls_per_task: int = 0
    stream: bool = False
    max_tokens: int | None = None
    model: str | None = None  # request a model other than the agent's primary one
    # `X-Sibyl-Fallback` (API §3): `none` opts the client out of inline fallback, so a tier-2
    # outage is not masked (B35: a masked outage starts no saga) and the failover path runs
    fallback: str | None = None

    @classmethod
    def parse(cls, name: str, raw: Mapping[str, Any]) -> Profile:
        known = {
            "rps",
            "via",
            "tools",
            "tool_calls_per_task",
            "stream",
            "max_tokens",
            "model",
            "fallback",
        }
        unknown = set(raw) - known
        if unknown:
            raise ScenarioError(f"profile {name}: unknown keys {sorted(unknown)}")
        via = raw.get("via", "gateway")
        if via not in ("gateway", "sdk"):
            raise ScenarioError(f"profile {name}: via must be gateway or sdk")
        fallback = raw.get("fallback")
        if fallback is not None and fallback not in ("inherit", "none", "inline"):
            raise ScenarioError(f"profile {name}: fallback must be inherit, none or inline")
        rps = float(raw.get("rps", 0.1))
        if not 0 <= rps <= 50:
            raise ScenarioError(f"profile {name}: rps must be in [0, 50]")
        return cls(
            name,
            rps,
            via,
            bool(raw.get("tools", False)),
            int(raw.get("tool_calls_per_task", 0)),
            bool(raw.get("stream", False)),
            raw.get("max_tokens"),
            raw.get("model"),
            fallback,
        )


BUILTIN_PROFILES: Final[Mapping[str, Profile]] = MappingProxyType(
    {
        "idle": Profile("idle", rps=0.0),
        "steady": Profile("steady", rps=0.1),
        "busy": Profile("busy", rps=0.5),
        "hot": Profile("hot", rps=1.0),
        "sdk_steady": Profile("sdk_steady", rps=0.2, via="sdk"),
        "sdk_tools": Profile("sdk_tools", rps=0.4, via="sdk", tools=True, tool_calls_per_task=1),
        "sdk_tasks": Profile("sdk_tasks", rps=0.2, via="sdk", tools=True, tool_calls_per_task=3),
    }
)


@dataclass(frozen=True)
class TenantPlan:
    slug: str
    default_profile: str = "steady"
    agents: Mapping[str, str] = field(default_factory=dict)  # slug -> profile


@dataclass(frozen=True)
class ChaosStep:
    at: float
    kind: str  # double | status | ingest | actor
    target: str
    patch: Mapping[str, Any] = field(default_factory=dict)
    reset: bool = False
    agents: tuple[AgentRef, ...] = ()
    tenants: tuple[str, ...] = ()
    pause_s: float = 0.0
    note: str = ""


@dataclass(frozen=True)
class Label:
    agent: AgentRef
    kind: str
    t: float
    failure_mode: str | None = None
    # B35: the agent's every call is rescued by inline fallback, so it has no failed call
    # of its own; detection is provider scope (R4 + its band failed) or L5 fallback pressure
    masked: bool = False


@dataclass(frozen=True)
class Expectation:
    predicate: str
    args: Mapping[str, Any]
    requires: tuple[str, ...] = ()
    severity: str = "MEDIUM"
    note: str = ""
    report_only: bool = False  # measured and reported, never failing the run (lane not merged)

    @property
    def name(self) -> str:
        target = self.args.get("agent") or self.args.get("tenant") or self.args.get("provider")
        return f"{self.predicate}({target})" if target else self.predicate


@dataclass(frozen=True)
class PersonaStep:
    at: float | str  # seconds, or "end"
    persona: str
    verb: str
    tenant: str = DEFAULT_TENANT
    args: Mapping[str, Any] = field(default_factory=dict)
    requires: tuple[str, ...] = ()


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    duration_s: float
    seed: int = DEFAULT_SEED
    smoke: bool = False
    phase: str = "1"
    gate_class: str = "none"  # hard | silent | ramp | none: which TTD row applies
    requires: tuple[str, ...] = ()
    tenants: Mapping[str, TenantPlan] = field(default_factory=dict)
    profiles: Mapping[str, Profile] = field(default_factory=dict)
    chaos: tuple[ChaosStep, ...] = ()
    labels: tuple[Label, ...] = ()
    expect: tuple[Expectation, ...] = ()
    personas: tuple[PersonaStep, ...] = ()
    notes: str = ""
    settle_s: float = 25.0  # after traffic stops: let rollup + scoring close the last ticks
    warmup_min: int = 60  # history replayed before t=0 so agents are not provisional (ML §3.8)
    warmup_agents: Mapping[AgentRef, int] = field(default_factory=dict)  # per-agent minutes
    drift: Mapping[str, float] = field(default_factory=dict)  # scaled DriftConfig (S-31)
    health_poll_s: float = 15.0
    # continuity-plan monthly budgets set through the API before t=0 (S-05, S-06)
    budgets: Mapping[AgentRef, str] = field(default_factory=dict)
    # continuity-plan expected_cadence_s, same path: R9 runs on declared cadences only (S-18)
    cadences: Mapping[AgentRef, int] = field(default_factory=dict)

    def tenant(self, slug: str) -> TenantPlan:
        return self.tenants.get(slug) or TenantPlan(slug, "idle" if slug == "sandbox" else "steady")

    def profile(self, name: str) -> Profile:
        found = self.profiles.get(name) or BUILTIN_PROFILES.get(name)
        if found is None:
            raise ScenarioError(f"{self.id}: unknown profile {name!r}")
        return found

    def agents_with_profile(self, name: str) -> tuple[AgentRef, ...]:
        return tuple(
            sorted(
                AgentRef(t.slug, slug)
                for t in self.tenants.values()
                for slug, profile in t.agents.items()
                if profile == name
            )
        )

    def lanes_needed(self) -> frozenset[str]:
        lanes = set(self.requires)
        for exp in self.expect:
            lanes |= set(exp.requires)
        for step in self.personas:
            lanes |= set(step.requires)
        return frozenset(lanes)


# ---------------------------------------------------------------------------- parsing


def _lanes(raw: Any, where: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list) or any(r not in LANES for r in raw):
        raise ScenarioError(f"{where}: requires must be a list drawn from {LANES}")
    return tuple(sorted(set(raw)))


def _num(raw: Any, where: str, *, minimum: float = 0.0) -> float:
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or raw < minimum:
        raise ScenarioError(f"{where} must be a number >= {minimum}")
    return float(raw)


def _tenants(raw: Any) -> dict[str, TenantPlan]:
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ScenarioError("tenants must be a mapping")
    out: dict[str, TenantPlan] = {}
    for slug in TENANTS:
        body = raw.get(slug) or {}
        default = body.get("default_profile", "idle" if slug == "sandbox" else "steady")
        agents = body.get("agents") or {}
        if not isinstance(agents, Mapping):
            raise ScenarioError(f"tenants.{slug}.agents must map slug -> profile")
        out[slug] = TenantPlan(slug, str(default), {str(k): str(v) for k, v in agents.items()})
    unknown = set(raw) - set(TENANTS)
    if unknown:
        raise ScenarioError(f"unknown tenant(s) {sorted(unknown)}; the world has {TENANTS}")
    return out


def _repeat(base: ChaosStep, raw: Mapping[str, Any], where: str) -> list[ChaosStep]:
    every = _num(raw.get("every_s"), f"{where}.repeat.every_s", minimum=1)
    times = int(_num(raw.get("times"), f"{where}.repeat.times", minimum=1))
    after = _num(raw.get("then_after_s", 0), f"{where}.repeat.then_after_s")
    then = raw.get("then")
    steps: list[ChaosStep] = []
    for n in range(times):
        at = base.at + n * every
        steps.append(ChaosStep(at, base.kind, base.target, base.patch, base.reset, base.agents))
        if then is not None:
            if not isinstance(then, Mapping):
                raise ScenarioError(f"{where}.repeat.then must be a knob mapping")
            steps.append(
                ChaosStep(at + after, base.kind, base.target, dict(then), False, base.agents)
            )
    return steps


def _chaos_step(raw: Any, n: int, duration: float) -> list[ChaosStep]:
    where = f"chaos[{n}]"
    if not isinstance(raw, Mapping):
        raise ScenarioError(f"{where} must be a mapping")
    at = _num(raw.get("at"), f"{where}.at")
    if at > duration:
        raise ScenarioError(f"{where}.at={at} is after the end ({duration} s)")
    kinds = [k for k in ("double", "status", "ingest", "actor") if k in raw]
    if len(kinds) != 1:
        raise ScenarioError(f"{where} needs exactly one target: double, status, ingest or actor")
    kind = kinds[0]
    target = str(raw[kind])
    if kind == "double" and target not in DOUBLES:
        raise ScenarioError(f"{where}: unknown double {target!r}; expected one of {DOUBLES}")
    if kind == "status" and target not in FEEDS:
        raise ScenarioError(f"{where}: unknown status feed {target!r}; expected one of {FEEDS}")
    if kind == "ingest" and target not in TENANTS:
        raise ScenarioError(f"{where}: ingest target must be a tenant")
    if kind == "actor":
        target = str(AgentRef.parse(target))
    patch = raw.get("set") or {}
    if not isinstance(patch, Mapping):
        raise ScenarioError(f"{where}.set must be a mapping")
    agents = tuple(AgentRef.parse(a) for a in raw.get("agents") or ())
    tenants = tuple(str(t) for t in raw.get("tenants") or ())
    step = ChaosStep(
        at,
        kind,
        target,
        dict(patch),
        bool(raw.get("reset", False)),
        agents,
        tenants,
        float(raw.get("pause_s", 0) or 0),
        str(raw.get("note", "")),
    )
    if "repeat" in raw:
        steps = _repeat(step, raw["repeat"], where)
        if any(s.at > duration for s in steps):
            raise ScenarioError(f"{where}.repeat runs after the end ({duration} s)")
        return steps
    return [step]


def _label(raw: Any, n: int) -> Label:
    where = f"labels[{n}]"
    if not isinstance(raw, Mapping):
        raise ScenarioError(f"{where} must be a mapping")
    kind = raw.get("kind")
    if kind not in LABEL_KINDS:
        raise ScenarioError(f"{where}.kind must be one of {LABEL_KINDS}")
    masked = raw.get("masked", False)
    if not isinstance(masked, bool):
        raise ScenarioError(f"{where}.masked must be true or false")
    return Label(
        AgentRef.parse(raw.get("agent")),
        str(kind),
        _num(raw.get("t"), f"{where}.t"),
        raw.get("failure_mode"),
        masked,
    )


def _expectation(raw: Any, n: int) -> Expectation:
    where = f"expect[{n}]"
    if not isinstance(raw, Mapping):
        raise ScenarioError(f"{where} must be a mapping")
    names = [k for k in raw if k not in ("requires", "severity", "note", "report_only")]
    if len(names) != 1:
        raise ScenarioError(f"{where} must name exactly one predicate, got {names}")
    name = names[0]
    spec = PREDICATES.get(name)
    if spec is None:
        raise ScenarioError(f"{where}: unknown predicate {name!r}")
    args = raw[name] or {}
    if not isinstance(args, Mapping):
        raise ScenarioError(f"{where}.{name} arguments must be a mapping")
    severity = raw.get("severity") or spec.severity
    if severity not in SEVERITIES:
        raise ScenarioError(f"{where}.severity must be one of {SEVERITIES}")
    if name in ("quiet", "scores_at_least") and args.get("tenant") == "northstar":
        severity = "CRITICAL"  # any northstar alert is an isolation failure first (ML §8.3)
    lanes = tuple(sorted(set(spec.lanes) | set(_lanes(raw.get("requires"), where))))
    return Expectation(
        name,
        dict(args),
        lanes,
        str(severity),
        str(raw.get("note", "")),
        bool(raw.get("report_only", False)),
    )


def _persona(raw: Any, n: int) -> PersonaStep:
    where = f"personas[{n}]"
    if not isinstance(raw, Mapping):
        raise ScenarioError(f"{where} must be a mapping")
    persona = raw.get("persona")
    if persona not in PERSONAS:
        raise ScenarioError(f"{where}.persona must be one of {PERSONAS}")
    verb = str(raw.get("do"))
    if verb not in PERSONA_VERBS:
        raise ScenarioError(f"{where}: unknown verb {raw.get('do')!r}")
    at = raw.get("at")
    if at != "end":
        at = _num(at, f"{where}.at")
    args = {k: v for k, v in raw.items() if k not in ("at", "persona", "do", "tenant", "requires")}
    lanes = tuple(sorted(set(PERSONA_VERBS[verb]) | set(_lanes(raw.get("requires"), where))))
    return PersonaStep(at, str(persona), verb, str(raw.get("tenant", DEFAULT_TENANT)), args, lanes)


def _with_contract(expect: tuple[Expectation, ...]) -> tuple[Expectation, ...]:
    """Every run checks what it read against the published schemas (sibyl-health/1)."""
    if any(e.predicate == "contract" for e in expect):
        return expect
    return (*expect, Expectation("contract", {}, (), PREDICATES["contract"].severity))


DRIFT_KEYS: Final = frozenset(
    {
        "baseline_min_span_s",
        "baseline_max_span_s",
        "eval_window_s",
        "eval_every_s",
        "baseline_min_samples",
        "eval_min_samples",
        "tool_min_samples",
        "identity_min_count",
        "raise_after",
        "clear_after",
        "identity_clear_after",
    }
)


def _drift(raw: Any) -> dict[str, float]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ScenarioError("drift must map DriftConfig settings to numbers")
    unknown = set(raw) - DRIFT_KEYS
    if unknown:
        raise ScenarioError(f"drift: unknown settings {sorted(unknown)}")
    return {str(k): _num(v, f"drift.{k}", minimum=1) for k, v in raw.items()}


def _budgets(raw: Any) -> dict[AgentRef, str]:
    """Agent -> monthly budget (USD, the API's 4-decimal money string, above zero)."""
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ScenarioError("budgets must map agents to USD amounts like '4.4100'")
    out: dict[AgentRef, str] = {}
    for key, value in raw.items():
        if not isinstance(value, str) or not MONEY.fullmatch(value) or Decimal(value) <= 0:
            raise ScenarioError(f"budgets.{key}: {value!r} is not a positive USD amount '0.0000'")
        out[AgentRef.parse(key)] = value
    return out


def _cadences(raw: Any) -> dict[AgentRef, int]:
    """Agent -> expected traffic cadence in whole seconds (the plan's ``expected_cadence_s``)."""
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ScenarioError("cadences must map agents to whole seconds")
    out: dict[AgentRef, int] = {}
    for key, value in raw.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ScenarioError(f"cadences.{key}: {value!r} is not a positive whole second count")
        out[AgentRef.parse(key)] = value
    return out


def parse_scenario(raw: Mapping[str, Any]) -> Scenario:
    if not isinstance(raw, Mapping):
        raise ScenarioError("a scenario is a mapping")
    sid = raw.get("id")
    if not isinstance(sid, str) or not sid.startswith("S-") or not sid[2:].isdigit():
        raise ScenarioError(f"id must look like S-01, got {sid!r}")
    duration = _num(raw.get("duration_s"), "duration_s", minimum=1)
    profiles = {
        name: Profile.parse(name, body) for name, body in (raw.get("profiles") or {}).items()
    }
    chaos: list[ChaosStep] = []
    for n, step in enumerate(raw.get("chaos") or ()):
        chaos.extend(_chaos_step(step, n, duration))
    chaos.sort(key=lambda c: c.at)  # stable: same-time steps keep file order
    gate_class = raw.get("gate_class", "none")
    if gate_class not in ("hard", "silent", "ramp", "none"):
        raise ScenarioError("gate_class must be hard, silent, ramp or none")
    scenario = Scenario(
        id=sid,
        title=str(raw.get("title", "")),
        duration_s=duration,
        seed=int(raw.get("seed", DEFAULT_SEED)),
        smoke=bool(raw.get("smoke", False)),
        phase=str(raw.get("phase", "1")),
        gate_class=str(gate_class),
        requires=_lanes(raw.get("requires"), "requires"),
        tenants=_tenants(raw.get("tenants")),
        profiles=profiles,
        chaos=tuple(chaos),
        labels=tuple(_label(lab, n) for n, lab in enumerate(raw.get("labels") or ())),
        expect=_with_contract(
            tuple(_expectation(e, n) for n, e in enumerate(raw.get("expect") or ()))
        ),
        personas=tuple(_persona(p, n) for n, p in enumerate(raw.get("personas") or ())),
        notes=str(raw.get("notes", "")),
        settle_s=_num(raw.get("settle_s", 25.0), "settle_s"),
        health_poll_s=_num(raw.get("health_poll_s", 15.0), "health_poll_s", minimum=1),
        warmup_min=int(_num(raw.get("warmup_min", 60), "warmup_min")),
        drift=_drift(raw.get("drift")),
        warmup_agents={
            AgentRef.parse(k): int(_num(v, f"warmup_agents.{k}"))
            for k, v in (raw.get("warmup_agents") or {}).items()
        },
        budgets=_budgets(raw.get("budgets")),
        cadences=_cadences(raw.get("cadences")),
    )
    for tenant in scenario.tenants.values():
        scenario.profile(tenant.default_profile)
        for profile in tenant.agents.values():
            scenario.profile(profile)
    return scenario


def require_mapping(raw: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(raw, Mapping):
        raise ScenarioError(f"{where} must be a mapping")
    return raw


__all__: Sequence[str] = (
    "LANES",
    "PREDICATES",
    "AgentRef",
    "ChaosStep",
    "Expectation",
    "Label",
    "PersonaStep",
    "Profile",
    "Scenario",
    "ScenarioError",
    "parse_scenario",
)
