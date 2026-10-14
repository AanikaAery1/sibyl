"""Provider status-feed double (Statuspage v2 JSON, `provider.status` feed `statuspage_json`).

Modes:
- `truthful`: worst of the scripted incidents active now and the linked double's outage.
- `late`: the truthful answer as it was `delay_s` ago (S-17 "status page late").
- `lies`: always reports `lie_status` with a fabricated incident (S-16 "status page lies").
`feed_down` makes the feed itself answer 503. Times are seconds on the sim clock relative
to when the script was (re)loaded, so identical scripts give identical timelines.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final, Literal, cast

WireStatus = Literal[
    "operational",
    "degraded_performance",
    "partial_outage",
    "major_outage",
    "maintenance",
    "unknown",
]
Mode = Literal["truthful", "late", "lies"]
WIRE: Final = (
    "operational",
    "degraded_performance",
    "partial_outage",
    "major_outage",
    "maintenance",
    "unknown",
)
_RANK: Final = {
    "operational": 0,
    "maintenance": 1,
    "degraded_performance": 2,
    "partial_outage": 3,
    "major_outage": 4,
    "unknown": 0,
}
_COMPONENT: Final = {"maintenance": "under_maintenance", "unknown": "operational"}
_INDICATOR: Final = {
    "operational": "none",
    "maintenance": "maintenance",
    "degraded_performance": "minor",
    "partial_outage": "major",
    "major_outage": "critical",
    "unknown": "none",
}
_DESCRIPTION: Final = {
    "none": "All Systems Operational",
    "minor": "Minor Service Outage",
    "major": "Partial System Outage",
    "critical": "Major System Outage",
    "maintenance": "Service Under Maintenance",
}


class FeedError(ValueError):
    pass


@dataclass(frozen=True)
class Incident:
    id: str
    name: str
    status: WireStatus
    start_s: float
    duration_s: float | None = None
    component: str = "API"

    def active(self, t: float) -> bool:
        return self.start_s <= t and (self.duration_s is None or t < self.start_s + self.duration_s)

    @classmethod
    def parse(cls, raw: Mapping[str, Any], n: int) -> Incident:
        status = raw.get("status", "major_outage")
        if status not in WIRE:
            raise FeedError(f"incident status must be one of {WIRE}")
        duration = raw.get("duration_s")
        try:
            start = float(raw.get("start_s", 0))
            dur = None if duration is None else float(duration)
        except (TypeError, ValueError):
            raise FeedError("start_s and duration_s must be numbers") from None
        if start < 0 or (dur is not None and dur <= 0):
            raise FeedError("start_s must be >= 0 and duration_s > 0")
        return cls(
            id=str(raw.get("id") or f"sim-inc-{n:04d}"),
            name=str(raw.get("name") or "Elevated error rates"),
            status=cast(WireStatus, status),
            start_s=start,
            duration_s=dur,
            component=str(raw.get("component", "API")),
        )


@dataclass(frozen=True)
class FeedConfig:
    mode: Mode = "truthful"
    delay_s: float = 0.0
    lie_status: WireStatus = "major_outage"
    feed_down: bool = False
    link_double: str | None = None
    incidents: tuple[Incident, ...] = ()

    def merged(self, patch: Mapping[str, Any]) -> FeedConfig:
        unknown = set(patch) - {
            "mode",
            "delay_s",
            "lie_status",
            "feed_down",
            "link_double",
            "incidents",
        }
        if unknown:
            raise FeedError(f"unknown feed keys {sorted(unknown)}")
        changes: dict[str, Any] = {}
        if "mode" in patch:
            if patch["mode"] not in ("truthful", "late", "lies"):
                raise FeedError("mode must be truthful, late or lies")
            changes["mode"] = patch["mode"]
        if "delay_s" in patch:
            if not isinstance(patch["delay_s"], (int, float)) or patch["delay_s"] < 0:
                raise FeedError("delay_s must be a non-negative number")
            changes["delay_s"] = float(patch["delay_s"])
        if "lie_status" in patch:
            if patch["lie_status"] not in WIRE:
                raise FeedError(f"lie_status must be one of {WIRE}")
            changes["lie_status"] = patch["lie_status"]
        if "feed_down" in patch:
            changes["feed_down"] = bool(patch["feed_down"])
        if "link_double" in patch:
            changes["link_double"] = patch["link_double"]
        if "incidents" in patch:
            if not isinstance(patch["incidents"], list):
                raise FeedError("incidents must be a list")
            changes["incidents"] = tuple(
                Incident.parse(i, n) for n, i in enumerate(patch["incidents"], 1)
            )
        return replace(self, **changes)


OutageLookup = Callable[[str, float], bool]


@dataclass
class ProviderFeed:
    provider: str
    page_name: str
    clock: Callable[[], float]
    outage_at: OutageLookup
    config: FeedConfig = field(default_factory=FeedConfig)
    started_at: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self.started_at = self.clock()

    def configure(self, patch: Mapping[str, Any], *, restart: bool = False) -> None:
        config = self.config.merged(patch)
        with self._lock:
            self.config = config
            if restart or "incidents" in patch:
                self.started_at = self.clock()

    def add_incident(self, raw: Mapping[str, Any]) -> Incident:
        with self._lock:
            incident = Incident.parse(raw, len(self.config.incidents) + 1)
            self.config = replace(self.config, incidents=(*self.config.incidents, incident))
            return incident

    def reset(self) -> None:
        with self._lock:
            self.config = FeedConfig(link_double=self.config.link_double)
            self.started_at = self.clock()

    # -------------------------------------------------------------- evaluation

    def _truth(self, wall: float) -> tuple[WireStatus, list[Incident]]:
        t = wall - self.started_at
        active = [i for i in self.config.incidents if i.active(t)]
        status: WireStatus = "operational"
        for incident in active:
            if _RANK[incident.status] > _RANK[status]:
                status = incident.status
        link = self.config.link_double
        if link and self.outage_at(link, wall):
            status = "major_outage"
            active.append(
                Incident(
                    id=f"sim-outage-{link}",
                    name=f"{link} is unavailable",
                    status="major_outage",
                    start_s=0.0,
                )
            )
        return status, active

    def status(self, now: float | None = None) -> tuple[WireStatus, list[Incident]]:
        wall = self.clock() if now is None else now
        cfg = self.config
        if cfg.mode == "lies":
            if cfg.lie_status == "operational":
                return "operational", []
            return cfg.lie_status, [
                Incident(
                    id="sim-lie-0001",
                    name="Investigating reports",
                    status=cfg.lie_status,
                    start_s=0.0,
                )
            ]
        if cfg.mode == "late":
            return self._truth(wall - cfg.delay_s)
        return self._truth(wall)

    def summary(self) -> dict[str, Any]:
        now = self.clock()
        status, incidents = self.status(now)
        indicator = _INDICATOR[status]
        stamp = _iso(now)
        component_status = _COMPONENT.get(status, status)
        return {
            "page": {
                "id": f"sim-{self.provider}",
                "name": self.page_name,
                "url": f"https://status.sim/{self.provider}",
                "updated_at": stamp,
            },
            "status": {"indicator": indicator, "description": _DESCRIPTION[indicator]},
            "components": [
                {
                    "id": f"sim-{self.provider}-api",
                    "name": "API",
                    "status": component_status,
                    "updated_at": stamp,
                }
            ],
            "incidents": [
                {
                    "id": i.id,
                    "name": i.name,
                    "status": "investigating",
                    "impact": _INDICATOR[i.status] if i.status != "maintenance" else "none",
                    "created_at": _iso(self.started_at + i.start_s),
                    "updated_at": stamp,
                    "resolved_at": None,
                    "shortlink": f"https://status.sim/i/{i.id}",
                    "components": [
                        {"name": i.component, "status": _COMPONENT.get(i.status, i.status)}
                    ],
                }
                for i in incidents
            ],
            "scheduled_maintenances": [],
            "sibyl_sim": {"wire_status": status, "mode": self.config.mode},
        }

    def describe(self) -> dict[str, Any]:
        cfg = self.config
        status, _ = self.status()
        return {
            "provider": self.provider,
            "mode": cfg.mode,
            "delay_s": cfg.delay_s,
            "lie_status": cfg.lie_status,
            "feed_down": cfg.feed_down,
            "link_double": cfg.link_double,
            "status": status,
            "incidents": [vars(i) for i in cfg.incidents],
        }


def _iso(epoch: float) -> str:
    moment = datetime.fromtimestamp(epoch, tz=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
