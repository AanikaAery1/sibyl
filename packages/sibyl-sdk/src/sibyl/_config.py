"""`init()` configuration: exporter and policy knobs plus env-var resolution (API §8.1-8.2)."""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Literal, cast
from urllib.parse import urlsplit

from sibyl._errors import SibylConfigError
from sibyl._types import CAPTURE_MODES, CaptureMode, FailMode

log = logging.getLogger("sibyl")

KEY_RE = re.compile(r"^sbl_(live|test)_([A-Za-z0-9]{12})_([A-Za-z0-9_-]{43})$")
FORBIDDEN_SDK_SCOPES = frozenset({"gateway:proxy", "killswitch:pull"})
"""`init()` refuses keys carrying these (API §8.1); detected from the signed snapshot."""
INSTRUMENTABLE = (
    "openai",
    "anthropic",
    "google",
    "langchain",
    "openai_agents",
    "crewai",
    "mcp",
    "httpx",
)
_ALIASES = {"openai-agents": "openai_agents", "google-genai": "google", "langgraph": "langchain"}
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_SALT_INFO = b"sibyl-sdk-scrub-salt/1"
MIN_SALT_BYTES = 16
CRITICAL_LANE_MAX = 1_000


@dataclass(frozen=True, kw_only=True)
class ExporterConfig:
    """Bounded, non-blocking exporter (API §8.4). All sizes are hard caps."""

    max_queue_spans: int = 10_000
    max_queue_bytes: int = 32 * 1024 * 1024
    batch_size: int = 512
    schedule_delay: timedelta = timedelta(seconds=2)
    export_timeout: timedelta = timedelta(seconds=10)
    spool_dir: str | None = None
    spool_max_bytes: int = 256 * 1024 * 1024
    spool_max_age: timedelta = timedelta(days=7)
    critical_lane: bool = True
    shutdown_flush_timeout: timedelta = timedelta(seconds=2)
    heartbeat_interval: timedelta = timedelta(seconds=10)
    buffer_report_interval: timedelta = timedelta(seconds=60)

    def __post_init__(self) -> None:
        positive = {
            "max_queue_spans": self.max_queue_spans,
            "max_queue_bytes": self.max_queue_bytes,
            "batch_size": self.batch_size,
            "spool_max_bytes": self.spool_max_bytes,
        }
        for name, value in positive.items():
            if value <= 0:
                raise SibylConfigError(f"ExporterConfig.{name} must be positive")
        if self.export_timeout <= timedelta(0) or self.schedule_delay <= timedelta(0):
            raise SibylConfigError("ExporterConfig delays must be positive")


@dataclass(frozen=True, kw_only=True)
class PolicyConfig:
    """Signed-snapshot poll for the kill switch (API §8.4; R33 key pinning).

    `endpoint` is the api base URL (`SIBYL_API_URL`); it defaults to the ingest endpoint
    for single-host deployments where Caddy routes `/api/v1/policy/*` there.
    """

    poll_interval: timedelta = timedelta(seconds=20)
    max_stale: timedelta = timedelta(minutes=15)
    public_key: str | None = None
    cache_dir: str | None = None
    enforce_kill_switch: bool = True
    endpoint: str | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.poll_interval <= timedelta(0):
            raise SibylConfigError("PolicyConfig.poll_interval must be positive")


@dataclass(frozen=True)
class ParsedKey:
    env: Literal["live", "test"]
    prefix: str
    secret: str = field(repr=False)


@dataclass(frozen=True)
class Settings:
    api_key: str = field(repr=False)
    key: ParsedKey
    endpoint: str
    api_endpoint: str
    agent_ref: str | None
    capture_mode: CaptureMode
    env: Literal["live", "test"]
    fail_mode: FailMode | None
    instrument: tuple[str, ...]
    exporter: ExporterConfig
    policy: PolicyConfig
    resource_attributes: Mapping[str, str]
    scrub_salt: bytes = field(repr=False)


def parse_key(api_key: str) -> ParsedKey:
    match = KEY_RE.match(api_key)
    if match is None:
        raise SibylConfigError("SIBYL_API_KEY is not a sbl_<env>_<prefix12>_<secret> key")
    env = cast(Literal["live", "test"], match.group(1))
    return ParsedKey(env=env, prefix=match.group(2), secret=match.group(3))


def _check_url(name: str, url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SibylConfigError(f"{name} must be an http(s) URL, got {url!r}")
    if parts.username or parts.password or parts.query:
        raise SibylConfigError(f"{name} must not carry credentials or a query string")
    if parts.scheme == "http" and parts.hostname not in _LOOPBACK:
        log.warning("sibyl: %s uses plain http; the API key travels unencrypted", name)
    return url.rstrip("/")


def scrub_salt(key: ParsedKey) -> bytes:
    """Platform salt when configured, else a per-key salt that never leaves the process."""
    configured = os.environ.get("SIBYL_SCRUB_SALT", "").encode("utf-8")
    if len(configured) >= MIN_SALT_BYTES:
        return configured
    return hmac.new(key.secret.encode("ascii"), _SALT_INFO, hashlib.sha256).digest()


def _instrument_list(instrument: Sequence[str] | str) -> tuple[str, ...]:
    if instrument == "auto":
        return INSTRUMENTABLE
    if isinstance(instrument, str):
        raise SibylConfigError("instrument must be 'auto' or a sequence of library names")
    names = [_ALIASES.get(name, name) for name in instrument]
    unknown = [name for name in names if name not in INSTRUMENTABLE]
    if unknown:
        raise SibylConfigError(f"cannot instrument {unknown}; known: {list(INSTRUMENTABLE)}")
    return tuple(dict.fromkeys(names))


def resolve(
    *,
    api_key: str | None,
    endpoint: str | None,
    agent_id: str | None,
    capture_mode: str | None,
    env: str | None,
    fail_mode: str | None,
    instrument: Sequence[str] | str,
    exporter: ExporterConfig | None,
    policy: PolicyConfig | None,
    resource_attributes: Mapping[str, str] | None,
) -> Settings:
    """Explicit arguments win over `SIBYL_*` env vars; every failure is `SibylConfigError`."""
    key_text = api_key or os.environ.get("SIBYL_API_KEY")
    if not key_text:
        raise SibylConfigError("no API key: pass api_key= or set SIBYL_API_KEY")
    key = parse_key(key_text)
    raw_endpoint = endpoint or os.environ.get("SIBYL_ENDPOINT")
    if not raw_endpoint:
        raise SibylConfigError("no ingest endpoint: pass endpoint= or set SIBYL_ENDPOINT")
    ingest = _check_url("endpoint", raw_endpoint)
    policy_cfg = policy or PolicyConfig()
    api_raw = policy_cfg.endpoint or os.environ.get("SIBYL_API_URL") or ingest
    mode_text = capture_mode or os.environ.get("SIBYL_CAPTURE_MODE") or "full"
    if mode_text not in CAPTURE_MODES:
        raise SibylConfigError(f"capture_mode must be one of {CAPTURE_MODES}, got {mode_text!r}")
    mode: CaptureMode = mode_text
    resolved_env = env or os.environ.get("SIBYL_ENV") or key.env
    if resolved_env not in ("live", "test"):
        raise SibylConfigError(f"env must be 'live' or 'test', got {resolved_env!r}")
    if resolved_env != key.env:
        raise SibylConfigError(f"env {resolved_env!r} does not match the {key.env!r} API key")
    if fail_mode not in (None, "open", "closed"):
        raise SibylConfigError(f"fail_mode must be 'open' or 'closed', got {fail_mode!r}")
    return Settings(
        api_key=key_text,
        key=key,
        endpoint=ingest,
        api_endpoint=_check_url("policy endpoint", api_raw),
        agent_ref=agent_id or os.environ.get("SIBYL_AGENT_ID") or None,
        capture_mode=mode,
        env=key.env,
        fail_mode=cast(FailMode | None, fail_mode),
        instrument=_instrument_list(instrument),
        exporter=exporter or ExporterConfig(),
        policy=policy_cfg,
        resource_attributes=dict(resource_attributes or {}),
        scrub_salt=scrub_salt(key),
    )
