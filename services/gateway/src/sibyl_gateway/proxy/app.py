"""The data-plane ASGI app (G-hot): ``/v1/chat/completions``, ``/v1/embeddings``, ``/v1/models``,
the native surfaces (D50) ``/v1/messages`` (+ ``/count_tokens``) and
``/v1beta/models/{model}:generateContent|streamGenerateContent``, ``/healthz``, ``/readyz``.
Pure ASGI so the gateway controls exactly when the status line and each chunk go out; no CORS
(API §2.9). G-hot reads policy only through ``PolicyView``. Every surface gets the same policy
semantics; protocol specifics live in ``proxy.protocols``.

Per call: snapshot present -> Sibyl key (``X-Sibyl-Key``, or ``Authorization`` for Sibyl-only
calls) -> header rules -> body -> ``decide`` -> limits -> forward/relay -> after the last byte,
telemetry is built and offered to the bounded queue (never awaited, never blocking).
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Awaitable, Callable
from uuid import UUID

from ..actions.api import ActionApi
from ..actions.gate import ToolCallGate
from ..limits import Limits
from ..policy.view import (
    DecisionRequest,
    KeyPrincipal,
    KeyRejected,
    ModelList,
    PolicyState,
    PolicyView,
    Refuse,
    Serve,
)
from ..telemetry.events import CallRecord, EventFactory, uuid7
from ..telemetry.queue import TelemetryQueue
from .forward import Forwarder, Outcome, ProxyCall
from .http import (
    SAFE_ID,
    BodyTooLarge,
    ErrorStyle,
    Receive,
    Scope,
    Send,
    header_map,
    read_body,
    send_error,
    send_json,
    upstream_headers,
)
from .meta import response_meta
from .obo import OnBehalfOfInvalid, parse_on_behalf_of
from .protocols import OPENAI, Route, WireProtocol, route_for
from .upstream import UpstreamClient

log = logging.getLogger("sibyl.gateway")
MAX_BODY_BYTES = 16 * 1024 * 1024
_NO_GENERATION_TELEMETRY = frozenset({"anthropic.count_tokens"})
_CAPTURE = {"redacted", "metadata"}
_FALLBACK = {"inherit", "none", "inline"}
_WINDOW_S = 60.0
_MAX_ACTION_EVENTS = 16
Hook = Callable[[], Awaitable[None]]


class GatewayApp:
    def __init__(
        self,
        view: PolicyView,
        upstream: UpstreamClient,
        events: EventFactory,
        telemetry: TelemetryQueue,
        *,
        gateway_id: str,
        limits: Limits | None = None,
        on_startup: list[Hook] | None = None,
        on_shutdown: list[Hook] | None = None,
        actions: ActionApi | None = None,
    ) -> None:
        self.view = view
        self.upstream = upstream
        self.events = events
        self.telemetry = telemetry
        self.gateway_id = gateway_id
        self.limits = limits or Limits()
        self.forwarder = Forwarder(view, upstream, ToolCallGate(actions, events.scrubber))
        self.on_startup = on_startup or []
        self.on_shutdown = on_shutdown or []
        self._windows: dict[tuple[str, str], float] = {}
        self._discovered: set[tuple[UUID, str]] = set()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        path, method = scope["path"], scope["method"]
        route = route_for(path)
        if route is not None:
            if method != "POST":
                style = route.protocol.error_style
                await send_error(send, "sibyl_bad_request", self._base_headers(scope), style=style)
                return
            await self._proxy(scope, receive, send, route)
        elif path.startswith("/v1beta/"):
            await send_json(send, 404, _GEMINI_NOT_FOUND)
        elif path == "/v1/models" and method == "GET":
            await self._models(scope, send)
        elif path == "/healthz":
            await send_json(send, 200, {"status": "ok"})
        elif path == "/readyz":
            await self._ready(send)
        else:
            await send_json(
                send,
                404,
                {
                    "error": {
                        "message": "Not found",
                        "type": "not_found_error",
                        "param": None,
                        "code": "not_found",
                    }
                },
            )

    async def _lifespan(self, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    for hook in self.on_startup:
                        await hook()
                except Exception as exc:
                    log.exception("gateway startup failed")
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                for hook in self.on_shutdown:
                    try:
                        await hook()
                    except Exception:
                        log.exception("gateway shutdown hook failed")
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _ready(self, send: Send) -> None:
        status = self.view.status()
        if status.state is PolicyState.UNAVAILABLE:
            await send_json(send, 503, {"snapshot": "none"})
            return
        await send_json(
            send,
            200,
            {"status": "ready", "snapshot": status.state.value, "version": status.version},
        )

    # -- helpers ------------------------------------------------------------------------------

    def _base_headers(self, scope: Scope, request_id: str | None = None) -> list[tuple[str, str]]:
        out = [("x-sibyl-gateway-id", self.gateway_id)]
        if request_id:
            out.append(("x-request-id", request_id))
        return out

    def _client(self, scope: Scope) -> str:
        client = scope.get("client")
        return str(client[0]) if client else "unknown"

    async def _authenticate(
        self,
        scope: Scope,
        headers: dict[str, str],
        send: Send,
        base: list[tuple[str, str]],
        protocol: WireProtocol = OPENAI,
    ) -> tuple[KeyPrincipal, bool, tuple[str, str] | None] | None:
        """(principal, has_provider_credential, provider credential header) or None after a
        4xx in the protocol's own envelope. Credentials are located by ``protocol``."""
        style = protocol.error_style
        status = self.view.status()
        if status.state is PolicyState.UNAVAILABLE:
            await send_error(send, "sibyl_no_snapshot", base, style=style)
            return None
        query = scope.get("query_string", b"").decode("latin-1")
        creds = protocol.credentials(headers, query)
        principal = self.view.authenticate(creds.sibyl_key or "")
        if isinstance(principal, KeyRejected):
            limit = self.limits.failed_auth(self._client(scope))
            if not limit.allowed:
                await send_error(send, "sibyl_rate_limited", base, limit.retry_after_s, style=style)
            else:
                await send_error(send, principal.code, base, style=style)
            return None
        return principal, creds.has_provider_credential, creds.provider

    # -- /v1/models -------------------------------------------------------------------------

    async def _models(self, scope: Scope, send: Send) -> None:
        headers = header_map(scope)
        base = self._base_headers(scope, _request_id(headers))
        auth = await self._authenticate(scope, headers, send, base)
        if auth is None:
            return
        listing = self.view.models(auth[0], headers.get("x-sibyl-agent"))
        if isinstance(listing, Refuse):
            await send_error(send, listing.error_code, base, listing.retry_after_s)
            return
        assert isinstance(listing, ModelList)
        data = [
            {"id": m, "object": "model", "created": 0, "owned_by": "sibyl"} for m in listing.models
        ]
        await send_json(send, 200, {"object": "list", "data": data}, base)

    # -- proxied calls ----------------------------------------------------------------------

    async def _proxy(self, scope: Scope, receive: Receive, send: Send, route: Route) -> None:
        started = time.perf_counter()
        wall_start = time.time()
        headers = header_map(scope)
        call_id = uuid7()
        op, protocol = route.operation, route.protocol
        style = protocol.error_style
        base = self._base_headers(scope, _request_id(headers))
        base.append(("x-sibyl-request-id", str(call_id)))
        if "x-sibyl-fail-mode" in headers:
            await send_error(send, "sibyl_header_not_allowed", base, style=style)
            return
        fallback = headers.get("x-sibyl-fallback", "inherit").strip().lower()
        if fallback not in _FALLBACK:
            await send_error(send, "sibyl_bad_request", base, style=style)
            return
        try:
            on_behalf_of = parse_on_behalf_of(headers.get("x-sibyl-on-behalf-of"))
        except OnBehalfOfInvalid:
            await send_error(send, "sibyl_bad_request", base, style=style)
            return
        auth = await self._authenticate(scope, headers, send, base, protocol)
        if auth is None:
            return
        principal, has_cred, provider_credential = auth
        try:
            body = await read_body(receive, MAX_BODY_BYTES)
            parsed = json.loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("body must be an object")
        except (BodyTooLarge, ValueError, UnicodeDecodeError):
            await send_error(send, "sibyl_bad_request", base, style=style)
            return
        except ConnectionResetError:
            return
        model = route.path_model or (
            parsed.get("model") if isinstance(parsed.get("model"), str) else None
        )
        capture = headers.get("x-sibyl-capture", "").strip().lower()
        decision = self.view.decide(
            DecisionRequest(
                principal=principal,
                operation=op,
                request_id=str(call_id),
                has_provider_credential=has_cred,
                agent_header=headers.get("x-sibyl-agent") or None,
                task_id=headers.get("x-sibyl-task-id"),
                requested_model=model,
                fallback_header=fallback,  # type: ignore[arg-type]
                capture_header=capture if capture in _CAPTURE else None,  # type: ignore[arg-type]
                has_tools=bool(parsed.get("tools") or parsed.get("functions")),
                dialect=protocol.dialect,
            )
        )
        record = CallRecord(
            tenant_id=principal.tenant_id,
            agent_id="",
            operation=op,
            provider="none",
            request_model=model or "unknown",
            status="error",
            started=wall_start,
            ended=wall_start,
            route="primary",
            capture_mode="metadata",
            policy_state=decision.policy.state.value if decision.policy else "unavailable",
            policy_version=decision.policy.version if decision.policy else None,
            fail_mode=None,
            call_id=call_id,
            task_id=headers.get("x-sibyl-task-id"),
            traceparent=headers.get("traceparent"),
            snapshot_age_s=None,
        )
        if isinstance(decision, Refuse):
            await self._refuse(send, decision, base, record, style)
            return
        await self._serve(
            scope,
            send,
            decision,
            base,
            record,
            started,
            ProxyCall(
                operation=op,
                path_suffix=route.path_suffix,
                body=body,
                parsed=parsed,
                model=model,
                client_credential=provider_credential,
                passthrough_headers=upstream_headers(scope),
                request_id=str(call_id),
                route=route,
                query=protocol.upstream_query(scope.get("query_string", b"").decode("latin-1")),
                on_behalf_of=on_behalf_of,
            ),
            principal,
        )

    async def _refuse(
        self,
        send: Send,
        refusal: Refuse,
        base: list[tuple[str, str]],
        record: CallRecord,
        style: ErrorStyle = "openai",
    ) -> None:
        extra = list(base)
        if refusal.policy is not None:
            extra.append(("x-sibyl-policy-state", refusal.policy.state.value))
            extra.append(("x-sibyl-policy-version", str(refusal.policy.version or 0)))
        if refusal.agent_id is not None:
            extra.append(("x-sibyl-agent-id", str(refusal.agent_id)))
        status = await send_error(
            send, refusal.error_code, extra, refusal.retry_after_s, style=style
        )
        if refusal.agent_id is None:
            return
        record.agent_id = refusal.agent_id
        record.http_status, record.error_type = status, refusal.error_code
        record.ended = time.time()
        self._emit(record)
        action = {
            "sibyl_agent_killed": "reject_killed",
            "sibyl_policy_expired": "reject_closed",
            "sibyl_agent_quarantined": "reject_quarantined",
        }.get(refusal.error_code)
        if action and refusal.policy is not None:
            self._decision_event(record, action, refusal.error_code, status)

    async def _serve(
        self,
        scope: Scope,
        send: Send,
        serve: Serve,
        base: list[tuple[str, str]],
        record: CallRecord,
        started: float,
        call: ProxyCall,
        principal: KeyPrincipal,
    ) -> None:
        agent_key = str(serve.agent_id)
        limit = self.limits.key(principal.api_key_id)
        rate_headers = limit.headers("key")
        if limit.allowed and serve.limits.rps_limit:
            limit = self.limits.agent(agent_key, serve.limits.rps_limit, serve.limits.burst)
            rate_headers = limit.headers("agent")
        code = None if limit.allowed else "sibyl_rate_limited"
        if code is None and serve.limits.budget_exhausted:
            code = "sibyl_budget_exhausted"
        if code is None and not self.limits.inflight.acquire(agent_key, serve.limits.max_inflight):
            code = "sibyl_inflight_limit"
        record.agent_id, record.fail_mode = serve.agent_id, serve.fail_mode
        record.capture_mode, record.profile_hash = serve.capture_mode, serve.redaction_profile_hash
        record.snapshot_age_s = (
            float(serve.policy.age_s) if serve.policy.age_s is not None else None
        )
        if code is not None:
            await self._refuse(
                send,
                Refuse.of(code, agent_id=serve.agent_id, policy=serve.policy),
                [*base, *rate_headers],
                record,
                call.protocol.error_style,
            )
            return
        try:
            out = await self._relay(send, serve, base, rate_headers, call, started)
        finally:
            self.limits.inflight.release(agent_key)
        self._after(serve, record, call, out)

    async def _relay(
        self,
        send: Send,
        serve: Serve,
        base: list[tuple[str, str]],
        rate_headers: list[tuple[str, str]],
        call: ProxyCall,
        started: float,
    ) -> Outcome:
        sibyl = [*base, *serve.response_headers().items(), *rate_headers]
        forwarder_out = await self.forwarder.forward(call, serve, send, sibyl, started)
        if not forwarder_out.committed:
            code = forwarder_out.error_code or "upstream_error"
            extra = [*sibyl]
            if code == "upstream_rate_limited" and forwarder_out.upstream_retry_after:
                extra.append(("retry-after", forwarder_out.upstream_retry_after))
            await send_error(
                send,
                code,
                [(k, v) for k, v in extra if k.lower() != "x-sibyl-error"],
                style=call.protocol.error_style,
            )
        return forwarder_out

    def _after(self, serve: Serve, record: CallRecord, call: ProxyCall, out: Outcome) -> None:
        """Runs after the last byte went out: telemetry is built here and only offered."""
        record.ended = time.time()
        record.attempts = max(1, out.attempts)
        record.http_status = out.http_status if out.committed else _status_for(out)
        record.error_type = (
            out.error_type if out.committed else (out.error_code or "upstream_error")
        )
        record.status = "ok" if out.committed and (out.http_status or 500) < 400 else "error"
        record.streamed = out.streamed
        target = out.target or serve.targets[0]
        record.provider, record.route = target.provider_slug, target.route
        record.ttfb_ms = out.ttfb_s * 1000 if out.ttfb_s is not None else None
        record.inline_fallback_used = target.route == "inline_fallback"
        if target is not serve.targets[0]:
            first = serve.targets[0]
            record.from_target = {"provider": first.provider_slug, "model": first.model}
            record.to_target = {"provider": target.provider_slug, "model": target.model}
        meta = response_meta(out, call.protocol.dialect) if out.committed else {}
        record.response_model = meta.get("response_model")
        record.response_id = meta.get("response_id")
        record.system_fingerprint = meta.get("system_fingerprint")
        record.usage, record.finish_reasons = meta.get("usage"), meta.get("finish_reasons")
        if out.ratelimit_target is target:  # headroom of the provider the event names
            record.ratelimit = out.ratelimit
        if serve.capture_mode != "metadata":
            record.request_body = call.body
            record.response_body = (
                bytes(out.head) if out.content_encoding in ("", "identity") else None
            )
        self._emit(record)
        if out.actions is not None:
            self._action_events(record, out)
        if "agent.discovered" in serve.audit_events:
            self._discovered_event(serve, record)
        if "policy.stale_bypass" in serve.audit_events:
            self._decision_event(
                record, "forward_stale", "policy expired; fail-open", record.http_status
            )

    def _emit(self, record: CallRecord) -> None:
        if record.operation in _NO_GENERATION_TELEMETRY:
            return  # a token count is not a generation: it would skew health and drift
        try:
            self.telemetry.offer(self.events.gen_ai_request(record))
        except Exception:
            log.exception("telemetry event build failed")

    def _decision_event(
        self, record: CallRecord, action: str, reason: str, status: int | None
    ) -> None:
        key = (str(record.agent_id), action)
        now = time.monotonic()
        if now - self._windows.get(key, -_WINDOW_S) < _WINDOW_S:
            return  # windowed (§3.5): one decision event per agent and action per minute
        self._windows[key] = now
        self.telemetry.offer(
            self.events.policy_decision(
                record.tenant_id,
                record.agent_id,
                action=action,
                state=record.policy_state,
                fail_mode=record.fail_mode or "open",
                reason=reason,
                http_status=status,
                policy_version=record.policy_version,
            )
        )

    def _action_events(self, record: CallRecord, out: Outcome) -> None:
        """One ``policy.decision`` (``tool_blocked``) per refused tool call; never windowed,
        capped per response. Allowed calls are visible in the call record itself."""
        assert out.actions is not None
        refused = [v for v in out.actions.verdicts if v.outcome != "allowed"][:_MAX_ACTION_EVENTS]
        for verdict in refused:
            held = f" {verdict.held_action_id}" if verdict.held_action_id else ""
            reason = (
                f"{verdict.outcome}{held}: {verdict.call.name[:60]} "
                f"rule={verdict.decision.rule_id}: {verdict.decision.reason}"
            )
            try:
                self.telemetry.offer(
                    self.events.policy_decision(
                        record.tenant_id,
                        record.agent_id,
                        action="tool_blocked",
                        state=record.policy_state,
                        fail_mode=record.fail_mode or "open",
                        reason=reason,
                        http_status=record.http_status,
                        policy_version=record.policy_version,
                    )
                )
            except Exception:
                log.exception("action decision event build failed")

    def _discovered_event(self, serve: Serve, record: CallRecord) -> None:
        slug = str(serve.agent_id)
        if (serve.tenant_id, slug) in self._discovered:
            return
        self._discovered.add((serve.tenant_id, slug))
        from ..routing.decide import candidate_hash

        self.telemetry.offer(
            self.events.agent_discovered(
                serve.tenant_id,
                slug,
                candidate=slug,
                candidate_hash=candidate_hash(serve.tenant_id, slug),
                via="gateway_header",
                fail_mode=serve.fail_mode,
                call_id=record.call_id,
                traceparent=record.traceparent,
                policy_version=record.policy_version,
                policy_state=record.policy_state,
            )
        )


_GEMINI_NOT_FOUND = {
    "error": {"code": 404, "message": "Not found", "status": "NOT_FOUND"},
}


def _status_for(out: Outcome) -> int:
    return {"upstream_timeout": 504, "upstream_rate_limited": 429}.get(out.error_code or "", 502)


def _request_id(headers: dict[str, str]) -> str:
    incoming = headers.get("x-request-id")
    return incoming if incoming and SAFE_ID.match(incoming) else str(uuid7())
