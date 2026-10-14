"""``SnapshotPolicyView``: G-policy's implementation of the frozen ``PolicyView`` (R62).

Everything here is synchronous and in-memory: a key check is one dict lookup, one HMAC and one
constant-time compare (an unknown prefix costs the same), a decision is ``routing.decide`` over
the tenant block of the key's snapshot.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable
from datetime import UTC, datetime

from ..credentials.vault import CredentialVault
from ..routing.decide import Provisional, decide, resolve_agent
from .store import SnapshotStore
from .view import (
    CredentialRef,
    DecisionRequest,
    KeyPrincipal,
    KeyRejected,
    ModelList,
    PolicyState,
    PolicyStatus,
    Refuse,
    SecretHandle,
    Serve,
)

_KEY_RE = re.compile(r"^sbl_(live|test)_([A-Za-z0-9]{12})_([A-Za-z0-9_-]{43})$")
_DUMMY = hashlib.sha256(b"sibyl-gateway-dummy-key").digest()


def utcnow() -> datetime:
    return datetime.now(UTC)


class SnapshotPolicyView:
    def __init__(
        self,
        store: SnapshotStore,
        *,
        pepper: bytes,
        env: str,
        vault: CredentialVault | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if len(pepper) < 32:
            raise ValueError("SIBYL_KEY_PEPPER must be at least 32 bytes")
        self._store = store
        self._pepper = pepper
        self._env = env
        self._vault = vault or CredentialVault(clock=clock)
        self._clock = clock

    @property
    def store(self) -> SnapshotStore:
        return self._store

    @property
    def vault(self) -> CredentialVault:
        return self._vault

    def status(self) -> PolicyStatus:
        return self._store.status(self._clock())

    def authenticate(self, presented_key: str) -> KeyPrincipal | KeyRejected:
        match = _KEY_RE.fullmatch(presented_key or "")
        if match is None:
            hmac.compare_digest(self._hash("x"), _DUMMY)
            return KeyRejected("sibyl_key_invalid")
        env, prefix, secret = match.groups()
        found = self._store.key(prefix)
        computed = self._hash(secret)
        if found is None:
            hmac.compare_digest(computed, _DUMMY)
            return KeyRejected("sibyl_key_invalid")
        block, entry, _doc = found
        if not hmac.compare_digest(computed, entry.secret_hash):
            return KeyRejected("sibyl_key_invalid")
        if entry.env != env or env != self._env:
            return KeyRejected("sibyl_key_invalid")
        now = self._clock()
        if entry.expires_at <= now:
            return KeyRejected("sibyl_key_expired")
        if entry.status == "rotating" and (
            entry.rotation_grace_until is None or entry.rotation_grace_until <= now
        ):
            return KeyRejected("sibyl_key_expired")
        if entry.status not in ("active", "rotating"):
            return KeyRejected("sibyl_key_revoked")
        return KeyPrincipal(
            tenant_id=block.tenant_id,
            api_key_id=entry.key_id,
            prefix=prefix,
            env=entry.env,  # type: ignore[arg-type]
            scopes=entry.scopes,
            bound_agent_id=entry.agent_id,
        )

    def _hash(self, secret: str) -> bytes:
        return hmac.new(self._pepper, secret.encode("ascii"), hashlib.sha256).digest()

    def _tenant(self, principal: KeyPrincipal) -> tuple[object, PolicyStatus] | Refuse:
        held = self._store.tenant(principal.tenant_id)
        if held is None:
            return Refuse.of("sibyl_no_snapshot", policy=PolicyStatus(PolicyState.UNAVAILABLE))
        block, doc = held
        return block, self._store.tenant_status(doc, self._clock())

    def decide(self, request: DecisionRequest) -> Serve | Refuse:
        held = self._tenant(request.principal)
        if isinstance(held, Refuse):
            return held
        block, status = held
        return decide(block, status, request, key_version=self._vault.key_version)  # type: ignore[arg-type]

    def models(self, principal: KeyPrincipal, agent_header: str | None) -> ModelList | Refuse:
        held = self._tenant(principal)
        if isinstance(held, Refuse):
            return held
        block, status = held
        if "gateway:proxy" not in principal.scopes:
            return Refuse.of("sibyl_scope_missing", policy=status)
        agent = resolve_agent(block, principal, agent_header)  # type: ignore[arg-type]
        if isinstance(agent, Refuse):
            return agent
        if isinstance(agent, Provisional):
            return ModelList(())
        if agent.identity.allowed_models is not None:
            return ModelList(tuple(sorted(agent.identity.allowed_models)))
        names = {agent.primary_model} | {s.model for s in agent.steps if s.model and s.viable}
        return ModelList(tuple(sorted(names)))

    def credential(self, ref: CredentialRef) -> SecretHandle | None:
        return self._vault.get(ref)
