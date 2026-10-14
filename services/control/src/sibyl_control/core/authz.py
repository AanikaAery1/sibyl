"""Deny-by-default ``authorize()`` over the scope catalogue (API.md §2.2, R21).

The scope catalogue, the role matrix, the key-grantable (M) set, the step-up (↑) set and the
break-glass scope are imported from ``sibyl_schemas.values`` (G0 single source); this module
only projects them onto plain strings and evaluates them. The DB ``role_permission`` seed is
diffed against the same registry after migrating (``tests/db/test_single_source_db.py``).
OIDC grants are derived live from ``role_permission`` per request by lane A;
``grants_from_memberships`` mirrors that derivation for tests and for the generated authz wall.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from sibyl_schemas import values as sv

from .problems import ProblemError

__all__ = [
    "BREAK_GLASS_SCOPE",
    "KEY_SCOPES",
    "MONITOR_SCOPES",
    "M_ONLY_SCOPES",
    "NOT_APPLICABLE",
    "PSEUDO_SCOPES",
    "ROLES",
    "ROLE_GRANTS",
    "SCOPES",
    "SCOPE_CATALOGUE",
    "STEP_UP_SCOPES",
    "STEP_UP_WINDOW",
    "Grant",
    "Mark",
    "MembershipGrant",
    "Principal",
    "PrincipalKind",
    "authorize",
    "grants_for_api_key",
    "grants_from_memberships",
]

SCOPE_CATALOGUE = sv.SCOPE_CATALOGUE
ROLES: tuple[str, ...] = tuple(role.value for role in sv.Role)
SCOPES: frozenset[str] = frozenset(scope.value for scope in sv.SCOPE_CATALOGUE)
KEY_SCOPES: frozenset[str] = frozenset(scope.value for scope in sv.MACHINE_SCOPES)
M_ONLY_SCOPES: frozenset[str] = frozenset(scope.value for scope in sv.MACHINE_ONLY_SCOPES)
MONITOR_SCOPES: frozenset[str] = frozenset(scope.value for scope in sv.MONITOR_KEY_SCOPES)
BREAK_GLASS_SCOPE: str = sv.BREAK_GLASS_SCOPE.value
STEP_UP_SCOPES: frozenset[str] = frozenset(scope.value for scope in sv.STEP_UP_SCOPES)
STEP_UP_WINDOW = timedelta(minutes=5)
PSEUDO_SCOPES: frozenset[str] = frozenset({"public", "authenticated"})


class _NotApplicable(StrEnum):
    NOT_APPLICABLE = "not_applicable"


NOT_APPLICABLE = _NotApplicable.NOT_APPLICABLE
"""Pass as ``resource_group_id`` when the route has no group object rule (the default)."""


class Mark(StrEnum):
    TENANT = "T"
    GROUP = "G"
    AUDITED = "A"


def _mark(mode: sv.GrantMode, audited: bool) -> Mark:
    if mode is sv.GrantMode.GROUP:
        return Mark.GROUP
    return Mark.AUDITED if audited else Mark.TENANT


ROLE_GRANTS: Mapping[str, Mapping[str, Mark]] = MappingProxyType(
    {
        role.value: MappingProxyType(
            {
                spec.scope.value: _mark(spec.grants[role].mode, spec.grants[role].audited)
                for spec in sv.SCOPE_CATALOGUE.values()
                if role in spec.grants
            }
        )
        for role in sv.Role
    }
)
"""Role → scope → mark, projected from the schemas catalogue (T tenant, G group, A audited)."""


class PrincipalKind(StrEnum):
    SESSION = "session"
    OIDC = "oidc"
    API_KEY = "api_key"


@dataclass(frozen=True)
class Grant:
    """One scope held by a principal. ``group_ids is None`` means tenant-wide."""

    scope: str
    group_ids: frozenset[UUID] | None = None
    audited: bool = False


@dataclass(frozen=True)
class MembershipGrant:
    role: str
    group_id: UUID | None = None  # None = tenant-scoped membership


@dataclass(frozen=True)
class Principal:
    kind: PrincipalKind
    tenant_id: UUID
    id: UUID  # app_user.id or api_key.id
    grants: Mapping[str, Grant] = field(default_factory=dict)
    session_id: UUID | None = None
    step_up_at: datetime | None = None
    bound_agent_id: UUID | None = None
    roles: frozenset[str] = frozenset()
    monitor_id: UUID | None = None  # D53: a monitor-bound API key's monitor

    @property
    def scopes(self) -> frozenset[str]:
        return frozenset(self.grants)

    @property
    def is_human(self) -> bool:
        return self.kind is not PrincipalKind.API_KEY

    @property
    def is_break_glass(self) -> bool:
        return self.kind is PrincipalKind.API_KEY and self.scopes == {BREAK_GLASS_SCOPE}

    def has(self, scope: str) -> bool:
        return scope in self.grants


def _merge(existing: Grant | None, incoming: Grant) -> Grant:
    if existing is None:
        return incoming
    audited = existing.audited or incoming.audited
    if existing.group_ids is None or incoming.group_ids is None:
        return Grant(incoming.scope, None, audited)
    return Grant(incoming.scope, existing.group_ids | incoming.group_ids, audited)


def grants_from_memberships(memberships: Iterable[MembershipGrant]) -> dict[str, Grant]:
    """Union of role grants; G marks narrow to the membership's group when it has one."""
    out: dict[str, Grant] = {}
    for membership in memberships:
        for scope, mark in ROLE_GRANTS[membership.role].items():
            groups = None
            if mark is Mark.GROUP and membership.group_id is not None:
                groups = frozenset({membership.group_id})
            grant = Grant(scope, groups, mark is Mark.AUDITED)
            out[scope] = _merge(out.get(scope), grant)
    return out


def grants_for_api_key(scopes: Iterable[str]) -> dict[str, Grant]:
    scope_set = frozenset(scopes)
    unknown = scope_set - KEY_SCOPES
    if unknown:
        raise ValueError(f"not key-grantable: {sorted(unknown)}")
    return {s: Grant(s) for s in scope_set}


def _check_known(*scopes: str) -> None:
    for scope in scopes:
        if scope not in SCOPES:
            raise ValueError(f"unknown scope {scope!r}")


def _denied(permission: str) -> ProblemError:
    return ProblemError("forbidden", extensions={"permission": permission}, audit_denied=True)


def _not_found() -> ProblemError:
    return ProblemError("not_found", audit_denied=True)


def _find_grant(principal: Principal, wanted: tuple[str, ...]) -> Grant | None:
    for scope in wanted:
        grant = principal.grants.get(scope)
        if grant is not None:
            return grant
    return None


def _check_key(principal: Principal, wanted: tuple[str, ...], key_scopes: tuple[str, ...]) -> None:
    if principal.is_break_glass and BREAK_GLASS_SCOPE not in wanted:
        raise ProblemError("break_glass_key_misuse", audit_denied=True)
    if not set(wanted) & set(key_scopes):
        raise _denied(wanted[0])


def _check_step_up(principal: Principal, now: datetime, step_up_url: str | None) -> None:
    fresh = (
        principal.kind is PrincipalKind.SESSION
        and principal.step_up_at is not None
        and now - principal.step_up_at <= STEP_UP_WINDOW
    )
    if not fresh:
        ext = {"step_up_url": step_up_url} if step_up_url else {}
        raise ProblemError("step_up_required", extensions=ext, audit_denied=True)


def authorize(
    principal: Principal | None,
    scope: str,
    *,
    now: datetime,
    scope_any: tuple[str, ...] = (),
    key_scopes: tuple[str, ...] = (),
    step_up: bool = False,
    step_up_url: str | None = None,
    resource_group_id: UUID | _NotApplicable | None = NOT_APPLICABLE,
    resource_agent_id: UUID | None = None,
    self_id: UUID | None = None,
) -> Grant:
    """Deny by default: ``scope ∈ principal`` ∧ object rules ∧ step-up.

    ``resource_group_id`` is the resource's ``agent.agent_group_id`` (``None`` = ungrouped, which a
    group-limited grant cannot reach). Out-of-group and foreign-agent resources raise 404, never
    403, so existence does not leak. List routes filter in SQL with ``grant.group_ids`` instead.
    Every refusal carries ``audit_denied=True``; the caller writes ``access.denied``.
    """
    wanted = (scope, *scope_any)
    _check_known(*wanted)
    if principal is None:
        raise ProblemError("unauthenticated")
    if principal.kind is PrincipalKind.API_KEY:
        _check_key(principal, wanted, key_scopes)
        # A key may use only the scopes the route lists for keys (x-sibyl-key-scopes): holding
        # another of the route's scopes (e.g. agents:read where only monitor:read is
        # key-grantable) does not let it in.
        wanted = tuple(s for s in wanted if s in key_scopes)
    grant = _find_grant(principal, wanted)
    if grant is None:
        if self_id is not None and self_id == principal.id:
            return Grant(scope)
        raise _denied(scope)
    if (
        grant.group_ids is not None
        and resource_group_id is not NOT_APPLICABLE
        and resource_group_id not in grant.group_ids
    ):
        raise _not_found()
    if (
        principal.bound_agent_id is not None
        and resource_agent_id is not None
        and resource_agent_id != principal.bound_agent_id
    ):
        raise _not_found()
    if step_up and principal.is_human:
        _check_step_up(principal, now, step_up_url)
    return grant
