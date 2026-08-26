"""Characterization tests for the kp_authorization RBAC matrix (AUTH-002).

These pin CURRENT behavior so later waves can refactor safely: the exact
role→capability mapping, fail-closed handling of unknown roles (HIGH-01
regression guard), role-name resolution edge cases, and the CAMP-002
self-approval rule. They assert what the code does today, not what a future
spec might want; suspicious behavior is flagged with TODO(T-07) notes.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest
from kp_authorization import (
    APPROVE_CAMPAIGN,
    EXPORT_BULK,
    HANDLE_PRIVACY,
    USE_KILL_SWITCH,
    AuthorizationError,
    Capability,
    Principal,
    Role,
    require,
    roles_for_names,
    self_approval_blocked,
)
from kp_authorization.rbac import require_any

# Exact capability sets per role, as "action:object" strings, mirroring the
# mapping documented in kp_authorization.rbac (_ROLE_CAPABILITIES).
ROLE_CAPABILITY_STRINGS: dict[Role, frozenset[str]] = {
    Role.SOURCE_CURATOR: frozenset({"submit:source", "manage:source", "approve:pattern", "view_aggregate:results"}),
    Role.CAMPAIGN_AUTHOR: frozenset({"create:campaign", "view_aggregate:results"}),
    Role.SECURITY_APPROVER: frozenset(
        {
            "approve:campaign",
            "approve_security:campaign",
            # Generated content is security-reviewed before it can be scheduled.
            "approve:template",
            "view_named:results",
            "view_aggregate:results",
            "stop:campaign",
        }
    ),
    Role.PRIVACY_APPROVER: frozenset(
        {
            "approve:campaign",
            "approve_privacy:campaign",
            "handle:privacy_requests",
            "delete:data",
            "view_named:results",
            "view_aggregate:results",
            "manage:exclusions",
        }
    ),
    Role.CAMPAIGN_OPERATOR: frozenset(
        {
            "schedule:campaign",
            "send:campaign",
            "stop:campaign",
            "use:kill_switch",
            "view_aggregate:results",
            "manage:recipients",
            "approve:campaign",
            "subscribe:alerts",
            "verify:sending_domain",
            "sign:rules_of_engagement",
        }
    ),
    Role.AUDITOR: frozenset({"view:audit", "view_named:results", "view_aggregate:results"}),
    Role.ADMINISTRATOR: frozenset(
        {
            "approve:campaign",
            "approve_security:campaign",
            "approve_privacy:campaign",
            "create:campaign",
            "schedule:campaign",
            "stop:campaign",
            "send:campaign",
            "manage:source",
            "submit:source",
            "view_named:results",
            "view_aggregate:results",
            "export_bulk:results",
            "view:audit",
            "manage:recipients",
            "manage:exclusions",
            "handle:privacy_requests",
            "delete:data",
            "approve:pattern",
            "approve:template",
            "manage:roles",
            "use:kill_switch",
            "subscribe:alerts",
            "verify:sending_domain",
            "sign:rules_of_engagement",
        }
    ),
}


def _caps(principal: Principal) -> set[str]:
    return {f"{c.action}:{c.object}" for c in principal.capabilities()}


def _principal(roles: Iterable[Role], subject_id: str = "subject-1") -> Principal:
    return Principal(subject_id, set(roles))


@pytest.mark.parametrize("role", list(Role))
def test_role_capability_mapping_matches_documented_matrix(role: Role) -> None:
    assert _caps(_principal([role])) == set(ROLE_CAPABILITY_STRINGS[role])


def test_administrator_holds_every_defined_capability() -> None:
    all_caps = {f"{c.action}:{c.object}" for c in vars(Capability).values() if isinstance(c, Capability)}
    assert all_caps, "expected the Capability class to define at least one capability"
    assert _caps(_principal([Role.ADMINISTRATOR])) == all_caps


def test_multi_role_principal_unions_capabilities() -> None:
    principal = _principal([Role.CAMPAIGN_AUTHOR, Role.SECURITY_APPROVER])
    assert _caps(principal) == set(ROLE_CAPABILITY_STRINGS[Role.CAMPAIGN_AUTHOR]) | set(
        ROLE_CAPABILITY_STRINGS[Role.SECURITY_APPROVER]
    )


# --- Fail-closed handling of unknown roles (HIGH-01 regression) ---


def test_principal_with_no_roles_has_no_capabilities() -> None:
    principal = _principal([])
    assert principal.capabilities() == frozenset()
    assert not principal.can(Capability("manage", "roles"))
    with pytest.raises(AuthorizationError, match="lacks capability manage:roles"):
        require(principal, Capability("manage", "roles"))


def test_unknown_role_name_is_rejected_by_roles_for_names() -> None:
    """HIGH-01: an unrecognized role name must never resolve to capabilities."""
    with pytest.raises(ValueError, match="not a valid Role"):
        roles_for_names(["superuser"])


def test_principal_with_unrecognized_role_value_grants_nothing() -> None:
    """Characterization: an unknown role value in `Principal.roles` grants no
    capabilities, but `capabilities()` raises KeyError instead of returning an
    empty set — fail-closed, yet loud rather than silent.

    TODO(T-07): consider normalizing unknown role values to zero capabilities
    (or a typed error) so callers cannot crash the auth path.
    """
    principal = Principal("subject-1", {"wizard"})  # type: ignore[arg-type]
    with pytest.raises(KeyError):
        principal.capabilities()
    with pytest.raises(KeyError):
        principal.can(USE_KILL_SWITCH)


def test_plain_string_role_values_resolve_capabilities() -> None:
    """Characterization: because Role is a StrEnum, a plain string equal to a
    role value hashes like the enum member, so `Principal.roles` accepts
    unvalidated strings that happen to match. TODO(T-07): validate at the
    boundary instead of relying on str hashing.
    """
    principal = Principal("subject-1", {"campaign_author"})  # type: ignore[arg-type]
    assert _caps(principal) == set(ROLE_CAPABILITY_STRINGS[Role.CAMPAIGN_AUTHOR])


# --- Role-name resolution (claims → roles) edge cases ---


@pytest.mark.parametrize("name", ["campaign-author", "Campaign_Author", "CAMPAIGN_AUTHOR", "Administrator", ""])
def test_role_name_resolution_is_exact_and_has_no_alias_handling(name: str) -> None:
    """Characterization: only the exact lowercase underscore value resolves.
    There is no hyphen/underscore alias normalization at this base (the task
    references an auth.py:83-89 alias layer that does not exist yet).
    TODO(T-07): add alias handling when the auth module lands.
    """
    with pytest.raises(ValueError):
        roles_for_names([name])


def test_roles_for_names_empty_iterable_yields_no_roles() -> None:
    assert roles_for_names([]) == set()


def test_roles_for_names_resolves_and_deduplicates_valid_names() -> None:
    assert roles_for_names(["administrator", "auditor", "administrator"]) == {
        Role.ADMINISTRATOR,
        Role.AUDITOR,
    }


@pytest.mark.parametrize("bad", [None, 7, 3.14, b"administrator", ["administrator"]])
def test_roles_for_names_rejects_non_string_entries(bad: Any) -> None:
    with pytest.raises(ValueError):
        roles_for_names([bad])


# --- Representative grant/deny capability checks ---


def test_use_kill_switch_grants() -> None:
    granted = {Role.CAMPAIGN_OPERATOR, Role.ADMINISTRATOR}
    for role in Role:
        assert _principal([role]).can(USE_KILL_SWITCH) == (role in granted), role


def test_approve_campaign_grants() -> None:
    granted = {Role.SECURITY_APPROVER, Role.PRIVACY_APPROVER, Role.CAMPAIGN_OPERATOR, Role.ADMINISTRATOR}
    for role in Role:
        assert _principal([role]).can(APPROVE_CAMPAIGN) == (role in granted), role


def test_handle_privacy_grants() -> None:
    granted = {Role.PRIVACY_APPROVER, Role.ADMINISTRATOR}
    for role in Role:
        assert _principal([role]).can(HANDLE_PRIVACY) == (role in granted), role


def test_export_bulk_is_administrator_only() -> None:
    for role in Role:
        assert _principal([role]).can(EXPORT_BULK) == (role is Role.ADMINISTRATOR), role


# --- require / require_any ---


def test_require_passes_when_capability_held() -> None:
    require(_principal([Role.ADMINISTRATOR]), EXPORT_BULK)


def test_require_raises_with_subject_and_capability_in_message() -> None:
    with pytest.raises(AuthorizationError, match="principal author-1 lacks capability export_bulk:results"):
        require(_principal([Role.CAMPAIGN_AUTHOR], subject_id="author-1"), EXPORT_BULK)


def test_require_any_accepts_any_listed_capability() -> None:
    require_any(_principal([Role.AUDITOR]), USE_KILL_SWITCH, Capability("view", "audit"))


def test_require_any_raises_when_none_held() -> None:
    with pytest.raises(AuthorizationError, match="lacks any of"):
        require_any(_principal([Role.AUDITOR]), USE_KILL_SWITCH, HANDLE_PRIVACY)


def test_require_any_with_no_capabilities_fails_closed() -> None:
    with pytest.raises(AuthorizationError, match="lacks any of"):
        require_any(_principal([Role.ADMINISTRATOR]))


def test_authorization_error_is_a_permission_error() -> None:
    assert issubclass(AuthorizationError, PermissionError)


# --- CAMP-002: self-approval prohibition ---


def test_self_approval_is_blocked_for_own_work() -> None:
    principal = _principal([Role.SECURITY_APPROVER], subject_id="author-1")
    with pytest.raises(AuthorizationError, match="self-approval is prohibited"):
        self_approval_blocked(principal, author_id="author-1", object_type="campaign")


def test_self_approval_not_blocked_for_other_authors() -> None:
    principal = _principal([Role.SECURITY_APPROVER], subject_id="approver-1")
    assert self_approval_blocked(principal, author_id="author-1", object_type="campaign") is None


# --- Principal basics ---


def test_principal_id_aliases_subject_id() -> None:
    principal = _principal([Role.AUDITOR], subject_id="subject-9")
    assert principal.principal_id == principal.subject_id == "subject-9"


def test_has_role_membership_check() -> None:
    principal = _principal([Role.AUDITOR])
    assert principal.has_role(Role.AUDITOR)
    assert not principal.has_role(Role.ADMINISTRATOR)
