"""Security contracts for the kp_authorization RBAC matrix (AUTH-002)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import kp_authorization
import pytest
from kp_authorization import (
    APPROVE_PRIVACY,
    APPROVE_SECURITY,
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
            "subscribe:alerts",
            "verify:sending_domain",
            "sign:rules_of_engagement",
            "manage:job_queue",
        }
    ),
    Role.AUDITOR: frozenset({"view:audit", "view_named:results", "view_aggregate:results"}),
    Role.ADMINISTRATOR: frozenset(
        {
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
            "manage:job_queue",
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


def test_every_capability_has_a_public_module_export() -> None:
    for name, capability in vars(Capability).items():
        if isinstance(capability, Capability):
            assert getattr(kp_authorization, name) is capability
            assert name in kp_authorization.__all__


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
    with pytest.raises(AuthorizationError, match="required capability is not assigned: manage:roles"):
        require(principal, Capability("manage", "roles"))


def test_unknown_role_name_is_rejected_by_roles_for_names() -> None:
    """HIGH-01: an unrecognized role name must never resolve to capabilities."""
    with pytest.raises(ValueError, match="unknown role name"):
        roles_for_names(["superuser"])


def test_principal_with_unrecognized_role_value_grants_nothing() -> None:
    """Unknown runtime values neither grant access nor crash the auth path."""
    principal = Principal("subject-1", {"wizard"})  # type: ignore[arg-type]
    assert principal.capabilities() == frozenset()
    assert not principal.can(USE_KILL_SWITCH)


@pytest.mark.parametrize("role_name", [role.value for role in Role])
def test_plain_string_role_values_grant_no_capabilities(role_name: str) -> None:
    """StrEnum-compatible strings must not bypass typed role validation."""
    principal = Principal("subject-1", {role_name})  # type: ignore[arg-type]
    assert principal.capabilities() == frozenset()
    assert not principal.has_role(Role(role_name))


def test_has_role_requires_typed_arguments_and_assignments() -> None:
    principal = Principal("subject-1", {Role.AUDITOR})

    assert principal.has_role(Role.AUDITOR)
    assert not principal.has_role("auditor")  # type: ignore[arg-type]


def test_invalid_runtime_role_does_not_remove_valid_typed_role_capabilities() -> None:
    principal = Principal("subject-1", {Role.AUDITOR, "administrator"})  # type: ignore[arg-type]

    assert _caps(principal) == set(ROLE_CAPABILITY_STRINGS[Role.AUDITOR])


def test_principal_snapshots_roles_against_post_authentication_mutation() -> None:
    assigned = {Role.AUDITOR}
    principal = Principal("subject-1", assigned)

    assigned.clear()
    assigned.add(Role.ADMINISTRATOR)

    assert principal.roles == frozenset({Role.AUDITOR})
    assert not principal.has_role(Role.ADMINISTRATOR)
    with pytest.raises(AttributeError):
        principal.roles = frozenset({Role.ADMINISTRATOR})  # type: ignore[misc]


# --- Role-name resolution (claims → roles) edge cases ---


@pytest.mark.parametrize("name", ["campaign-author", "Campaign_Author", "CAMPAIGN_AUTHOR", "Administrator", ""])
def test_role_name_resolution_is_exact_and_has_no_alias_handling(name: str) -> None:
    """Only exact canonical values resolve at this provider-neutral layer."""
    with pytest.raises(ValueError):
        roles_for_names([name])


def test_roles_for_names_empty_iterable_yields_no_roles() -> None:
    assert roles_for_names([]) == set()


def test_roles_for_names_resolves_and_deduplicates_valid_names() -> None:
    assert roles_for_names(["administrator", "auditor", "administrator"]) == {
        Role.ADMINISTRATOR,
        Role.AUDITOR,
    }


@pytest.mark.parametrize("names", ["administrator", b"administrator", None, 7])
def test_roles_for_names_rejects_non_iterable_or_scalar_containers(names: object) -> None:
    with pytest.raises(ValueError):
        roles_for_names(names)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [None, 7, 3.14, b"administrator", ["administrator"]])
def test_roles_for_names_rejects_non_string_entries(bad: Any) -> None:
    with pytest.raises(ValueError):
        roles_for_names([bad])


# --- Representative grant/deny capability checks ---


def test_use_kill_switch_grants() -> None:
    granted = {Role.CAMPAIGN_OPERATOR, Role.ADMINISTRATOR}
    for role in Role:
        assert _principal([role]).can(USE_KILL_SWITCH) == (role in granted), role


@pytest.mark.parametrize(
    ("capability", "granted"),
    [
        (APPROVE_SECURITY, {Role.SECURITY_APPROVER, Role.ADMINISTRATOR}),
        (APPROVE_PRIVACY, {Role.PRIVACY_APPROVER, Role.ADMINISTRATOR}),
    ],
)
def test_approval_lane_capabilities_are_separated(capability: Capability, granted: set[Role]) -> None:
    for role in Role:
        assert _principal([role]).can(capability) == (role in granted), role


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


def test_require_does_not_leak_subject_in_message() -> None:
    with pytest.raises(AuthorizationError, match="required capability is not assigned") as excinfo:
        require(_principal([Role.CAMPAIGN_AUTHOR], subject_id="secret-author-1"), EXPORT_BULK)
    assert "secret-author-1" not in str(excinfo.value)


def test_require_any_accepts_any_listed_capability() -> None:
    require_any(_principal([Role.AUDITOR]), USE_KILL_SWITCH, Capability("view", "audit"))


def test_require_any_raises_when_none_held() -> None:
    with pytest.raises(AuthorizationError, match="none of the required capabilities"):
        require_any(_principal([Role.AUDITOR]), USE_KILL_SWITCH, HANDLE_PRIVACY)


def test_require_any_with_no_capabilities_fails_closed() -> None:
    with pytest.raises(AuthorizationError, match="none of the required capabilities"):
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


def test_self_approval_compares_uuid_identifiers_canonically_without_leaking_them() -> None:
    subject = "A42E8F0C-AD2E-4C25-9E4B-D2D53EC7AC4C"
    principal = _principal([Role.SECURITY_APPROVER], subject_id=subject)

    with pytest.raises(AuthorizationError, match="self-approval is prohibited") as excinfo:
        self_approval_blocked(principal, author_id=subject.lower(), object_type="campaign")
    assert subject not in str(excinfo.value)


@pytest.mark.parametrize(
    ("action", "object_name"),
    [("", "campaign"), ("read:*", "campaign"), ("read", ""), ("read", "Campaign")],
)
def test_capability_identifiers_must_be_canonical(action: str, object_name: str) -> None:
    with pytest.raises(ValueError):
        Capability(action, object_name)


# --- Principal basics ---


def test_principal_id_aliases_subject_id() -> None:
    principal = _principal([Role.AUDITOR], subject_id="subject-9")
    assert principal.principal_id == principal.subject_id == "subject-9"


@pytest.mark.parametrize("subject_id", ["", " ", " subject-1", "subject-1\n", "x" * 256])
def test_principal_rejects_ambiguous_or_log_unsafe_subject_identifiers(subject_id: str) -> None:
    with pytest.raises(ValueError, match="subject identifier"):
        Principal(subject_id, {Role.AUDITOR})


def test_has_role_membership_check() -> None:
    principal = _principal([Role.AUDITOR])
    assert principal.has_role(Role.AUDITOR)
    assert not principal.has_role(Role.ADMINISTRATOR)
