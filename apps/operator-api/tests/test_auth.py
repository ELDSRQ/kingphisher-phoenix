"""Focused identity-claim mapping tests for OIDC principals."""

from __future__ import annotations

from kp_authorization.rbac import Role
from kp_operator_api.auth import _claims_to_principal


def test_distinct_oidc_subjects_remain_distinct_principals() -> None:
    security = _claims_to_principal({"sub": "security-reviewer", "realm_access": {"roles": ["security_approver"]}})
    privacy = _claims_to_principal({"sub": "privacy-reviewer", "realm_access": {"roles": ["privacy_approver"]}})

    assert security.subject_id == "security-reviewer"
    assert security.roles == {Role.SECURITY_APPROVER}
    assert privacy.subject_id == "privacy-reviewer"
    assert privacy.roles == {Role.PRIVACY_APPROVER}
    assert security.subject_id != privacy.subject_id


def test_unrecognized_oidc_roles_fail_closed() -> None:
    principal = _claims_to_principal(
        {"sub": "unprivileged-user", "realm_access": {"roles": ["default-roles", "offline_access"]}}
    )

    assert principal.roles == set()
