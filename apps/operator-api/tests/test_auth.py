"""Focused identity-claim mapping tests for OIDC principals."""

from __future__ import annotations

import uuid

import pytest
from kp_authorization.rbac import Role
from kp_operator_api.auth import _claims_to_principal
from kp_telemetry.errors import AuthenticationError, ErrorCode, PermissionDeniedError

_SECURITY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_PRIVACY = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_UNPRIVILEGED = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def test_distinct_oidc_subjects_remain_distinct_principals() -> None:
    security = _claims_to_principal({"sub": _SECURITY, "realm_access": {"roles": ["security_approver"]}})
    privacy = _claims_to_principal({"sub": _PRIVACY, "realm_access": {"roles": ["privacy_approver"]}})

    assert security.subject_id == _SECURITY
    assert security.roles == {Role.SECURITY_APPROVER}
    assert privacy.subject_id == _PRIVACY
    assert privacy.roles == {Role.PRIVACY_APPROVER}
    assert security.subject_id != privacy.subject_id


def test_unrecognized_oidc_roles_fail_closed() -> None:
    principal = _claims_to_principal(
        {"sub": _UNPRIVILEGED, "realm_access": {"roles": ["default-roles", "offline_access"]}}
    )

    assert principal.roles == set()


def test_hyphen_alias_role_claims_fail_closed() -> None:
    """HIGH-01: hyphenated role names must not map to capabilities by implicit default."""
    principal = _claims_to_principal(
        {"sub": _UNPRIVILEGED, "realm_access": {"roles": ["security-approver", "privacy-approver"]}}
    )

    assert principal.roles == set()


@pytest.mark.parametrize("subject", ["auth0|123", "", "not-a-uuid"])
def test_non_uuid_subject_fails_closed_as_403(subject: str) -> None:
    """HIGH-02 residual: non-UUID `sub` is rejected at the identity boundary, never ValueError/500 downstream."""
    with pytest.raises(PermissionDeniedError) as excinfo:
        _claims_to_principal({"sub": subject, "realm_access": {"roles": ["operator"]}})

    assert excinfo.value.http_status == 403
    assert excinfo.value.code == ErrorCode.AUTHORIZATION
    assert "sub" in str(excinfo.value)
    assert "not a valid UUID" in str(excinfo.value)


def test_missing_subject_still_rejected_as_401() -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        _claims_to_principal({"realm_access": {"roles": ["operator"]}})

    assert excinfo.value.http_status == 401


@pytest.mark.parametrize(
    "subject",
    [
        "11111111-1111-4111-8111-111111111111",  # console operator (console.py CONSOLE_OPERATOR_UUID)
        "12345678-1234-5678-1234-567812345678",  # Entra-style object id
        "aaaabbbbccccddddeeeeffff00001111",  # hyphenless hex; uuid.UUID accepts it, so must we
    ],
)
def test_valid_uuid_subject_builds_principal(subject: str) -> None:
    principal = _claims_to_principal({"sub": subject, "realm_access": {"roles": ["operator"]}})

    assert principal.subject_id == subject  # preserved verbatim, never normalized
    assert principal.roles == {Role.CAMPAIGN_OPERATOR}
    uuid.UUID(principal.subject_id)  # exactly what routers do; must not raise


def test_random_uuid4_subject_builds_principal() -> None:
    subject = str(uuid.uuid4())

    principal = _claims_to_principal({"sub": subject, "realm_access": {"roles": ["administrator"]}})

    assert principal.subject_id == subject
    assert principal.roles == {Role.ADMINISTRATOR}
