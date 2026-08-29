"""Focused discovery, verification and identity-claim tests for OIDC principals."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Self

import httpx
import jwt
import pytest
from kp_authorization.rbac import AuthorizationError, Capability, Principal, Role
from kp_operator_api import auth as auth_module
from kp_operator_api.auth import (
    DevIdP,
    OidcEndpointPolicyError,
    OidcIdP,
    _claims_to_principal,
    require_any_capability,
    require_capability,
    resolve_oidc_endpoint,
    validate_oidc_endpoint,
)
from kp_telemetry.errors import AuthenticationError, ErrorCode, PermissionDeniedError

_SECURITY = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_PRIVACY = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_UNPRIVILEGED = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
_DEV_SECRET = "dedicated-dev-secret-at-least-32-bytes"
_PUBLIC_TEST_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _stable_oidc_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, port: int, **_kwargs: object) -> list[tuple[object, ...]]:
        if host == "localhost":
            return [(auth_module.socket.AF_INET, auth_module.socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        return [(auth_module.socket.AF_INET, auth_module.socket.SOCK_STREAM, 6, "", (_PUBLIC_TEST_IP, port))]

    monkeypatch.setattr(auth_module.socket, "getaddrinfo", resolve)


@pytest.mark.parametrize(
    "url",
    [
        "http://id.example/jwks",
        "https://user:password@id.example/jwks",
        "https://id.example/jwks#fragment",
        "https://keys.example/jwks",
        "https://id.example:444/jwks",
    ],
)
def test_oidc_endpoint_must_be_https_and_exactly_issuer_origin_bound(url: str) -> None:
    with pytest.raises(OidcEndpointPolicyError):
        validate_oidc_endpoint(
            url,
            issuer="https://id.example/tenant/v2.0",
            endpoint_name="JWKS endpoint",
        )


def test_oidc_endpoint_explicit_origin_allowlist_is_narrow_and_exact() -> None:
    assert (
        validate_oidc_endpoint(
            "https://keys.example/jwks",
            issuer="https://id.example/tenant/v2.0",
            endpoint_name="JWKS endpoint",
            allowed_origins=("https://keys.example",),
        )
        == "https://keys.example/jwks"
    )
    with pytest.raises(OidcEndpointPolicyError):
        validate_oidc_endpoint(
            "https://keys.example/jwks",
            issuer="https://id.example/tenant/v2.0",
            endpoint_name="JWKS endpoint",
            allowed_origins=("https://keys.example/allowed-path",),
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "0.0.0.0",  # noqa: S104 - adversarial destination classification input
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ],
)
def test_oidc_endpoint_rejects_every_non_public_resolution(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    family = auth_module.socket.AF_INET6 if ":" in address else auth_module.socket.AF_INET
    monkeypatch.setattr(
        auth_module.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(family, auth_module.socket.SOCK_STREAM, 6, "", (address, 443))],
    )

    with pytest.raises(OidcEndpointPolicyError, match="public addresses"):
        resolve_oidc_endpoint(
            "https://id.example/jwks",
            issuer="https://id.example/tenant/v2.0",
            endpoint_name="JWKS endpoint",
        )


def test_oidc_endpoint_rejects_mixed_public_private_and_excessive_dns_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mixed = [
        (auth_module.socket.AF_INET, auth_module.socket.SOCK_STREAM, 6, "", (_PUBLIC_TEST_IP, 443)),
        (auth_module.socket.AF_INET, auth_module.socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443)),
    ]
    monkeypatch.setattr(auth_module.socket, "getaddrinfo", lambda *_args, **_kwargs: mixed)
    with pytest.raises(OidcEndpointPolicyError, match="public addresses"):
        resolve_oidc_endpoint(
            "https://id.example/jwks",
            issuer="https://id.example",
            endpoint_name="JWKS endpoint",
        )

    excessive = [mixed[0]] * (auth_module._MAX_OIDC_DNS_ANSWERS + 1)
    monkeypatch.setattr(auth_module.socket, "getaddrinfo", lambda *_args, **_kwargs: excessive)
    with pytest.raises(OidcEndpointPolicyError, match="DNS results"):
        resolve_oidc_endpoint(
            "https://id.example/jwks",
            issuer="https://id.example",
            endpoint_name="JWKS endpoint",
        )


def test_oidc_endpoint_pins_public_address_and_preserves_host_and_sni() -> None:
    endpoint = resolve_oidc_endpoint(
        "https://id.example:8443/tenant/keys?version=2",
        issuer="https://id.example:8443/tenant",
        endpoint_name="JWKS endpoint",
    )

    assert endpoint.request_url == f"https://{_PUBLIC_TEST_IP}:8443/tenant/keys?version=2"
    assert endpoint.host_header == "id.example:8443"
    assert endpoint.extensions == {"sni_hostname": "id.example"}


def test_distinct_oidc_subjects_remain_distinct_principals() -> None:
    security = _claims_to_principal({"sub": _SECURITY, "realm_access": {"roles": ["security_approver"]}})
    privacy = _claims_to_principal({"sub": _PRIVACY, "realm_access": {"roles": ["privacy_approver"]}})

    assert security.subject_id == _SECURITY
    assert security.roles == {Role.SECURITY_APPROVER}
    assert privacy.subject_id == _PRIVACY
    assert privacy.roles == {Role.PRIVACY_APPROVER}
    assert security.subject_id != privacy.subject_id


def test_entra_oid_and_top_level_roles_build_principal() -> None:
    principal = _claims_to_principal(
        {
            "sub": "pairwise-opaque-entra-subject",
            "oid": _SECURITY,
            "roles": ["security_approver", "operator", "unknown-application-role"],
        }
    )

    assert principal.subject_id == _SECURITY
    assert principal.roles == {Role.SECURITY_APPROVER, Role.CAMPAIGN_OPERATOR}


def test_entra_oid_takes_precedence_over_uuid_subject() -> None:
    principal = _claims_to_principal({"sub": _PRIVACY, "oid": _SECURITY, "roles": ["auditor"]})

    assert principal.subject_id == _SECURITY
    assert principal.roles == {Role.AUDITOR}


def test_keycloak_subject_and_realm_roles_remain_supported() -> None:
    principal = _claims_to_principal(
        {"sub": _PRIVACY, "realm_access": {"roles": ["privacy_approver", "campaign_operator"]}}
    )

    assert principal.subject_id == _PRIVACY
    assert principal.roles == {Role.PRIVACY_APPROVER, Role.CAMPAIGN_OPERATOR}


def test_provider_role_claims_are_merged_without_escalation() -> None:
    principal = _claims_to_principal(
        {
            "sub": _UNPRIVILEGED,
            "roles": ["auditor"],
            "realm_access": {"roles": ["source_curator", "does-not-exist"]},
        }
    )

    assert principal.roles == {Role.AUDITOR, Role.SOURCE_CURATOR}


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
    assert excinfo.value.message == "token principal identifier must be a UUID"
    assert str(excinfo.value) == "KP-003: token principal identifier must be a UUID"


def test_missing_subject_still_rejected_as_401() -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        _claims_to_principal({"realm_access": {"roles": ["operator"]}})

    assert excinfo.value.http_status == 401


def test_malformed_oid_does_not_fall_back_to_subject() -> None:
    with pytest.raises(PermissionDeniedError) as excinfo:
        _claims_to_principal({"oid": "not-a-uuid", "sub": _SECURITY, "roles": ["administrator"]})

    assert excinfo.value.http_status == 403
    assert excinfo.value.message == "token principal identifier must be a UUID"
    assert "not-a-uuid" not in str(excinfo.value)


def test_capability_dependency_does_not_expose_principal_identifier() -> None:
    secret_principal = "principal-secret@example.invalid"
    checker = require_capability(Capability.EXPORT_BULK)

    with pytest.raises(PermissionDeniedError) as excinfo:
        checker(Principal(secret_principal, {Role.CAMPAIGN_AUTHOR}))

    assert excinfo.value.message == "required capability is not assigned"
    assert secret_principal not in str(excinfo.value)


def test_any_capability_dependency_does_not_expose_principal_identifier() -> None:
    secret_principal = "principal-secret@example.invalid"
    checker = require_any_capability(Capability.USE_KILL_SWITCH, Capability.HANDLE_PRIVACY)

    with pytest.raises(PermissionDeniedError) as excinfo:
        checker(Principal(secret_principal, {Role.AUDITOR}))

    assert excinfo.value.message == "none of the required capabilities are assigned"
    assert secret_principal not in str(excinfo.value)


@pytest.mark.parametrize(
    ("factory", "expected_message"),
    [
        (lambda: require_capability(Capability.EXPORT_BULK), "required capability is not assigned"),
        (
            lambda: require_any_capability(Capability.USE_KILL_SWITCH, Capability.HANDLE_PRIVACY),
            "none of the required capabilities are assigned",
        ),
    ],
)
def test_capability_dependencies_do_not_reflect_arbitrary_authorization_errors(
    monkeypatch: pytest.MonkeyPatch,
    factory: Any,
    expected_message: str,
) -> None:
    leaked_detail = "Bearer secret-token / tenant/user identifier"

    def reject(*_args: object, **_kwargs: object) -> None:
        raise AuthorizationError(leaked_detail)

    monkeypatch.setattr(auth_module, "require", reject)
    monkeypatch.setattr(auth_module, "require_any", reject)
    checker = factory()

    with pytest.raises(PermissionDeniedError) as excinfo:
        checker(Principal(_UNPRIVILEGED, set()))

    assert excinfo.value.message == expected_message
    assert leaked_detail not in str(excinfo.value)


@pytest.mark.parametrize(
    ("claims", "expected_roles"),
    [
        ({"roles": "administrator"}, set()),
        ({"roles": [None, 42, {"role": "administrator"}]}, set()),
        ({"realm_access": "administrator"}, set()),
        ({"realm_access": {"roles": "administrator"}}, set()),
    ],
)
def test_malformed_role_claims_fail_closed(claims: dict[str, Any], expected_roles: set[Role]) -> None:
    principal = _claims_to_principal({"sub": _UNPRIVILEGED, **claims})

    assert principal.roles == expected_roles


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


@pytest.mark.parametrize("missing_claim", ["exp", "iss", "aud"])
def test_dev_verifier_requires_standard_validation_claims(missing_claim: str) -> None:
    claims: dict[str, Any] = {
        "sub": _SECURITY,
        "iss": "http://localhost:8443/realms/dev",
        "aud": "operator",
        "exp": 2_000_000_000,
        "realm_access": {"roles": ["operator"]},
    }
    del claims[missing_claim]
    token = jwt.encode(claims, _DEV_SECRET, algorithm="HS256")

    with pytest.raises(AuthenticationError):
        DevIdP("http://localhost:8443/realms/dev", "operator", _DEV_SECRET).verify(token)


def test_dev_verifier_rejects_expired_token() -> None:
    token = jwt.encode(
        {
            "sub": _SECURITY,
            "iss": "http://localhost:8443/realms/dev",
            "aud": "operator",
            "exp": 1,
            "realm_access": {"roles": ["operator"]},
        },
        _DEV_SECRET,
        algorithm="HS256",
    )

    with pytest.raises(AuthenticationError):
        DevIdP("http://localhost:8443/realms/dev", "operator", _DEV_SECRET).verify(token)


class _DiscoveryClient:
    response: httpx.Response
    requests: list[tuple[str, dict[str, object]]] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    @contextmanager
    def stream(self, method: str, url: str, **kwargs: object) -> Iterator[httpx.Response]:
        assert method == "GET"
        type(self).requests.append((url, kwargs))
        yield type(self).response


class _SigningKey:
    key = "public-key"


class _JwkClient:
    created_urls: list[str] = []

    def __init__(self, url: str, **_kwargs: object) -> None:
        self.created_urls.append(url)

    def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
        return _SigningKey()


class _FailingJwkClient(_JwkClient):
    def get_signing_key_from_jwt(self, _token: str) -> _SigningKey:
        raise jwt.PyJWKClientError("JWKS unavailable")


def _mock_discovery(
    monkeypatch: pytest.MonkeyPatch,
    metadata: object,
    *,
    status_code: int = 200,
) -> None:
    _DiscoveryClient.requests = []
    _JwkClient.created_urls = []
    _DiscoveryClient.response = httpx.Response(
        status_code,
        request=httpx.Request("GET", "https://id.example/.well-known/openid-configuration"),
        json=metadata,
    )
    monkeypatch.setattr(httpx, "Client", _DiscoveryClient)
    monkeypatch.setattr(auth_module, "BoundedPyJWKClient", _JwkClient)


def test_discovery_uses_provider_jwks_uri_and_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_discovery(
        monkeypatch,
        {"issuer": "https://id.example/tenant/v2.0", "jwks_uri": "https://id.example/discovery/v2.0/keys"},
    )
    decoded: list[tuple[str, str, str]] = []

    def decode(_token: str, key: str, **kwargs: Any) -> dict[str, Any]:
        decoded.append((key, kwargs["audience"], kwargs["issuer"]))
        return {"sub": _SECURITY, "realm_access": {"roles": ["operator"]}}

    monkeypatch.setattr(jwt, "decode", decode)
    idp = OidcIdP("https://id.example/tenant/v2.0/", "api://operator")

    assert idp.verify("first-token").subject_id == _SECURITY
    assert idp.verify("second-token").roles == {Role.CAMPAIGN_OPERATOR}
    assert _DiscoveryClient.requests == [
        (
            f"https://{_PUBLIC_TEST_IP}/tenant/v2.0/.well-known/openid-configuration",
            {"extensions": {"sni_hostname": "id.example"}},
        )
    ]
    assert _JwkClient.created_urls == ["https://id.example/discovery/v2.0/keys"]
    assert decoded == [
        ("public-key", "api://operator", "https://id.example/tenant/v2.0"),
        ("public-key", "api://operator", "https://id.example/tenant/v2.0"),
    ]


@pytest.mark.parametrize(
    "metadata",
    [
        [],
        {"issuer": "https://attacker.example", "jwks_uri": "https://keys.example/jwks"},
        {"issuer": "https://id.example", "jwks_uri": "http://keys.example/jwks"},
        {"issuer": "https://id.example", "jwks_uri": "https://user:password@keys.example/jwks"},
        {"issuer": "https://id.example", "jwks_uri": "https://keys.example/jwks"},
        {"issuer": "https://id.example"},
    ],
)
def test_invalid_discovery_metadata_fails_closed(monkeypatch: pytest.MonkeyPatch, metadata: object) -> None:
    _mock_discovery(monkeypatch, metadata)

    with pytest.raises(AuthenticationError):
        OidcIdP("https://id.example", "api://operator").verify("token")


def test_discovery_http_failure_is_authentication_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_discovery(monkeypatch, {}, status_code=503)

    with pytest.raises(AuthenticationError) as excinfo:
        OidcIdP("https://id.example", "api://operator").verify("token")

    assert excinfo.value.http_status == 401
    assert "discovery failed" in str(excinfo.value)


def test_discovery_redirect_is_refused_without_following(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_discovery(monkeypatch, {}, status_code=302)
    _DiscoveryClient.response.headers["location"] = "https://attacker.example/discovery"

    with pytest.raises(AuthenticationError, match="discovery failed"):
        OidcIdP("https://id.example", "api://operator").verify("token")

    assert len(_DiscoveryClient.requests) == 1


def test_jwks_failure_is_authentication_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_discovery(monkeypatch, {"issuer": "https://id.example", "jwks_uri": "https://id.example/jwks"})
    monkeypatch.setattr(auth_module, "BoundedPyJWKClient", _FailingJwkClient)

    with pytest.raises(AuthenticationError) as excinfo:
        OidcIdP("https://id.example", "api://operator").verify("token")

    assert excinfo.value.http_status == 401
    assert "invalid or expired token" in str(excinfo.value)


def test_invalid_signature_or_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_discovery(monkeypatch, {"issuer": "https://id.example", "jwks_uri": "https://id.example/jwks"})

    def decode(*_args: object, **_kwargs: object) -> dict[str, Any]:
        raise jwt.InvalidSignatureError("bad signature")

    monkeypatch.setattr(jwt, "decode", decode)

    with pytest.raises(AuthenticationError) as excinfo:
        OidcIdP("https://id.example", "api://operator").verify("token")

    assert excinfo.value.http_status == 401


def test_local_dev_oidc_can_discover_local_http_jwks(monkeypatch: pytest.MonkeyPatch) -> None:
    _DiscoveryClient.response = httpx.Response(
        200,
        request=httpx.Request("GET", "http://localhost:8443/.well-known/openid-configuration"),
        json={"issuer": "http://localhost:8443/realms/dev", "jwks_uri": "http://localhost:8443/jwks"},
    )
    _DiscoveryClient.requests = []
    _JwkClient.created_urls = []
    monkeypatch.setattr(httpx, "Client", _DiscoveryClient)
    monkeypatch.setattr(auth_module, "BoundedPyJWKClient", _JwkClient)

    idp = OidcIdP("http://localhost:8443/realms/dev", "operator")
    idp._discover_jwk_client()

    assert _JwkClient.created_urls == ["http://localhost:8443/jwks"]
