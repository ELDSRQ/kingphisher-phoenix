"""Hermetic contract tests for the Entra Alternative IdP component.

These tests validate that the Keycloak realm definition (realm-kingphisher.json)
is consistent with the operator API's fail-closed RBAC role mapping. They run
without any external dependencies (no Keycloak, no database).

The contract: every realm role in the Keycloak realm MUST map to a valid
Role enum value or alias in kp_authorization.rbac, so that the operator API's
_claims_to_principal function grants the expected capabilities. Unknown roles
are silently dropped (fail-closed).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REALM_FILE = Path(__file__).parents[1] / "infrastructure" / "idp" / "realm-kingphisher.json"

# Expected realm roles from the design doc / rbac.py enum
EXPECTED_REALM_ROLES = frozenset([
    "source_curator",
    "campaign_author",
    "security_approver",
    "privacy_approver",
    "campaign_operator",
    "auditor",
    "administrator",
])

# Role aliases accepted by _claims_to_principal (auth.py:_ROLE_ALIASES)
ROLE_ALIASES = {
    "operator": "CAMPAIGN_OPERATOR",
    "campaign-operator": "CAMPAIGN_OPERATOR",
    "campaign_operator": "CAMPAIGN_OPERATOR",
    "admin": "ADMINISTRATOR",
    "administrator": "ADMINISTRATOR",
}


def _load_realm() -> dict:
    """Load and parse the realm JSON file."""
    content = REALM_FILE.read_text(encoding="utf-8")
    return json.loads(content)


def test_realm_file_exists() -> None:
    """The realm definition file must exist."""
    assert REALM_FILE.exists(), f"Realm file not found: {REALM_FILE}"


def test_realm_has_correct_name() -> None:
    """The realm must be named 'kingphisher'."""
    realm = _load_realm()
    assert realm["realm"] == "kingphisher"


def test_realm_has_expected_roles() -> None:
    """The realm must define exactly the 7 expected roles."""
    realm = _load_realm()
    realm_roles = {r["name"] for r in realm.get("roles", {}).get("realm", [])}

    # Check all expected roles are present
    missing = EXPECTED_REALM_ROLES - realm_roles
    assert not missing, f"Missing expected roles: {sorted(missing)}"

    # Check no extra roles (strict contract)
    extra = realm_roles - EXPECTED_REALM_ROLES
    assert not extra, f"Unexpected extra roles in realm: {sorted(extra)}"


def test_realm_roles_match_rbac_enum() -> None:
    """Every realm role must be a valid Role enum value or alias.

    This is the critical fail-closed contract: if a realm role doesn't match
    the Role enum or an alias, _claims_to_principal will drop it silently,
    granting no capabilities.
    """
    from kp_authorization.rbac import Role

    realm = _load_realm()
    realm_roles = {r["name"] for r in realm.get("roles", {}).get("realm", [])}

    valid_names = {r.value for r in Role}
    valid_names.update(ROLE_ALIASES.keys())

    for role in realm_roles:
        assert role in valid_names, (
            f"Realm role '{role}' is not a valid Role enum value "
            f"or alias. Valid: {sorted(valid_names)}"
        )


def test_realm_has_required_clients() -> None:
    """The realm must have the two required OIDC clients."""
    realm = _load_realm()
    client_ids = {c["clientId"] for c in realm.get("clients", [])}

    assert "kp-operator-console" in client_ids, "Missing kp-operator-console client"
    assert "kp-operator-api" in client_ids, "Missing kp-operator-api client"


def test_console_client_has_correct_config() -> None:
    """The console client must be configured for auth-code flow with PKCE."""
    realm = _load_realm()
    console_client = next(
        c for c in realm.get("clients", []) if c["clientId"] == "kp-operator-console"
    )

    assert console_client["enabled"] is True
    assert console_client["protocol"] == "openid-connect"
    assert console_client["standardFlowEnabled"] is True
    assert console_client["implicitFlowEnabled"] is False
    assert console_client["directAccessGrantsEnabled"] is False
    assert console_client["serviceAccountsEnabled"] is False
    # fullScopeAllowed MUST be true: with false, Keycloak strips the user's
    # realm roles from the token (no realm roles are in the client's scope),
    # so realm_access.roles is absent and every login maps to zero roles.
    # The app's fail-closed _claims_to_principal handles unknown roles.
    assert console_client["fullScopeAllowed"] is True

    # Redirect URI must match operator API callback
    redirect_uris = console_client.get("redirectUris", [])
    assert "http://localhost:8000/api/v1/console/oidc/callback" in redirect_uris


def test_console_client_has_audience_mapper() -> None:
    """The console client must have an audience mapper for kp-operator-api.

    This ensures access tokens issued to the console client include
    'aud: kp-operator-api' which the operator API requires for validation.
    The config key MUST be the dotted spelling: Keycloak's provider config
    property is "included.client.audience" — a camelCase key is stored
    verbatim by the Admin API but never read, so the audience silently
    never lands in the token (verified empirically against KC 26.0.8).
    """
    realm = _load_realm()
    console_client = next(
        c for c in realm.get("clients", []) if c["clientId"] == "kp-operator-console"
    )

    mappers = console_client.get("protocolMappers", [])
    audience_mappers = [
        m for m in mappers
        if m.get("protocolMapper") == "oidc-audience-mapper"
        and m.get("config", {}).get("included.client.audience") == "kp-operator-api"
    ]

    assert len(audience_mappers) == 1, (
        "Console client must have exactly one audience mapper for kp-operator-api "
        "with the dotted included.client.audience config key"
    )
    mapper = audience_mappers[0]
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["id.token.claim"] == "false"


def test_api_client_exists_as_audience_reference() -> None:
    """The API client must exist so it can be referenced as an audience."""
    realm = _load_realm()
    api_client = next(
        c for c in realm.get("clients", []) if c["clientId"] == "kp-operator-api"
    )

    assert api_client["enabled"] is True
    assert api_client["protocol"] == "openid-connect"
    # API client doesn't need standard flow enabled
    assert api_client["standardFlowEnabled"] is False


def test_no_duplicate_audience_mechanism() -> None:
    """The audience must be mapped by exactly ONE mechanism.

    The client-level protocol mapper is the single mechanism (matching what
    provision_idp.py creates). A second audience client scope in the default
    scopes would double-apply the mapper; the earlier design carried both and
    the redundant scope was removed.
    """
    realm = _load_realm()
    scope_names = {s["name"] for s in realm.get("clientScopes", [])}
    assert "kp-operator-api-audience" not in scope_names
    assert "kp-operator-api-audience" not in realm.get("defaultDefaultClientScopes", [])


def test_role_descriptions_present() -> None:
    """Each realm role should have a description for admin clarity."""
    realm = _load_realm()
    realm_roles = realm.get("roles", {}).get("realm", [])

    for role in realm_roles:
        assert "description" in role, f"Role '{role['name']}' missing description"
        assert role["description"].strip(), f"Role '{role['name']}' has empty description"


def test_no_groups_or_identity_providers() -> None:
    """The realm should not have groups or identity providers configured.

    This is a single-tenant, self-contained IdP for operator login only.
    """
    realm = _load_realm()
    assert realm.get("groups", []) == [], "Realm should not have groups configured"
    assert realm.get("identityProviders", []) == [], (
        "Realm should not have identity providers configured"
    )


def test_ssl_required_none_for_loopback_idp() -> None:
    """sslRequired must be 'none' for this loopback-only dev IdP.

    Keycloak sees the docker-proxy bridge IP as a non-loopback client, so
    'external' would make it mark auth cookies Secure and refuse the plain
    HTTP loopback flow (httpx correctly never sends Secure cookies over
    HTTP). The published port binds 127.0.0.1 only — that host-level loopback
    binding is the transport protection; a public deployment must sit behind
    HTTPS via the Path (a) public-issuer route in the README.
    """
    realm = _load_realm()
    assert realm.get("sslRequired") == "none"


def test_registration_disabled() -> None:
    """User self-registration must be disabled."""
    realm = _load_realm()
    assert realm.get("registrationAllowed") is False


def test_verify_email_disabled() -> None:
    """Email verification should be disabled for this internal IdP."""
    realm = _load_realm()
    assert realm.get("verifyEmail") is False


# --- Provisioning script structure tests ---

def test_provision_script_imports() -> None:
    """The provisioning script must be importable without Keycloak."""
    script_path = Path(__file__).parents[1] / "infrastructure" / "idp" / "provision_idp.py"
    assert script_path.exists()

    # Verify it can be imported (dry-run mode doesn't need Keycloak)
    spec = __import__("importlib.util").util.spec_from_file_location(
        "provision_idp", script_path
    )
    __import__("importlib.util").util.module_from_spec(spec)
    # Don't actually execute, just verify syntax
    compile(script_path.read_text(), str(script_path), "exec")


def test_provision_script_defines_realm_roles() -> None:
    """The provisioning script's REALM_ROLES must match the realm JSON."""
    script_path = Path(__file__).parents[1] / "infrastructure" / "idp" / "provision_idp.py"
    content = script_path.read_text()

    # Extract REALM_ROLES from the script
    # Simple check: all expected roles should appear in the script
    for role in EXPECTED_REALM_ROLES:
        assert role in content, f"Provisioning script missing role: {role}"


def test_provision_script_defines_test_users() -> None:
    """The provisioning script should define test users for local development."""
    script_path = Path(__file__).parents[1] / "infrastructure" / "idp" / "provision_idp.py"
    content = script_path.read_text()

    assert "TEST_USERS" in content
    # Should have at least operator, administrator, author, security, privacy
    for username in ["operator", "administrator", "author", "security", "privacy"]:
        assert username in content, f"Test user {username} not in provisioning script"


def test_provision_script_dry_run_flag() -> None:
    """The provisioning script must support --dry-run flag."""
    script_path = Path(__file__).parents[1] / "infrastructure" / "idp" / "provision_idp.py"
    content = script_path.read_text()

    assert "dry_run" in content
    assert "dry-run" in content or "--dry-run" in content


# --- Integration with operator API auth module ---

def test_operator_api_accepts_keycloak_claim_shape() -> None:
    """Verify the operator API's _claims_to_principal accepts Keycloak claims.

    This test uses the actual auth module to ensure the Keycloak claim shape
    (realm_access.roles) is correctly handled.
    """
    from kp_authorization.rbac import Role
    from kp_operator_api.auth import _claims_to_principal

    # Simulate a Keycloak-issued token with realm_access.roles
    claims = {
        "sub": "12345678-1234-4123-8123-123456789012",  # valid UUID
        "realm_access": {
            "roles": ["campaign_operator", "security_approver"]
        },
        "iss": "http://localhost:8443/realms/kingphisher",
        "aud": "kp-operator-api",
        "exp": 9999999999,
    }

    principal = _claims_to_principal(claims)

    assert principal.subject_id == "12345678-1234-4123-8123-123456789012"
    assert Role.CAMPAIGN_OPERATOR in principal.roles
    assert Role.SECURITY_APPROVER in principal.roles
    assert len(principal.roles) == 2


def test_operator_api_rejects_unknown_realm_roles() -> None:
    """Verify unknown realm roles are dropped (fail-closed)."""
    from kp_authorization.rbac import Role
    from kp_operator_api.auth import _claims_to_principal

    claims = {
        "sub": "12345678-1234-4123-8123-123456789012",
        "realm_access": {
            "roles": ["campaign_operator", "unknown-role", "another-invalid"]
        },
    }

    principal = _claims_to_principal(claims)

    # Only the known role should be mapped
    assert principal.roles == {Role.CAMPAIGN_OPERATOR}


def test_operator_api_prefers_oid_over_sub() -> None:
    """Verify Entra 'oid' claim is preferred over 'sub' for principal ID."""
    from kp_operator_api.auth import _claims_to_principal

    claims = {
        "oid": "87654321-4321-4321-8321-210987654321",  # Entra OID
        "sub": "12345678-1234-4123-8123-123456789012",  # Keycloak sub
        "realm_access": {"roles": ["administrator"]},
    }

    principal = _claims_to_principal(claims)

    # Should prefer oid when present
    assert principal.subject_id == "87654321-4321-4321-8321-210987654321"


def test_operator_api_requires_uuid_subject() -> None:
    """Verify non-UUID subject is rejected."""
    from kp_operator_api.auth import _claims_to_principal
    from kp_telemetry.errors import PermissionDeniedError

    claims = {
        "sub": "not-a-uuid",
        "realm_access": {"roles": ["administrator"]},
    }

    with pytest.raises(PermissionDeniedError, match="must be a UUID"):
        _claims_to_principal(claims)


def test_role_aliases_work() -> None:
    """Verify role aliases are correctly mapped."""
    from kp_authorization.rbac import Role
    from kp_operator_api.auth import _claims_to_principal

    for alias, expected_role in ROLE_ALIASES.items():
        claims = {
            "sub": "12345678-1234-4123-8123-123456789012",
            "realm_access": {"roles": [alias]},
        }
        principal = _claims_to_principal(claims)
        assert Role[expected_role] in principal.roles, f"Alias '{alias}' not mapped to {expected_role}"