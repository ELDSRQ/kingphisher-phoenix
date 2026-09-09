#!/usr/bin/env python3
"""Keycloak IdP provisioning script for Kingphisher.

Provisions the Keycloak realm, clients, roles, and optionally test users via
the Keycloak Admin REST API. Idempotent: re-running against an already
provisioned realm changes nothing (secrets are read, not rotated) unless
--rotate-secrets is passed.

Usage:
  # Dry-run (validate structure, no Keycloak connection)
  python infrastructure/idp/provision_idp.py --dry-run

  # Full provision against running Keycloak
  python infrastructure/idp/provision_idp.py \
    --keycloak-url http://localhost:8444 \
    --admin-user admin \
    --admin-password admin \
    --realm kingphisher

  # Provision and create test operator users with role assignments
  python infrastructure/idp/provision_idp.py --create-test-users

  # Rotate the console client secret (print a new one; update .env after)
  python infrastructure/idp/provision_idp.py --rotate-secrets

Environment variables (alternative to flags):
  KEYCLOAK_URL, KEYCLOAK_ADMIN, KEYCLOAK_ADMIN_PASSWORD, KEYCLOAK_REALM
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from typing import Any

import httpx

REALM_NAME = "kingphisher"
CLIENT_CONSOLE = "kp-operator-console"
CLIENT_API = "kp-operator-api"
DEFAULT_KEYCLOAK_URL = "http://localhost:8444"
DEFAULT_REDIRECT_URI = "http://localhost:8000/api/v1/console/oidc/callback"

REALM_ROLES = [
    "source_curator",
    "campaign_author",
    "security_approver",
    "privacy_approver",
    "campaign_operator",
    "auditor",
    "administrator",
]

TEST_USERS: list[dict[str, Any]] = [
    {
        "username": "operator",
        "email": "operator@kingphisher.local",
        "firstName": "Operator",
        "lastName": "Test",
        "roles": ["campaign_operator"],
    },
    {
        "username": "administrator",
        "email": "admin@kingphisher.local",
        "firstName": "Admin",
        "lastName": "Test",
        "roles": ["administrator"],
    },
    {
        "username": "author",
        "email": "author@kingphisher.local",
        "firstName": "Author",
        "lastName": "Test",
        "roles": ["campaign_author"],
    },
    {
        "username": "security",
        "email": "security@kingphisher.local",
        "firstName": "Security",
        "lastName": "Test",
        "roles": ["security_approver"],
    },
    {
        "username": "privacy",
        "email": "privacy@kingphisher.local",
        "firstName": "Privacy",
        "lastName": "Test",
        "roles": ["privacy_approver"],
    },
]


@dataclass
class ProvisionResult:
    realm_created: bool
    console_client_id: str
    console_client_secret: str
    api_client_id: str
    api_client_secret: str
    roles_created: list[str]
    users_created: list[str]


class _DryResponse:
    """Stand-in returned by the request helpers in --dry-run mode."""

    def __init__(self, status_code: int = 201) -> None:
        self.status_code = status_code
        self.headers: dict[str, str] = {}

    def json(self) -> dict[str, Any]:
        return {"id": "dry-run-id", "value": "dry-run-secret"}

    def raise_for_status(self) -> None:
        return None


# Both shapes expose only status_code/headers/json/raise_for_status, which is
# all the call sites use; the dry-run stand-in is never passed to httpx.
type _Response = httpx.Response | _DryResponse


class KeycloakAdminClient:
    def __init__(self, base_url: str, admin_user: str, admin_password: str, dry_run: bool = False):
        self.base_url = base_url.rstrip("/")
        self.admin_user = admin_user
        self.admin_password = admin_password
        self.dry_run = dry_run
        self._token: str | None = None
        self._client: httpx.Client | None = None if dry_run else httpx.Client(timeout=30.0)

    def _http(self) -> httpx.Client:
        """The live client; every caller is behind a dry_run early-return."""
        assert self._client is not None, "live request attempted in dry-run mode"
        return self._client

    def _get_token(self) -> str:
        if self.dry_run:
            return "dry-run-token"
        if self._token:
            return self._token
        resp = self._http().post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_password,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        self._token = str(resp.json()["access_token"])
        return self._token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def _get(self, path: str) -> _Response | None:
        if self.dry_run:
            return _DryResponse(200)
        resp = self._http().get(f"{self.base_url}{path}", headers=self._headers())
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp

    def _post(self, path: str, data: dict[str, Any] | list[Any]) -> _Response:
        if self.dry_run:
            return _DryResponse(201)
        resp = self._http().post(f"{self.base_url}{path}", headers=self._headers(), json=data)
        if resp.status_code == 409:
            return resp
        resp.raise_for_status()
        return resp

    def _put(self, path: str, data: dict[str, Any]) -> _Response:
        if self.dry_run:
            return _DryResponse(204)
        resp = self._http().put(f"{self.base_url}{path}", headers=self._headers(), json=data)
        resp.raise_for_status()
        return resp

    def realm_exists(self, realm: str) -> bool:
        if self.dry_run:
            return False
        return self._get(f"/admin/realms/{realm}") is not None

    def create_realm(self, realm: str) -> bool:
        if self.dry_run:
            print(f"[dry-run] Would create realm: {realm}")
            return True
        if self.realm_exists(realm):
            print(f"Realm '{realm}' already exists")
            return False
        data = {
            "realm": realm,
            "enabled": True,
            "displayName": "Kingphisher Phishing Awareness Platform",
            "sslRequired": "none",
            "registrationAllowed": False,
            "registrationEmailAsUsername": False,
            "rememberMe": True,
            "verifyEmail": False,
            "loginTheme": "keycloak",
            "accountTheme": "keycloak",
            "emailTheme": "keycloak",
        }
        self._post("/admin/realms", data)
        print(f"Created realm: {realm}")
        return True

    def get_client(self, realm: str, client_id: str) -> dict[str, Any] | None:
        if self.dry_run:
            return None
        resp = self._http().get(
            f"{self.base_url}/admin/realms/{realm}/clients",
            headers=self._headers(),
            params={"clientId": client_id},
        )
        resp.raise_for_status()
        clients = resp.json()
        return clients[0] if clients else None

    def create_client(self, realm: str, client_data: dict[str, Any]) -> str:
        if self.dry_run:
            print(f"[dry-run] Would create client: {client_data['clientId']}")
            return "dry-run-client-id"
        existing = self.get_client(realm, str(client_data["clientId"]))
        if existing:
            print(f"Client '{client_data['clientId']}' already exists (id: {existing['id']})")
            return str(existing["id"])
        resp = self._post(f"/admin/realms/{realm}/clients", client_data)
        if resp.status_code == 409:
            existing = self.get_client(realm, str(client_data["clientId"]))
            if existing:
                print(f"Client '{client_data['clientId']}' already exists (id: {existing['id']})")
                return str(existing["id"])
        resp.raise_for_status()
        location = resp.headers.get("Location", "")
        client_id = location.rsplit("/", 1)[-1] if location else "unknown"
        print(f"Created client: {client_data['clientId']} (id: {client_id})")
        return client_id

    def regenerate_client_secret(self, realm: str, client_uuid: str) -> str:
        if self.dry_run:
            return "dry-run-rotated-secret"
        resp = self._http().post(
            f"{self.base_url}/admin/realms/{realm}/clients/{client_uuid}/client-secret",
            headers=self._headers(),
        )
        resp.raise_for_status()
        return str(resp.json()["value"])

    def ensure_client_secret(self, realm: str, client_uuid: str) -> str:
        """Read the client secret, generating one if Keycloak never did.

        A client created via the Admin API without an explicit "secret" field
        reports {"type": "secret"} with no value until one is regenerated, so
        the first read of a freshly created client has to generate it.
        """
        if self.dry_run:
            return "dry-run-secret"
        resp = self._http().get(
            f"{self.base_url}/admin/realms/{realm}/clients/{client_uuid}/client-secret",
            headers=self._headers(),
        )
        resp.raise_for_status()
        data = resp.json()
        value = data.get("value") if isinstance(data, dict) else None
        if value:
            return str(value)
        return self.regenerate_client_secret(realm, client_uuid)

    def add_protocol_mapper(self, realm: str, client_uuid: str, mapper: dict[str, Any]) -> bool:
        if self.dry_run:
            print(f"[dry-run] Would add protocol mapper to client {client_uuid}: {mapper['name']}")
            return True
        resp = self._http().post(
            f"{self.base_url}/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models",
            headers=self._headers(),
            json=mapper,
        )
        if resp.status_code == 409:
            print(f"Protocol mapper '{mapper['name']}' already exists")
            return False
        resp.raise_for_status()
        print(f"Added protocol mapper: {mapper['name']}")
        return True

    def get_realm_roles(self, realm: str) -> list[str]:
        if self.dry_run:
            return []
        resp = self._http().get(
            f"{self.base_url}/admin/realms/{realm}/roles",
            headers=self._headers(),
        )
        resp.raise_for_status()
        return [str(r["name"]) for r in resp.json()]

    def create_realm_role(self, realm: str, role_name: str, description: str = "") -> bool:
        if self.dry_run:
            print(f"[dry-run] Would create realm role: {role_name}")
            return True
        if role_name in self.get_realm_roles(realm):
            print(f"Realm role '{role_name}' already exists")
            return False
        self._post(f"/admin/realms/{realm}/roles", {"name": role_name, "description": description})
        print(f"Created realm role: {role_name}")
        return True

    def get_user(self, realm: str, username: str) -> dict[str, Any] | None:
        if self.dry_run:
            return None
        resp = self._http().get(
            f"{self.base_url}/admin/realms/{realm}/users",
            headers=self._headers(),
            params={"username": username, "exact": "true"},
        )
        resp.raise_for_status()
        users = resp.json()
        return users[0] if users else None

    def create_user(self, realm: str, user_data: dict[str, Any]) -> str:
        if self.dry_run:
            print(f"[dry-run] Would create user: {user_data['username']}")
            return "dry-run-user-id"
        existing = self.get_user(realm, str(user_data["username"]))
        if existing:
            print(f"User '{user_data['username']}' already exists (id: {existing['id']})")
            return str(existing["id"])
        resp = self._post(f"/admin/realms/{realm}/users", user_data)
        resp.raise_for_status()
        location = resp.headers.get("Location", "")
        user_id = location.rsplit("/", 1)[-1] if location else "unknown"
        print(f"Created user: {user_data['username']} (id: {user_id})")
        return user_id

    def set_user_password(self, realm: str, user_id: str, password: str, temporary: bool = False) -> None:
        if self.dry_run:
            print(f"[dry-run] Would set password for user {user_id}")
            return
        self._put(
            f"/admin/realms/{realm}/users/{user_id}/reset-password",
            {"type": "password", "value": password, "temporary": temporary},
        )
        print(f"Set password for user {user_id}")

    def assign_realm_roles(self, realm: str, user_id: str, role_names: list[str]) -> None:
        if self.dry_run:
            print(f"[dry-run] Would assign roles {role_names} to user {user_id}")
            return
        role_objs = []
        for role_name in role_names:
            resp = self._http().get(
                f"{self.base_url}/admin/realms/{realm}/roles/{role_name}",
                headers=self._headers(),
            )
            if resp.status_code == 404:
                print(f"Warning: role '{role_name}' not found, skipping")
                continue
            resp.raise_for_status()
            role_objs.append(resp.json())
        if role_objs:
            self._post(
                f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
                role_objs,
            )
            print(f"Assigned roles {[r['name'] for r in role_objs]} to user {user_id}")

    def close(self) -> None:
        if self._client:
            self._client.close()


def build_console_client(redirect_uri: str) -> dict[str, Any]:
    return {
        "clientId": CLIENT_CONSOLE,
        "name": "Kingphisher Operator Console",
        "description": "Confidential browser client for operator login; tokens carry the kp-operator-api audience.",
        "enabled": True,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": [redirect_uri],
        "webOrigins": [redirect_uri.rsplit("/", 1)[0] if "/" in redirect_uri else "*"],
        "protocol": "openid-connect",
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": True,
        "fullScopeAllowed": True,
    }


def build_api_client() -> dict[str, Any]:
    return {
        "clientId": CLIENT_API,
        "name": "Kingphisher Operator API",
        "description": "API audience for access token validation. Confidential client used as audience reference.",
        "enabled": True,
        "clientAuthenticatorType": "client-secret",
        "redirectUris": [],
        "webOrigins": [],
        "protocol": "openid-connect",
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "frontchannelLogout": False,
        "fullScopeAllowed": False,
    }


def build_audience_mapper(api_client_id: str) -> dict[str, Any]:
    return {
        "name": "Audience Mapper - kp-operator-api",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.client.audience": api_client_id,
            "id.token.claim": "false",
            "access.token.claim": "true",
        },
    }


def provision(
    keycloak_url: str,
    admin_user: str,
    admin_password: str,
    realm: str,
    redirect_uri: str,
    create_test_users: bool = False,
    test_user_password: str = "TestPass123!",
    rotate_secrets: bool = False,
    dry_run: bool = False,
) -> ProvisionResult:
    client = KeycloakAdminClient(keycloak_url, admin_user, admin_password, dry_run)

    try:
        realm_created = client.create_realm(realm)

        # Create API client first (needed for audience mapper)
        api_client_data = build_api_client()
        api_client_uuid = client.create_client(realm, api_client_data)
        api_client_secret = client.ensure_client_secret(realm, api_client_uuid)

        # Create console client
        console_client_data = build_console_client(redirect_uri)
        console_client_uuid = client.create_client(realm, console_client_data)
        if rotate_secrets:
            console_client_secret = client.regenerate_client_secret(realm, console_client_uuid)
            print(f"Rotated console client secret (client {console_client_uuid})")
        else:
            console_client_secret = client.ensure_client_secret(realm, console_client_uuid)

        # Add audience mapper to console client pointing to API client
        audience_mapper = build_audience_mapper(CLIENT_API)
        client.add_protocol_mapper(realm, console_client_uuid, audience_mapper)

        # Create realm roles
        created_roles = []
        for role in REALM_ROLES:
            if client.create_realm_role(realm, role, f"Kingphisher role: {role}"):
                created_roles.append(role)

        # Create test users
        created_users = []
        if create_test_users:
            for user_def in TEST_USERS:
                user_id = client.create_user(realm, {
                    "username": user_def["username"],
                    "email": user_def["email"],
                    "firstName": user_def["firstName"],
                    "lastName": user_def["lastName"],
                    "enabled": True,
                    "emailVerified": True,
                })
                client.set_user_password(realm, user_id, test_user_password, temporary=False)
                client.assign_realm_roles(realm, user_id, list(user_def["roles"]))
                created_users.append(str(user_def["username"]))

        return ProvisionResult(
            realm_created=realm_created,
            console_client_id=console_client_uuid,
            console_client_secret=console_client_secret,
            api_client_id=api_client_uuid,
            api_client_secret=api_client_secret,
            roles_created=created_roles,
            users_created=created_users,
        )
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision Keycloak IdP for Kingphisher")
    parser.add_argument("--keycloak-url", default=os.environ.get("KEYCLOAK_URL", DEFAULT_KEYCLOAK_URL))
    parser.add_argument("--admin-user", default=os.environ.get("KEYCLOAK_ADMIN", "admin"))
    parser.add_argument("--admin-password", default=os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "admin"))
    parser.add_argument("--realm", default=os.environ.get("KEYCLOAK_REALM", REALM_NAME))
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    parser.add_argument("--create-test-users", action="store_true")
    parser.add_argument("--test-user-password", default="TestPass123!")
    parser.add_argument("--rotate-secrets", action="store_true",
                        help="Rotate the console client secret instead of reading the existing one")
    parser.add_argument("--dry-run", action="store_true", help="Validate structure without connecting to Keycloak")
    args = parser.parse_args()

    if args.dry_run:
        print("=== DRY RUN MODE ===")
        print("No Keycloak connection will be made.")
        print()

    try:
        result = provision(
            keycloak_url=args.keycloak_url,
            admin_user=args.admin_user,
            admin_password=args.admin_password,
            realm=args.realm,
            redirect_uri=args.redirect_uri,
            create_test_users=args.create_test_users,
            test_user_password=args.test_user_password,
            rotate_secrets=args.rotate_secrets,
            dry_run=args.dry_run,
        )

        print("\n=== PROVISIONING COMPLETE ===")
        print(f"Realm: {args.realm}")
        print(f"Console Client ID: {result.console_client_id}")
        print(f"Console Client Secret: {result.console_client_secret}")
        print(f"API Client ID: {result.api_client_id}")
        print(f"API Client Secret: {result.api_client_secret}")
        print(f"Roles Created: {', '.join(result.roles_created) if result.roles_created else 'none'}")
        print(f"Test Users Created: {', '.join(result.users_created) if result.users_created else 'none'}")

        if not args.dry_run:
            print("\n--- Environment Variables for Operator API ---")
            print("OPERATOR_API_OIDC_MODE=oidc")
            print(f"OPERATOR_API_OIDC_ISSUER={args.keycloak_url}/realms/{args.realm}")
            print("OPERATOR_API_OIDC_AUDIENCE=kp-operator-api")
            print("OPERATOR_API_OIDC_CLIENT_ID=kp-operator-console")
            print(f"OPERATOR_API_OIDC_CLIENT_SECRET={result.console_client_secret}")
            print(f"OPERATOR_API_OIDC_REDIRECT_URI={args.redirect_uri}")
            print("OPERATOR_API_OIDC_SCOPES=openid profile")

        return 0
    except httpx.HTTPStatusError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
