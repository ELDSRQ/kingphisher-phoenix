"""Console session and OIDC browser-login support.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split. The six authentication *endpoints* deliberately stay in the console
facade (``kp_operator_api.console``) because the route-authorization inventory
pins them to that module identity; everything they lean on — cookie names,
session TTLs, response models, redirect-URI validation, and the bounded
identity-provider discovery/token exchanges — lives here.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import Request
from kp_authorization.rbac import Principal
from kp_telemetry.errors import AuthenticationError
from pydantic import BaseModel, Field

from kp_operator_api.auth import (
    OidcEndpointPolicyError,
    resolve_oidc_endpoint,
)
from kp_operator_api.oidc_provider import (
    MAX_OIDC_DISCOVERY_BYTES,
    MAX_OIDC_TOKEN_RESPONSE_BYTES,
    OidcProviderResponseError,
    bounded_json_async,
)

# Stable, valid-UUID principal for the browser console operator. Downstream
# code does `uuid.UUID(principal.principal_id)`; the legacy `console-operator`
# subject made that raise ValueError (500) and broke self-approval checks.
CONSOLE_OPERATOR_UUID = "11111111-1111-4111-8111-111111111111"
_SESSION_TTL_SECONDS = 8 * 60 * 60
_OIDC_TRANSACTION_TTL_SECONDS = 10 * 60
_OIDC_TRANSACTION_COOKIE = "kp_oidc_transaction"
_OIDC_SESSION_COOKIE = "kp_oidc_session"


_OIDC_CALLBACK_PATH = "/api/v1/console/oidc/callback"
_LOCAL_OIDC_REDIRECT_URI = f"http://localhost:8000{_OIDC_CALLBACK_PATH}"


class SessionRequest(BaseModel):
    password: str = Field(min_length=1)


class SessionResponse(BaseModel):
    token: str
    expires_in: int
    auth_mode: str
    principal_id: str
    approval_limited: bool
    #: "enforce" or "single-admin". The console uses this to decide whether a
    #: draft can be scheduled directly or must go through two-person approval,
    #: so an operator is not offered an action the API will reject.
    approval_policy: str = "single-admin"
    roles: tuple[str, ...]
    capabilities: tuple[str, ...]


def _session_authority(principal: Principal) -> dict[str, tuple[str, ...]]:
    """Return deterministic, non-secret authority facts for console rendering."""
    return {
        "roles": tuple(sorted(role.value for role in principal.roles)),
        "capabilities": tuple(
            sorted(f"{capability.action}:{capability.object}" for capability in principal.capabilities())
        ),
    }


class OidcStartResponse(BaseModel):
    authorization_url: str


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _valid_uri_hostname(value: str) -> bool:
    if not value or "%" in value or value.endswith(".") or len(value) > 253:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        try:
            labels = value.rstrip(".").encode("idna").decode("ascii").split(".")
        except UnicodeError:
            return False
        return bool(labels) and all(
            label
            and len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )


def _validated_oidc_redirect_uri(raw: str) -> str:
    """Accept the exact local callback or an HTTPS callback at that path."""
    if (
        not raw
        or raw != raw.strip()
        or len(raw.encode("utf-8")) > 2048
        or any(character.isspace() or ord(character) == 127 for character in raw)
    ):
        raise ValueError("invalid OIDC redirect URI")
    try:
        parsed = urlparse(raw)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid OIDC redirect URI") from None
    if (
        not parsed.hostname
        or not _valid_uri_hostname(parsed.hostname)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.path != _OIDC_CALLBACK_PATH
        or port is not None
        and not 1 <= port <= 65535
    ):
        raise ValueError("invalid OIDC redirect URI")
    if raw == _LOCAL_OIDC_REDIRECT_URI:
        return raw
    if parsed.scheme != "https":
        raise ValueError("invalid OIDC redirect URI")
    return raw


def _transaction_secret(request: Request) -> bytes:
    return bytes(request.app.state.settings.require_console_jwt_secret())


async def _oidc_metadata(issuer: str) -> dict[str, Any]:
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        endpoint = await asyncio.to_thread(
            resolve_oidc_endpoint,
            url,
            issuer=issuer,
            endpoint_name="discovery endpoint",
        )
        async with (
            httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=False,
                trust_env=False,
                http2=False,
            ) as client,
            client.stream(
                "GET",
                endpoint.request_url,
                headers={"Host": endpoint.host_header},
                extensions=endpoint.extensions,
            ) as response,
        ):
            if response.is_redirect:
                raise OidcProviderResponseError("identity provider discovery redirected")
            response.raise_for_status()
            metadata = await bounded_json_async(response, max_bytes=MAX_OIDC_DISCOVERY_BYTES)
    except (httpx.HTTPError, OidcEndpointPolicyError, OidcProviderResponseError) as exc:
        raise AuthenticationError("identity provider discovery failed") from exc
    if not isinstance(metadata, dict):
        raise AuthenticationError("identity provider discovery returned an invalid issuer")
    metadata_issuer = metadata.get("issuer")
    if not isinstance(metadata_issuer, str) or metadata_issuer.rstrip("/") != issuer.rstrip("/"):
        raise AuthenticationError("identity provider discovery returned an invalid issuer")
    return metadata


async def _oidc_token_response(
    token_endpoint: str,
    form: dict[str, str],
    *,
    issuer: str,
) -> dict[str, Any]:
    try:
        endpoint = await asyncio.to_thread(
            resolve_oidc_endpoint,
            token_endpoint,
            issuer=issuer,
            endpoint_name="token endpoint",
        )
        async with (
            httpx.AsyncClient(
                timeout=5.0,
                follow_redirects=False,
                trust_env=False,
                http2=False,
            ) as client,
            client.stream(
                "POST",
                endpoint.request_url,
                data=form,
                headers={"Host": endpoint.host_header},
                extensions=endpoint.extensions,
            ) as response,
        ):
            if response.is_redirect:
                raise OidcProviderResponseError("identity provider token endpoint redirected")
            if response.status_code != 200:
                raise AuthenticationError("identity provider rejected the authorization code")
            tokens = await bounded_json_async(response, max_bytes=MAX_OIDC_TOKEN_RESPONSE_BYTES)
    except (httpx.HTTPError, OidcEndpointPolicyError) as exc:
        raise AuthenticationError("identity provider token exchange failed") from exc
    except OidcProviderResponseError as exc:
        raise AuthenticationError("identity provider returned an invalid token response") from exc
    if not isinstance(tokens, dict):
        raise AuthenticationError("identity provider returned an invalid token response")
    return tokens
