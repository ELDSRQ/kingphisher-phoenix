"""Console endpoints: GUI-driven configuration and lifecycle control.

The operator console is a browser single-page app. This module provides the
few non-operator endpoints it needs:

* ``POST /api/v1/console/session``  — password login issuing a short-lived
  admin bearer token (the console has no external identity provider).
* ``GET /api/v1/console/config``    — masked view of the local ``.env``.
* ``PUT /api/v1/console/config``    — apply configuration edits to ``.env``.
* ``GET /api/v1/console/status``    — process + dependency health for the UI.
* ``POST /api/v1/console/restart``  — signal the supervisor to restart services.

The console password is stored in ``.env`` as ``KP_CONSOLE_PASSWORD``. It is
read only from the on-disk env file (not the process environment), so a
freshly written value takes effect without a process restart.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import os
import re
import secrets
import smtplib
import socket
import ssl
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from dotenv import dotenv_values, set_key
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from kp_authorization.rbac import Capability, Principal
from kp_telemetry.errors import AuthenticationError, PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import OidcIdP, require_capability
from kp_operator_api.ratelimit import LoginThrottle

router = APIRouter(prefix="/api/v1/console", tags=["console"])

CONSOLE_PASSWORD_KEY = "KP_CONSOLE_PASSWORD"  # noqa: S105
# Stable, valid-UUID principal for the browser console operator. Downstream
# code does `uuid.UUID(principal.principal_id)`; the legacy `console-operator`
# subject made that raise ValueError (500) and broke self-approval checks.
CONSOLE_OPERATOR_UUID = "11111111-1111-4111-8111-111111111111"
_SESSION_TTL_SECONDS = 8 * 60 * 60
_OIDC_TRANSACTION_TTL_SECONDS = 10 * 60
_OIDC_TRANSACTION_COOKIE = "kp_oidc_transaction"
_OIDC_SESSION_COOKIE = "kp_oidc_session"

_SECRET_KEYS: frozenset[str] = frozenset(
    {
        CONSOLE_PASSWORD_KEY,
        "OPERATOR_API_AUDIT_HMAC_KEY",
        "OPERATOR_API_CIPHERTEXT_KEK",
        "OPERATOR_API_CONSOLE_JWT_SECRET",
        "OPERATOR_API_OIDC_CLIENT_SECRET",
        "KP_WORKER_AUDIT_HMAC_KEY",
        "KP_WORKER_CIPHERTEXT_KEK",
        "KP_WORKER_SMTP_PASSWORD",
        "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD",
        "KP_WORKER_AI_BEARER_TOKEN",
        "KP_WORKER_AI_API_KEY",
        "KP_WORKER_GRAPH_BEARER_TOKEN",
        "KP_WORKER_GRAPH_API_KEY",
        "MAILPIT_API_PASSWORD",
    }
)


def _env_path(request: Request) -> Path:
    return Path(request.app.state.settings.env_file or ".env")


def _env_values(path: Path) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


def _console_password(path: Path) -> str | None:
    return _env_values(path).get(CONSOLE_PASSWORD_KEY)


def _verify_console_password(path: Path, supplied: str) -> bool:
    stored = _console_password(path)
    if not stored:
        return False
    return hmac.compare_digest(stored, supplied)


class SessionRequest(BaseModel):
    password: str = Field(min_length=1)


class SessionResponse(BaseModel):
    token: str
    expires_in: int
    auth_mode: str
    principal_id: str
    approval_limited: bool


class OidcStartResponse(BaseModel):
    authorization_url: str


@router.get("/auth-mode")
def auth_mode(request: Request) -> dict[str, str]:
    """Public, non-sensitive hint used to choose the console login screen."""
    return {
        "auth_mode": request.app.state.settings.oidc_mode,
        "deployment_mode": request.app.state.settings.deployment_mode,
    }


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _transaction_secret(request: Request) -> bytes:
    return bytes(request.app.state.settings.require_console_jwt_secret())


async def _oidc_metadata(issuer: str) -> dict[str, Any]:
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.get(url)
            response.raise_for_status()
        metadata = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise AuthenticationError("identity provider discovery failed") from exc
    if not isinstance(metadata, dict) or metadata.get("issuer", "").rstrip("/") != issuer.rstrip("/"):
        raise AuthenticationError("identity provider discovery returned an invalid issuer")
    return metadata


@router.get("/oidc/start", response_model=OidcStartResponse)
async def oidc_start(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    if settings.oidc_mode != "oidc":
        raise AuthenticationError("OIDC login is not enabled")
    metadata = await _oidc_metadata(settings.oidc_issuer)
    authorization_endpoint = metadata.get("authorization_endpoint")
    if not isinstance(authorization_endpoint, str):
        raise AuthenticationError("identity provider has no authorization endpoint")
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    now = datetime.datetime.now(datetime.UTC)
    transaction = jwt.encode(
        {
            "state": state,
            "nonce": nonce,
            "verifier": verifier,
            "iat": now,
            "exp": now + datetime.timedelta(seconds=_OIDC_TRANSACTION_TTL_SECONDS),
        },
        _transaction_secret(request),
        algorithm="HS256",
    )
    query = urlencode(
        {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
    )
    response = OidcStartResponse(authorization_url=f"{authorization_endpoint}?{query}")
    result = JSONResponse(response.model_dump())
    result.set_cookie(
        _OIDC_TRANSACTION_COOKIE,
        transaction,
        max_age=_OIDC_TRANSACTION_TTL_SECONDS,
        httponly=True,
        secure=urlparse(settings.oidc_redirect_uri).scheme == "https",
        samesite="lax",
        path="/api/v1/console/oidc",
    )
    return result


@router.get("/oidc/callback")
async def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "") -> RedirectResponse:
    settings = request.app.state.settings
    if settings.oidc_mode != "oidc" or error or not code or not state:
        raise AuthenticationError("identity provider login was not completed")
    raw_transaction = request.cookies.get(_OIDC_TRANSACTION_COOKIE, "")
    try:
        transaction = jwt.decode(raw_transaction, _transaction_secret(request), algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise AuthenticationError("OIDC transaction is missing or expired") from exc
    if not hmac.compare_digest(str(transaction.get("state", "")), state):
        raise AuthenticationError("OIDC state validation failed")
    metadata = await _oidc_metadata(settings.oidc_issuer)
    token_endpoint = metadata.get("token_endpoint")
    if not isinstance(token_endpoint, str):
        raise AuthenticationError("identity provider has no token endpoint")
    form = {
        "grant_type": "authorization_code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "code": code,
        "code_verifier": str(transaction["verifier"]),
    }
    if settings.oidc_client_secret:
        form["client_secret"] = settings.oidc_client_secret
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            token_response = await client.post(token_endpoint, data=form)
    except httpx.HTTPError as exc:
        raise AuthenticationError("identity provider token exchange failed") from exc
    if token_response.status_code != 200:
        raise AuthenticationError("identity provider rejected the authorization code")
    try:
        tokens = token_response.json()
    except ValueError as exc:
        raise AuthenticationError("identity provider returned an invalid token response") from exc
    access_token, id_token = tokens.get("access_token"), tokens.get("id_token")
    if not isinstance(access_token, str) or not isinstance(id_token, str):
        raise AuthenticationError("identity provider returned an incomplete token response")
    idp = request.app.state.idp
    if not isinstance(idp, OidcIdP):
        raise AuthenticationError("OIDC verifier is not configured")
    claims = idp.verify_claims(id_token, audience=settings.oidc_client_id)
    if not hmac.compare_digest(str(claims.get("nonce", "")), str(transaction.get("nonce", ""))):
        raise AuthenticationError("OIDC nonce validation failed")
    # Verify the API access token now as well as on every subsequent request.
    idp.verify(access_token)
    response = RedirectResponse(url="/console/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(_OIDC_TRANSACTION_COOKIE, path="/api/v1/console/oidc")
    response.set_cookie(
        _OIDC_SESSION_COOKIE,
        access_token,
        max_age=_SESSION_TTL_SECONDS,
        httponly=True,
        secure=urlparse(settings.oidc_redirect_uri).scheme == "https",
        samesite="lax",
        path="/",
    )
    return response


@router.get("/session", response_model=SessionResponse)
def current_session(request: Request) -> SessionResponse:
    if request.app.state.settings.oidc_mode != "oidc":
        raise AuthenticationError("OIDC session lookup is not enabled")
    raw = request.cookies.get(_OIDC_SESSION_COOKIE, "")
    if not raw:
        raise AuthenticationError("missing browser session")
    principal = request.app.state.idp.verify(raw)
    return SessionResponse(
        token="",
        expires_in=_SESSION_TTL_SECONDS,
        auth_mode="oidc",
        principal_id=principal.subject_id,
        approval_limited=False,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout() -> RedirectResponse:
    response = RedirectResponse(url="/console/", status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(_OIDC_SESSION_COOKIE, path="/")
    return response


@router.post("/session", response_model=SessionResponse)
def create_session(
    body: SessionRequest,
    request: Request,
) -> SessionResponse:
    settings = request.app.state.settings
    if settings.oidc_mode != "dev":
        raise AuthenticationError("console password login is disabled; sign in via the identity provider")
    client_ip = request.client.host if request.client else "unknown"
    throttle: LoginThrottle = request.app.state.login_throttle
    if throttle.locked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many failed logins; try again later"
        )

    env_path = _env_path(request)
    if not _verify_console_password(env_path, body.password):
        throttle.record_failure(client_ip)
        raise AuthenticationError("invalid console password")
    throttle.record_success(client_ip)

    now = datetime.datetime.now(datetime.UTC)
    claims = {
        "sub": CONSOLE_OPERATOR_UUID,
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + _SESSION_TTL_SECONDS,
        "realm_access": {"roles": ["administrator"]},
    }
    token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
    return SessionResponse(
        token=token,
        expires_in=_SESSION_TTL_SECONDS,
        auth_mode="dev",
        principal_id=CONSOLE_OPERATOR_UUID,
        # Password login intentionally represents one fixed development
        # principal.  The UI uses this flag to explain that campaigns created
        # by this identity require a different OIDC principal for approval.
        approval_limited=True,
    )


_ALLOWED_KEYS: frozenset[str] = frozenset(
    {
        CONSOLE_PASSWORD_KEY,
        "OPERATOR_API_HOST",
        "OPERATOR_API_PORT",
        "OPERATOR_API_OIDC_ISSUER",
        "OPERATOR_API_OIDC_AUDIENCE",
        "OPERATOR_API_OIDC_MODE",
        "OPERATOR_API_OIDC_CLIENT_ID",
        "OPERATOR_API_OIDC_CLIENT_SECRET",
        "OPERATOR_API_OIDC_REDIRECT_URI",
        "OPERATOR_API_OIDC_SCOPES",
        "OPERATOR_API_LOG_LEVEL",
        "OPERATOR_API_RATE_LIMIT_USER_PER_MIN",
        "OPERATOR_API_RATE_LIMIT_IP_PER_MIN",
        "OPERATOR_API_MAX_BODY_BYTES",
        "OPERATOR_API_TRACKING_BASE_URL",
        "OPERATOR_API_TRAINING_BASE_URL",
        "OPERATOR_API_TRAINING_DOMAINS",
        "OPERATOR_API_APP_NAME",
        "OPERATOR_API_AUDIT_HMAC_KEY",
        "OPERATOR_API_CIPHERTEXT_KEK",
        "OPERATOR_API_CONSOLE_JWT_SECRET",
        "TRACKING_API_HOST",
        "TRACKING_API_PORT",
        "KP_WORKER_AUDIT_HMAC_KEY",
        "KP_WORKER_CIPHERTEXT_KEK",
        "KP_WORKER_POLL_SECONDS",
        "KP_WORKER_LOG_LEVEL",
        "KP_WORKER_MAILPIT_SMTP",
        "KP_WORKER_MAILPIT_SMTP_TLS",
        "KP_WORKER_MAILPIT_API_URL",
        "KP_WORKER_PROVIDER_TIMEOUT_SECONDS",
        "KP_WORKER_MAILBOX_POLL_LIMIT",
        "KP_WORKER_REMINDER_AFTER_HOURS",
        "KP_WORKER_REMINDER_BATCH_SIZE",
        "KP_WORKER_REMINDER_SENDER",
        "KP_WORKER_ALERT_WEBHOOK_DOMAINS",
        "KP_WORKER_ALERT_WEBHOOK_URL",
        "KP_WORKER_SMTP_ADDRESS",
        "KP_WORKER_SMTP_USERNAME",
        "KP_WORKER_SMTP_PASSWORD",
        "KP_WORKER_SMTP_STARTTLS",
        "KP_WORKER_SMTP_SSL",
        "KP_WORKER_SMTP_SENDER",
        "KP_WORKER_REPORTED_MAILBOX_URL",
        "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD",
        "KP_WORKER_AI_BASE_URL",
        "KP_WORKER_AI_BEARER_TOKEN",
        "KP_WORKER_AI_API_KEY",
        "KP_WORKER_GRAPH_BASE_URL",
        "KP_WORKER_GRAPH_BEARER_TOKEN",
        "KP_WORKER_GRAPH_API_KEY",
        "KP_WORKER_GRAPH_MAX_USERS",
        "KP_WORKER_GRAPH_MAX_PAGES",
        "KP_WORKER_TRAINING_BASE_URL",
        "KP_WORKER_TRAINING_DOMAINS",
        "AZURE_GRAPH_TENANT_ID",
        "AZURE_GRAPH_CLIENT_ID",
        "AZURE_GRAPH_CERT_PATH",
        "AZURE_GRAPH_CERT_THUMBPRINT",
        "OPERATOR_API_ONBOARDING_COMPLETED",
        "MOCK_IDP_URL",
        "MOCK_GRAPH_URL",
        "MOCK_AI_URL",
        "MAILPIT_URL",
        "MAILPIT_API_PASSWORD",
    }
)
# Database DSNs embed credentials and are deliberately NOT exposed or writable
# through the console (rotation happens in .env/run_console.sh).


class ConfigPatch(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)

    # Keys the console may mutate. Anything not listed is rejected so a
    # compromised console token cannot rewrite arbitrary files.


class ConfigResponse(BaseModel):
    values: dict[str, str]
    masked: dict[str, bool]


_ONBOARDING_STEPS: tuple[dict[str, Any], ...] = (
    {
        "id": "identity",
        "title": "Identity provider",
        "description": (
            "Use local development login or connect an OpenID Connect provider with separate operator roles."
        ),
        "optional": False,
        "estimated_minutes": 8,
        "prerequisites": (
            "Identity-provider administrator access",
            "Permission to register a browser application and API",
            "The public HTTPS address operators will use for this console",
        ),
        "configured_any": (("OPERATOR_API_OIDC_MODE",),),
        "fields": (
            ("OPERATOR_API_OIDC_MODE", "Authentication mode", "text", True, False, "dev or oidc"),
            ("OPERATOR_API_OIDC_ISSUER", "OIDC issuer URL", "url", False, False, "https://id.example/tenant"),
            ("OPERATOR_API_OIDC_AUDIENCE", "API audience", "text", False, False, "kp-operator-api"),
            ("OPERATOR_API_OIDC_CLIENT_ID", "Console client ID", "text", False, False, "kp-operator-console"),
            (
                "OPERATOR_API_OIDC_CLIENT_SECRET",
                "Client secret",
                "password",
                False,
                True,
                "optional for public clients",
            ),
            (
                "OPERATOR_API_OIDC_REDIRECT_URI",
                "Redirect URI",
                "url",
                False,
                False,
                "https://console.example/api/v1/console/oidc/callback",
            ),
        ),
    },
    {
        "id": "graph",
        "title": "Employee directory",
        "description": (
            "Connect a bounded Microsoft Graph-compatible users endpoint for encrypted recipient synchronization."
        ),
        "optional": True,
        "estimated_minutes": 5,
        "prerequisites": (
            "A read-only directory application or gateway",
            "Permission to read the users collection",
            "An expected upper bound for employee records",
        ),
        "configured_any": (("KP_WORKER_GRAPH_BASE_URL",), ("MOCK_GRAPH_URL",)),
        "fields": (
            ("KP_WORKER_GRAPH_BASE_URL", "Graph base URL", "url", True, False, "https://graph.microsoft.com/v1.0"),
            ("KP_WORKER_GRAPH_BEARER_TOKEN", "Bearer token", "password", False, True, "short-lived access token"),
            ("KP_WORKER_GRAPH_API_KEY", "API key", "password", False, True, "optional gateway key"),
            ("KP_WORKER_GRAPH_MAX_USERS", "Maximum users", "number", False, False, "1000"),
        ),
    },
    {
        "id": "smtp",
        "title": "Email delivery",
        "description": "Connect an SMTP relay. STARTTLS is automatic for non-local hosts unless SSL is selected.",
        "optional": False,
        "estimated_minutes": 5,
        "prerequisites": (
            "An approved SMTP relay or service account",
            "The sender mailbox authorized by that relay",
            "The relay's TLS requirement and port",
        ),
        "configured_any": (("KP_WORKER_SMTP_ADDRESS",), ("KP_WORKER_MAILPIT_SMTP",)),
        "fields": (
            ("KP_WORKER_SMTP_ADDRESS", "SMTP host and port", "text", True, False, "smtp.example.com:587"),
            ("KP_WORKER_SMTP_USERNAME", "SMTP username", "text", False, False, "service account"),
            ("KP_WORKER_SMTP_PASSWORD", "SMTP password", "password", False, True, "leave blank to keep existing"),
            ("KP_WORKER_SMTP_STARTTLS", "Use STARTTLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SSL", "Use implicit TLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SENDER", "Sender mailbox", "email", False, False, "awareness@example.com"),
        ),
    },
    {
        "id": "mailbox",
        "title": "Reported-message mailbox",
        "description": "Poll a Mailpit-compatible reporting API for messages explicitly marked as reported.",
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "A Mailpit-compatible reported-message API",
            "One supported authentication method: bearer token or basic authentication",
        ),
        "configured_any": (("KP_WORKER_REPORTED_MAILBOX_URL",), ("KP_WORKER_MAILPIT_API_URL",)),
        "fields": (
            ("KP_WORKER_REPORTED_MAILBOX_URL", "Mailbox API base URL", "url", True, False, "https://mail.example/api"),
            ("KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN", "Bearer token", "password", False, True, "optional"),
            ("KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME", "Basic-auth username", "text", False, False, "optional"),
            ("KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD", "Basic-auth password", "password", False, True, "optional"),
        ),
    },
    {
        "id": "ai",
        "title": "Content-generation service",
        "description": (
            "Connect a compatible /propose service. Deterministic safety validation remains mandatory after generation."
        ),
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "A compatible service exposing /propose and /setup-assist",
            "A dedicated, least-privilege credential if authentication is required",
        ),
        "configured_any": (("KP_WORKER_AI_BASE_URL",), ("MOCK_AI_URL",)),
        "fields": (
            ("KP_WORKER_AI_BASE_URL", "AI service base URL", "url", True, False, "https://ai-gateway.example"),
            ("KP_WORKER_AI_BEARER_TOKEN", "Bearer token", "password", False, True, "optional"),
            ("KP_WORKER_AI_API_KEY", "API key", "password", False, True, "optional"),
        ),
    },
    {
        "id": "training",
        "title": "Training experience",
        "description": "Set the recipient training destination and the exact domains allowed in campaign content.",
        "optional": False,
        "estimated_minutes": 3,
        "prerequisites": (
            "The exact training landing-page URL",
            "Every domain that may host approved training content",
        ),
        "configured_any": (("OPERATOR_API_TRAINING_BASE_URL", "OPERATOR_API_TRAINING_DOMAINS"),),
        "fields": (
            (
                "OPERATOR_API_TRAINING_BASE_URL",
                "Training URL",
                "url",
                True,
                False,
                "https://training.example/awareness",
            ),
            ("OPERATOR_API_TRAINING_DOMAINS", "Allowed training domains", "text", True, False, "training.example"),
        ),
    },
    {
        "id": "webhook",
        "title": "Operational alerts",
        "description": "Allowlist HTTPS webhook hosts and test a destination without sending campaign data.",
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "An HTTPS receiver for operational alerts",
            "The receiver hostname approved for the outbound allowlist",
        ),
        "configured_any": (("KP_WORKER_ALERT_WEBHOOK_DOMAINS",),),
        "fields": (
            ("KP_WORKER_ALERT_WEBHOOK_DOMAINS", "Allowed webhook domains", "text", True, False, "hooks.example.com"),
            (
                "KP_WORKER_ALERT_WEBHOOK_URL",
                "Test webhook or ntfy topic URL",
                "url",
                False,
                False,
                "https://hooks.example.com/health",
            ),
        ),
    },
)


class OnboardingPatch(ConfigPatch):
    completed: bool | None = None


class ConnectionTest(BaseModel):
    component: str
    values: dict[str, str] = Field(default_factory=dict)


class SetupAssistRequest(BaseModel):
    component: str = Field(min_length=1, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    question: str = Field(min_length=1, max_length=1000)
    values: dict[str, str] = Field(default_factory=dict)


class SetupAssistResponse(BaseModel):
    answer: str
    suggestions: dict[str, str]
    source: str
    warnings: list[str]


class AzureDeploymentValidationRequest(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)


_AZURE_DEPLOYMENT_STEPS: tuple[dict[str, Any], ...] = (
    {
        "id": "azure_foundation",
        "title": "Azure account and environment",
        "description": "Choose the Azure subscription, region, environment, and short resource-name prefix.",
        "estimated_minutes": 5,
        "prerequisites": (
            "Azure subscription Owner or an approved deployment identity",
            "A region approved for organizational data residency",
            "A separate staging environment before production",
        ),
        "fields": (
            (
                "subscription_id",
                "Azure subscription ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Azure portal → Subscriptions → select the target subscription → Subscription ID.",
            ),
            (
                "environment",
                "Environment",
                "select",
                True,
                "staging",
                "Choose staging for the first deployment. Production enables HA and stronger retention controls.",
            ),
            (
                "location",
                "Azure region",
                "text",
                True,
                "eastus2",
                "Azure portal → a permitted resource group → Location, or ask the cloud governance team.",
            ),
            (
                "name_prefix",
                "Resource prefix",
                "text",
                True,
                "kp",
                "Choose 2–11 lowercase letters, numbers, or hyphens used to recognize these resources.",
            ),
        ),
    },
    {
        "id": "azure_identity_dns",
        "title": "Identity and public addresses",
        "description": "Connect the deployment to Microsoft Entra and choose the two public HTTPS hostnames.",
        "estimated_minutes": 10,
        "prerequisites": (
            "Microsoft Entra permission to register an application",
            "Two DNS names in a domain the organization controls",
            "Approval for an operator console hostname and a separate tracking hostname",
        ),
        "fields": (
            (
                "entra_tenant_id",
                "Microsoft Entra tenant ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Azure portal → Microsoft Entra ID → Overview → Tenant ID.",
            ),
            (
                "entra_client_id",
                "Entra application client ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Microsoft Entra ID → App registrations → the console application → Application (client) ID.",
            ),
            (
                "operator_fqdn",
                "Operator console hostname",
                "text",
                True,
                "awareness.example.com",
                "DNS provider → the organization's approved zone. Create a dedicated hostname for administrators.",
            ),
            (
                "tracking_fqdn",
                "Tracking hostname",
                "text",
                True,
                "awareness-track.example.com",
                "DNS provider → the same approved zone. Keep this separate from the operator console hostname.",
            ),
        ),
    },
    {
        "id": "azure_integrations",
        "title": "Azure services and optional integrations",
        "description": "Choose email data residency and optional private AI and alert endpoints.",
        "estimated_minutes": 5,
        "prerequisites": (
            "Organizational data-residency policy",
            "An approved Azure-hosted AI gateway if AI guidance is required",
            "An authenticated Azure-hosted webhook or ntfy service if alerts are required",
        ),
        "fields": (
            (
                "communication_data_location",
                "Email data location",
                "select",
                True,
                "United States",
                "Choose the geography approved for Azure Communication Services email data.",
            ),
            (
                "ai_endpoint",
                "AI gateway endpoint",
                "url",
                False,
                "https://ai-gateway.example.com",
                "Azure-hosted gateway → Overview → endpoint. It must expose /propose and /setup-assist.",
            ),
            (
                "alert_webhook_domains",
                "Allowed alert hostnames",
                "text",
                False,
                "ntfy.example.com",
                "Copy hostname only from each approved Azure-hosted HTTPS webhook; separate multiple hosts "
                "with commas.",
            ),
        ),
    },
    {
        "id": "azure_automation",
        "title": "Deployment automation",
        "description": "Identify the private Terraform-state location and confirm the protected deployment runner.",
        "estimated_minutes": 8,
        "prerequisites": (
            "Azure Storage account with blob versioning and RBAC",
            "A private self-hosted GitHub runner attached to the deployment network",
            "GitHub staging and production environments with required production reviewers",
        ),
        "fields": (
            (
                "tf_state_resource_group",
                "Terraform-state resource group",
                "text",
                True,
                "rg-kp-terraform-state",
                "Azure portal → Resource groups → the dedicated infrastructure-state resource group.",
            ),
            (
                "tf_state_storage_account",
                "Terraform-state storage account",
                "text",
                True,
                "kptfstateprod",
                "Azure portal → Storage accounts → the private account holding the tfstate container.",
            ),
            (
                "tf_state_container",
                "Terraform-state container",
                "text",
                True,
                "tfstate",
                "Storage account → Data storage → Containers → the private state container.",
            ),
            (
                "runner_label",
                "Private runner label",
                "text",
                True,
                "azure-vnet",
                "GitHub repository → Settings → Actions → Runners → labels. The workflow expects azure-vnet.",
            ),
        ),
    },
)


def _azure_deployment_schema() -> dict[str, Any]:
    select_choices = {
        "environment": [
            {"value": "staging", "label": "Staging (recommended first)"},
            {"value": "production", "label": "Production"},
        ],
        "communication_data_location": [
            {"value": value, "label": value}
            for value in ("United States", "Canada", "Europe", "UK", "Australia", "Asia Pacific")
        ],
    }
    return {
        "steps": [
            {
                **{key: value for key, value in step.items() if key != "fields"},
                "fields": [
                    {
                        "key": key,
                        "label": label,
                        "type": input_type,
                        "required": required,
                        "secret": False,
                        "placeholder": placeholder,
                        "where_to_find": location,
                        "choices": select_choices.get(key, []),
                    }
                    for key, label, input_type, required, placeholder, location in step["fields"]
                ],
            }
            for step in _AZURE_DEPLOYMENT_STEPS
        ],
        "safety_note": "This wizard never asks for Azure passwords, client secrets, access keys, or Terraform state.",
        "workflow": ".github/workflows/azure-deploy.yml",
    }


@router.get("/azure-deployment", response_model=dict[str, Any])
def get_azure_deployment(
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _azure_deployment_schema()


@router.post("/azure-deployment/validate", response_model=dict[str, Any])
def validate_azure_deployment(
    body: AzureDeploymentValidationRequest,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    allowed = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"]}
    unknown = set(body.values) - allowed
    if unknown:
        raise PermissionDeniedError(f"rejected Azure deployment keys: {sorted(unknown)}")
    values = {key: value.strip() for key, value in body.values.items()}
    errors: dict[str, str] = {}
    uuid_keys = ("subscription_id", "entra_tenant_id", "entra_client_id")
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    for key in uuid_keys:
        if not uuid_pattern.fullmatch(values.get(key, "")):
            errors[key] = "Enter the complete UUID shown in Azure or Microsoft Entra."
    if values.get("environment") not in {"staging", "production"}:
        errors["environment"] = "Choose staging or production."
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,10}", values.get("name_prefix", "")):
        errors["name_prefix"] = "Use 2–11 lowercase letters, numbers, or hyphens."
    if not re.fullmatch(r"[a-z0-9]+", values.get("location", "")):
        errors["location"] = "Enter the Azure region code, such as eastus2."
    hostname_pattern = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
    for key in ("operator_fqdn", "tracking_fqdn"):
        if not hostname_pattern.fullmatch(values.get(key, "").lower()):
            errors[key] = "Enter a hostname only, without https:// or a path."
    if values.get("operator_fqdn", "").lower() == values.get("tracking_fqdn", "").lower():
        errors["tracking_fqdn"] = "Use a hostname separate from the operator console."
    endpoint = values.get("ai_endpoint", "")
    if endpoint:
        parsed = urlparse(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            errors["ai_endpoint"] = "Use an HTTPS base URL without credentials or query parameters."
    domains = [item.strip().lower() for item in values.get("alert_webhook_domains", "").split(",") if item.strip()]
    if any(not hostname_pattern.fullmatch(domain) for domain in domains):
        errors["alert_webhook_domains"] = "Enter hostnames only, separated by commas."
    if not re.fullmatch(r"[a-z0-9]{3,24}", values.get("tf_state_storage_account", "")):
        errors["tf_state_storage_account"] = "Use the 3–24 character lowercase Azure Storage account name."
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", values.get("tf_state_container", "")):
        errors["tf_state_container"] = "Enter the lowercase blob container name."
    if values.get("communication_data_location") not in {
        "United States",
        "Canada",
        "Europe",
        "UK",
        "Australia",
        "Asia Pacific",
    }:
        errors["communication_data_location"] = "Choose one of the supported data locations."
    required = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"] if field[3]}
    for key in required:
        if not values.get(key):
            errors.setdefault(key, "This value is required.")
    warnings = []
    if not endpoint:
        warnings.append("No AI gateway is configured; deterministic local setup guidance will remain available.")
    if values.get("runner_label") != "azure-vnet":
        warnings.append("The checked-in workflow currently selects the azure-vnet runner label.")
    return {"ok": not errors, "errors": errors, "warnings": warnings}


_FIELD_HELP: dict[str, tuple[str, str]] = {
    "OPERATOR_API_OIDC_MODE": (
        "Choose 'dev' only for local testing. Choose 'oidc' to let employees sign in through your identity provider.",
        "oidc",
    ),
    "OPERATOR_API_OIDC_ISSUER": (
        "The trusted sign-in authority. Copy the issuer exactly from your provider's OpenID Connect metadata; "
        "it is usually a tenant-specific HTTPS URL.",
        "https://login.microsoftonline.com/your-tenant-id/v2.0",
    ),
    "OPERATOR_API_OIDC_AUDIENCE": (
        "The identifier written into access tokens to show they were issued for this API. It must match the "
        "audience configured for the API in your identity provider.",
        "api://phishing-awareness-platform",
    ),
    "OPERATOR_API_OIDC_CLIENT_ID": (
        "The public identifier assigned to the browser console application by your identity provider. "
        "It is not a secret.",
        "00000000-0000-0000-0000-000000000000",
    ),
    "OPERATOR_API_OIDC_CLIENT_SECRET": (
        "A private credential for a confidential OIDC client. Leave blank for a public PKCE client and never "
        "paste it into support messages.",
        "Leave blank to keep the existing secret",
    ),
    "OPERATOR_API_OIDC_REDIRECT_URI": (
        "The exact URL the identity provider returns users to after sign-in. Register this same value with "
        "the provider.",
        "https://awareness.example/api/v1/console/oidc/callback",
    ),
    "KP_WORKER_GRAPH_BASE_URL": (
        "The root URL of a Microsoft Graph-compatible employee directory. The platform reads its /users "
        "collection in bounded pages.",
        "https://graph.microsoft.com/v1.0",
    ),
    "KP_WORKER_GRAPH_MAX_USERS": (
        "A safety ceiling on employees imported in one synchronization. Start near your expected workforce "
        "size and raise deliberately.",
        "5000",
    ),
    "KP_WORKER_SMTP_ADDRESS": (
        "The mail relay hostname followed by its port. Port 587 normally uses STARTTLS; port 465 normally uses "
        "implicit TLS.",
        "smtp.example.com:587",
    ),
    "KP_WORKER_SMTP_STARTTLS": (
        "Upgrades a normal SMTP connection to encrypted TLS. Usually true on port 587 and false when implicit "
        "TLS is enabled.",
        "true",
    ),
    "KP_WORKER_SMTP_SSL": (
        "Starts SMTP inside TLS immediately, normally on port 465. Do not enable this and STARTTLS together.",
        "false",
    ),
    "KP_WORKER_AI_API_KEY": (
        "A private credential used to authenticate to your AI gateway. It is masked, never returned, and must "
        "not be included in assistant questions.",
        "Leave blank to keep the existing key",
    ),
    "KP_WORKER_ALERT_WEBHOOK_DOMAINS": (
        "A comma-separated allowlist of hosts that may receive signed operational alerts. This prevents alerts "
        "from being sent to arbitrary destinations.",
        "hooks.example.com,events.example.net",
    ),
    "KP_WORKER_ALERT_WEBHOOK_URL": (
        "An HTTPS endpoint used only for the connection test. Webhooks are signed so the receiver can verify "
        "their origin.",
        "https://hooks.example.com/awareness-health",
    ),
}

_FIELD_LOCATIONS: dict[str, str] = {
    "OPERATOR_API_OIDC_MODE": "Use 'dev' only on this computer. For production, choose 'oidc'.",
    "OPERATOR_API_OIDC_ISSUER": (
        "Identity provider → application or tenant settings → OpenID Connect metadata → issuer."
    ),
    "OPERATOR_API_OIDC_AUDIENCE": "Identity provider → API registration → application ID URI or audience.",
    "OPERATOR_API_OIDC_CLIENT_ID": (
        "Identity provider → app registrations → your console application → client/application ID."
    ),
    "OPERATOR_API_OIDC_CLIENT_SECRET": (
        "Identity provider → console application → credentials or client secrets. Create a dedicated secret "
        "only if the provider requires a confidential client."
    ),
    "OPERATOR_API_OIDC_REDIRECT_URI": (
        "Copy the suggested console callback URL here, then register the identical value under the provider "
        "application's redirect URIs."
    ),
    "KP_WORKER_GRAPH_BASE_URL": (
        "Microsoft Graph normally uses https://graph.microsoft.com/v1.0. For a gateway, copy its documented "
        "API base URL."
    ),
    "KP_WORKER_GRAPH_BEARER_TOKEN": (
        "Identity provider → directory application → token/credential flow. Request only the read-only user "
        "permission needed by your directory policy."
    ),
    "KP_WORKER_GRAPH_API_KEY": (
        "Your API gateway → application credentials or subscriptions. Leave blank when the gateway does not "
        "require a key."
    ),
    "KP_WORKER_GRAPH_MAX_USERS": (
        "Use your HR or directory count, rounded up modestly; this is a safety ceiling, not a license limit."
    ),
    "KP_WORKER_SMTP_ADDRESS": (
        "Mail provider administration → SMTP relay or authenticated SMTP settings → server name and port."
    ),
    "KP_WORKER_SMTP_USERNAME": (
        "Mail provider → SMTP service account. This is often a mailbox address or generated account name."
    ),
    "KP_WORKER_SMTP_PASSWORD": (
        "Mail provider → SMTP service account → app password or credential. Never use a personal password."
    ),
    "KP_WORKER_SMTP_STARTTLS": "Mail provider's encryption instructions. Port 587 usually uses STARTTLS.",
    "KP_WORKER_SMTP_SSL": "Mail provider's encryption instructions. Enable for implicit TLS, usually on port 465.",
    "KP_WORKER_SMTP_SENDER": (
        "Mail provider → approved senders. Use the exact mailbox or address authorized for the relay account."
    ),
    "KP_WORKER_REPORTED_MAILBOX_URL": (
        "Reported-mail provider → API or integration settings → base URL, without a message identifier."
    ),
    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": "Reported-mail provider → API credentials → bearer/access token.",
    "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME": "Reported-mail provider → API basic-auth credentials → username.",
    "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD": "Reported-mail provider → API basic-auth credentials → password.",
    "KP_WORKER_AI_BASE_URL": (
        "AI gateway administration → API endpoints. Enter the base before /propose or /setup-assist."
    ),
    "KP_WORKER_AI_BEARER_TOKEN": "AI gateway → service accounts or API credentials → bearer token.",
    "KP_WORKER_AI_API_KEY": "AI gateway → API keys. Create a dedicated restricted key for this platform.",
    "OPERATOR_API_TRAINING_BASE_URL": (
        "Training provider → course publication or share settings → learner landing-page URL."
    ),
    "OPERATOR_API_TRAINING_DOMAINS": (
        "Take the hostname from every approved training URL; enter hostnames only, separated by commas."
    ),
    "KP_WORKER_TRAINING_BASE_URL": "Filled automatically from the training URL when this step is saved.",
    "KP_WORKER_TRAINING_DOMAINS": "Filled automatically from the allowed training domains when this step is saved.",
    "KP_WORKER_ALERT_WEBHOOK_DOMAINS": (
        "Alert receiver URL → copy only its hostname. Add multiple approved hosts as a comma-separated list."
    ),
    "KP_WORKER_ALERT_WEBHOOK_URL": (
        "Alerting or automation provider → incoming webhook → HTTPS endpoint used for testing."
    ),
}

_FIELD_CHOICES: dict[str, tuple[dict[str, str], ...]] = {
    "OPERATOR_API_OIDC_MODE": (
        {"value": "dev", "label": "Local development login"},
        {"value": "oidc", "label": "Organization identity provider (OIDC)"},
    ),
    "KP_WORKER_SMTP_STARTTLS": (
        {"value": "", "label": "Automatic (recommended)"},
        {"value": "true", "label": "Require STARTTLS"},
        {"value": "false", "label": "Do not use STARTTLS"},
    ),
    "KP_WORKER_SMTP_SSL": (
        {"value": "false", "label": "No implicit TLS"},
        {"value": "true", "label": "Use implicit TLS"},
    ),
}

_GLOSSARY: tuple[dict[str, str], ...] = (
    {
        "term": "OIDC",
        "meaning": "OpenID Connect: a standard that lets this console use your organization's existing "
        "sign-in service.",
    },
    {"term": "Issuer", "meaning": "The identity provider URL that signs and identifies trusted login tokens."},
    {
        "term": "Audience",
        "meaning": "The API identifier a token is intended for; it prevents a token for another service being "
        "reused here.",
    },
    {"term": "Client ID", "meaning": "A non-secret identifier assigned to an application by an identity provider."},
    {
        "term": "Microsoft Graph",
        "meaning": "Microsoft's API for directory data such as users. This platform uses a bounded, read-only "
        "users interface.",
    },
    {"term": "SMTP", "meaning": "The standard protocol used to hand campaign email to your approved mail relay."},
    {
        "term": "STARTTLS",
        "meaning": "A command that upgrades an SMTP connection to encrypted TLS, commonly on port 587.",
    },
    {
        "term": "API key",
        "meaning": "A private credential sent to a service. Treat it like a password and rotate it if exposed.",
    },
    {"term": "Webhook", "meaning": "An HTTPS endpoint that receives automatic event notifications from this platform."},
    {
        "term": "Azure subscription ID",
        "meaning": "The non-secret identifier for the Azure subscription that will own the deployment resources.",
    },
    {
        "term": "Tenant ID",
        "meaning": "The non-secret identifier for your Microsoft Entra directory; find it on the Entra overview page.",
    },
    {
        "term": "Terraform state",
        "meaning": "Terraform's record of deployed resources. Store it in the dedicated, access-controlled "
        "Azure Storage backend prepared before deployment.",
    },
    {
        "term": "Workload identity",
        "meaning": "A short-lived, federated identity used by deployment automation instead of a stored Azure "
        "client secret.",
    },
)

_TOPICS: tuple[dict[str, str], ...] = (
    {
        "id": "identity",
        "title": "Sign-in and roles",
        "summary": "Register the console and API with your identity provider, then map separate operator and "
        "approval roles.",
    },
    {
        "id": "email",
        "title": "Email delivery",
        "summary": "Use a dedicated SMTP relay account, require TLS, and authorize the configured sender address.",
    },
    {
        "id": "secrets",
        "title": "Handling credentials",
        "summary": "Enter credentials only in masked fields. Blank secret fields preserve their existing values.",
    },
    {
        "id": "testing",
        "title": "Connection tests",
        "summary": "Test each connection before completing setup. Tests use entered values transiently and do "
        "not save them.",
    },
    {
        "id": "azure-deployment",
        "title": "Azure deployment preparation",
        "summary": "Use Azure deployment to collect and validate non-secret subscription, Entra, DNS, integration, "
        "and Terraform backend values. Export them for the protected GitHub workflow; the wizard never requests "
        "Azure credentials, saves values on the server, or starts a deployment.",
    },
)


def _onboarding_state(path: Path) -> dict[str, Any]:
    values = _env_values(path)
    effective_values = dict(values)
    for preferred, fallback in {
        "KP_WORKER_GRAPH_BASE_URL": "MOCK_GRAPH_URL",
        "KP_WORKER_AI_BASE_URL": "MOCK_AI_URL",
        "KP_WORKER_REPORTED_MAILBOX_URL": "KP_WORKER_MAILPIT_API_URL",
        "KP_WORKER_SMTP_ADDRESS": "KP_WORKER_MAILPIT_SMTP",
    }.items():
        if not effective_values.get(preferred):
            effective_values[preferred] = effective_values.get(fallback, "")
    steps = []
    for definition in _ONBOARDING_STEPS:
        configured = any(
            all(bool(values.get(key, "").strip()) for key in key_group) for key_group in definition["configured_any"]
        )
        fields = [
            {
                "key": key,
                "label": label,
                "type": input_type,
                "required": required,
                "secret": secret,
                "placeholder": _FIELD_HELP.get(key, ("", placeholder))[1],
                "help": _FIELD_HELP.get(
                    key,
                    ("Stored in the local environment; restart services after changing this value.", placeholder),
                )[0],
                "example": _FIELD_HELP.get(key, ("", placeholder))[1],
                "where_to_find": _FIELD_LOCATIONS.get(
                    key, "See the provider's administration or integration documentation."
                ),
                "choices": list(_FIELD_CHOICES.get(key, ())),
                "value": "" if secret else effective_values.get(key, ""),
            }
            for key, label, input_type, required, secret, placeholder in definition["fields"]
        ]
        steps.append(
            {
                "id": definition["id"],
                "component": definition["id"],
                "title": definition["title"],
                "description": definition["description"],
                "optional": definition["optional"],
                "estimated_minutes": definition["estimated_minutes"],
                "prerequisites": list(definition["prerequisites"]),
                "configured": configured,
                "ready": configured,
                "fields": fields,
            }
        )
    complete = values.get("OPERATOR_API_ONBOARDING_COMPLETED", "").lower() == "true"
    return {
        "complete": complete,
        "completed": complete,
        "steps": steps,
    }


@router.get("/onboarding", response_model=dict[str, Any])
def get_onboarding(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Return wizard metadata, non-secret values, and readiness flags."""
    return _onboarding_state(_env_path(request))


@router.get("/help", response_model=dict[str, Any])
def get_console_help(
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Return curated setup help without exposing environment configuration."""
    return {
        "glossary": list(_GLOSSARY),
        "topics": list(_TOPICS),
        "safety_note": "Never paste passwords, tokens, API keys, or client secrets into the setup assistant.",
    }


def _component_nonsecret_keys(component: str) -> frozenset[str]:
    for definition in _ONBOARDING_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"] if not field[4])
    for definition in _AZURE_DEPLOYMENT_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"])
    return frozenset()


_CREDENTIAL_KEY = re.compile(r"(?:password|secret|token|api[_-]?key|credential|authorization)", re.IGNORECASE)
_CREDENTIAL_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)


def _safe_assist_question(question: str, values: dict[str, str], environment: dict[str, str]) -> str:
    result = _CREDENTIAL_VALUE.sub("[credential removed]", question.strip())
    possible_secrets = [
        value
        for key, value in {**environment, **values}.items()
        if value and (_CREDENTIAL_KEY.search(key) or key in _SECRET_KEYS) and len(value) >= 4
    ]
    for secret in sorted(possible_secrets, key=len, reverse=True):
        result = result.replace(secret, "[credential removed]")
    return result


def _curated_assistance(component: str) -> str:
    guidance = {
        "identity": (
            "Start with your identity provider's application registration page. Register the exact redirect URI, "
            "identify the issuer and API audience, and use separate people for campaign creation and approval."
        ),
        "graph": (
            "Use a read-only directory application with permission to list users. Set a conservative import "
            "limit, test the /users connection, and review the first synchronization before scheduling it."
        ),
        "smtp": (
            "Ask your mail administrator for the relay host, port, service account, TLS mode, and approved "
            "sender. Port 587 normally uses STARTTLS; port 465 normally uses implicit TLS."
        ),
        "mailbox": (
            "Provide the reporting API base URL and the least-privileged credential able to read reported "
            "messages. Test access before enabling polling."
        ),
        "ai": (
            "Connect a compatible /propose gateway. AI output remains advisory and is still checked by "
            "deterministic safety rules before use."
        ),
        "azure_foundation": (
            "Open Azure portal → Subscriptions to copy the subscription ID, then confirm the approved Azure "
            "region with your cloud governance team. Start with staging and use a short lowercase prefix."
        ),
        "azure_identity_dns": (
            "Find the tenant ID under Microsoft Entra ID → Overview and the client ID under App registrations. "
            "Ask the DNS administrator for separate operator and tracking hostnames; never paste a client secret."
        ),
        "azure_integrations": (
            "Choose the ACS data geography required by policy. An AI value must be an approved Azure-hosted "
            "gateway exposing /propose and /setup-assist, not a raw model endpoint. Use hostnames only for alerts."
        ),
        "azure_automation": (
            "Use a dedicated private Storage container for Terraform state and a self-hosted GitHub runner with "
            "the azure-vnet label. Configure deployment identity through OIDC; do not create a CI client secret."
        ),
        "training": (
            "Choose the exact HTTPS training destination and allowlist only domains your organization controls "
            "or has approved."
        ),
        "webhook": (
            "The allowed webhook domain is the hostname of an approved HTTPS application that receives signed "
            "operational alerts. It is not an email destination and does not require an MTA or mail relay. "
            "Test reachability and configure the receiver to verify the platform's HMAC signature."
        ),
    }
    return guidance.get(component, "Choose a setup component and use its field help and connection test before saving.")


def _validated_ai_assistance(payload: Any, allowed_keys: frozenset[str]) -> tuple[str, dict[str, str], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("answer"), str):
        raise ValueError("invalid setup assistant response")
    answer = payload["answer"].strip()
    if not answer or len(answer) > 4000:
        raise ValueError("invalid setup assistant answer")
    raw_suggestions = payload.get("suggestions", {})
    if not isinstance(raw_suggestions, dict):
        raise ValueError("invalid setup assistant suggestions")
    suggestions: dict[str, str] = {}
    warnings: list[str] = []
    for key, value in raw_suggestions.items():
        if key not in allowed_keys or _CREDENTIAL_KEY.search(str(key)):
            warning = "The AI returned a suggestion outside this setup step; it was ignored."
            if warning not in warnings:
                warnings.append(warning)
            continue
        if not isinstance(value, str) or len(value) > 2048 or _CREDENTIAL_VALUE.search(value):
            warnings.append(f"An unsafe suggestion for {key} was ignored.")
            continue
        suggestions[key] = value
    raw_warnings = payload.get("warnings", [])
    if isinstance(raw_warnings, list):
        warnings.extend(str(item)[:500] for item in raw_warnings[:5] if isinstance(item, str))
    return answer, suggestions, warnings


@router.post("/onboarding/assist", response_model=SetupAssistResponse)
async def assist_onboarding(
    body: SetupAssistRequest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> SetupAssistResponse:
    """Provide advisory setup guidance without persisting or auditing prompt content."""
    component = body.component.lower()
    allowed_keys = _component_nonsecret_keys(component)
    if not allowed_keys:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsupported component")
    azure_assist_keys = {field[0] for step in _AZURE_DEPLOYMENT_STEPS for field in step["fields"]}
    forbidden = set(body.values) - (_ALLOWED_KEYS | azure_assist_keys)
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    environment = _env_values(_env_path(request))
    safe_values = {
        key: value
        for key, value in body.values.items()
        if key in allowed_keys
        and not _CREDENTIAL_KEY.search(key)
        and len(value) <= 2048
        and not _CREDENTIAL_VALUE.search(value)
        and not (urlparse(value).username or urlparse(value).password)
    }
    safe_question = _safe_assist_question(body.question, body.values, environment)
    base_url = environment.get("KP_WORKER_AI_BASE_URL") or environment.get("MOCK_AI_URL", "")
    warnings = ["AI suggestions are advisory. Review them and run the connection test before saving."]
    if base_url:
        headers = _auth_headers(environment, "KP_WORKER_AI")
        try:
            endpoint = _safe_url(base_url.rstrip("/") + "/setup-assist")
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                response = await client.post(
                    endpoint,
                    headers=headers,
                    json={"component": component, "question": safe_question, "values": safe_values},
                )
                response.raise_for_status()
            answer, suggestions, provider_warnings = _validated_ai_assistance(response.json(), allowed_keys)
            return SetupAssistResponse(
                answer=answer,
                suggestions=suggestions,
                source="configured-ai",
                warnings=warnings + provider_warnings,
            )
        except (httpx.HTTPError, ValueError):
            warnings.append(
                "The configured AI service was unavailable or returned an invalid response; local guidance is "
                "shown instead."
            )
    else:
        warnings.append("No AI setup service is configured; local guidance is shown instead.")
    return SetupAssistResponse(
        answer=_curated_assistance(component), suggestions={}, source="curated", warnings=warnings
    )


def _persist_onboarding(body: OnboardingPatch, request: Request, principal: Principal) -> list[str]:
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    desired = dict(body.values)
    # Training configuration is consumed by both the operator safety gate and
    # workers. Mirror it here so the wizard cannot leave the two processes on
    # inconsistent allowlists or destinations.
    mirrors = {
        "OPERATOR_API_TRAINING_BASE_URL": "KP_WORKER_TRAINING_BASE_URL",
        "OPERATOR_API_TRAINING_DOMAINS": "KP_WORKER_TRAINING_DOMAINS",
    }
    for source, target in mirrors.items():
        if source in desired and target not in desired:
            desired[target] = desired[source]
    if body.completed is not None:
        desired["OPERATOR_API_ONBOARDING_COMPLETED"] = str(body.completed).lower()
    path = _env_path(request)
    current = _env_values(path)
    proposed = {**current, **desired}
    if proposed.get("OPERATOR_API_OIDC_MODE", "dev") not in {"dev", "oidc"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="authentication mode must be dev or oidc",
        )
    boolean_keys = ("KP_WORKER_SMTP_STARTTLS", "KP_WORKER_SMTP_SSL")
    if any(proposed.get(key, "").lower() not in {"", "true", "false"} for key in boolean_keys):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="TLS settings must be true or false",
        )
    if (
        proposed.get("KP_WORKER_SMTP_STARTTLS", "").lower() == "true"
        and proposed.get("KP_WORKER_SMTP_SSL", "").lower() == "true"
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="SMTP SSL and STARTTLS are exclusive",
        )
    if body.completed:
        missing = [
            definition["title"]
            for definition in _ONBOARDING_STEPS
            if not definition["optional"]
            and not any(
                all(bool(proposed.get(key, "").strip()) for key in key_group)
                for key_group in definition["configured_any"]
            )
        ]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"required setup steps are incomplete: {', '.join(missing)}",
            )
    changed: list[str] = []
    for key, value in desired.items():
        if key in _SECRET_KEYS and not value:
            continue
        if current.get(key, "") == value:
            continue
        set_key(str(path), key, value)
        changed.append(key)
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="console.onboarding.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return changed


@router.put("/onboarding", response_model=dict[str, Any])
def put_onboarding(
    body: OnboardingPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    changed = _persist_onboarding(body, request, principal)
    return {"ok": True, "changed": changed, **_onboarding_state(_env_path(request))}


def _safe_url(raw: str, *, https_only: bool = False) -> str:
    parsed = urlparse(raw)
    schemes = {"https"} if https_only else {"http", "https"}
    if (
        parsed.scheme not in schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port is not None
        and not 1 <= parsed.port <= 65535
    ):
        raise ValueError("invalid endpoint")
    return raw


def _test_http(url: str, *, headers: dict[str, str] | None = None, reachable_only: bool = False) -> bool:
    try:
        response = httpx.get(_safe_url(url), headers=headers, timeout=3.0, follow_redirects=False)
        if reachable_only:
            return response.status_code < 500 and response.status_code not in {401, 403}
        return 200 <= response.status_code < 400
    except (httpx.HTTPError, ValueError):
        return False


def _test_smtp(
    address: str,
    use_tls: bool,
    *,
    use_ssl: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> bool:
    try:
        host, raw_port = address.rsplit(":", 1)
        port = int(raw_port)
        if not host or not 1 <= port <= 65535 or any(char.isspace() for char in host):
            return False
        client = (
            smtplib.SMTP_SSL(host, port, timeout=3, context=ssl.create_default_context())
            if use_ssl
            else smtplib.SMTP(host, port, timeout=3)
        )
        with client:
            if use_tls:
                client.starttls(context=ssl.create_default_context())
            if username and password:
                client.login(username, password)
            client.noop()
        return True
    except (OSError, TypeError, ValueError, smtplib.SMTPException):
        return False


def _auth_headers(values: dict[str, str], prefix: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    bearer = values.get(f"{prefix}_BEARER_TOKEN", "")
    api_key = values.get(f"{prefix}_API_KEY", "")
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def _test_webhook(raw: str) -> bool:
    try:
        parsed = urlparse(_safe_url(raw, https_only=True))
        host = parsed.hostname
        assert host is not None
        port = parsed.port or 443
        with (
            socket.create_connection((host, port), timeout=3) as connection,
            ssl.create_default_context().wrap_socket(connection, server_hostname=host),
        ):
            return True
    except (OSError, ValueError, ssl.SSLError):
        return False


@router.post("/onboarding/test", response_model=dict[str, Any])
def test_onboarding_connection(
    body: ConnectionTest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    values = {**_env_values(_env_path(request)), **body.values}
    component = body.component.lower()
    if component in {"identity", "oidc"}:
        endpoint = values.get("OPERATOR_API_OIDC_ISSUER", "").rstrip("/") + "/.well-known/openid-configuration"
        ok = _test_http(endpoint)
    elif component == "graph":
        base = values.get("KP_WORKER_GRAPH_BASE_URL") or values.get("MOCK_GRAPH_URL", "")
        ok = _test_http(base.rstrip("/") + "/users", headers=_auth_headers(values, "KP_WORKER_GRAPH"))
    elif component == "ai":
        base = values.get("KP_WORKER_AI_BASE_URL") or values.get("MOCK_AI_URL", "")
        ok = _test_http(
            base.rstrip("/") + "/propose",
            headers=_auth_headers(values, "KP_WORKER_AI"),
            reachable_only=True,
        )
    elif component == "mailbox":
        base = values.get("KP_WORKER_REPORTED_MAILBOX_URL") or values.get("KP_WORKER_MAILPIT_API_URL", "")
        headers = _auth_headers(values, "KP_WORKER_REPORTED_MAILBOX")
        basic_username = values.get("KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME", "")
        basic_password = values.get("KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD", "")
        if basic_username and basic_password:
            token = base64.b64encode(f"{basic_username}:{basic_password}".encode()).decode()
            headers["Authorization"] = f"Basic {token}"
        ok = _test_http(base.rstrip("/") + "/api/v1/messages", headers=headers)
    elif component == "training":
        ok = _test_http(values.get("OPERATOR_API_TRAINING_BASE_URL", ""))
    elif component == "smtp":
        ok = _test_smtp(
            values.get("KP_WORKER_SMTP_ADDRESS") or values.get("KP_WORKER_MAILPIT_SMTP", ""),
            values.get("KP_WORKER_SMTP_STARTTLS", values.get("KP_WORKER_MAILPIT_SMTP_TLS", "false")).lower() == "true",
            use_ssl=values.get("KP_WORKER_SMTP_SSL", "false").lower() == "true",
            username=values.get("KP_WORKER_SMTP_USERNAME") or None,
            password=values.get("KP_WORKER_SMTP_PASSWORD") or None,
        )
    elif component == "webhook":
        ok = _test_webhook(values.get("KP_WORKER_ALERT_WEBHOOK_URL", ""))
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsupported component")
    return {
        "component": component,
        "ok": ok,
        "message": (
            "Connection successful." if ok else "Connection failed; verify the endpoint, credentials, and TLS settings."
        ),
    }


@router.get("/config", response_model=ConfigResponse)
def get_config(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> ConfigResponse:
    values = _env_values(_env_path(request))
    masked: dict[str, bool] = {}
    display: dict[str, str] = {}
    for key in _ALLOWED_KEYS:
        raw = values.get(key, "")
        # Secrets are never returned — not even masked — so the GUI cannot
        # round-trip a masked placeholder back into .env (CRIT-01).
        display[key] = "" if key in _SECRET_KEYS else raw
        masked[key] = key in _SECRET_KEYS
    return ConfigResponse(values=display, masked=masked)


@router.put("/config", response_model=dict[str, Any])
def put_config(
    body: ConfigPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")

    env_path = _env_path(request)
    changed: list[str] = []
    current = _env_values(env_path)
    for key, value in body.values.items():
        if key in _SECRET_KEYS and not value:
            continue  # blank secret means "keep the current value"
        if value == current.get(key, ""):
            continue
        set_key(str(env_path), key, value)
        changed.append(key)

    audit = request.app.state.audit_store
    audit.record(
        actor=principal.principal_id,
        action="console.config.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return {"ok": True, "changed": changed}


class StatusResponse(BaseModel):
    operator_api: bool
    tracking_api: bool
    postgres: bool
    redis: bool
    console_password_set: bool
    workers: dict[str, bool]


@router.get("/status", response_model=StatusResponse)
def get_status(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> StatusResponse:
    run_dir = _run_dir(request.app.state.settings)
    workers: dict[str, bool] = {}
    for name in ("ingestion", "generation", "delivery", "retention", "mailbox", "reminder", "alert", "directory"):
        workers[name] = _process_alive(run_dir / f"worker-{name}.pid")
    tracking_health = request.app.state.settings.tracking_base_url.rstrip("/") + "/healthz"
    return StatusResponse(
        operator_api=True,
        tracking_api=_http_ok(tracking_health),
        postgres=_tcp_ok("127.0.0.1", 5432),
        redis=_tcp_ok("127.0.0.1", 6379),
        console_password_set=_console_password(_env_path(request)) is not None,
        workers=workers,
    )


@router.post("/restart", response_model=dict[str, Any])
def restart_stack(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Signal the launcher supervisor to restart the whole stack."""
    marker = _run_dir(request.app.state.settings) / "restart"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return {"ok": True, "message": "restart requested"}


@router.post("/stop", response_model=dict[str, Any])
def stop_stack(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Signal the launcher supervisor to shut down every service."""
    marker = _run_dir(request.app.state.settings) / "stop"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return {"ok": True, "message": "stop requested"}


def _run_dir(settings: Any) -> Path:
    return Path(settings.env_file or ".env").resolve().parent / "data" / "run"


def _process_alive(pid_path: Path) -> bool:
    try:
        pid = int(pid_path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _http_ok(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return False
    try:
        return httpx.get(url, timeout=3, follow_redirects=False).status_code == 200
    except httpx.HTTPError:
        return False


def _tcp_ok(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _worker_pid_path(settings: Any, name: str) -> Path:
    return _run_dir(settings) / f"worker-{name}.pid"
