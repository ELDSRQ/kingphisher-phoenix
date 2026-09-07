"""Browser-console authentication, configuration, and lifecycle endpoints.

Local development uses password login plus editable ``.env`` configuration
and process controls. Managed Azure deployments use OIDC, disable password
login, and expose managed configuration and lifecycle status as read-only.

The implementation lives in this package, one module per seam (ARC-002 Item 2):
``env_store`` (the local ``.env`` write path), ``console_auth`` (session/OIDC
support), ``azure_deployment_routes`` (the flagged Azure deploy connector),
``config`` (configuration models, step schema, candidate validation),
``onboarding`` (the setup wizard, AI assistance, connection tests), and
``runtime_status`` (local dependency probes and restart). This module is the
facade: it owns the single ``/api/v1/console`` router ``main.py`` includes,
appends each seam router's route objects in exactly the registration order the
routes had when they all lived in one file, and re-exports the names the
operator tests import.

The six authentication endpoints below stay defined *here* on purpose. They are
the console's dedicated/public routes, and ``tests/test_route_authorization_inventory.py``
pins each of them to the ``kp_operator_api.console`` module identity.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets
from urllib.parse import urlencode, urlparse

import jwt
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from kp_authorization.rbac import Principal, Role
from kp_telemetry.errors import AuthenticationError
from pydantic import BaseModel  # noqa: F401  (re-exported base for console models)

from kp_operator_api.auth import (
    OidcEndpointPolicyError,
    OidcIdP,
    validate_oidc_endpoint,
)
from kp_operator_api.connection_probes import (
    _allow_development_loopback,
    _auth_headers,
    _connect_pinned,
    _connection_test_result,
    _credentials_for_destination,
    _EndpointPolicyError,
    _explicit_loopback_host,
    _http_failure_kind,
    _microsoft365_probe_url,
    _parse_smtp_address,
    _pinned_http_status,
    _PinnedHTTPConnection,
    _PinnedHTTPSConnection,
    _PinnedSMTP,
    _PinnedSMTPSSL,
    _probe_http,
    _probe_smtp,
    _probe_webhook,
    _resolve_pinned_target,
    _resolve_setup_assist_endpoint,
    _ResolvedSetupAssistEndpoint,
    _ResolvedTarget,
    _safe_url,
    _selected_destination,
    _test_http,
    _test_smtp,
    _test_webhook,
    _validated_acs_endpoint,
)
from kp_operator_api.console.azure_deployment_routes import (
    AzureDeploymentAdvanceRequest,
    AzureDeploymentConfirmationRequest,
    AzureDeploymentValidationRequest,
    _azure_deployment_schema,
    _azure_release_readiness,
    _require_deploy_connector_enabled,
    validate_azure_deployment,
)
from kp_operator_api.console.azure_deployment_routes import (
    router as _azure_deployment_router,
)
from kp_operator_api.console.config import (
    _ONBOARDING_STEPS,
    ConfigPatch,
    ConfigResponse,
    _onboarding_step_configured,
    _validate_config_candidate,
    get_config,
    put_config,
)
from kp_operator_api.console.config import (
    router as _config_router,
)
from kp_operator_api.console.console_auth import (
    _LOCAL_OIDC_REDIRECT_URI,
    _OIDC_CALLBACK_PATH,
    _OIDC_SESSION_COOKIE,
    _OIDC_TRANSACTION_COOKIE,
    _OIDC_TRANSACTION_TTL_SECONDS,
    _SESSION_TTL_SECONDS,
    CONSOLE_OPERATOR_UUID,
    OidcStartResponse,
    SessionRequest,
    SessionResponse,
    _b64url,
    _oidc_metadata,
    _oidc_token_response,
    _session_authority,
    _transaction_secret,
    _valid_uri_hostname,
    _validated_oidc_redirect_uri,
)
from kp_operator_api.console.env_store import (
    _ALLOWED_KEYS,
    _SECRET_KEYS,
    CONSOLE_PASSWORD_KEY,
    MANAGED_CONFIG_MESSAGE,
    MANAGED_PROCESS_MESSAGE,
    _atomic_update_env,
    _AtomicEnvUpdateError,
    _console_password,
    _env_path,
    _env_values,
    _reject_if_managed,
    _verify_console_password,
)
from kp_operator_api.console.onboarding import (
    _AZURE_EMAIL_PROTECTED_AI_OUTPUT,
    ConnectionTest,
    OnboardingPatch,
    SetupAssistRequest,
    SetupAssistResponse,
    _bounded_setup_assist_json,
    _component_nonsecret_keys,
    _curated_assistance,
    _onboarding_state,
    _validated_ai_assistance,
    assist_onboarding,
    get_console_help,
    get_onboarding,
    put_onboarding,
    test_onboarding_connection,
)
from kp_operator_api.console.onboarding import (
    router as _onboarding_router,
)
from kp_operator_api.console.runtime_status import (
    RuntimeCapabilities,
    StatusResponse,
    _probe_target,
    _process_alive,
    _run_dir,
    _worker_pid_path,
    get_status,
    restart_stack,
)
from kp_operator_api.console.runtime_status import (
    router as _runtime_status_router,
)
from kp_operator_api.ratelimit import LoginThrottle

router = APIRouter(prefix="/api/v1/console", tags=["console"])

# The probe cluster lives in kp_operator_api.connection_probes; console re-exports
# every probe name here so route handlers and operator tests that reference
# console._probe_http / console._PinnedSMTPSSL / console._ResolvedTarget etc.
# keep resolving exactly as before the extraction. __all__ marks these as
# intentional re-exports for ruff (F401) and documents the facade surface.
# The seam modules below are re-exported on the same terms.
__all__ = [
    "AzureDeploymentAdvanceRequest",
    "AzureDeploymentConfirmationRequest",
    "AzureDeploymentValidationRequest",
    "BaseModel",
    "CONSOLE_OPERATOR_UUID",
    "CONSOLE_PASSWORD_KEY",
    "ConfigPatch",
    "ConfigResponse",
    "ConnectionTest",
    "MANAGED_CONFIG_MESSAGE",
    "MANAGED_PROCESS_MESSAGE",
    "OidcStartResponse",
    "OnboardingPatch",
    "RuntimeCapabilities",
    "SessionRequest",
    "SessionResponse",
    "SetupAssistRequest",
    "SetupAssistResponse",
    "StatusResponse",
    "_ALLOWED_KEYS",
    "_AZURE_EMAIL_PROTECTED_AI_OUTPUT",
    "_AtomicEnvUpdateError",
    "_EndpointPolicyError",
    "_LOCAL_OIDC_REDIRECT_URI",
    "_OIDC_CALLBACK_PATH",
    "_ONBOARDING_STEPS",
    "_PinnedHTTPConnection",
    "_PinnedHTTPSConnection",
    "_PinnedSMTP",
    "_PinnedSMTPSSL",
    "_ResolvedSetupAssistEndpoint",
    "_ResolvedTarget",
    "_SECRET_KEYS",
    "_allow_development_loopback",
    "_atomic_update_env",
    "_auth_headers",
    "_azure_deployment_schema",
    "_azure_release_readiness",
    "_bounded_setup_assist_json",
    "_component_nonsecret_keys",
    "_connect_pinned",
    "_connection_test_result",
    "_console_password",
    "_credentials_for_destination",
    "_curated_assistance",
    "_env_values",
    "_explicit_loopback_host",
    "_http_failure_kind",
    "_microsoft365_probe_url",
    "_onboarding_state",
    "_onboarding_step_configured",
    "_parse_smtp_address",
    "_pinned_http_status",
    "_probe_http",
    "_probe_smtp",
    "_probe_target",
    "_probe_webhook",
    "_process_alive",
    "_reject_if_managed",
    "_require_deploy_connector_enabled",
    "_resolve_pinned_target",
    "_resolve_setup_assist_endpoint",
    "_run_dir",
    "_safe_url",
    "_selected_destination",
    "_test_http",
    "_test_smtp",
    "_test_webhook",
    "_valid_uri_hostname",
    "_validate_config_candidate",
    "_validated_acs_endpoint",
    "_validated_ai_assistance",
    "_worker_pid_path",
    "assist_onboarding",
    "get_config",
    "get_console_help",
    "get_onboarding",
    "get_status",
    "put_config",
    "put_onboarding",
    "restart_stack",
    "router",
    "test_onboarding_connection",
    "validate_azure_deployment",
]


@router.get("/auth-mode")
def auth_mode(request: Request) -> dict[str, object]:
    """Public, non-sensitive hint used to choose the console login screen.

    ARC-002 Item 1 Phase 1: this is also the hint the console reads to decide
    whether to show the Azure "Deployment" nav item. The ``deploy_connector_enabled``
    key is emitted ONLY when the connector is turned off, so with the connector on
    (the default) the response is byte-identical to before the flag existed and
    the nav shows exactly as today; when off the key appears as ``false`` and the
    console hides the nav. Flipping the flag back on restores both.
    """
    settings = request.app.state.settings
    payload: dict[str, object] = {
        "auth_mode": settings.oidc_mode,
        "deployment_mode": settings.deployment_mode,
    }
    if not settings.deploy_connector_enabled:
        payload["deploy_connector_enabled"] = False
    return payload


@router.get("/oidc/start", response_model=OidcStartResponse)
async def oidc_start(request: Request) -> JSONResponse:
    settings = request.app.state.settings
    if settings.oidc_mode != "oidc":
        raise AuthenticationError("OIDC login is not enabled")
    try:
        redirect_uri = _validated_oidc_redirect_uri(settings.oidc_redirect_uri)
    except ValueError as exc:
        raise AuthenticationError("OIDC redirect URI is invalid") from exc
    metadata = await _oidc_metadata(settings.oidc_issuer)
    authorization_endpoint = metadata.get("authorization_endpoint")
    if not isinstance(authorization_endpoint, str):
        raise AuthenticationError("identity provider has no authorization endpoint")
    try:
        authorization_endpoint = validate_oidc_endpoint(
            authorization_endpoint,
            issuer=settings.oidc_issuer,
            endpoint_name="authorization endpoint",
        )
    except OidcEndpointPolicyError as exc:
        raise AuthenticationError("identity provider has an invalid authorization endpoint") from exc
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
            "redirect_uri": redirect_uri,
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
        secure=urlparse(redirect_uri).scheme == "https",
        samesite="lax",
        path="/api/v1/console/oidc",
    )
    return result


@router.get("/oidc/callback")
async def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "") -> RedirectResponse:
    settings = request.app.state.settings
    if settings.oidc_mode != "oidc" or error or not code or not state:
        raise AuthenticationError("identity provider login was not completed")
    try:
        redirect_uri = _validated_oidc_redirect_uri(settings.oidc_redirect_uri)
    except ValueError as exc:
        raise AuthenticationError("OIDC redirect URI is invalid") from exc
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
    try:
        token_endpoint = validate_oidc_endpoint(
            token_endpoint,
            issuer=settings.oidc_issuer,
            endpoint_name="token endpoint",
        )
    except OidcEndpointPolicyError as exc:
        raise AuthenticationError("identity provider has an invalid token endpoint") from exc
    form = {
        "grant_type": "authorization_code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": str(transaction["verifier"]),
    }
    if settings.oidc_client_secret:
        form["client_secret"] = settings.oidc_client_secret
    tokens = await _oidc_token_response(token_endpoint, form, issuer=settings.oidc_issuer)
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
        secure=urlparse(redirect_uri).scheme == "https",
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
        approval_policy=request.app.state.settings.approval_policy.value,
        **_session_authority(principal),
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
    principal = Principal(subject_id=CONSOLE_OPERATOR_UUID, roles={Role.ADMINISTRATOR})
    return SessionResponse(
        token=token,
        expires_in=_SESSION_TTL_SECONDS,
        auth_mode="dev",
        principal_id=CONSOLE_OPERATOR_UUID,
        approval_limited=False,
        approval_policy=request.app.state.settings.approval_policy.value,
        **_session_authority(principal),
    )


# FastAPI >=0.141 wraps ``include_router`` in a lazy ``_IncludedRouter`` instead
# of flattening, which hides the routes from one-level ``router.routes`` walkers
# (the operator-api route-inventory and console-wiring contracts). Every seam
# router carries the same ``/api/v1/console`` prefix, so copying their route
# objects into the facade router preserves both the exact registration order and
# the fully-qualified paths.
for _seam_router in (
    _azure_deployment_router,
    _onboarding_router,
    _config_router,
    _runtime_status_router,
):
    for _seam_route in _seam_router.routes:
        router.routes.append(_seam_route)
