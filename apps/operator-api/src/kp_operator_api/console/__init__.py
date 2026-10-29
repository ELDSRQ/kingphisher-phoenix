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

import contextlib
import datetime
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from kp_authorization.rbac import Capability, Principal, Role
from kp_database.audit_store import AuditStore
from kp_database.models import ConsoleSessionEpoch, CredentialRotation
from kp_telemetry.errors import AuthenticationError, ConflictError
from pydantic import BaseModel, Field  # noqa: F401  (re-exported base for console models)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from kp_operator_api.auth import (
    CONSOLE_SESSION_EPOCH_MARKER,
    OidcEndpointPolicyError,
    OidcIdP,
    SessionEpochMarkerError,
    console_run_dir,
    console_session_epoch_floor,
    console_session_principal_allow_expired,
    require_capability,
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
from kp_operator_api.console.ai_providers import (
    router as _ai_providers_router,
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
    SetPasswordRequest,
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
    _MIN_CONSOLE_PASSWORD_LENGTH,
    _SECRET_KEYS,
    CONSOLE_PASSWORD_KEY,
    MANAGED_CONFIG_MESSAGE,
    MANAGED_PROCESS_MESSAGE,
    _atomic_update_env,
    _AtomicEnvUpdateError,
    _console_password,
    _console_password_unset,
    _env_path,
    _env_values,
    _reject_if_managed,
    _verify_console_password,
    set_console_password,
)
from kp_operator_api.console.model_control import (
    ModelControlStatus,
    ModelSwapRequest,
    ModelSwapResponse,
)
from kp_operator_api.console.model_control import (
    router as _model_control_router,
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
from kp_operator_api.deps import get_audit_store, get_session, get_settings
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
    "CredentialRotationApplyError",
    "MANAGED_CONFIG_MESSAGE",
    "MANAGED_PROCESS_MESSAGE",
    "ModelControlStatus",
    "ModelSwapRequest",
    "ModelSwapResponse",
    "OidcStartResponse",
    "OnboardingPatch",
    "PasswordRotateRequest",
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
    "reconcile_session_epoch",
    "request_live_gated_rotation",
    "restart_stack",
    "rotate_console_password",
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


# --- Session epoch / credential-rotation state machine (W1-07, KP-AUD-019) ----
#
# Local dev-mode console sessions are stateless HS256 tokens, so a logged-out or
# post-password-rotation token still validates until it expires. The persisted
# fix is a monotonic session epoch: the database holds the authoritative epoch
# (:class:`ConsoleSessionEpoch`), the console stamps it into every minted token
# and bumps + audits it on logout and on a successful password rotation, and the
# committed value is mirrored to a mode-0600 on-disk marker the DB-free auth hot
# path reads as the revocation floor (``kp_operator_api.auth``). Credential
# rotation itself is modelled by :class:`CredentialRotation`, mirroring W1-04's
# committed-generation / reconcile shape so a failed new-secret application
# leaves the OLD working secret in place (fail-closed), never half-rotated.

#: Singleton row id of :class:`ConsoleSessionEpoch`.
_SESSION_EPOCH_SINGLETON_ID = 1
#: The one locally-rotatable credential. External provider secrets are LIVE-gated
#: (recorded as ``pending_live`` and never rotated by this service).
_CONSOLE_PASSWORD_CREDENTIAL = "console_password"  # noqa: S105  (a credential identifier, not a secret)


class CredentialRotationApplyError(RuntimeError):
    """A new-secret application or epoch side effect failed or did not verify.

    The rotation is left in blocked drift (``generation != applied_generation``)
    and the OLD working secret and existing sessions stay valid. Carries no
    secret detail.
    """


def _atomic_write_private_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write ``payload`` as compact JSON, mode 0600 (tmp + rename).

    Mirrors the W1-04 marker writer (``console.ai_providers._atomic_write_private``):
    a UNIQUE per-write temp name (``mkstemp``) so concurrent writes cannot
    interleave on a shared ``.tmp`` path, ``fchmod`` to enforce 0600 on the fresh
    fd, and an fsync of both the file and its parent directory so the rename is
    durable (N6).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    tmp = Path(raw_tmp)
    renamed = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        renamed = True
    finally:
        if not renamed:
            with contextlib.suppress(OSError):
                tmp.unlink()
    with contextlib.suppress(OSError):
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _write_session_epoch_marker(settings: Any, epoch: int) -> None:
    """Mirror the committed epoch to the mode-0600 marker the auth path reads."""
    _atomic_write_private_json(console_run_dir(settings) / CONSOLE_SESSION_EPOCH_MARKER, {"epoch": epoch})


def _verify_session_epoch_marker(settings: Any, epoch: int) -> None:
    """Confirm the on-disk revocation floor now reflects the committed epoch."""
    try:
        if console_session_epoch_floor(settings) != epoch:
            raise CredentialRotationApplyError("session epoch marker verification failed")
    except SessionEpochMarkerError as exc:
        raise CredentialRotationApplyError("session epoch marker verification failed") from exc


def _bump_session_epoch_row(session: Session) -> int:
    """Increment the authoritative DB session epoch and return the new value.

    The singleton row is locked ``FOR UPDATE`` (mirroring W1-04's generation
    bump) so two concurrent logout/rotation bumps cannot both read epoch N and
    both write N+1, losing a revocation (N7). The row is seeded by migration
    0049, so the create branch is only for a pre-seed/test session.
    """
    row = session.get(ConsoleSessionEpoch, _SESSION_EPOCH_SINGLETON_ID, with_for_update=True)
    if row is None:
        row = ConsoleSessionEpoch(id=_SESSION_EPOCH_SINGLETON_ID, epoch=0)
        session.add(row)
    row.epoch = (row.epoch or 0) + 1
    return row.epoch


def reconcile_session_epoch(
    session: Session,
    audit: AuditStore,
    settings: Any,
    *,
    best_effort: bool = False,
) -> None:
    """Converge the on-disk marker and any stuck rotation toward MORE revocation.

    Two fail-closed convergences, run wherever a DB handle exists (login,
    rotation) — never in the DB-free auth hot path:

    * N3: if the ``console_password`` rotation is stuck ``rotating`` (a crash
      between committing the rotation intent and completing the epoch bump left
      the new password possibly live but old sessions un-revoked), bump the epoch
      and settle the row. Converging forward can only ADD revocation, so it is
      safe even if the stuck attempt had not actually changed the password.
    * N2: if the committed DB epoch is ahead of the marker — e.g. ``data/run``
      was wiped and the marker read as a fresh 0, silently un-revoking every
      previously revoked token — rewrite the marker up to the DB epoch. A corrupt
      marker is treated as behind and rewritten. The marker is never lowered.

    ``best_effort`` swallows database errors (used on the login path, where the
    database may be transiently unreachable): convergence then simply happens on
    the next call that can reach the database. It never lowers the floor.
    """
    try:
        rotation = session.get(CredentialRotation, _CONSOLE_PASSWORD_CREDENTIAL)
        if rotation is not None and rotation.state == "rotating":
            new_epoch = _bump_session_epoch_row(session)
            rotation.applied_generation = rotation.generation
            rotation.state = "idle"
            audit.record(
                session=session,
                actor=CONSOLE_OPERATOR_UUID,
                action="credential-rotation.reconciled",
                object_type="credential_rotation",
                object_id=_CONSOLE_PASSWORD_CREDENTIAL,
                detail={"generation": rotation.generation, "session_epoch": new_epoch},
            )
            session.commit()
            _write_session_epoch_marker(settings, new_epoch)

        epoch_row = session.get(ConsoleSessionEpoch, _SESSION_EPOCH_SINGLETON_ID)
        db_epoch = epoch_row.epoch if (epoch_row and epoch_row.epoch) else 0
        if db_epoch > 0:
            try:
                marker = console_session_epoch_floor(settings)
            except SessionEpochMarkerError:
                marker = -1  # unreadable/corrupt -> behind; rewrite from the DB
            if marker < db_epoch:
                _write_session_epoch_marker(settings, db_epoch)
    except Exception:  # noqa: BLE001 - best-effort reconcile must never block login
        if not best_effort:
            raise
        # On the login path reconcile is best-effort: a database that is
        # unreachable OR forbidden (e.g. the deliberately DB-free console smoke)
        # must not break sign-in. Convergence then happens on the next login or
        # rotation that can reach the database. Roll back defensively in case a
        # partial unit of work is open; ignore a rollback that itself cannot
        # reach the database.
        with contextlib.suppress(Exception):
            session.rollback()


def _revoke_console_sessions(
    session: Session,
    audit: AuditStore,
    settings: Any,
    *,
    actor: str,
    reason: str,
) -> int:
    """Bump + audit the session epoch, then publish it to the on-disk marker.

    After this returns, every previously minted local session (stamped with an
    older epoch, or none) is rejected by token validation. The epoch value is
    recorded; no secret is.
    """
    new_epoch = _bump_session_epoch_row(session)
    audit.record(
        session=session,
        actor=actor,
        action="console-session.revoke",
        object_type="console_session_epoch",
        object_id=str(_SESSION_EPOCH_SINGLETON_ID),
        detail={"session_epoch": new_epoch, "reason": reason},
    )
    session.commit()
    _write_session_epoch_marker(settings, new_epoch)
    _verify_session_epoch_marker(settings, new_epoch)
    return new_epoch


def _credential_rotation_row(session: Session, credential: str, *, live_gated: bool = False) -> CredentialRotation:
    row = session.get(CredentialRotation, credential)
    if row is None:
        row = CredentialRotation(
            credential=credential,
            generation=0,
            applied_generation=0,
            state="idle",
            live_gated=live_gated,
        )
        session.add(row)
    return row


def _begin_credential_rotation(session: Session, credential: str) -> int:
    """Bump the rotation generation and enter ``rotating`` (blocked drift).

    ``applied_generation`` is left behind until the new secret is written and
    verified, exactly as W1-04 leaves ``applied_generation`` behind until its
    side effects verify.
    """
    row = _credential_rotation_row(session, credential)
    row.generation = (row.generation or 0) + 1
    row.state = "rotating"
    return row.generation


def _mark_credential_rotation_applied(session: Session, credential: str, generation: int) -> None:
    """Advance ``applied_generation`` and settle the state (clears drift)."""
    row = session.get(CredentialRotation, credential)
    if row is not None:
        row.applied_generation = generation
        row.state = "idle"


def _fail_credential_rotation(session: Session, credential: str) -> None:
    """Record a failed apply; ``applied_generation`` stays behind (drift)."""
    row = session.get(CredentialRotation, credential)
    if row is not None:
        row.state = "failed"


def request_live_gated_rotation(
    session: Session,
    audit: AuditStore,
    credential: str,
    *,
    actor: str,
) -> int:
    """Record intent to rotate an EXTERNAL credential, performing nothing.

    Real rotation of an external provider secret requires a live action this
    service must never take on its own (AGENTS.md: no live credential rotation).
    This marks the credential ``pending_live`` and audits the intent; the actual
    rotation happens out of band and is reconciled later. No secret is recorded,
    and no external call is made.
    """
    row = _credential_rotation_row(session, credential, live_gated=True)
    row.generation = (row.generation or 0) + 1
    row.live_gated = True
    row.state = "pending_live"
    audit.record(
        session=session,
        actor=actor,
        action="credential-rotation.pending-live",
        object_type="credential_rotation",
        object_id=credential,
        detail={"generation": row.generation, "live_gated": True},
    )
    return row.generation


def _validate_new_console_password(new_password: str) -> None:
    """Reject a policy-violating new password BEFORE any rotation state changes.

    Validating here (not inside the apply step) keeps a mere policy rejection
    from committing a ``rotating`` row and being mislabeled as an apply failure
    (N4a). ``set_console_password`` re-checks the same policy when it writes, so
    env_store stays the authoritative writer; this is an early, value-free guard.
    These three rules mirror ``env_store.set_console_password`` exactly (a shared
    validator in env_store would remove this duplication but is out of lease).
    """
    if len(new_password) < _MIN_CONSOLE_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"console password must be at least {_MIN_CONSOLE_PASSWORD_LENGTH} characters",
        )
    if new_password != new_password.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="console password must not start or end with whitespace",
        )
    if not any(character.isalpha() for character in new_password) or not any(
        character.isdigit() for character in new_password
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="console password must include at least one letter and one digit",
        )


def _apply_console_password_rotation(env_path: Path, new_password: str) -> None:
    """Write + verify the new console password, fail-closed.

    ``set_console_password`` commits through the atomic, self-verifying,
    recoverable env path, so a write fault leaves the OLD password durably in
    place. Any apply fault — including an OSError or other error not wrapped by
    env_store — is caught and re-raised as :class:`CredentialRotationApplyError`
    so the caller always lands in the fail-closed branch (N4b) rather than
    escaping with the rotation row stuck ``rotating`` and no audit.
    """
    try:
        set_console_password(env_path, new_password)
    except Exception as exc:  # noqa: BLE001 - any apply fault is fail-closed; detail stays internal
        raise CredentialRotationApplyError("console password rotation could not be applied") from exc
    if not _verify_console_password(env_path, new_password):
        raise CredentialRotationApplyError("console password did not verify after rotation")


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: Any = Depends(get_settings),
) -> RedirectResponse:
    response = RedirectResponse(url="/console/", status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(_OIDC_SESSION_COOKIE, path="/")
    # Local sessions are our own stateless tokens, so expiring the cookie is not
    # enough: bump the server-side epoch so a copied/active token is rejected too.
    # Managed OIDC tokens are the identity provider's and carry no epoch of ours,
    # so there is nothing to revoke here and the DB is left untouched.
    #
    # The epoch bump is a persistent, audited revocation, so it must not be
    # triggerable by an anonymous or cross-site POST (forced-logout DoS +
    # spoofed-actor DB write, N1). Require a signature-valid local session token
    # from the request (an EXPIRED one still counts, so a normal logout works);
    # an absent/forged/unsigned token means there is nothing to revoke, so the
    # cookie is cleared and we return WITHOUT any DB/audit write. The bump is
    # attributed to the real principal from that token, never a hardcoded UUID.
    if request.app.state.settings.oidc_mode == "dev":
        principal = console_session_principal_allow_expired(request)
        if principal is not None:
            _revoke_console_sessions(session, audit, settings, actor=principal.principal_id, reason="logout")
    return response


def _mint_dev_session(request: Request) -> SessionResponse:
    settings = request.app.state.settings
    now = datetime.datetime.now(datetime.UTC)
    try:
        epoch = console_session_epoch_floor(settings)
    except SessionEpochMarkerError as exc:
        raise AuthenticationError("session epoch could not be established") from exc
    claims = {
        "sub": CONSOLE_OPERATOR_UUID,
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + _SESSION_TTL_SECONDS,
        "realm_access": {"roles": ["administrator"]},
        # Stamp the current revocation floor so this token survives until the
        # next logout/rotation raises the epoch above it.
        "epoch": epoch,
    }
    token = jwt.encode(claims, settings.require_console_jwt_secret(), algorithm="HS256")
    principal = Principal(subject_id=CONSOLE_OPERATOR_UUID, roles={Role.ADMINISTRATOR})
    return SessionResponse(
        token=token,
        expires_in=_SESSION_TTL_SECONDS,
        auth_mode="dev",
        principal_id=CONSOLE_OPERATOR_UUID,
        approval_limited=False,
        approval_policy=settings.approval_policy.value,
        **_session_authority(principal),
    )


@router.post("/session", response_model=SessionResponse)
def create_session(
    body: SessionRequest,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
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
    if _console_password_unset(env_path):
        # First run: no password exists to verify, so point the operator at the
        # one-time set-password flow instead of reporting a misleading "invalid
        # password". The UI keys off this status + message.
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="console password is not set; complete first-run setup",
        )
    if not _verify_console_password(env_path, body.password):
        throttle.record_failure(client_ip)
        raise AuthenticationError("invalid console password")
    throttle.record_success(client_ip)
    # Converge the on-disk marker up to the committed DB epoch before minting, so
    # a wiped run directory or a crash-stuck rotation cannot un-revoke older
    # sessions (N2/N3). Best-effort: a transiently unreachable database must not
    # block login; convergence then happens on the next login or rotation.
    reconcile_session_epoch(session, audit, settings, best_effort=True)
    return _mint_dev_session(request)


@router.post("/password", response_model=SessionResponse)
def first_run_set_password(
    body: SetPasswordRequest,
    request: Request,
) -> SessionResponse:
    """One-time first-run console password setup.

    Only reachable while the password is unset (a brand-new local dev stack);
    once set, this refuses with 409 so it can never be used to silently rotate
    the credential. The value is validated and committed atomically, never
    logged, and never written to the audit store.
    """
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    settings = request.app.state.settings
    if settings.oidc_mode != "dev":
        raise AuthenticationError("console password login is disabled; sign in via the identity provider")
    env_path = _env_path(request)
    if not _console_password_unset(env_path):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="console password is already set")
    if body.password != body.confirm:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="password and confirmation do not match",
        )
    set_console_password(env_path, body.password)
    return _mint_dev_session(request)


class PasswordRotateRequest(BaseModel):
    """Rotate an already-set console password.

    Re-authenticates with the current password in-band before rotating, and
    compares the confirmation before any write so a typo cannot lock the
    operator out. None of these values is ever logged or audited.
    """

    current_password: str = Field(min_length=1)
    new_password: str = Field(min_length=1)
    confirm: str = Field(min_length=1)


@router.post("/password/rotate", response_model=SessionResponse)
def rotate_console_password(
    body: PasswordRotateRequest,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: Any = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> SessionResponse:
    """Rotate the console password and revoke every pre-rotation session.

    Fail-closed, mirroring W1-04: the rotation generation is bumped and
    committed as ``rotating`` (blocked drift) BEFORE the new secret is written,
    and ``applied_generation`` is advanced only after the new password is
    written and verified. If application fails, the rotation is marked failed,
    the OLD password and existing sessions stay valid, and no epoch is bumped. On
    success the session epoch is bumped (so old tokens are rejected) and a fresh
    session stamped with the new epoch is returned. Every outcome is audited
    without any secret value.
    """
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    if request.app.state.settings.oidc_mode != "dev":
        raise AuthenticationError("console password login is disabled; sign in via the identity provider")
    env_path = _env_path(request)
    if _console_password_unset(env_path):
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="console password is not set; complete first-run setup",
        )
    # Throttle the current-password check so a stolen session cookie cannot be
    # used to brute-force the existing password here, reusing the same per-IP
    # lockout that guards the login path (N5).
    client_ip = request.client.host if request.client else "unknown"
    throttle: LoginThrottle = request.app.state.login_throttle
    if throttle.locked(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many failed attempts; try again later"
        )
    if not _verify_console_password(env_path, body.current_password):
        throttle.record_failure(client_ip)
        raise AuthenticationError("current console password is incorrect")
    throttle.record_success(client_ip)
    if body.new_password != body.confirm:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="password and confirmation do not match",
        )
    # Validate the new password's policy BEFORE touching the rotation state
    # machine, so a policy rejection is a clean 422 and never a committed
    # ``rotating`` row mislabeled as an apply failure (N4a).
    _validate_new_console_password(body.new_password)

    # Converge any prior crash-stuck rotation / behind marker before starting a
    # new rotation, so an older un-revoked session cannot survive this one (N2/N3).
    reconcile_session_epoch(session, audit, settings)

    # Commit the rotation intent (blocked drift) before the risky side effect.
    generation = _begin_credential_rotation(session, _CONSOLE_PASSWORD_CREDENTIAL)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="credential-rotation.begin",
        object_type="credential_rotation",
        object_id=_CONSOLE_PASSWORD_CREDENTIAL,
        detail={"generation": generation},
    )
    session.commit()

    try:
        _apply_console_password_rotation(env_path, body.new_password)
    except CredentialRotationApplyError as exc:
        _fail_credential_rotation(session, _CONSOLE_PASSWORD_CREDENTIAL)
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="credential-rotation.failed",
            object_type="credential_rotation",
            object_id=_CONSOLE_PASSWORD_CREDENTIAL,
            detail={"generation": generation, "reason": "apply_failed"},
        )
        session.commit()
        raise ConflictError(
            "console password rotation could not be applied; the existing password is unchanged"
        ) from exc

    # New secret durable and verified: revoke old sessions and settle the
    # rotation in one transaction, then publish the epoch to the marker. If this
    # final step faults AFTER the password changed, the rotation row stays
    # ``rotating`` (blocked drift) with the epoch un-bumped — the new password is
    # live but old sessions are briefly still valid. That is converged forward
    # (epoch bumped, row settled) by reconcile on the next login/rotation, which
    # can only ADD revocation; here we surface it rather than claim success.
    try:
        new_epoch = _bump_session_epoch_row(session)
        _mark_credential_rotation_applied(session, _CONSOLE_PASSWORD_CREDENTIAL, generation)
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="credential-rotation.applied",
            object_type="credential_rotation",
            object_id=_CONSOLE_PASSWORD_CREDENTIAL,
            detail={"generation": generation, "session_epoch": new_epoch},
        )
        session.commit()
        _write_session_epoch_marker(settings, new_epoch)
        _verify_session_epoch_marker(settings, new_epoch)
    except (SQLAlchemyError, CredentialRotationApplyError) as exc:
        with contextlib.suppress(SQLAlchemyError):
            session.rollback()
        raise ConflictError(
            "console password was changed but session revocation did not complete; "
            "it will be reconciled on the next sign-in"
        ) from exc
    return _mint_dev_session(request)


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
    _model_control_router,
    _ai_providers_router,
):
    for _seam_route in _seam_router.routes:
        router.routes.append(_seam_route)
