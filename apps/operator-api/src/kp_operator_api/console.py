"""Browser-console authentication, configuration, and lifecycle endpoints.

Local development uses password login plus editable ``.env`` configuration
and process controls. Managed Azure deployments use OIDC, disable password
login, and expose managed configuration and lifecycle status as read-only.
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import stat
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlencode, urlparse, urlsplit

import httpx
import jwt
from dotenv import dotenv_values, set_key
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from kp_authorization.rbac import Capability, Principal, Role
from kp_telemetry.errors import AuthenticationError, ConflictError, PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import (
    OidcEndpointPolicyError,
    OidcIdP,
    require_capability,
    resolve_oidc_endpoint,
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
from kp_operator_api.deployment_orchestration import (
    DeploymentConflict,
    DeploymentOrchestrator,
    DeploymentUnavailable,
    public_deployment_error,
)
from kp_operator_api.oidc_provider import (
    MAX_OIDC_DISCOVERY_BYTES,
    MAX_OIDC_TOKEN_RESPONSE_BYTES,
    OidcProviderResponseError,
    bounded_json_async,
)
from kp_operator_api.ratelimit import LoginThrottle

router = APIRouter(prefix="/api/v1/console", tags=["console"])

# The probe cluster lives in kp_operator_api.connection_probes; console re-exports
# every probe name here so route handlers and operator tests that reference
# console._probe_http / console._PinnedSMTPSSL / console._ResolvedTarget etc.
# keep resolving exactly as before the extraction. __all__ marks these as
# intentional re-exports for ruff (F401) and documents the facade surface.
__all__ = [
    "_EndpointPolicyError",
    "_PinnedHTTPConnection",
    "_PinnedHTTPSConnection",
    "_PinnedSMTP",
    "_PinnedSMTPSSL",
    "_ResolvedSetupAssistEndpoint",
    "_ResolvedTarget",
    "_allow_development_loopback",
    "_auth_headers",
    "_connect_pinned",
    "_connection_test_result",
    "_credentials_for_destination",
    "_explicit_loopback_host",
    "_http_failure_kind",
    "_microsoft365_probe_url",
    "_parse_smtp_address",
    "_pinned_http_status",
    "_probe_http",
    "_probe_smtp",
    "_probe_webhook",
    "_resolve_pinned_target",
    "_resolve_setup_assist_endpoint",
    "_safe_url",
    "_selected_destination",
    "_test_http",
    "_test_smtp",
    "_test_webhook",
    "_validated_acs_endpoint",
]

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
        "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
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


MANAGED_CONFIG_MESSAGE = (
    "this deployment reads its configuration from Terraform and Key Vault, not from a file the "
    "console can edit. Change the value in infrastructure/terraform (or the corresponding Key Vault "
    "secret) and re-run the Azure deployment workflow. Editing it here would be discarded on the "
    "next container restart."
)

MANAGED_PROCESS_MESSAGE = (
    "this deployment runs as Azure Container Apps revisions, which have no local supervisor to "
    "signal. Restart or scale the container app instead (az containerapp revision restart)."
)


def _reject_if_managed(request: Request, message: str) -> None:
    """Refuse local-only console actions when configuration is externally managed.

    Without this the console appears to succeed on Azure: it writes a file on an
    ephemeral layer that disappears on the next restart, which is a worse
    failure than an explicit refusal because it looks like it worked.
    """
    if request.app.state.settings.config_is_managed:
        raise ConflictError(message)


def _env_values(path: Path) -> dict[str, str]:
    return {k: v for k, v in dotenv_values(path).items() if v is not None}


class _AtomicEnvUpdateError(RuntimeError):
    """A sanitized, fail-closed local configuration commit failure."""


_ENV_UPDATE_THREAD_LOCK = threading.Lock()
_MAX_ENV_VALUE_BYTES = 64 * 1024
_OIDC_CALLBACK_PATH = "/api/v1/console/oidc/callback"
_LOCAL_OIDC_REDIRECT_URI = f"http://localhost:8000{_OIDC_CALLBACK_PATH}"


def _selected_binding_destination(values: dict[str, str], primary: str, fallback: str) -> str:
    return values.get(primary) or values.get(fallback, "")


def _require_fresh_credentials_for_rebound_destinations(
    current: dict[str, str],
    desired: dict[str, str],
) -> None:
    """Keep stored credentials bound to the destination they were entered for.

    This runs under the same advisory lock as the eventual env-file replace.
    Consequently another console process cannot change a destination between
    this comparison and the atomic commit. Blank secret fields retain their
    normal meaning only when the credential's destination is unchanged.
    """

    candidate = {**current, **desired}
    email_provider = candidate.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp"
    mailbox_provider = candidate.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
    oidc_mode = candidate.get("OPERATOR_API_OIDC_MODE", "dev").strip()
    bindings: tuple[tuple[str, object, object, tuple[str, ...], bool], ...] = (
        (
            "OIDC issuer",
            (
                current.get("OPERATOR_API_OIDC_MODE", "dev").strip(),
                current.get("OPERATOR_API_OIDC_ISSUER", ""),
                current.get("OPERATOR_API_OIDC_CLIENT_ID", ""),
            ),
            (
                oidc_mode,
                candidate.get("OPERATOR_API_OIDC_ISSUER", ""),
                candidate.get("OPERATOR_API_OIDC_CLIENT_ID", ""),
            ),
            ("OPERATOR_API_OIDC_CLIENT_SECRET",),
            oidc_mode == "oidc",
        ),
        (
            "AI service base URL",
            _selected_binding_destination(current, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL"),
            _selected_binding_destination(candidate, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL"),
            ("KP_WORKER_AI_BEARER_TOKEN", "KP_WORKER_AI_API_KEY"),
            bool(_selected_binding_destination(candidate, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")),
        ),
        (
            "Graph service base URL",
            _selected_binding_destination(current, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL"),
            _selected_binding_destination(candidate, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL"),
            ("KP_WORKER_GRAPH_BEARER_TOKEN", "KP_WORKER_GRAPH_API_KEY"),
            bool(_selected_binding_destination(candidate, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")),
        ),
        (
            "reported-mailbox provider or base URL",
            (
                current.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit",
                _selected_binding_destination(
                    current,
                    "KP_WORKER_REPORTED_MAILBOX_URL",
                    "KP_WORKER_MAILPIT_API_URL",
                ),
            ),
            (
                mailbox_provider,
                _selected_binding_destination(
                    candidate,
                    "KP_WORKER_REPORTED_MAILBOX_URL",
                    "KP_WORKER_MAILPIT_API_URL",
                ),
            ),
            ("KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN", "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD"),
            mailbox_provider in {"mailpit", "microsoft365"},
        ),
        (
            "SMTP provider or destination",
            (
                current.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp",
                _selected_binding_destination(current, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP"),
            ),
            (
                email_provider,
                _selected_binding_destination(candidate, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP"),
            ),
            ("KP_WORKER_SMTP_PASSWORD",),
            email_provider == "smtp",
        ),
        (
            "ACS provider or endpoint",
            (
                current.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp",
                current.get("KP_WORKER_ACS_EMAIL_ENDPOINT", ""),
            ),
            (email_provider, candidate.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")),
            ("KP_WORKER_ACS_EMAIL_CONNECTION_STRING",),
            email_provider == "azure_communication_services",
        ),
    )
    for label, previous_identity, candidate_identity, credential_keys, active in bindings:
        if not active or previous_identity == candidate_identity:
            continue
        existing_credentials = tuple(key for key in credential_keys if current.get(key, "").strip())
        if existing_credentials and any(not desired.get(key, "").strip() for key in existing_credentials):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    f"changing the {label} requires re-entering every configured credential in the same save; "
                    "blank secret fields cannot preserve credentials across destinations"
                ),
            )


def _validate_env_fields(values: dict[str, str]) -> None:
    """Validate every proposed field before creating staging or recovery files."""
    for key, value in values.items():
        if key not in _ALLOWED_KEYS:
            raise PermissionDeniedError(f"rejected configuration keys: {[key]}")
        if "\x00" in value or "\r" in value or "\n" in value:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} must be a single-line value",
            )
        if key in _SECRET_KEYS and value and not value.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} cannot be a whitespace-only secret",
            )
        if len(value.encode("utf-8")) > _MAX_ENV_VALUE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"{key} exceeds the configuration value size limit",
            )


def _safe_env_mode(original_mode: int | None) -> int:
    """Preserve an owner-readable mode only when it does not expose secrets."""
    if original_mode is None:
        return 0o600
    mode = stat.S_IMODE(original_mode)
    # Owner read/write plus optional group read is sufficiently restrictive for
    # a local secret-bearing env file. Never retain execute, group-write, or
    # any world permission from a mistakenly permissive source file.
    if mode in {0o600, 0o640}:
        return mode
    return 0o600


def _write_private_file(fd: int, content: bytes) -> None:
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()


def _fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_env_file(source: Path, target: Path) -> None:
    os.replace(source, target)


def _create_recovery_copy(path: Path, content: bytes) -> Path:
    descriptor, raw_recovery = tempfile.mkstemp(
        prefix=f"{path.name}.recovery.",
        suffix=".bak",
        dir=path.parent,
    )
    recovery = Path(raw_recovery)
    try:
        os.fchmod(descriptor, 0o600)
        _write_private_file(descriptor, content)
        _fsync_path(recovery)
    except Exception:
        # This copy belongs only to the failed current attempt and was never a
        # valid recovery artifact. Older recovery copies are never touched.
        with suppress(OSError):
            recovery.unlink(missing_ok=True)
        raise
    return recovery


def _restore_original_after_sync_failure(
    path: Path,
    original: bytes,
    original_existed: bool,
    mode: int,
    directory_fd: int,
) -> bool:
    """Best-effort rollback when the post-replace directory sync fails."""
    try:
        if not original_existed:
            path.unlink(missing_ok=True)
            with suppress(OSError):
                os.fsync(directory_fd)
            return True
        descriptor, raw_rollback = tempfile.mkstemp(
            prefix=f"{path.name}.rollback.",
            suffix=".tmp",
            dir=path.parent,
        )
        rollback = Path(raw_rollback)
        try:
            _write_private_file(descriptor, original)
            os.chmod(rollback, mode)
            # Even a repeated sync error must not prevent restoring the
            # original logical contents. The retained recovery copy remains
            # the durability fallback if the filesystem cannot sync.
            with suppress(OSError):
                _fsync_path(rollback)
            _replace_env_file(rollback, path)
            with suppress(OSError):
                os.fsync(directory_fd)
            return True
        finally:
            rollback.unlink(missing_ok=True)
    except OSError:
        return False


def _atomic_update_env(
    path: Path,
    desired: dict[str, str],
    *,
    validate_candidate: Callable[[dict[str, str]], None] | None = None,
) -> list[str]:
    """Apply a complete env update with one durable, recoverable replacement.

    A process-local lock prevents same-process thread races, while an advisory
    lock on the containing directory coordinates independent API processes
    without creating lock metadata before validation. All mutation happens in
    an isolated file on the same filesystem as the target.
    """
    parent = path.parent
    staged: Path | None = None
    replaced = False
    original = b""
    original_existed = False
    mode = 0o600
    directory_fd = -1
    with _ENV_UPDATE_THREAD_LOCK:
        try:
            directory_fd = os.open(parent, os.O_RDONLY)
            fcntl.flock(directory_fd, fcntl.LOCK_EX)
            try:
                original = path.read_bytes()
                original_existed = True
                mode = _safe_env_mode(path.stat().st_mode)
            except FileNotFoundError:
                original = b""
                original_existed = False
                mode = 0o600

            current = _env_values(path)
            effective = {key: value for key, value in desired.items() if not (key in _SECRET_KEYS and not value)}
            _validate_env_fields(effective)
            _require_fresh_credentials_for_rebound_destinations(current, desired)
            candidate = {**current, **effective}
            if validate_candidate is not None:
                validate_candidate(candidate)
            changed = [key for key, value in effective.items() if current.get(key, "") != value]
            if not changed:
                return []

            descriptor, raw_staged = tempfile.mkstemp(
                prefix=f"{path.name}.staged.",
                suffix=".tmp",
                dir=parent,
            )
            staged = Path(raw_staged)
            os.fchmod(descriptor, 0o600)
            _write_private_file(descriptor, original)
            for key in changed:
                result = set_key(str(staged), key, effective[key])
                if result[0] is not True:
                    raise _AtomicEnvUpdateError("configuration staging failed")

            staged_values = _env_values(staged)
            if any(staged_values.get(key) != effective[key] for key in changed):
                raise _AtomicEnvUpdateError("configuration staging verification failed")
            os.chmod(staged, mode)
            _fsync_path(staged)
            _create_recovery_copy(path, original)
            os.fsync(directory_fd)
            _replace_env_file(staged, path)
            staged = None
            replaced = True
            try:
                os.fsync(directory_fd)
            except OSError:
                restored = _restore_original_after_sync_failure(
                    path,
                    original,
                    original_existed,
                    mode,
                    directory_fd,
                )
                replaced = not restored
                raise
            return changed
        except (HTTPException, PermissionDeniedError):
            raise
        except Exception:
            message = "configuration update failed"
            if not replaced:
                message += "; original configuration is unchanged"
            else:
                message += "; use the retained recovery copy"
            raise _AtomicEnvUpdateError(message) from None
        finally:
            if staged is not None:
                with suppress(OSError):
                    staged.unlink(missing_ok=True)
            if directory_fd >= 0:
                try:
                    fcntl.flock(directory_fd, fcntl.LOCK_UN)
                finally:
                    os.close(directory_fd)


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


@router.get("/auth-mode")
def auth_mode(request: Request) -> dict[str, str]:
    """Public, non-sensitive hint used to choose the console login screen."""
    return {
        "auth_mode": request.app.state.settings.oidc_mode,
        "deployment_mode": request.app.state.settings.deployment_mode,
    }


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
        "KP_WORKER_MAILPIT_API_URL",
        "KP_WORKER_PROVIDER_TIMEOUT_SECONDS",
        "KP_WORKER_MAILBOX_POLL_LIMIT",
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
        "KP_WORKER_EMAIL_PROVIDER",
        "KP_WORKER_ACS_EMAIL_ENDPOINT",
        "KP_WORKER_ACS_CLIENT_ID",
        "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
        "KP_WORKER_ACS_SENDING_DOMAIN",
        "KP_WORKER_ACS_SENDER_LOCAL_PART",
        "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
        "KP_WORKER_ACS_DOMAIN_VERIFICATION_STATUS",
        "KP_WORKER_ACS_SPF_VERIFICATION_STATUS",
        "KP_WORKER_ACS_DKIM_VERIFICATION_STATUS",
        "KP_WORKER_ACS_DKIM2_VERIFICATION_STATUS",
        "KP_WORKER_ACS_READINESS_CHECKED_AT",
        "KP_WORKER_ACS_DAILY_MESSAGE_LIMIT",
        "KP_WORKER_ACS_MESSAGES_PER_MINUTE",
        "KP_WORKER_ACS_RAMP_BATCH_SIZE",
        "KP_WORKER_ACS_RAMP_INTERVAL_SECONDS",
        "KP_WORKER_REPORTED_MAILBOX_URL",
        "KP_WORKER_REPORTED_MAILBOX_PROVIDER",
        "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
        "KP_WORKER_REPORTED_MAILBOX_ID",
        "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID",
        "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME",
        "KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD",
        "KP_WORKER_AI_BASE_URL",
        "KP_WORKER_AI_BEARER_TOKEN",
        "KP_WORKER_AI_API_KEY",
        "KP_WORKER_GRAPH_BASE_URL",
        "KP_WORKER_GRAPH_CLIENT_ID",
        "KP_WORKER_GRAPH_GROUP_IDS",
        "KP_WORKER_MICROSOFT_TENANT_ID",
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
# Database DSNs embed credentials and are deliberately not exposed or writable
# through the console. ``scripts/bootstrap_env.sh`` generates and synchronizes
# those credentials; the local console launcher invokes that bootstrap step.


class ConfigPatch(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)

    # Keys the console may mutate. Anything not listed is rejected so a
    # compromised console token cannot rewrite arbitrary files.


class ConfigResponse(BaseModel):
    values: dict[str, str]
    masked: dict[str, bool]
    config_store: str = "env_file"
    mutable: bool = True


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
        "description": ("Use a dedicated managed identity to synchronize only selected Microsoft Entra groups."),
        "optional": True,
        "estimated_minutes": 5,
        "prerequisites": (
            "A dedicated directory managed identity",
            "Tenant-admin consent for GroupMember.Read.All and User.ReadBasic.All",
            "One or more selected Entra group object IDs",
            "An expected upper bound for employee records",
        ),
        "configured_any": (("KP_WORKER_GRAPH_BASE_URL",), ("MOCK_GRAPH_URL",)),
        "fields": (
            ("KP_WORKER_GRAPH_BASE_URL", "Graph base URL", "url", True, False, "https://graph.microsoft.com/v1.0"),
            ("KP_WORKER_MICROSOFT_TENANT_ID", "Microsoft tenant ID", "text", True, False, "tenant UUID"),
            ("KP_WORKER_GRAPH_CLIENT_ID", "Directory identity client ID", "text", True, False, "identity UUID"),
            ("KP_WORKER_GRAPH_GROUP_IDS", "Selected group object IDs", "text", True, False, "UUIDs, comma-separated"),
            ("KP_WORKER_GRAPH_MAX_USERS", "Maximum users", "number", False, False, "1000"),
        ),
    },
    {
        "id": "smtp",
        "provider_key": "KP_WORKER_EMAIL_PROVIDER",
        "title": "Email delivery",
        "description": (
            "Choose SMTP or ACS. Managed ACS requires a verified customer domain and current readiness evidence."
        ),
        "optional": False,
        "estimated_minutes": 5,
        "prerequisites": (
            "An approved SMTP relay or service account",
            "The sender mailbox authorized by that relay",
            "The relay's TLS requirement and port",
        ),
        "configured_any": (("KP_WORKER_SMTP_ADDRESS",), ("KP_WORKER_MAILPIT_SMTP",), ("KP_WORKER_ACS_EMAIL_ENDPOINT",)),
        "fields": (
            ("KP_WORKER_EMAIL_PROVIDER", "Email provider", "text", True, False, "Choose a provider"),
            ("KP_WORKER_SMTP_ADDRESS", "SMTP host and port", "text", True, False, "smtp.example.com:587"),
            ("KP_WORKER_SMTP_USERNAME", "SMTP username", "text", False, False, "service account"),
            ("KP_WORKER_SMTP_PASSWORD", "SMTP password", "password", False, True, "leave blank to keep existing"),
            ("KP_WORKER_SMTP_STARTTLS", "Use STARTTLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SSL", "Use implicit TLS", "text", False, False, "true or false"),
            ("KP_WORKER_SMTP_SENDER", "Sender mailbox", "email", False, False, "awareness@example.com"),
            (
                "KP_WORKER_ACS_EMAIL_ENDPOINT",
                "ACS endpoint",
                "url",
                False,
                False,
                "https://name.communication.azure.com",
            ),
            (
                "KP_WORKER_ACS_CLIENT_ID",
                "ACS sending identity client ID",
                "text",
                False,
                False,
                "identity UUID",
            ),
            (
                "KP_WORKER_ACS_EMAIL_CONNECTION_STRING",
                "ACS connection string",
                "password",
                False,
                True,
                "local use only",
            ),
            ("KP_WORKER_ACS_SENDING_DOMAIN", "ACS customer domain", "text", False, False, "mail.example.com"),
            ("KP_WORKER_ACS_SENDER_LOCAL_PART", "ACS sender local part", "text", False, False, "awareness"),
            (
                "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
                "ACS sender display name",
                "text",
                False,
                False,
                "Security Awareness",
            ),
        ),
    },
    {
        "id": "mailbox",
        "provider_key": "KP_WORKER_REPORTED_MAILBOX_PROVIDER",
        "title": "Reported-message mailbox",
        "description": "Poll one Microsoft 365 report mailbox using a separate mailbox-scoped managed identity.",
        "optional": True,
        "estimated_minutes": 4,
        "prerequisites": (
            "A dedicated report mailbox",
            "A dedicated mailbox managed identity",
            "Exchange Online Application RBAC scoped to only that mailbox",
        ),
        "configured_any": (("KP_WORKER_REPORTED_MAILBOX_URL",), ("KP_WORKER_MAILPIT_API_URL",)),
        "fields": (
            ("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "Mailbox provider", "text", True, False, "Choose a provider"),
            (
                "KP_WORKER_REPORTED_MAILBOX_URL",
                "Mailbox API base URL",
                "url",
                True,
                False,
                "https://graph.microsoft.com/v1.0",
            ),
            (
                "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
                "Mailbox identity client ID",
                "text",
                True,
                False,
                "identity UUID",
            ),
            ("KP_WORKER_REPORTED_MAILBOX_ID", "Report mailbox", "email", True, False, "phish-reports@example.com"),
            ("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", "Mailbox folder", "text", False, False, "inbox"),
            (
                "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN",
                "Development bearer token",
                "password",
                False,
                True,
                "optional local test credential",
            ),
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


class AzureDeploymentConfirmationRequest(BaseModel):
    confirm: bool
    review_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    rationale: str = Field(min_length=10, max_length=500)


class AzureDeploymentAdvanceRequest(BaseModel):
    confirm: bool
    review_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


def _azure_release_readiness() -> dict[str, Any]:
    """Return immutable implementation truth, never operator attestation."""
    return {
        "evidence_level": "local_contract_only",
        "production_plan_allowed": False,
        "staging_plan_allowed": True,
        "summary": (
            "Application controls are locally testable, but production edge and recovery readiness has not "
            "been proven in Azure."
        ),
        "gates": [
            {
                "id": "operator_hsts_application",
                "label": "Operator HSTS application contract",
                "status": "implemented_unproven_at_edge",
                "detail": "Every operator response emits HSTS; browser-to-edge delivery has not been observed live.",
            },
            {
                "id": "operator_custom_domain",
                "label": "Operator custom-domain binding",
                "status": "external_unverified",
                "detail": "The selected hostname is configuration only; no live Azure binding is inspected here.",
            },
            {
                "id": "tracking_custom_domain",
                "label": "Tracking custom-domain binding",
                "status": "external_unverified",
                "detail": "The selected hostname is configuration only; no live Azure binding is inspected here.",
            },
            {
                "id": "managed_certificates",
                "label": "Custom-domain certificates",
                "status": "external_unverified",
                "detail": "Certificate issuance, hostname coverage, expiry, and renewal are not inspected here.",
            },
            {
                "id": "default_host_restriction",
                "label": "Default Container Apps host restriction",
                "status": "not_implemented",
                "detail": "Direct default-host access is not restricted by the current infrastructure.",
            },
            {
                "id": "waf_edge",
                "label": "WAF and edge policy",
                "status": "not_implemented",
                "detail": "No Azure edge or WAF policy is implemented by the current deployment.",
            },
            {
                "id": "live_hsts_observation",
                "label": "Live custom-host HSTS observation",
                "status": "external_unverified",
                "detail": "The local header contract is not proof of the response seen through the production edge.",
            },
            {
                "id": "backup_restore",
                "label": "Backup and restore qualification",
                "status": "external_unverified",
                "detail": "No disposable-Azure restore exercise is recorded by this GUI.",
            },
            {
                "id": "rollback",
                "label": "Reviewed rollback workflow",
                "status": "unsupported",
                "detail": "No allowlisted GUI rollback workflow or previously qualified revision target exists.",
            },
        ],
    }


_DEPLOYMENT_RATIONALE_SECRET = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=]\s*\S+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)


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
                "deployment_stage",
                "Deployment stage",
                "select",
                True,
                "foundation_bootstrap",
                "Run the three stages in order. The server advances only after exact protected-workflow evidence.",
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
        "id": "azure_email",
        "title": "ACS customer sending domain",
        "description": (
            "Provision dedicated ACS email resources or reference reviewed existing resources, then verify a "
            "customer-managed domain."
        ),
        "estimated_minutes": 15,
        "prerequisites": (
            "A dedicated customer-managed simulation domain",
            "Access to its public DNS zone or a DNS administrator",
            "Current ACS quota and ramp limits approved for the campaign",
        ),
        "fields": (
            (
                "acs_resource_mode",
                "ACS resource mode",
                "select",
                True,
                "provision",
                "Choose provision unless an approved Communication Service and email domain already exist.",
            ),
            (
                "acs_existing_communication_service_id",
                "Existing Communication Service resource ID",
                "text",
                False,
                "",
                "Azure portal → Communication Service → JSON view → Resource ID. This is not a secret.",
            ),
            (
                "acs_existing_email_endpoint",
                "Existing Communication Service endpoint",
                "text",
                False,
                "",
                "Use the non-secret HTTPS endpoint ending in .communication.azure.com; "
                "never paste a connection string.",
            ),
            (
                "acs_existing_email_domain_id",
                "Existing email-domain resource ID",
                "text",
                False,
                "",
                "Azure portal → Email Communication Service → custom domain → JSON view → Resource ID.",
            ),
            (
                "acs_sending_domain",
                "Customer sending domain",
                "text",
                True,
                "mail.example.com",
                "Use a dedicated public domain controlled by the organization; Azure-managed test domains are blocked.",
            ),
            (
                "acs_sender_local_part",
                "Sender local part",
                "text",
                True,
                "awareness",
                "Choose the mailbox text before @; Terraform provisions it in provision mode.",
            ),
            (
                "acs_sender_display_name",
                "Sender display name",
                "text",
                True,
                "Security Awareness",
                "Use a recognizable 1–64 character name without control characters.",
            ),
            (
                "acs_dns_zone_id",
                "Azure DNS zone resource ID",
                "text",
                False,
                "",
                "Optional: supply only a same-subscription public Azure DNS zone containing the sending domain.",
            ),
            (
                "acs_daily_message_limit",
                "Daily message limit",
                "number",
                True,
                "1000",
                "Use the reviewed limit shown for the ACS resource/support-approved quota.",
            ),
            (
                "acs_messages_per_minute",
                "Messages per minute",
                "number",
                True,
                "20",
                "Choose a value no greater than the reviewed ACS rate limit.",
            ),
            (
                "acs_ramp_batch_size",
                "Initial ramp batch",
                "number",
                True,
                "10",
                "Start below the per-minute limit and increase only after deliverability review.",
            ),
            (
                "acs_ramp_interval_seconds",
                "Ramp interval seconds",
                "number",
                True,
                "60",
                "Use 1–3600 seconds between planned ramp batches.",
            ),
        ),
    },
    {
        "id": "azure_integrations",
        "title": "Azure services and integrations",
        "description": "Choose email data residency, the required private AI gateway, and optional alert endpoints.",
        "estimated_minutes": 5,
        "prerequisites": (
            "Organizational data-residency policy",
            "An approved Azure-hosted AI gateway implementing the platform generation contract",
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
                True,
                "https://ai-gateway.example.com",
                "Azure-hosted gateway → Overview → endpoint. Managed deployments require it to expose "
                "/propose and /setup-assist so the first approved pattern can produce a template.",
            ),
            (
                "enable_directory_sync",
                "Enable selected-group directory sync",
                "select",
                True,
                "false",
                "Enable only after a tenant administrator reviews and grants the directory permission matrix.",
            ),
            (
                "directory_group_ids",
                "Selected Entra group object IDs",
                "text",
                False,
                "UUIDs, comma-separated",
                "Microsoft Entra admin center → Groups → each approved group → Object ID.",
            ),
            (
                "enable_reported_mailbox",
                "Enable Microsoft 365 report mailbox",
                "select",
                True,
                "false",
                "Enable only after Exchange Application RBAC is scoped and tested for the report mailbox.",
            ),
            (
                "reported_mailbox_address",
                "Report mailbox address",
                "email",
                False,
                "phish-reports@example.com",
                "Exchange admin center → Recipients → the dedicated mailbox receiving reported simulations.",
            ),
            (
                "reported_mailbox_folder",
                "Report mailbox folder",
                "text",
                False,
                "inbox",
                "Use inbox or the immutable Microsoft Graph folder ID selected for reported messages.",
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
            (
                "allowed_recipient_domains",
                "Allowed recipient domains",
                "text",
                True,
                "example.com",
                "Enter only organization-owned mail domains authorized by the Rules of Engagement; "
                "separate multiple domains with commas.",
            ),
        ),
    },
    {
        "id": "azure_automation",
        "title": "Deployment automation",
        "description": "Choose the reviewed network path, Terraform-state location, and protected deployment runner.",
        "estimated_minutes": 8,
        "prerequisites": (
            "Azure Storage account with blob versioning and RBAC",
            "A private azure-vnet runner for all three guided deployment stages",
            "GitHub staging and production environments with required production reviewers",
        ),
        "fields": (
            (
                "network_mode",
                "Azure network mode",
                "select",
                True,
                "private",
                "The guided three-stage deployment uses the private azure-vnet runner from bootstrap through "
                "workloads.",
            ),
            (
                "azure_deployment_client_id",
                "Azure deployment identity client ID",
                "text",
                True,
                "00000000-0000-0000-0000-000000000000",
                "Microsoft Entra ID → App registrations → the GitHub OIDC deployment application → "
                "Application (client) ID. This is not the operator-console application ID.",
            ),
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
                False,
                "azure-vnet",
                "GitHub repository → Settings → Actions → Runners → labels. The workflow expects azure-vnet.",
            ),
            (
                "ciphertext_active_key_id",
                "Active ciphertext key ID",
                "text",
                True,
                "primary",
                "Choose the non-secret 1–32 character identifier shared by the operator and every worker. "
                "It is fixed after foundation deployment; active-key rotation is not yet supported.",
            ),
            (
                "ciphertext_prior_key_ids",
                "Prior decrypt-only key IDs",
                "text",
                False,
                "2026q2,2026q1",
                "For legacy recovery, list up to four retired key IDs in the external Key Vault keyring value. "
                "This does not rotate the active key. Do not enter key material here.",
            ),
            (
                "ciphertext_prior_keys_secret_id",
                "Prior-key Key Vault reference",
                "text",
                False,
                "/subscriptions/.../vaults/.../secrets/ciphertext-prior-keys",
                "After foundation, create the legacy decrypt-only keyring directly in this deployment's Key "
                "Vault and paste its versionless Azure resource ID. Never paste its value.",
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
        "deployment_stage": [
            {"value": "foundation_bootstrap", "label": "1. Bootstrap ACS and publish DNS guidance"},
            {"value": "foundation_finalize", "label": "2. Verify DNS and finalize the sender"},
            {"value": "workloads", "label": "3. Deploy workloads after final evidence"},
        ],
        "network_mode": [
            {"value": "private", "label": "Private network (guided deployment)"},
        ],
        "communication_data_location": [
            {"value": value, "label": value}
            for value in ("United States", "Canada", "Europe", "UK", "Australia", "Asia Pacific")
        ],
        "enable_directory_sync": [
            {"value": "false", "label": "Disabled"},
            {"value": "true", "label": "Enabled"},
        ],
        "enable_reported_mailbox": [
            {"value": "false", "label": "Disabled"},
            {"value": "true", "label": "Enabled"},
        ],
        "acs_resource_mode": [
            {"value": "provision", "label": "Provision dedicated resources"},
            {"value": "existing", "label": "Use reviewed existing resources"},
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
                        "server_controlled": key == "deployment_stage",
                        "placeholder": placeholder,
                        "where_to_find": location,
                        # DEP-010: advanced internals collapse behind a disclosure;
                        # suggested_default seeds the common path from strong defaults.
                        "advanced": key in _AZURE_ADVANCED_KEYS,
                        "suggested_default": _AZURE_SUGGESTED_DEFAULTS.get(key),
                        "choices": select_choices.get(key, []),
                    }
                    for key, label, input_type, required, placeholder, location in step["fields"]
                ],
            }
            for step in _AZURE_DEPLOYMENT_STEPS
        ],
        "safety_note": "This wizard never asks for Azure passwords, client secrets, access keys, or Terraform state.",
        "workflow": ".github/workflows/azure-deploy.yml",
        "microsoft_graph": {
            "endpoint": "https://graph.microsoft.com/v1.0",
            "identity_separation": "Directory and report-mailbox roles use different user-assigned identities.",
            "permission_matrix": [
                {
                    "role": "directory",
                    "permissions": ["GroupMember.Read.All", "User.ReadBasic.All"],
                    "scope": "Queries are limited to selected group object IDs.",
                    "admin_required": True,
                },
                {
                    "role": "mailbox",
                    "permissions": ["Application Mail.Read"],
                    "scope": "Exchange Online Application RBAC must target only the report mailbox.",
                    "admin_required": True,
                },
            ],
            "manual_steps_required": True,
            "readiness_claim": "configuration_only",
        },
        "acs_email": {
            "managed_domain_fallback": False,
            "dns_automation": "only_when_same_subscription_azure_dns_zone_id_is_supplied",
            "readiness_claim": "configuration_only",
            "provider_acceptance_is_delivery": False,
            "delivery_events_implemented": True,
        },
        "release_readiness": _azure_release_readiness(),
        "orchestration": DeploymentOrchestrator.public_configuration(),
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
        raise PermissionDeniedError("rejected unrecognized Azure deployment keys")
    values = {key: value.strip() for key, value in body.values.items()}
    errors: dict[str, str] = {}
    for key, value in values.items():
        if _DEPLOYMENT_RATIONALE_SECRET.search(value):
            errors[key] = "Do not enter credentials, access keys, connection strings, or tokens."
    uuid_keys = ("subscription_id", "entra_tenant_id", "entra_client_id", "azure_deployment_client_id")
    uuid_pattern = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    for key in uuid_keys:
        if not uuid_pattern.fullmatch(values.get(key, "")):
            errors[key] = "Enter the complete UUID shown in Azure or Microsoft Entra."
    if values.get("environment") not in {"staging", "production"}:
        errors["environment"] = "Choose staging or production."
    deployment_stage = values.get("deployment_stage", "")
    if deployment_stage not in {"foundation_bootstrap", "foundation_finalize", "workloads"}:
        errors["deployment_stage"] = "Choose one of the three deployment stages."
    network_mode = values.get("network_mode", "")
    if network_mode not in {"private", "starter"}:
        errors["network_mode"] = "Choose private or the staging-foundation starter path."
    elif network_mode == "starter" and (
        values.get("environment") != "staging"
        or deployment_stage not in {"foundation_bootstrap", "foundation_finalize"}
    ):
        errors["network_mode"] = "Starter mode is allowed only for staging foundation stages."
    elif deployment_stage == "workloads" and network_mode != "private":
        errors["network_mode"] = "Workloads require private mode and the azure-vnet runner."
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
    acs_mode = values.get("acs_resource_mode", "")
    if acs_mode not in {"provision", "existing"}:
        errors["acs_resource_mode"] = "Choose provision or existing."
    acs_domain = values.get("acs_sending_domain", "").lower().rstrip(".")
    # Microsoft-owned zones (azurecomm.net, onmicrosoft.com) cannot have their
    # DNS edited by the tenant, so ACS custom-domain verification can never
    # complete against them. Require a customer-managed public DNS domain.
    microsoft_managed_zones = ("azurecomm.net", "onmicrosoft.com")
    if (
        not hostname_pattern.fullmatch(acs_domain)
        or acs_domain in microsoft_managed_zones
        or any(acs_domain.endswith("." + zone) for zone in microsoft_managed_zones)
    ):
        errors["acs_sending_domain"] = (
            "Use a customer-managed public DNS domain whose DNS you can edit, not an "
            "Azure/Microsoft-managed domain (azurecomm.net, onmicrosoft.com)."
        )
    local_part = values.get("acs_sender_local_part", "").lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._+-]{0,63}", local_part):
        errors["acs_sender_local_part"] = "Use 1–64 lowercase mailbox characters before @."
    display_name = values.get("acs_sender_display_name", "")
    if not 1 <= len(display_name) <= 64 or any(ord(character) < 32 for character in display_name):
        errors["acs_sender_display_name"] = "Use 1–64 printable characters."
    if acs_mode == "existing":
        if not re.fullmatch(
            r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Communication/"
            r"CommunicationServices/[^/]+",
            values.get("acs_existing_communication_service_id", ""),
            flags=re.IGNORECASE,
        ):
            errors["acs_existing_communication_service_id"] = (
                "Enter the complete Communication Service Azure resource ID."
            )
        try:
            _validated_acs_endpoint(values.get("acs_existing_email_endpoint", ""))
        except ValueError:
            errors["acs_existing_email_endpoint"] = (
                "Enter the non-secret HTTPS Communication Service endpoint, not a connection string."
            )
        if not re.fullmatch(
            r"/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Communication/"
            r"emailServices/[^/]+/domains/[^/]+",
            values.get("acs_existing_email_domain_id", ""),
            flags=re.IGNORECASE,
        ):
            errors["acs_existing_email_domain_id"] = "Enter the complete customer email-domain Azure resource ID."
    dns_zone_id = values.get("acs_dns_zone_id", "")
    if dns_zone_id:
        match = re.fullmatch(
            r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.Network/dnszones/([^/]+)",
            dns_zone_id,
            flags=re.IGNORECASE,
        )
        if not match or match.group(1).lower() != values.get("subscription_id", "").lower():
            errors["acs_dns_zone_id"] = "Use a complete same-subscription public Azure DNS zone resource ID."
        elif acs_domain != match.group(2).lower() and not acs_domain.endswith(f".{match.group(2).lower()}"):
            errors["acs_dns_zone_id"] = "The Azure DNS zone must contain the customer sending domain."
    pacing: dict[str, int] = {}
    for key, minimum, maximum in (
        ("acs_daily_message_limit", 1, 1_000_000),
        ("acs_messages_per_minute", 1, 10_000),
        ("acs_ramp_batch_size", 1, 2_000),
        ("acs_ramp_interval_seconds", 1, 3_600),
    ):
        try:
            pacing[key] = int(values.get(key, ""))
        except ValueError:
            errors[key] = "Enter a whole number."
            continue
        if not minimum <= pacing[key] <= maximum:
            errors[key] = f"Enter a value from {minimum} to {maximum}."
    if pacing.get("acs_messages_per_minute", 1) > pacing.get("acs_daily_message_limit", 1):
        errors["acs_messages_per_minute"] = "The per-minute limit cannot exceed the daily limit."
    if pacing.get("acs_ramp_batch_size", 1) > pacing.get("acs_messages_per_minute", 1):
        errors["acs_ramp_batch_size"] = "The initial batch cannot exceed the per-minute limit."
    endpoint = values.get("ai_endpoint", "")
    if not endpoint:
        errors["ai_endpoint"] = (
            "Enter the approved HTTPS AI gateway that exposes /propose and /setup-assist; "
            "managed deployments cannot create their first template without it."
        )
    else:
        parsed = urlparse(endpoint)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or _explicit_loopback_host(parsed.hostname)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            errors["ai_endpoint"] = (
                "Use a non-local HTTPS base URL without credentials, query parameters, or fragments."
            )
    for key in ("enable_directory_sync", "enable_reported_mailbox"):
        if values.get(key) not in {"true", "false"}:
            errors[key] = "Choose enabled or disabled."
    group_ids = [item.strip() for item in values.get("directory_group_ids", "").split(",") if item.strip()]
    if values.get("enable_directory_sync") == "true":
        if not group_ids:
            errors["directory_group_ids"] = "Select at least one Entra group object ID."
        elif any(not uuid_pattern.fullmatch(group_id) for group_id in group_ids):
            errors["directory_group_ids"] = "Enter comma-separated Entra group object UUIDs."
    mailbox = values.get("reported_mailbox_address", "")
    if values.get("enable_reported_mailbox") == "true" and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", mailbox):
        errors["reported_mailbox_address"] = "Enter the dedicated Microsoft 365 report mailbox address."
    if values.get("enable_reported_mailbox") == "true" and not values.get("reported_mailbox_folder", ""):
        errors["reported_mailbox_folder"] = "Enter inbox or a Microsoft Graph mail folder ID."
    domains = [item.strip().lower() for item in values.get("alert_webhook_domains", "").split(",") if item.strip()]
    if any(not hostname_pattern.fullmatch(domain) for domain in domains):
        errors["alert_webhook_domains"] = "Enter hostnames only, separated by commas."
    recipient_domains = [
        item.strip().lower() for item in values.get("allowed_recipient_domains", "").split(",") if item.strip()
    ]
    if not recipient_domains or any(not hostname_pattern.fullmatch(domain) for domain in recipient_domains):
        errors["allowed_recipient_domains"] = "Enter at least one authorized mail domain, separated by commas."
    if not re.fullmatch(r"[A-Za-z0-9_.()\-]{1,90}", values.get("tf_state_resource_group", "")):
        errors["tf_state_resource_group"] = "Enter the 1–90 character Azure resource-group name."
    if not re.fullmatch(r"[a-z0-9]{3,24}", values.get("tf_state_storage_account", "")):
        errors["tf_state_storage_account"] = "Use the 3–24 character lowercase Azure Storage account name."
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", values.get("tf_state_container", "")):
        errors["tf_state_container"] = "Enter the lowercase blob container name."
    ciphertext_key_id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
    active_ciphertext_key_id = values.get("ciphertext_active_key_id", "")
    if ciphertext_key_id_pattern.fullmatch(active_ciphertext_key_id) is None:
        errors["ciphertext_active_key_id"] = "Use 1–32 ASCII letters, digits, underscores, or hyphens."
    prior_ciphertext_key_ids = (
        [item.strip() for item in values.get("ciphertext_prior_key_ids", "").split(",")]
        if values.get("ciphertext_prior_key_ids", "").strip()
        else []
    )
    if (
        len(prior_ciphertext_key_ids) > 4
        or len(set(prior_ciphertext_key_ids)) != len(prior_ciphertext_key_ids)
        or any(ciphertext_key_id_pattern.fullmatch(key_id) is None for key_id in prior_ciphertext_key_ids)
        or active_ciphertext_key_id in prior_ciphertext_key_ids
    ):
        errors["ciphertext_prior_key_ids"] = "List at most four unique valid key IDs, excluding the active key ID."
    prior_ciphertext_secret_id = values.get("ciphertext_prior_keys_secret_id", "")
    secret_id_match = re.fullmatch(
        r"/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.KeyVault/"
        r"vaults/([A-Za-z0-9-]{3,24})/secrets/([A-Za-z0-9-]{1,127})",
        prior_ciphertext_secret_id,
        flags=re.IGNORECASE,
    )
    if bool(prior_ciphertext_key_ids) != bool(prior_ciphertext_secret_id):
        rotation_reference_error = "Prior key IDs and their versionless Key Vault reference must be supplied together."
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
    elif prior_ciphertext_secret_id and (
        secret_id_match is None or secret_id_match.group(1).lower() != values.get("subscription_id", "").lower()
    ):
        rotation_reference_error = (
            "Use a versionless secret resource ID from the selected subscription; never paste a secret value."
        )
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
    if deployment_stage != "workloads" and (prior_ciphertext_key_ids or prior_ciphertext_secret_id):
        rotation_reference_error = (
            "Prior-key recovery is allowed only in the workloads phase after the deployment Key Vault exists."
        )
        errors["ciphertext_prior_keys_secret_id"] = rotation_reference_error
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
    if network_mode == "private" and values.get("runner_label") != "azure-vnet":
        errors["runner_label"] = "Private mode requires the exact protected runner label azure-vnet."
    elif network_mode == "starter":
        warnings.append("Starter mode uses a hosted runner and must transition to private before workloads.")
    enabled_roles = [
        role
        for role, enabled in (
            ("directory", values.get("enable_directory_sync") == "true"),
            ("mailbox", values.get("enable_reported_mailbox") == "true"),
        )
        if enabled
    ]
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "provider_readiness": {
            "enabled_roles": enabled_roles,
            "configuration_valid": not any(
                key in errors
                for key in (
                    "enable_directory_sync",
                    "directory_group_ids",
                    "enable_reported_mailbox",
                    "reported_mailbox_address",
                    "reported_mailbox_folder",
                )
            ),
            "admin_consent_verified": False,
            "live_connectivity_verified": False,
        },
        "acs_email_readiness": {
            "configuration_valid": not any(
                key in errors for key in ({field[0] for field in _AZURE_DEPLOYMENT_STEPS[2]["fields"]})
            ),
            "resource_mode": acs_mode,
            "deployment_stage": deployment_stage,
            "sender_address": f"{local_part}@{acs_domain}" if local_part and acs_domain else "",
            "dns_status": "azure_dns_automation_planned"
            if dns_zone_id and "acs_dns_zone_id" not in errors
            else "manual_dns_required",
            "evidence_source": "protected_workflow_artifact_only",
            "advance_blocked_until_verified_artifact": deployment_stage != "workloads",
            "live_verification_performed": False,
            "provider_acceptance_is_confirmed_delivery": False,
            "delivery_events_implemented": True,
            "pacing": pacing,
        },
        "release_readiness": _azure_release_readiness(),
    }


def _deployment_orchestrator(request: Request) -> DeploymentOrchestrator:
    existing = getattr(request.app.state, "deployment_orchestrator", None)
    if existing is not None:
        return cast(DeploymentOrchestrator, existing)
    try:
        orchestrator = DeploymentOrchestrator.from_environment(request.app.state.settings.redis_url)
    except DeploymentUnavailable as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.deployment_orchestrator = orchestrator
    return orchestrator


@router.post("/azure-deployment/orchestration/plan", response_model=dict[str, Any])
def plan_azure_deployment(
    body: AzureDeploymentValidationRequest,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    validation = validate_azure_deployment(body, principal)
    if not validation["ok"]:
        return validation
    values = {key: value.strip() for key, value in body.values.items()}
    if values.get("environment") == "production":
        raise ConflictError(
            "production deployment planning is blocked until custom-domain, certificate, edge restriction, "
            "live HSTS, backup/restore, and rollback gates are verifiable; use staging for bootstrap"
        )
    if values.get("deployment_stage") != "foundation_bootstrap":
        raise ConflictError(
            "a new GUI deployment must begin with foundation bootstrap; use the verified stage advance action"
        )
    if values.get("network_mode") != "private":
        raise ConflictError(
            "the GUI stage sequence requires the private azure-vnet runner from bootstrap through workloads"
        )
    try:
        plan = _deployment_orchestrator(request).create_plan(values, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="deployment.plan.review",
        object_type="azure_deployment",
        object_id=str(plan["plan_id"]),
        detail={
            "review_digest": plan["review_digest"],
            "environment": plan["review"]["environment"],
            "deployment_stage": plan["review"]["deployment_stage"],
            "workflow": plan["workflow"],
            "commit_sha": plan["source_revision"]["commit_sha"],
            "workflow_content_sha256": plan["source_revision"]["workflow_content_sha256"],
        },
    )
    return plan


@router.get("/azure-deployment/orchestration/latest", response_model=dict[str, Any])
def get_latest_azure_deployment_plan(
    request: Request,
    environment: str = "staging",
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    try:
        plan = _deployment_orchestrator(request).get_latest_plan(environment, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    return {"environment": environment, "plan": plan}


@router.get("/azure-deployment/orchestration/plans/{plan_id}", response_model=dict[str, Any])
def get_azure_deployment_plan(
    plan_id: str,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    try:
        return _deployment_orchestrator(request).get_plan(plan_id, actor=principal.principal_id)
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None


def _submit_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    principal: Principal,
    *,
    retry: bool,
) -> dict[str, Any]:
    if not body.confirm:
        raise PermissionDeniedError("deployment dispatch requires explicit reviewed confirmation")
    if _DEPLOYMENT_RATIONALE_SECRET.search(body.rationale):
        raise PermissionDeniedError("authorization reasons must not contain credentials or tokens")

    def audit(detail: dict[str, Any]) -> None:
        request.app.state.audit_store.record(
            actor=principal.principal_id,
            action="deployment.retry.request" if retry else "deployment.apply.request",
            object_type="azure_deployment",
            object_id=plan_id,
            detail=detail,
        )

    try:
        return _deployment_orchestrator(request).apply(
            plan_id,
            body.review_digest,
            actor=principal.principal_id,
            rationale=body.rationale.strip(),
            retry=retry,
            audit=audit,
        )
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None


@router.post("/azure-deployment/orchestration/plans/{plan_id}/apply", response_model=dict[str, Any])
def apply_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _submit_azure_deployment_plan(plan_id, body, request, principal, retry=False)


@router.post("/azure-deployment/orchestration/plans/{plan_id}/retry", response_model=dict[str, Any])
def retry_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentConfirmationRequest,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    return _submit_azure_deployment_plan(plan_id, body, request, principal, retry=True)


@router.post("/azure-deployment/orchestration/plans/{plan_id}/advance", response_model=dict[str, Any])
def advance_azure_deployment_plan(
    plan_id: str,
    body: AzureDeploymentAdvanceRequest,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    if not body.confirm:
        raise PermissionDeniedError("deployment stage advance requires explicit reviewed confirmation")
    try:
        plan = _deployment_orchestrator(request).advance_plan(
            plan_id,
            body.review_digest,
            actor=principal.principal_id,
        )
    except (DeploymentUnavailable, DeploymentConflict) as exc:
        raise ConflictError(public_deployment_error(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="deployment.stage.advance",
        object_type="azure_deployment",
        object_id=str(plan["plan_id"]),
        detail={
            "review_digest": plan["review_digest"],
            "deployment_stage": plan["review"]["deployment_stage"],
            "predecessor": plan["stage_predecessor"],
        },
    )
    return plan


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
    "KP_WORKER_EMAIL_PROVIDER": (
        {"value": "smtp", "label": "SMTP relay"},
        {"value": "azure_communication_services", "label": "Azure Communication Services Email"},
    ),
    "KP_WORKER_REPORTED_MAILBOX_PROVIDER": (
        {"value": "mailpit", "label": "Local Mailpit (development)"},
        {"value": "microsoft365", "label": "Microsoft 365 reported mailbox"},
    ),
}

_FIELD_PROVIDER_RULES: dict[str, dict[str, tuple[str, ...]]] = {
    "KP_WORKER_SMTP_ADDRESS": {"providers": ("smtp",), "required_for": ("smtp",)},
    "KP_WORKER_SMTP_USERNAME": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_PASSWORD": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_STARTTLS": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_SSL": {"providers": ("smtp",)},
    "KP_WORKER_SMTP_SENDER": {
        "providers": ("smtp", "azure_communication_services"),
        "required_for": ("smtp", "azure_communication_services"),
    },
    "KP_WORKER_ACS_EMAIL_ENDPOINT": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_CLIENT_ID": {"providers": ("azure_communication_services",)},
    "KP_WORKER_ACS_EMAIL_CONNECTION_STRING": {"providers": ("azure_communication_services",)},
    "KP_WORKER_ACS_SENDING_DOMAIN": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_SENDER_LOCAL_PART": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_ACS_SENDER_DISPLAY_NAME": {
        "providers": ("azure_communication_services",),
        "required_for": ("azure_communication_services",),
    },
    "KP_WORKER_REPORTED_MAILBOX_URL": {
        "providers": ("mailpit", "microsoft365"),
        "required_for": ("mailpit", "microsoft365"),
    },
    "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID": {
        "providers": ("microsoft365",),
        "required_for": ("microsoft365",),
    },
    "KP_WORKER_REPORTED_MAILBOX_BEARER_TOKEN": {"providers": ("microsoft365",)},
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


def _has_values(values: dict[str, str], *keys: str) -> bool:
    return all(bool(values.get(key, "").strip()) for key in keys)


def _onboarding_step_configured(definition: dict[str, Any], values: dict[str, str]) -> bool:
    step_id = definition["id"]
    if step_id == "smtp":
        provider = values.get("KP_WORKER_EMAIL_PROVIDER", "").strip()
        if provider == "smtp":
            return bool(
                (values.get("KP_WORKER_SMTP_ADDRESS") or values.get("KP_WORKER_MAILPIT_SMTP", "")).strip()
                and values.get("KP_WORKER_SMTP_SENDER", "").strip()
            )
        if provider == "azure_communication_services":
            return _has_values(
                values,
                "KP_WORKER_ACS_EMAIL_ENDPOINT",
                "KP_WORKER_ACS_SENDING_DOMAIN",
                "KP_WORKER_ACS_SENDER_LOCAL_PART",
                "KP_WORKER_ACS_SENDER_DISPLAY_NAME",
                "KP_WORKER_SMTP_SENDER",
            ) and bool(
                values.get("KP_WORKER_ACS_CLIENT_ID", "").strip()
                or values.get("KP_WORKER_ACS_EMAIL_CONNECTION_STRING", "").strip()
            )
        return False
    if step_id == "mailbox":
        provider = values.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "").strip()
        base = (values.get("KP_WORKER_REPORTED_MAILBOX_URL") or values.get("KP_WORKER_MAILPIT_API_URL", "")).strip()
        if provider == "mailpit":
            return bool(base)
        if provider == "microsoft365":
            return bool(base) and _has_values(
                values,
                "KP_WORKER_REPORTED_MAILBOX_CLIENT_ID",
                "KP_WORKER_REPORTED_MAILBOX_ID",
                "KP_WORKER_REPORTED_MAILBOX_FOLDER_ID",
            )
        return False
    return any(
        all(bool(values.get(key, "").strip()) for key in key_group) for key_group in definition["configured_any"]
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
        configured = _onboarding_step_configured(definition, values)
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
                "providers": list(_FIELD_PROVIDER_RULES.get(key, {}).get("providers", ())),
                "required_for": list(_FIELD_PROVIDER_RULES.get(key, {}).get("required_for", ())),
                "value": "" if secret else effective_values.get(key, ""),
            }
            for key, label, input_type, required, secret, placeholder in definition["fields"]
        ]
        steps.append(
            {
                "id": definition["id"],
                "component": definition["id"],
                "provider_key": definition.get("provider_key"),
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
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    """Return curated setup help without exposing environment configuration."""
    return {
        "glossary": list(_GLOSSARY),
        "topics": list(_TOPICS),
        "safety_note": "Never paste passwords, tokens, API keys, or client secrets into the setup assistant.",
    }


_AZURE_ASSIST_PROTECTED_KEYS = frozenset(
    {
        "environment",
        "deployment_stage",
        "network_mode",
        "subscription_id",
        "entra_tenant_id",
        "entra_client_id",
        "azure_deployment_client_id",
        "tf_state_resource_group",
        "tf_state_storage_account",
        "tf_state_container",
        "runner_label",
        "acs_resource_mode",
        "acs_existing_communication_service_id",
        "acs_existing_email_endpoint",
        "acs_existing_email_domain_id",
        "acs_dns_zone_id",
    }
)

# DEP-010: fields a normal operator does not see on the first pass. These are
# Azure resource IDs, GitHub/Terraform internals, key-vault references, exact
# quota numbers, or identity hooks that the wizard only needs when the default
# path is not used. The GUI collapses them under an explicit Advanced disclosure
# so the common path shows strong defaults rather than infrastructure noise.
_AZURE_ADVANCED_KEYS = frozenset(
    {
        # Existing-resource references (only needed when not provisioning).
        "acs_resource_mode",
        "acs_existing_communication_service_id",
        "acs_existing_email_endpoint",
        "acs_existing_email_domain_id",
        "acs_dns_zone_id",
        # Exact quota/ramp tuning; the reviewed defaults already apply.
        "acs_daily_message_limit",
        "acs_messages_per_minute",
        "acs_ramp_batch_size",
        "acs_ramp_interval_seconds",
        # GitHub Actions / Terraform / repository internals.
        "runner_label",
        "tf_state_resource_group",
        "tf_state_storage_account",
        "tf_state_container",
        "network_mode",
        "azure_deployment_client_id",
        # Key-vault and prior-key references (rotation/recovery only).
        "ciphertext_active_key_id",
        "ciphertext_prior_key_ids",
        "ciphertext_prior_keys_secret_id",
        # Optional identity selectors disclosed only when their feature is on.
        "directory_group_ids",
        "reported_mailbox_address",
        "reported_mailbox_folder",
        "alert_webhook_domains",
    }
)

# DEP-010 strong defaults: values a first-time operator rarely needs to change.
# They seed the form so "normal inputs" shrink to the genuinely organization-
# specific choices. Keys here are the field keys from _AZURE_DEPLOYMENT_STEPS.
_AZURE_SUGGESTED_DEFAULTS: dict[str, str] = {
    "deployment_stage": "foundation_bootstrap",
    "network_mode": "private",
    "acs_resource_mode": "provision",
    "acs_sending_domain": "mail.example.com",
    "acs_sender_local_part": "awareness",
    "acs_sender_display_name": "Security Awareness",
    "acs_daily_message_limit": "1000",
    "acs_messages_per_minute": "20",
    "acs_ramp_batch_size": "10",
    "acs_ramp_interval_seconds": "60",
    "communication_data_location": "United States",
    "enable_directory_sync": "false",
    "enable_reported_mailbox": "false",
    "reported_mailbox_folder": "inbox",
    "name_prefix": "kp",
    "location": "eastus2",
    "environment": "staging",
}
_AZURE_EMAIL_PROTECTED_AI_OUTPUT = re.compile(
    r"(?:foundation_bootstrap|foundation_finalize|\bworkloads\b|\bverified\b|verification[_ ]status|"
    r"readiness[_ ]checked|subscription[_ ]id|tenant[_ ]id|resource[_ ]id|dns[_ ]zone[_ ]id|\bauthority\b)",
    re.IGNORECASE,
)


def _component_nonsecret_keys(component: str) -> frozenset[str]:
    for definition in _ONBOARDING_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"] if not field[4])
    for definition in _AZURE_DEPLOYMENT_STEPS:
        if definition["id"] == component:
            return frozenset(field[0] for field in definition["fields"]) - _AZURE_ASSIST_PROTECTED_KEYS
    return frozenset()


_CREDENTIAL_KEY = re.compile(r"(?:password|secret|token|api[_-]?key|credential|authorization)", re.IGNORECASE)
_CREDENTIAL_VALUE = re.compile(
    r"(?:bearer\s+[A-Za-z0-9._~+/=-]{8,}|(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S+|"
    r"sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
    re.IGNORECASE,
)
_MAX_SETUP_ASSIST_RESPONSE_BYTES = 32 * 1024
_MAX_SETUP_ASSIST_SUGGESTIONS = 32
_MAX_SETUP_ASSIST_WARNINGS = 5
_MAX_SETUP_ASSIST_WARNING_LENGTH = 500


def _assist_secret_values(values: dict[str, str], environment: dict[str, str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value
                for key, value in {**environment, **values}.items()
                if value and (_CREDENTIAL_KEY.search(key) or key in _SECRET_KEYS) and len(value) >= 4
            },
            key=len,
            reverse=True,
        )
    )


def _redact_assist_text(value: str, secret_values: tuple[str, ...]) -> str:
    result = _CREDENTIAL_VALUE.sub("[credential removed]", value)
    for secret in secret_values:
        result = result.replace(secret, "[credential removed]")
    return result


def _safe_assist_question(question: str, values: dict[str, str], environment: dict[str, str]) -> str:
    return _redact_assist_text(question.strip(), _assist_secret_values(values, environment))


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
        "azure_email": (
            "Use a dedicated customer-managed simulation domain and a recognizable sender. Start with conservative "
            "daily, per-minute, and batch limits. The protected workflow—not AI or an operator checkbox—reads live "
            "Domain, SPF, DKIM, DKIM2, association, and sender state from Azure before advancing."
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


async def _bounded_setup_assist_json(response: httpx.Response) -> Any:
    content_lengths = response.headers.get_list("content-length")
    if len(content_lengths) > 1:
        raise ValueError("invalid setup assistant response length")
    if content_lengths:
        declared = content_lengths[0]
        if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None:
            raise ValueError("invalid setup assistant response length")
        if int(declared) > _MAX_SETUP_ASSIST_RESPONSE_BYTES:
            raise ValueError("setup assistant response is too large")

    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > _MAX_SETUP_ASSIST_RESPONSE_BYTES:
            raise ValueError("setup assistant response is too large")
        body.extend(chunk)
    try:
        text = bytes(body).decode("utf-8")
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid setup assistant JSON") from None


def _validated_ai_assistance(
    payload: Any,
    allowed_keys: frozenset[str],
    *,
    secret_values: tuple[str, ...] = (),
) -> tuple[str, dict[str, str], list[str]]:
    if (
        not isinstance(payload, dict)
        or set(payload) - {"answer", "suggestions", "warnings"}
        or not isinstance(payload.get("answer"), str)
    ):
        raise ValueError("invalid setup assistant response")
    raw_answer = payload["answer"].strip()
    if not raw_answer or len(raw_answer) > 4000:
        raise ValueError("invalid setup assistant answer")
    answer = _redact_assist_text(raw_answer, secret_values)
    raw_suggestions = payload.get("suggestions", {})
    if not isinstance(raw_suggestions, dict) or len(raw_suggestions) > _MAX_SETUP_ASSIST_SUGGESTIONS:
        raise ValueError("invalid setup assistant suggestions")
    suggestions: dict[str, str] = {}
    warnings: list[str] = []
    for key, value in raw_suggestions.items():
        if key not in allowed_keys or _CREDENTIAL_KEY.search(str(key)):
            warning = "The AI returned a suggestion outside this setup step; it was ignored."
            if warning not in warnings:
                warnings.append(warning)
            continue
        if not isinstance(value, str) or len(value) > 2048 or _redact_assist_text(value, secret_values) != value:
            if len(warnings) < _MAX_SETUP_ASSIST_WARNINGS:
                warnings.append(f"An unsafe suggestion for {key} was ignored.")
            continue
        suggestions[key] = value
    raw_warnings = payload.get("warnings", [])
    if (
        not isinstance(raw_warnings, list)
        or len(raw_warnings) > _MAX_SETUP_ASSIST_WARNINGS
        or any(not isinstance(item, str) or len(item) > _MAX_SETUP_ASSIST_WARNING_LENGTH for item in raw_warnings)
    ):
        raise ValueError("invalid setup assistant warnings")
    for item in raw_warnings:
        redacted = _redact_assist_text(item, secret_values)
        if redacted not in warnings and len(warnings) < _MAX_SETUP_ASSIST_WARNINGS:
            warnings.append(redacted)
    return answer, suggestions, warnings[:_MAX_SETUP_ASSIST_WARNINGS]


@router.post("/onboarding/assist", response_model=SetupAssistResponse)
async def assist_onboarding(
    body: SetupAssistRequest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> SetupAssistResponse:
    """Provide advisory setup guidance without persisting or auditing prompt content."""
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
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
    destination_key, base_url = _selected_destination(environment, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
    warnings = ["AI suggestions are advisory. Review them and run the connection test before saving."]
    if base_url:
        try:
            endpoint = await asyncio.to_thread(
                _resolve_setup_assist_endpoint,
                base_url,
                settings=request.app.state.settings,
                destination_key=destination_key,
            )
            headers = {**_auth_headers(environment, "KP_WORKER_AI"), "Host": endpoint.host_header}
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
                    headers=headers,
                    json={"component": component, "question": safe_question, "values": safe_values},
                    extensions=endpoint.extensions,
                ) as response,
            ):
                if response.is_redirect:
                    raise ValueError("setup assistant redirected")
                response.raise_for_status()
                payload = await _bounded_setup_assist_json(response)
            answer, suggestions, provider_warnings = _validated_ai_assistance(
                payload,
                allowed_keys,
                secret_values=_assist_secret_values(body.values, environment),
            )
            if component == "azure_email" and any(
                _AZURE_EMAIL_PROTECTED_AI_OUTPUT.search(value)
                for value in (answer, *provider_warnings, *suggestions.values())
            ):
                raise ValueError("AI attempted to influence protected Azure deployment state")
            return SetupAssistResponse(
                answer=answer,
                suggestions=suggestions,
                source="configured-ai",
                warnings=warnings + provider_warnings,
            )
        except (httpx.HTTPError, OSError, ValueError):
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

    def validate(proposed: dict[str, str]) -> None:
        _validate_config_candidate(proposed, require_complete=body.completed is True)

    try:
        changed = _atomic_update_env(_env_path(request), desired, validate_candidate=validate)
    except _AtomicEnvUpdateError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from None
    request.app.state.audit_store.record(
        actor=principal.principal_id,
        action="console.onboarding.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return changed


def _validate_config_candidate(proposed: dict[str, str], *, require_complete: bool = False) -> None:
    """Validate cross-field invariants against the complete post-update view."""
    if proposed.get("OPERATOR_API_OIDC_MODE", "dev") not in {"dev", "oidc"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="authentication mode must be dev or oidc",
        )
    redirect_uri = proposed.get("OPERATOR_API_OIDC_REDIRECT_URI", "")
    if redirect_uri:
        try:
            _validated_oidc_redirect_uri(redirect_uri)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "OIDC redirect URI must use HTTPS and the exact console callback path; only the documented "
                    "http://localhost:8000 development callback is permitted"
                ),
            ) from None
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
    email_provider = proposed.get("KP_WORKER_EMAIL_PROVIDER", "").strip()
    if email_provider and email_provider not in {"smtp", "azure_communication_services"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="email provider must be smtp or azure_communication_services",
        )
    if email_provider == "smtp":
        smtp_address = (proposed.get("KP_WORKER_SMTP_ADDRESS") or proposed.get("KP_WORKER_MAILPIT_SMTP", "")).strip()
        try:
            _parse_smtp_address(smtp_address)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP provider requires a valid relay host and port",
            ) from None
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", proposed.get("KP_WORKER_SMTP_SENDER", "").strip()):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP provider requires a valid sender mailbox",
            )
        if bool(proposed.get("KP_WORKER_SMTP_USERNAME", "").strip()) != bool(
            proposed.get("KP_WORKER_SMTP_PASSWORD", "").strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="SMTP username and password must be configured together",
            )
    elif email_provider == "azure_communication_services":
        endpoint = proposed.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")
        try:
            _validated_acs_endpoint(endpoint)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires an exact HTTPS *.communication.azure.com endpoint on port 443",
            ) from None
        if not (
            proposed.get("KP_WORKER_ACS_CLIENT_ID", "").strip()
            or proposed.get("KP_WORKER_ACS_EMAIL_CONNECTION_STRING", "").strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires a managed identity client ID or local connection string",
            )
        domain = proposed.get("KP_WORKER_ACS_SENDING_DOMAIN", "").strip().lower().rstrip(".")
        local_part = proposed.get("KP_WORKER_ACS_SENDER_LOCAL_PART", "").strip().lower()
        sender = proposed.get("KP_WORKER_SMTP_SENDER", "").strip().lower()
        display_name = proposed.get("KP_WORKER_ACS_SENDER_DISPLAY_NAME", "").strip()
        if (
            re.fullmatch(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain) is None
            or domain == "azurecomm.net"
            or domain.endswith(".azurecomm.net")
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider requires a customer-managed public sending domain",
            )
        if re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local_part) is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS provider sender local part is malformed",
            )
        if sender != f"{local_part}@{domain}":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS sender mailbox must match its local part and sending domain",
            )
        if not display_name or len(display_name) > 64 or any(ord(character) < 32 for character in display_name):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="ACS sender display name must be 1-64 printable characters",
            )
    mailbox_provider = proposed.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "").strip()
    if mailbox_provider and mailbox_provider not in {"mailpit", "microsoft365"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="reported mailbox provider must be mailpit or microsoft365",
        )
    if mailbox_provider:
        mailbox_base = (
            proposed.get("KP_WORKER_REPORTED_MAILBOX_URL") or proposed.get("KP_WORKER_MAILPIT_API_URL", "")
        ).strip()
        try:
            _safe_url(mailbox_base, https_only=mailbox_provider == "microsoft365")
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="reported mailbox provider requires a valid base URL",
            ) from None
        if mailbox_provider == "microsoft365":
            try:
                _microsoft365_probe_url(
                    mailbox_base,
                    proposed.get("KP_WORKER_REPORTED_MAILBOX_ID", ""),
                    proposed.get("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", ""),
                )
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Microsoft 365 provider requires a valid mailbox and folder",
                ) from None
            client_id = proposed.get("KP_WORKER_REPORTED_MAILBOX_CLIENT_ID", "").strip()
            if (
                re.fullmatch(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                    client_id,
                )
                is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="Microsoft 365 provider requires the mailbox managed identity client ID",
                )
    if require_complete:
        missing = [
            definition["title"]
            for definition in _ONBOARDING_STEPS
            if not definition["optional"] and not _onboarding_step_configured(definition, proposed)
        ]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=f"required setup steps are incomplete: {', '.join(missing)}",
            )


@router.put("/onboarding", response_model=dict[str, Any])
def put_onboarding(
    body: OnboardingPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    changed = _persist_onboarding(body, request, principal)
    return {"ok": True, "changed": changed, **_onboarding_state(_env_path(request))}


@router.post("/onboarding/test", response_model=dict[str, Any])
def test_onboarding_connection(
    body: ConnectionTest,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    if request.app.state.settings.config_is_managed:
        raise ConflictError(
            "connection tests based on a local env file are disabled for managed deployments. "
            "Use the Azure deployment workflow's validation results; this endpoint cannot safely read "
            "Key Vault-backed values."
        )
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")
    saved = _env_values(_env_path(request))
    values = {**saved, **body.values}
    settings = request.app.state.settings
    component = body.component.lower()
    scope = "connection"
    if component in {"identity", "oidc"}:
        scope = "oidc_discovery"
        destination_key = "OPERATOR_API_OIDC_ISSUER"
        base = values.get(destination_key, "")
        endpoint = base.rstrip("/") + "/.well-known/openid-configuration"
        ok, kind = _probe_http(
            endpoint,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "graph":
        scope = "directory_read"
        destination_key, base = _selected_destination(values, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")
        _saved_key, saved_base = _selected_destination(saved, "KP_WORKER_GRAPH_BASE_URL", "MOCK_GRAPH_URL")
        credentials = _credentials_for_destination(body.values, values, destination_changed=base != saved_base)
        ok, kind = _probe_http(
            base.rstrip("/") + "/users",
            headers=_auth_headers(credentials, "KP_WORKER_GRAPH"),
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "ai":
        scope = "ai_endpoint_reachability"
        destination_key, base = _selected_destination(values, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
        _saved_key, saved_base = _selected_destination(saved, "KP_WORKER_AI_BASE_URL", "MOCK_AI_URL")
        credentials = _credentials_for_destination(body.values, values, destination_changed=base != saved_base)
        ok, kind = _probe_http(
            base.rstrip("/") + "/propose",
            headers=_auth_headers(credentials, "KP_WORKER_AI"),
            reachable_only=True,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "mailbox":
        provider = values.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
        if provider not in {"mailpit", "microsoft365"}:
            return _connection_test_result(
                component,
                ok=False,
                error_kind="config",
                verification_scope="reported_mailbox",
                message="Choose Mailpit or Microsoft 365 before testing the reported mailbox.",
            )
        destination_key, base = _selected_destination(
            values, "KP_WORKER_REPORTED_MAILBOX_URL", "KP_WORKER_MAILPIT_API_URL"
        )
        _saved_key, saved_base = _selected_destination(
            saved, "KP_WORKER_REPORTED_MAILBOX_URL", "KP_WORKER_MAILPIT_API_URL"
        )
        saved_provider = saved.get("KP_WORKER_REPORTED_MAILBOX_PROVIDER", "mailpit").strip() or "mailpit"
        credentials = _credentials_for_destination(
            body.values,
            values,
            destination_changed=base != saved_base or provider != saved_provider,
        )
        if provider == "mailpit":
            scope = "mailpit_mailbox_read"
            headers = _auth_headers(credentials, "KP_WORKER_REPORTED_MAILBOX")
            basic_username = credentials.get("KP_WORKER_REPORTED_MAILBOX_BASIC_USERNAME", "")
            basic_password = credentials.get("KP_WORKER_REPORTED_MAILBOX_BASIC_PASSWORD", "")
            if basic_username and basic_password:
                token = base64.b64encode(f"{basic_username}:{basic_password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            ok, kind = _probe_http(
                base.rstrip("/") + "/api/v1/messages",
                headers=headers,
                allow_loopback=_allow_development_loopback(settings, destination_key, base),
            )
        else:
            try:
                endpoint = _microsoft365_probe_url(
                    base,
                    values.get("KP_WORKER_REPORTED_MAILBOX_ID", ""),
                    values.get("KP_WORKER_REPORTED_MAILBOX_FOLDER_ID", ""),
                )
            except ValueError:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind="config",
                    verification_scope="microsoft365_mailbox_read",
                )
            headers = _auth_headers(credentials, "KP_WORKER_REPORTED_MAILBOX")
            if headers.get("Authorization"):
                scope = "microsoft365_mailbox_read"
                ok, kind = _probe_http(endpoint, headers=headers, require_2xx=True)
            else:
                scope = "microsoft365_endpoint_reachability"
                ok, kind = _probe_http(
                    endpoint,
                    reachable_only=True,
                    accept_auth_challenge=True,
                )
                if ok:
                    return _connection_test_result(
                        component,
                        ok=False,
                        error_kind=None,
                        verification_scope=scope,
                        reachable_unverified=True,
                        message=(
                            "Microsoft Graph is reachable. The dedicated managed identity, Exchange Application "
                            "RBAC, and mailbox read remain unverified; run the bounded reported-mailbox poll after "
                            "deployment."
                        ),
                    )
    elif component == "training":
        scope = "training_page"
        destination_key = "OPERATOR_API_TRAINING_BASE_URL"
        base = values.get(destination_key, "")
        ok, kind = _probe_http(
            base,
            allow_loopback=_allow_development_loopback(settings, destination_key, base),
        )
    elif component == "smtp":
        provider = values.get("KP_WORKER_EMAIL_PROVIDER", "smtp").strip() or "smtp"
        if provider == "azure_communication_services":
            scope = "acs_endpoint_reachability"
            endpoint = values.get("KP_WORKER_ACS_EMAIL_ENDPOINT", "")
            try:
                endpoint = _validated_acs_endpoint(endpoint)
            except ValueError:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind="config",
                    verification_scope=scope,
                )
            ok, kind = _probe_http(
                endpoint,
                reachable_only=True,
                accept_auth_challenge=True,
            )
            if ok:
                return _connection_test_result(
                    component,
                    ok=False,
                    error_kind=None,
                    verification_scope=scope,
                    reachable_unverified=True,
                    message=(
                        "The ACS endpoint is reachable. No message or credential was sent; managed-identity access, "
                        "custom-domain readiness, delivery, and inbox placement remain unverified."
                    ),
                )
        elif provider == "smtp":
            scope = "smtp_session"
            destination_key, address = _selected_destination(values, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP")
            _saved_key, saved_address = _selected_destination(saved, "KP_WORKER_SMTP_ADDRESS", "KP_WORKER_MAILPIT_SMTP")
            credentials = _credentials_for_destination(
                body.values, values, destination_changed=address != saved_address
            )
            ok, kind = _probe_smtp(
                address,
                values.get("KP_WORKER_SMTP_STARTTLS", "false").lower() == "true",
                use_ssl=values.get("KP_WORKER_SMTP_SSL", "false").lower() == "true",
                username=credentials.get("KP_WORKER_SMTP_USERNAME") or None,
                password=credentials.get("KP_WORKER_SMTP_PASSWORD") or None,
                allow_loopback=_allow_development_loopback(settings, destination_key, address, smtp=True),
            )
        else:
            return _connection_test_result(
                component,
                ok=False,
                error_kind="config",
                verification_scope="email_provider",
                message="Choose SMTP or Azure Communication Services before testing email delivery.",
            )
    elif component == "webhook":
        scope = "webhook_tls"
        ok, kind = _probe_webhook(values.get("KP_WORKER_ALERT_WEBHOOK_URL", ""))
    else:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="unsupported component")
    return _connection_test_result(
        component,
        ok=ok,
        error_kind=kind,
        verification_scope=scope,
    )


@router.get("/config", response_model=ConfigResponse)
def get_config(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> ConfigResponse:
    settings = request.app.state.settings
    # An env file inside a managed container is neither the source of truth nor
    # durable. Do not present its incidental contents as current Azure
    # configuration. The UI can use ``mutable`` to render this view read-only.
    values = {} if settings.config_is_managed else _env_values(_env_path(request))
    masked: dict[str, bool] = {}
    display: dict[str, str] = {}
    for key in _ALLOWED_KEYS:
        raw = values.get(key, "")
        # Secrets are never returned — not even masked — so the GUI cannot
        # round-trip a masked placeholder back into .env (CRIT-01).
        display[key] = "" if key in _SECRET_KEYS else raw
        masked[key] = key in _SECRET_KEYS
    return ConfigResponse(
        values=display,
        masked=masked,
        config_store=settings.config_store,
        mutable=not settings.config_is_managed,
    )


@router.put("/config", response_model=dict[str, Any])
def put_config(
    body: ConfigPatch,
    request: Request,
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    _reject_if_managed(request, MANAGED_CONFIG_MESSAGE)
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")

    try:
        changed = _atomic_update_env(
            _env_path(request),
            body.values,
            validate_candidate=_validate_config_candidate,
        )
    except _AtomicEnvUpdateError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from None

    audit = request.app.state.audit_store
    audit.record(
        actor=principal.principal_id,
        action="console.config.update",
        object_type="system",
        object_id=".env",
        detail={"changed": changed},
    )
    return {"ok": True, "changed": changed}


class RuntimeCapabilities(BaseModel):
    config_mutation: bool
    process_restart: bool
    local_component_probes: bool


class StatusResponse(BaseModel):
    operator_api: bool
    tracking_api: bool | None
    postgres: bool | None
    redis: bool | None
    console_password_set: bool | None
    #: "env_file" (console may edit config) or "managed" (Terraform/Key Vault).
    config_store: str = "env_file"
    workers: dict[str, bool]
    runtime_control: str
    status_message: str
    capabilities: RuntimeCapabilities


@router.get("/status", response_model=StatusResponse)
def get_status(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> StatusResponse:
    settings = request.app.state.settings
    if settings.config_is_managed:
        # There is no local supervisor in Container Apps, and localhost probes
        # say nothing authoritative about managed Postgres, Redis, or separate
        # worker revisions. Azure health belongs to the external control plane.
        return StatusResponse(
            operator_api=True,
            tracking_api=None,
            postgres=None,
            redis=None,
            console_password_set=None,
            config_store=settings.config_store,
            workers={},
            runtime_control="azure_control_plane",
            status_message=(
                "Component health and lifecycle are managed by Azure Container Apps; "
                "this console does not have Azure control-plane access."
            ),
            capabilities=RuntimeCapabilities(
                config_mutation=False,
                process_restart=False,
                local_component_probes=False,
            ),
        )

    run_dir = _run_dir(settings)
    workers: dict[str, bool] = {}
    for name in ("ingestion", "generation", "delivery", "retention", "mailbox", "reminder", "alert", "directory"):
        workers[name] = _process_alive(run_dir / f"worker-{name}.pid")
    tracking_health = settings.tracking_base_url.rstrip("/") + "/healthz"
    return StatusResponse(
        operator_api=True,
        tracking_api=_http_ok(tracking_health),
        postgres=_tcp_ok(*_probe_target(settings.database_url, 5432)),
        redis=_tcp_ok(*_probe_target(settings.redis_url, 6379)),
        console_password_set=_console_password(_env_path(request)) is not None,
        config_store=settings.config_store,
        workers=workers,
        runtime_control="local_supervisor",
        status_message="Status is based on local dependency probes and supervisor process identifiers.",
        capabilities=RuntimeCapabilities(
            config_mutation=True,
            process_restart=True,
            local_component_probes=True,
        ),
    )


@router.post("/restart", response_model=dict[str, Any])
def restart_stack(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Signal the launcher supervisor to restart the whole stack."""
    _reject_if_managed(request, MANAGED_PROCESS_MESSAGE)
    marker = _run_dir(request.app.state.settings) / "restart"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()
    return {"ok": True, "message": "restart requested"}


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


def _probe_target(url: str, default_port: int) -> tuple[str, int]:
    """Resolve the host and port a local dependency probe should test.

    The probe previously hardcoded 127.0.0.1 with the default port, so an
    operator whose PostgreSQL or Redis listened anywhere else saw the console
    report the dependency down while the application was connected to it and
    healthy. Deriving the target from the same URL the application uses keeps
    the reported status truthful. Only the host and port are read; credentials
    in the URL are never touched.
    """

    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or default_port
    except ValueError:
        # A malformed URL is a configuration problem, not a reachable service.
        return "127.0.0.1", default_port
    return host, port


def _tcp_ok(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _worker_pid_path(settings: Any, name: str) -> Path:
    return _run_dir(settings) / f"worker-{name}.pid"
