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

import datetime
import hmac
import os
import socket
import urllib.request
from pathlib import Path
from typing import Any

import jwt
from dotenv import dotenv_values, set_key
from fastapi import APIRouter, Depends, Request
from kp_authorization.rbac import Capability, Principal
from kp_telemetry.errors import AuthenticationError, PermissionDeniedError
from pydantic import BaseModel, Field

from kp_operator_api.auth import require_capability

router = APIRouter(prefix="/api/v1/console", tags=["console"])

CONSOLE_PASSWORD_KEY = "KP_CONSOLE_PASSWORD"  # noqa: S105
_SESSION_TTL_SECONDS = 8 * 60 * 60


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


@router.post("/session", response_model=SessionResponse)
def create_session(
    body: SessionRequest,
    request: Request,
) -> SessionResponse:
    settings = request.app.state.settings
    env_path = _env_path(request)
    if not _verify_console_password(env_path, body.password):
        raise AuthenticationError("invalid console password")

    now = datetime.datetime.now(datetime.UTC)
    claims = {
        "sub": "console-operator",
        "iss": settings.oidc_issuer,
        "aud": settings.oidc_audience,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + _SESSION_TTL_SECONDS,
        "realm_access": {"roles": ["administrator"]},
    }
    secret = settings.require_secret_key().hex()
    token = jwt.encode(claims, secret, algorithm="HS256")
    return SessionResponse(token=token, expires_in=_SESSION_TTL_SECONDS)


_ALLOWED_KEYS: frozenset[str] = frozenset({
    CONSOLE_PASSWORD_KEY,
    "OPERATOR_API_HOST",
    "OPERATOR_API_PORT",
    "OPERATOR_API_OIDC_ISSUER",
    "OPERATOR_API_OIDC_AUDIENCE",
    "OPERATOR_API_LOG_LEVEL",
    "OPERATOR_API_RATE_LIMIT_USER_PER_MIN",
    "OPERATOR_API_RATE_LIMIT_IP_PER_MIN",
    "OPERATOR_API_TRACKING_BASE_URL",
    "OPERATOR_API_TRAINING_BASE_URL",
    "OPERATOR_API_TRAINING_DOMAINS",
    "OPERATOR_API_APP_NAME",
    "OPERATOR_API_DATABASE_URL",
    "OPERATOR_API_AUDIT_DATABASE_URL",
    "OPERATOR_API_AUDIT_HMAC_KEY",
    "OPERATOR_API_CIPHERTEXT_KEK",
    "TRACKING_API_HOST",
    "TRACKING_API_PORT",
    "KP_WORKER_AUDIT_HMAC_KEY",
    "KP_WORKER_CIPHERTEXT_KEK",
    "KP_WORKER_POLL_SECONDS",
    "KP_WORKER_LOG_LEVEL",
    "MOCK_IDP_URL",
    "MOCK_GRAPH_URL",
    "MOCK_AI_URL",
    "MAILPIT_URL",
})


class ConfigPatch(BaseModel):
    values: dict[str, str] = Field(default_factory=dict)

    # Keys the console may mutate. Anything not listed is rejected so a
    # compromised console token cannot rewrite arbitrary files.


class ConfigResponse(BaseModel):
    values: dict[str, str]
    masked: dict[str, bool]


def _mask(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:4] + "****" + value[-4:]


@router.get("/config", response_model=ConfigResponse)
def get_config(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> ConfigResponse:
    values = _env_values(_env_path(request))
    secret_keys = {CONSOLE_PASSWORD_KEY, "OPERATOR_API_AUDIT_HMAC_KEY", "OPERATOR_API_CIPHERTEXT_KEK",
                   "KP_WORKER_AUDIT_HMAC_KEY", "KP_WORKER_CIPHERTEXT_KEK"}
    masked: dict[str, bool] = {}
    display: dict[str, str] = {}
    for key in _ALLOWED_KEYS:
        raw = values.get(key, "")
        display[key] = _mask(raw) if raw and key in secret_keys else raw
        masked[key] = key in secret_keys
    return ConfigResponse(values=display, masked=masked)


@router.put("/config", response_model=dict[str, Any])
def put_config(
    body: ConfigPatch,
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    forbidden = set(body.values) - _ALLOWED_KEYS
    if forbidden:
        raise PermissionDeniedError(f"rejected configuration keys: {sorted(forbidden)}")

    env_path = _env_path(request)
    changed: list[str] = []
    for key, value in body.values.items():
        current = _env_values(env_path).get(key, "")
        if value == current:
            continue
        set_key(str(env_path), key, value)
        changed.append(key)

    # The console operator changes the console password; the next login uses it.
    audit = request.app.state.audit_store
    audit.record(
        actor="console-operator",
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
    for name in ("ingestion", "generation", "delivery", "retention", "mailbox", "reminder"):
        workers[name] = _process_alive(run_dir / f"worker-{name}.pid")
    return StatusResponse(
        operator_api=True,
        tracking_api=_http_ok("http://127.0.0.1:8001/healthz"),
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
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:  # noqa: S310
            return int(resp.status) == 200
    except OSError:
        return False


def _tcp_ok(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def _worker_pid_path(settings: Any, name: str) -> Path:
    return _run_dir(settings) / f"worker-{name}.pid"
