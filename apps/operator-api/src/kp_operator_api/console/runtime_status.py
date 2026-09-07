"""Local runtime status and lifecycle routes for the console.

Moved verbatim out of ``kp_operator_api.console`` during the ARC-002 Item 2
split: the dependency probes behind ``GET /status`` and the supervisor restart
signal behind ``POST /restart``. Managed (Azure) deployments short-circuit both
— there is no local supervisor and localhost probes say nothing authoritative
about managed Postgres, Redis, or separate worker revisions.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlsplit

import httpx
from fastapi import APIRouter, Depends, Request
from kp_authorization.rbac import Capability, Principal
from pydantic import BaseModel

from kp_operator_api.auth import require_capability
from kp_operator_api.console.env_store import (
    MANAGED_PROCESS_MESSAGE,
    _console_password,
    _env_path,
    _reject_if_managed,
)

router = APIRouter(prefix="/api/v1/console", tags=["console"])


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
