"""Console seam: bring-your-own generation model providers + API keys.

The operator saves an API key (encrypted at rest) for one or more hosted
providers and chooses which provider+model generates phishing-simulation
content, or keeps the on-prem local model. Selecting a provider:

* writes a small state file (``data/run/ai-provider.json``, mode 0600) that the
  AI gateway reads per request to route generation to that provider, and
* repins the worker's expected model (``KP_WORKER_AI_MODEL_ID``) and signals a
  stack restart, so the generation worker accepts the selected model's output.

Selecting a non-local provider deliberately sends generation content OUT to that
third party — an explicit operator decision, never a default. Keys are stored
with the application ``CipherText`` type and are never returned by the API.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import AiGenerationProvider
from kp_telemetry.errors import NotFoundError, ValidationError_
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api import ai_providers as registry
from kp_operator_api.auth import require_capability
from kp_operator_api.console.env_store import _atomic_update_env, _env_path, _env_values, _reject_if_managed
from kp_operator_api.console.runtime_status import _run_dir
from kp_operator_api.deps import get_audit_store, get_session, get_settings

router = APIRouter(prefix="/api/v1/console", tags=["console"])

_MANAGED_MESSAGE = "generation-provider configuration is managed in this deployment and cannot be changed here"
_WORKER_MODEL_PIN_KEY = "KP_WORKER_AI_MODEL_ID"
_STATE_FILENAME = "ai-provider.json"


class ProviderSaveRequest(BaseModel):
    # A blank/omitted api_key keeps the stored one (masked-secret convention).
    api_key: str | None = Field(default=None, max_length=8192)
    model_id: str | None = Field(default=None, max_length=128)
    base_url: str | None = Field(default=None, max_length=512)


class ProviderSelectRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=32)


def _rows_by_provider(session: Session) -> dict[str, AiGenerationProvider]:
    return {row.provider: row for row in session.scalars(select(AiGenerationProvider)).all()}


def _active_provider(rows: dict[str, AiGenerationProvider]) -> str:
    for provider, row in rows.items():
        if row.is_active:
            return provider
    return registry.LOCAL


def _state_path(settings: Any) -> Path:
    return _run_dir(settings) / _STATE_FILENAME


def _write_state_file(settings: Any, payload: dict[str, str]) -> None:
    """Atomically write the gateway-readable selection state, mode 0600."""
    path = _state_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _clear_state_file(settings: Any) -> None:
    _state_path(settings).unlink(missing_ok=True)


def _signal_restart(settings: Any) -> None:
    marker = _run_dir(settings) / "restart"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()


@router.get("/ai-providers", response_model=None)
def list_ai_providers(
    request: Request,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """List the provider presets with stored (never-secret) config + which is active."""
    managed = bool(request.app.state.settings.config_is_managed)
    rows = _rows_by_provider(session)
    providers = []
    for key, preset in registry.PROVIDERS.items():
        row = rows.get(key)
        providers.append(
            {
                "key": key,
                "label": preset.label,
                "default_base_url": preset.default_base_url,
                "default_model": preset.default_model,
                "needs_key": preset.needs_key,
                "sends_data_offsite": preset.sends_data_offsite,
                "notes": preset.notes,
                "has_key": bool(row and row.api_key),
                "model_id": (row.model_id if row else None),
                "base_url": (row.base_url if row else None),
                "is_active": bool(row and row.is_active),
            }
        )
    return {"active": _active_provider(rows), "managed": managed, "providers": providers}


@router.put("/ai-providers/{provider}", response_model=None)
def save_ai_provider(
    provider: str,
    body: ProviderSaveRequest,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Save a provider's API key (encrypted), model id, and optional base-URL override."""
    _reject_if_managed(request, _MANAGED_MESSAGE)
    if not registry.is_known_provider(provider):
        raise NotFoundError("unknown provider")
    row = session.get(AiGenerationProvider, provider)
    if row is None:
        row = AiGenerationProvider(provider=provider, is_active=False)
        session.add(row)
    # Blank api_key keeps the stored one (masked-secret convention); 'local'
    # never carries a key.
    if provider != registry.LOCAL and body.api_key is not None and body.api_key.strip():
        row.api_key = body.api_key.strip()
    if body.model_id is not None:
        row.model_id = body.model_id.strip() or None
    if body.base_url is not None:
        row.base_url = body.base_url.strip() or None
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="ai-provider.save",
        object_type="ai_generation_provider",
        object_id=provider,
        detail={"key_set": bool(row.api_key), "model_id": row.model_id},
    )
    session.commit()
    return {"provider": provider, "saved": True}


@router.post("/ai-providers/select", response_model=None)
def select_ai_provider(
    body: ProviderSelectRequest,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: Any = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> dict[str, Any]:
    """Make a provider the active generation model (or 'local'); repins + restarts."""
    _reject_if_managed(request, _MANAGED_MESSAGE)
    provider = body.provider.strip()
    if not registry.is_known_provider(provider):
        raise NotFoundError("unknown provider")

    rows = _rows_by_provider(session)
    row = rows.get(provider)
    preset = registry.preset(provider)

    if preset.needs_key and not (row and row.api_key):
        raise ValidationError_(f"save an API key for {preset.label} before selecting it")

    model_id = registry.resolve_model(provider, row.model_id if row else None)
    if provider != registry.LOCAL and not model_id:
        raise ValidationError_(f"set a model id for {preset.label} before selecting it")

    # Snapshot the current local pin the first time we leave local, so selecting
    # 'local' again can restore the on-prem model.
    env_path = _env_path(request)
    current_pin = _env_values(env_path).get(_WORKER_MODEL_PIN_KEY, "")
    local_row = rows.get(registry.LOCAL)
    if provider != registry.LOCAL:
        if local_row is None:
            local_row = AiGenerationProvider(provider=registry.LOCAL, model_id=current_pin or None, is_active=False)
            session.add(local_row)
        elif not local_row.model_id and current_pin:
            local_row.model_id = current_pin
        new_pin = model_id
    else:
        new_pin = (local_row.model_id if local_row and local_row.model_id else current_pin) or ""

    # Flip the active flag to exactly this provider.
    for existing in rows.values():
        existing.is_active = False
    if provider != registry.LOCAL:
        if row is None:
            row = AiGenerationProvider(provider=provider, is_active=True)
            session.add(row)
        else:
            row.is_active = True

    # Write (or clear) the gateway state file.
    if provider == registry.LOCAL:
        _clear_state_file(settings)
    else:
        _write_state_file(
            settings,
            {
                "provider": provider,
                "base_url": registry.resolve_base_url(provider, row.base_url if row else None),
                "model_id": model_id,
                "api_key": (row.api_key or "") if row else "",
                "auth_style": preset.auth_style,
            },
        )

    # Repin the worker's expected model and signal a restart so it takes effect.
    if new_pin and new_pin != current_pin:
        _atomic_update_env(env_path, {_WORKER_MODEL_PIN_KEY: new_pin})
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="ai-provider.select",
        object_type="ai_generation_provider",
        object_id=provider,
        detail={"model_id": model_id, "sends_data_offsite": preset.sends_data_offsite},
    )
    session.commit()
    _signal_restart(settings)
    return {"provider": provider, "active": True, "model_id": model_id, "restart_requested": True}
