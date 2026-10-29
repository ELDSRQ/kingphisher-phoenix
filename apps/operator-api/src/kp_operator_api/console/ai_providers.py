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

import contextlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import AiGenerationProvider, ProviderConfigGeneration
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
#: Authoritative on-disk shadow of the committed DB generation (W1-04). The
#: gateway holds no DB handle, so it reconciles its state file against THIS
#: marker and fails closed on a stale/mismatched generation.
_GENERATION_FILENAME = "ai-provider.generation"
#: Singleton row id of :class:`ProviderConfigGeneration`.
_GENERATION_SINGLETON_ID = 1
#: Environment variable the gateway may read the external provider's bearer key
#: from (W1-04 plaintext minimization), as a FALLBACK ONLY for a provider with
#: no stored key. A provider that HAS a stored (request/DB) key always gets that
#: exact key written to the 0600 file and the reference is never substituted —
#: the console cannot see the gateway's environment, so it must never drop a
#: usable key in favour of a single global variable that would be sent as the
#: bearer to whatever provider/base URL is selected. The reference is emitted
#: only when the selected provider has NO key of its own and this variable is
#: present in the console's env (a deployment that injects a key out of band,
#: e.g. via Key Vault, mirroring the gateway's own ``KP_AI_GATEWAY_UPSTREAM_API_KEY``).
#: The console never writes this value.
_PROVIDER_KEY_ENV = "KP_AI_GATEWAY_PROVIDER_API_KEY"


class ProviderConfigApplyError(RuntimeError):
    """A post-commit provider side effect failed or did not verify (W1-04).

    The durable selection and its bumped ``generation`` are already committed,
    but ``applied_generation`` is deliberately left behind, so the DB records an
    explicit "blocked drift" state and the gateway fails closed — nothing is
    silently half-applied. Carries no secret detail.
    """


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


def _generation_path(settings: Any) -> Path:
    return _run_dir(settings) / _GENERATION_FILENAME


def _atomic_write_private(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write ``payload`` as compact JSON, mode 0600 (tmp + rename).

    The temp file has a unique per-write name (``mkstemp``) so two concurrent
    selections cannot interleave on a shared ``.tmp`` path (N1), and the file
    and its directory are fsynced so the rename is durable (N4).
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


def _write_state_file(settings: Any, payload: dict[str, Any]) -> None:
    """Atomically write the gateway-readable selection state, mode 0600."""
    _atomic_write_private(_state_path(settings), payload)


def _write_generation_marker(settings: Any, generation: int, provider: str) -> None:
    """Atomically write the authoritative generation marker, mode 0600.

    This is the on-disk shadow of the committed DB generation. The stateless
    gateway reconciles its provider state file against it (see ``main.py``).
    """
    _atomic_write_private(_generation_path(settings), {"generation": generation, "provider": provider})


def _read_json_file(path: Path) -> dict[str, Any]:
    """Read a small JSON object written by this module; raises on any problem."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ProviderConfigApplyError("state artifact is not a JSON object")
    return data


def _clear_state_file(settings: Any) -> None:
    _state_path(settings).unlink(missing_ok=True)


def _signal_restart(settings: Any) -> None:
    marker = _run_dir(settings) / "restart"
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.touch()


def _bump_generation(session: Session, provider: str) -> int:
    """Bump the committed generation in the selection transaction and return it.

    ``applied_generation`` is left behind: once this transaction commits the DB
    records a half-applied ("blocked drift") state until the side effects are
    written and verified and ``_mark_generation_applied`` clears it.
    """
    # Lock the singleton row so two concurrent selections cannot both read
    # generation N and both write N+1 (N1). The row is seeded by migration 0048,
    # so the create branch is only for a pre-seed/test session.
    row = session.get(ProviderConfigGeneration, _GENERATION_SINGLETON_ID, with_for_update=True)
    if row is None:
        row = ProviderConfigGeneration(id=_GENERATION_SINGLETON_ID, generation=0, applied_generation=0)
        session.add(row)
    row.generation = (row.generation or 0) + 1
    row.active_provider = provider
    return row.generation


def _mark_generation_applied(session: Session, generation: int) -> None:
    """Advance ``applied_generation`` to clear the blocked-drift state."""
    row = session.get(ProviderConfigGeneration, _GENERATION_SINGLETON_ID)
    if row is not None:
        row.applied_generation = generation


def _build_state_payload(
    env_path: Path,
    *,
    provider: str,
    base_url: str,
    model_id: str,
    api_key: str,
    preset: registry.ProviderPreset,
    generation: int,
) -> dict[str, Any]:
    """Build the gateway state payload, writing the provider's own key when it
    has one and using the env reference only as a no-key fallback.

    A provider WITH a stored key always gets that exact key written to the 0600
    file — the env reference is never substituted (B1), because the console
    cannot see the gateway's environment and that single global variable would
    otherwise be sent as the bearer to whatever provider/base URL is selected.
    Only when the selected provider has NO key of its own, and the deployment
    has injected one through ``_PROVIDER_KEY_ENV`` out of band, is a reference
    emitted and no plaintext key written (minimizing plaintext exposure). A
    keyless provider with no such env value carries no credential at all.
    """
    payload: dict[str, Any] = {
        "provider": provider,
        "base_url": base_url,
        "model_id": model_id,
        "generation": generation,
    }
    if api_key:
        payload["api_key"] = api_key
        payload["auth_style"] = preset.auth_style
    elif _env_values(env_path).get(_PROVIDER_KEY_ENV, "").strip():
        # Fallback only: this provider has no stored key, but the deployment
        # provides one via the environment reference.
        payload["api_key_env"] = _PROVIDER_KEY_ENV
        payload["auth_style"] = preset.auth_style
    else:
        # No credential available (e.g. a self-hosted local model needs none).
        payload["auth_style"] = registry.AUTH_NONE
    return payload


def _apply_provider_side_effects(
    settings: Any,
    env_path: Path,
    *,
    provider: str,
    generation: int,
    base_url: str,
    model_id: str,
    api_key: str,
    preset: registry.ProviderPreset,
    new_pin: str,
    current_pin: str,
) -> None:
    """Write + verify the post-commit side effects for generation ``generation``.

    Order matters for fail-closed reconcile: the authoritative generation marker
    is written FIRST (the committed DB's on-disk shadow), then the state file
    stamped with the SAME generation, then the worker pin and restart signal. A
    fault between the marker and the state file leaves the marker ahead of the
    state file, which the gateway detects as a stale generation and fails closed;
    a fault before the marker leaves the previous working generation intact. Any
    failure is raised as ``ProviderConfigApplyError`` so the caller keeps the DB
    in its blocked-drift state.
    """
    try:
        _write_generation_marker(settings, generation, provider)
        if provider == registry.LOCAL:
            _clear_state_file(settings)
        else:
            _write_state_file(
                settings,
                _build_state_payload(
                    env_path,
                    provider=provider,
                    base_url=base_url,
                    model_id=model_id,
                    api_key=api_key,
                    preset=preset,
                    generation=generation,
                ),
            )
        if new_pin and new_pin != current_pin:
            _atomic_update_env(env_path, {_WORKER_MODEL_PIN_KEY: new_pin})
        _signal_restart(settings)
        _verify_provider_side_effects(
            settings, env_path, generation=generation, provider=provider, expected_pin=new_pin
        )
    except ProviderConfigApplyError:
        raise
    except Exception as exc:  # noqa: BLE001 - any apply fault keeps the DB in blocked drift; detail stays internal
        raise ProviderConfigApplyError("provider configuration could not be applied") from exc


def _verify_provider_side_effects(
    settings: Any, env_path: Path, *, generation: int, provider: str, expected_pin: str
) -> None:
    """Confirm the durable artifacts the gateway and worker read are consistent.

    Beyond re-reading the just-written marker and state file, this reads the env
    file BACK and confirms the worker model pin matches the selected model (B3).
    A pin write that faulted leaves the marker + state consistent at generation
    N (so the gateway would serve the new provider as valid) while the worker
    pin is stale — the worker would then ask the new provider for the old model.
    Verifying the pin here blocks ``applied_generation`` and surfaces the drift.
    """
    marker = _read_json_file(_generation_path(settings))
    if marker.get("generation") != generation or marker.get("provider") != provider:
        raise ProviderConfigApplyError("generation marker verification failed")
    if provider == registry.LOCAL:
        if _state_path(settings).exists():
            raise ProviderConfigApplyError("stale provider state file after local selection")
    else:
        state = _read_json_file(_state_path(settings))
        if state.get("generation") != generation or state.get("provider") != provider:
            raise ProviderConfigApplyError("provider state verification failed")
    # The worker model pin must reflect the selected model. ``expected_pin`` is
    # empty only when there is nothing to pin (e.g. local with no stored model
    # and no prior pin), in which case there is nothing to verify.
    if expected_pin and _env_values(env_path).get(_WORKER_MODEL_PIN_KEY, "") != expected_pin:
        raise ProviderConfigApplyError("worker model pin verification failed")


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
        # R-02: classify egress from the EFFECTIVE base URL the operator would
        # use, not the static per-preset guess — a custom/self-hosted base URL
        # can point anywhere. sends_data_offsite stays truthful for the UI's
        # offsite-confirmation gate; egress carries the three-way detail.
        egress = registry.provider_egress(key, registry.resolve_base_url(key, row.base_url if row else None))
        providers.append(
            {
                "key": key,
                "label": preset.label,
                "default_base_url": preset.default_base_url,
                "default_model": preset.default_model,
                "needs_key": preset.needs_key,
                "sends_data_offsite": egress != registry.EGRESS_ON_NETWORK,
                "egress": egress,
                "notes": preset.notes,
                "has_key": bool(row and row.api_key),
                "model_id": (row.model_id if row else None),
                "base_url": (row.base_url if row else None),
                "is_active": bool(row and row.is_active),
            }
        )
    # Surface the generation token so blocked drift is EXPLICIT, not latent: a
    # committed generation ahead of the applied one means a prior selection's
    # side effects did not fully apply (the gateway is failing closed) and the
    # provider must be reselected (W1-04 B2).
    gen_row = session.get(ProviderConfigGeneration, _GENERATION_SINGLETON_ID)
    committed = gen_row.generation if gen_row is not None else 0
    applied = gen_row.applied_generation if gen_row is not None else 0
    return {
        "active": _active_provider(rows),
        "managed": managed,
        "providers": providers,
        "generation": committed,
        "applied_generation": applied,
        "drift": committed > applied,
    }


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
    base_url = registry.resolve_base_url(provider, row.base_url if row else None)
    if provider != registry.LOCAL and not base_url:
        raise ValidationError_(f"set a base URL for {preset.label} before selecting it")

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

    # Flip the active flag to exactly this provider. Deactivate everything and
    # flush FIRST so the single-active partial unique index is never transiently
    # violated when switching between two hosted providers (deactivate must hit
    # the DB before the new activation).
    for existing in rows.values():
        existing.is_active = False
    session.flush()
    if provider != registry.LOCAL:
        if row is None:
            row = AiGenerationProvider(provider=provider, is_active=True)
            session.add(row)
        else:
            row.is_active = True

    # Capture the plaintext key before commit (CipherText decrypts on load).
    api_key = (row.api_key or "") if (provider != registry.LOCAL and row) else ""
    # Bump the generation token in the SAME transaction as the selection, so the
    # durable selection and the generation the gateway/worker reconcile against
    # commit atomically. applied_generation is left behind until the side
    # effects are verified (blocked drift until then).
    generation = _bump_generation(session, provider)
    # R-02: record the egress derived from the ACTUAL base URL, not the static
    # per-preset flag — otherwise the immutable audit chain can state "no data
    # leaves the network" for a custom provider pointing at the public internet.
    egress = registry.provider_egress(provider, base_url)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="ai-provider.select",
        object_type="ai_generation_provider",
        object_id=provider,
        detail={
            "model_id": model_id,
            "egress": egress,
            "sends_data_offsite": egress != registry.EGRESS_ON_NETWORK,
            "generation": generation,
        },
    )
    # Commit the durable selection + generation BEFORE any filesystem/env side
    # effects, so a constraint failure cannot leave an orphaned state file
    # pointing the gateway at a provider the database rolled back.
    session.commit()

    # Side effects the gateway + worker read, applied only after the DB is
    # durable. Written-then-verified in a fail-closed order (marker first); any
    # fault keeps the DB in blocked drift and the gateway fails closed, so the
    # config is never silently half-applied. Surface that blocked-drift state as
    # a typed 503 naming both generations (B2) rather than a bare 500.
    try:
        _apply_provider_side_effects(
            settings,
            env_path,
            provider=provider,
            generation=generation,
            base_url=base_url,
            model_id=model_id,
            api_key=api_key,
            preset=preset,
            new_pin=new_pin,
            current_pin=current_pin,
        )
    except ProviderConfigApplyError as exc:
        gen_row = session.get(ProviderConfigGeneration, _GENERATION_SINGLETON_ID)
        applied = gen_row.applied_generation if gen_row is not None else 0
        raise HTTPException(
            status_code=503,
            detail={
                "error": "provider_config_blocked_drift",
                "message": (
                    "provider selection committed but a side effect did not apply; the configuration "
                    "is in blocked drift and the gateway is failing closed — reselect the provider"
                ),
                "committed_generation": generation,
                "applied_generation": applied,
            },
        ) from exc
    # All side effects verified: clear the blocked-drift state.
    _mark_generation_applied(session, generation)
    session.commit()
    return {
        "provider": provider,
        "active": True,
        "model_id": model_id,
        "restart_requested": True,
        "generation": generation,
    }
