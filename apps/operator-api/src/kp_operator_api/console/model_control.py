"""Local model-residency control for the console.

The on-prem host's single GPU serves two models that cannot be resident at once:
this build's aggregation model (gpt-oss-20b, served by a llama.cpp ``llama-server``)
and the operator's separate qwen3:32b (served by Ollama). This seam reports which
is currently loaded and swaps between them by shelling out to the operator-owned
swap script (``scripts/operator/ai-model-swap.sh``), which preserves the
aggregation model's identity pin (``--alias gpt-oss-20b-aggregate``) so the
ai-gateway's fail-closed ``model_id`` check keeps passing after a swap back.

Managed (Azure) deployments short-circuit both routes: the model and its serving
endpoint there are external to this console, and there is no local swap script.
The swap is a fixed, closed set of two targets — never arbitrary command
execution — and every swap is audit-logged.
"""

from __future__ import annotations

import os
import subprocess

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.console.env_store import MANAGED_PROCESS_MESSAGE, _reject_if_managed
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1/console", tags=["console"])

#: The swap script deploys to /opt/kp-ai010 on the on-prem host; the endpoint
#: defaults match the live llama.cpp (:18082) and Ollama (:11434) ports. All are
#: overridable so the seam can be pointed elsewhere without touching this module.
_SWAP_SCRIPT = os.environ.get("KP_MODEL_SWAP_SCRIPT", "/opt/kp-ai010/kp-ai-swap.sh")
_LLAMA_URL = os.environ.get("KP_MODEL_CONTROL_LLAMA_URL", "http://127.0.0.1:18082").rstrip("/")
_OLLAMA_URL = os.environ.get("KP_MODEL_CONTROL_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
_QWEN_MODEL = os.environ.get("KP_MODEL_CONTROL_QWEN_MODEL", "qwen3:32b")

#: The only targets the swap endpoint accepts; anything else is rejected before
#: any subprocess is launched.
_VALID_TARGETS = frozenset({"qwen", "aggregate"})


class ModelControlStatus(BaseModel):
    enabled: bool
    aggregation_loaded: bool
    qwen_loaded: bool
    swap_script_present: bool


class ModelSwapRequest(BaseModel):
    target: str = Field(..., description='One of "qwen" or "aggregate"')


class ModelSwapResponse(BaseModel):
    ok: bool
    target: str
    message: str


def _swap_script_present() -> bool:
    return os.path.isfile(_SWAP_SCRIPT) and os.access(_SWAP_SCRIPT, os.X_OK)


def _llama_loaded() -> bool:
    try:
        return httpx.get(f"{_LLAMA_URL}/health", timeout=3).status_code == 200
    except httpx.HTTPError:
        return False


def _qwen_loaded() -> bool:
    try:
        payload = httpx.get(f"{_OLLAMA_URL}/api/ps", timeout=3).json()
    except (httpx.HTTPError, ValueError):
        return False
    return any(str(model.get("name", "")) == _QWEN_MODEL for model in payload.get("models", []))


@router.get("/model-control", response_model=ModelControlStatus)
def model_control_status(
    request: Request,
    _principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> ModelControlStatus:
    """Report which model is resident without mutating anything."""
    if request.app.state.settings.config_is_managed:
        return ModelControlStatus(
            enabled=False,
            aggregation_loaded=False,
            qwen_loaded=False,
            swap_script_present=False,
        )
    return ModelControlStatus(
        enabled=True,
        aggregation_loaded=_llama_loaded(),
        qwen_loaded=_qwen_loaded(),
        swap_script_present=_swap_script_present(),
    )


@router.post("/model-control/swap", response_model=ModelSwapResponse)
def model_control_swap(
    body: ModelSwapRequest,
    request: Request,
    audit: AuditStore = Depends(get_audit_store),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_ROLES)),
) -> ModelSwapResponse:
    """Swap GPU residency between qwen3:32b and the aggregation model.

    Managed deployments are rejected; the action is limited to the two fixed
    targets backed by the operator-owned swap script, and every attempt is
    audit-logged (actor, target, outcome).
    """
    _reject_if_managed(request, MANAGED_PROCESS_MESSAGE)
    target = body.target.strip().lower()
    if target not in _VALID_TARGETS:
        # Fail closed: unknown targets never reach a shell.
        raise _invalid_target(body.target)
    if not _swap_script_present():
        message = f"swap script not found or not executable at {_SWAP_SCRIPT}"
        _record(audit, session, principal.principal_id, target, ok=False, message=message)
        return ModelSwapResponse(ok=False, target=target, message=message)

    try:
        # S603: `target` is already restricted to the closed _VALID_TARGETS
        # frozenset above and `_SWAP_SCRIPT` is a module constant, so no
        # untrusted/request-derived value can reach the subprocess.
        completed = subprocess.run(  # noqa: S603
            [_SWAP_SCRIPT, target],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"swap failed to complete: {exc}"
        _record(audit, session, principal.principal_id, target, ok=False, message=message)
        return ModelSwapResponse(ok=False, target=target, message=message)

    ok = completed.returncode == 0
    message = (completed.stdout or completed.stderr or "").strip().splitlines()
    tail = "\n".join(message[-8:]) if message else "(no output)"
    if ok:
        summary = f"model swap to {target!r} completed"
    else:
        summary = f"model swap to {target!r} failed (exit {completed.returncode})"
    _record(audit, session, principal.principal_id, target, ok=ok, message=summary + "\n" + tail)
    return ModelSwapResponse(ok=ok, target=target, message=summary)


def _invalid_target(target: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"unsupported model-swap target {target!r}; expected one of {sorted(_VALID_TARGETS)}",
    )


def _record(audit: AuditStore, session: Session, actor: str, target: str, ok: bool, message: str) -> None:
    audit.record(
        session=session,
        actor=actor,
        action="model-residency.swap",
        object_type="system",
        object_id=f"model:{target}",
        detail={"target": target, "ok": ok, "message": message[:500]},
    )
