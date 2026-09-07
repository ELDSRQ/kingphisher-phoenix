"""Audit-log read/verify routes and the global kill switch."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

from fastapi import APIRouter, Depends, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import (
    Campaign,
    RecipientAssignment,
    TrackingToken,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import (
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.routes.alerts import _queue_campaign_alert
from kp_operator_api.routes.shared import (
    _system_safety_state,
)

router = APIRouter(prefix="/api/v1")


@router.get("/audit", status_code=status.HTTP_200_OK)
def view_audit(
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VIEW_AUDIT)),
) -> list[dict[str, Any]]:
    # CRIT-02: audit rows live on the dedicated audit engine and are not ORM
    # entities on the application session (previously selected pydantic
    # `dm.AuditEvent` and 500'd). Read them through the audit store.
    return audit.list_events(limit=500)


@router.post("/audit/verify", status_code=status.HTTP_200_OK)
def verify_audit(
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.VIEW_AUDIT)),
) -> dict[str, Any]:
    problems = audit.verify()
    return {"ok": not problems, "problems": problems}


class KillSwitchBody(BaseModel):
    campaign_id: uuid.UUID | None = None
    confirm: bool = False
    reason: str | None = Field(default=None, max_length=500)


class KillSwitchResetBody(BaseModel):
    confirm: bool = False
    reason: str = Field(min_length=1, max_length=500)


@router.post("/kill-switch", status_code=status.HTTP_200_OK)
def kill_switch(
    body: KillSwitchBody,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Revoke queued deliveries + tracking tokens.

    MED-13: scoped to a single campaign when `campaign_id` is given (global
    otherwise) and requires an explicit `confirm=true` so a misclick cannot
    cancel the whole delivery queue.
    """
    if not body.confirm:
        raise ValidationError_("kill switch requires explicit confirmation (confirm=true)")

    now = datetime.now(UTC)
    reason = (body.reason or "").strip()
    safety_state = None
    changed = True
    campaign = None
    if body.campaign_id is None:
        if not reason:
            raise ValidationError_("global kill switch requires a reason")
        safety_state = _system_safety_state(session, exclusive_lock=True)
        changed = not safety_state.emergency_stop_engaged
        if changed:
            safety_state.emergency_stop_engaged = True
            safety_state.generation += 1
            safety_state.engaged_at = now
            safety_state.engaged_by = principal.principal_id
            safety_state.engage_reason = reason
            safety_state.updated_at = now
    else:
        # A scoped emergency action must name a real campaign and persist a
        # terminal campaign fence. Expiring only the rows visible right now
        # allowed a queued test-send or a later publisher to recreate work for
        # the same campaign after this endpoint returned success.
        campaign = session.get(Campaign, body.campaign_id, with_for_update=True)
        if campaign is None:
            raise NotFoundError("campaign not found")
        changed = campaign.state != dm.CampaignState.STOPPED
        campaign.state = dm.CampaignState.STOPPED

    assignment_filter = RecipientAssignment.send_state == dm.SendState.QUEUED
    token_filter = TrackingToken.status == dm.TokenStatus.ACTIVE
    if body.campaign_id is not None:
        assignment_filter = assignment_filter & (RecipientAssignment.campaign_id == body.campaign_id)
        token_filter = token_filter & (TrackingToken.campaign_id == body.campaign_id)

    assignments_result = cast(
        CursorResult[Any],
        session.execute(
            update(RecipientAssignment)
            .where(assignment_filter)
            .values(
                send_state=dm.SendState.EXPIRED,
                failure_reason="global_emergency_stop" if body.campaign_id is None else "campaign_kill_switch",
            )
            .execution_options(synchronize_session=False)
        ),
    )
    cancelled = assignments_result.rowcount or 0
    tokens_result = cast(
        CursorResult[Any],
        session.execute(
            update(TrackingToken)
            .where(token_filter)
            .values(
                status=dm.TokenStatus.KILL_SWITCHED,
                revoked_at=now,
                revoked_reason=(
                    "global emergency stop engaged" if body.campaign_id is None else "campaign kill switch"
                ),
            )
            .execution_options(synchronize_session=False)
        ),
    )
    tokens_revoked = tokens_result.rowcount or 0
    if safety_state is not None:
        safety_state.last_cancelled = cancelled
        safety_state.last_tokens_revoked = tokens_revoked
        safety_state.updated_at = now
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="kill-switch.engage",
        object_type="campaign" if body.campaign_id else "system",
        object_id=str(body.campaign_id) if body.campaign_id else "delivery",
        detail={
            "cancelled": cancelled,
            "tokens_revoked": tokens_revoked,
            "confirm": body.confirm,
            "changed": changed,
            "reason": reason or None,
            "generation": safety_state.generation if safety_state is not None else None,
        },
    )
    if campaign is not None:
        _queue_campaign_alert(session, request, campaign, "campaign.kill_switch")
    session.commit()
    return {
        "cancelled": cancelled,
        "tokens_revoked": tokens_revoked,
        "engaged": safety_state.emergency_stop_engaged if safety_state is not None else None,
        "changed": changed,
        "generation": safety_state.generation if safety_state is not None else None,
    }


@router.post("/kill-switch/reset", status_code=status.HTTP_200_OK)
def reset_kill_switch(
    body: KillSwitchResetBody,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Deliberately disengage the persistent global emergency stop.

    Resetting only reopens future scheduling/delivery.  Assignments cancelled
    and tracking credentials revoked by engagement stay terminal.
    """

    if not body.confirm:
        raise ValidationError_("kill switch reset requires explicit confirmation (confirm=true)")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("kill switch reset requires a reason")

    state = _system_safety_state(session, exclusive_lock=True)
    changed = state.emergency_stop_engaged
    now = datetime.now(UTC)
    if changed:
        state.emergency_stop_engaged = False
        state.generation += 1
        state.disengaged_at = now
        state.disengaged_by = principal.principal_id
        state.disengage_reason = reason
        state.updated_at = now
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="kill-switch.disengage",
        object_type="system",
        object_id="delivery",
        detail={"confirm": body.confirm, "changed": changed, "reason": reason, "generation": state.generation},
    )
    session.commit()
    return {"engaged": state.emergency_stop_engaged, "changed": changed, "generation": state.generation}


@router.get("/kill-switch", status_code=status.HTTP_200_OK)
def kill_switch_state(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.USE_KILL_SWITCH)),
) -> dict[str, Any]:
    """Report the persistent global interlock rather than audit history."""

    state = _system_safety_state(session)
    return {
        "engaged": state.emergency_stop_engaged,
        "generation": state.generation,
        "engaged_at": state.engaged_at,
        "engaged_by": state.engaged_by,
        "engage_reason": state.engage_reason,
        "disengaged_at": state.disengaged_at,
        "disengaged_by": state.disengaged_by,
        "disengage_reason": state.disengage_reason,
        "last_cancelled": state.last_cancelled,
        "last_tokens_revoked": state.last_tokens_revoked,
    }
