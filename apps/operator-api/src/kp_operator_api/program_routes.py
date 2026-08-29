"""Finite campaign-program planning and lifecycle routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import Campaign, CampaignProgram, CampaignProgramOccurrence
from kp_database.program_service import (
    campaign_program_is_complete,
    get_campaign_program,
    list_campaign_program_occurrences,
    materialize_campaign_program,
    set_campaign_program_state,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, ValidationError_
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1/programs", tags=["campaign-programs"])

_COLLECTION_MAX_OFFSET = 10_000


class ProgramCreate(BaseModel):
    source_campaign_id: uuid.UUID
    cadence_days: Literal[7, 14, 28, 84]
    occurrence_count: int = Field(ge=2, le=12)


class ProgramStateChange(BaseModel):
    expected_version: int = Field(ge=1)
    rationale: str = Field(min_length=1, max_length=500)


def _utc_instant(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ConflictError("campaign program contains an invalid timeline")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _occurrence_payload(session: Session, occurrence: CampaignProgramOccurrence) -> dict[str, Any]:
    campaign = session.get(Campaign, occurrence.campaign_id)
    if campaign is None:
        raise ConflictError("campaign program occurrence is missing its campaign")
    return {
        "campaign_program_occurrence_id": str(occurrence.campaign_program_occurrence_id),
        "occurrence_number": occurrence.occurrence_number,
        "campaign_id": str(occurrence.campaign_id),
        "state": campaign.state.value,
        "schedule_start": _utc_instant(occurrence.schedule_start),
        "schedule_end": _utc_instant(occurrence.schedule_end),
    }


def _program_payload(
    session: Session,
    program: CampaignProgram,
    *,
    include_occurrences: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "campaign_program_id": str(program.campaign_program_id),
        "source_campaign_id": str(program.source_campaign_id),
        "state": program.state.value,
        "version": program.version,
        "cadence_days": program.cadence_days,
        "occurrence_count": program.occurrence_count,
        "complete": campaign_program_is_complete(session, program.campaign_program_id),
        "created_at": _utc_instant(program.created_at),
        "updated_at": _utc_instant(program.updated_at),
    }
    if include_occurrences:
        payload["occurrences"] = [
            _occurrence_payload(session, occurrence)
            for occurrence in list_campaign_program_occurrences(session, program.campaign_program_id)
        ]
    return payload


@router.post("", status_code=status.HTTP_201_CREATED)
def create_program(
    body: ProgramCreate,
    response: Response,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    result = materialize_campaign_program(
        session,
        source_campaign_id=body.source_campaign_id,
        cadence_days=body.cadence_days,
        occurrence_count=body.occurrence_count,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="campaign_program.create",
        object_type="campaign_program",
        object_id=str(result.program.campaign_program_id),
        detail={
            "source_campaign_id": str(body.source_campaign_id),
            "cadence_days": body.cadence_days,
            "occurrence_count": body.occurrence_count,
            "created": result.created,
        },
    )
    session.commit()
    response.status_code = status.HTTP_201_CREATED if result.created else status.HTTP_200_OK
    return {"created": result.created, **_program_payload(session, result.program, include_occurrences=True)}


@router.get("")
def list_programs(
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> list[dict[str, Any]]:
    del principal
    programs = session.scalars(
        select(CampaignProgram)
        .order_by(CampaignProgram.created_at.desc(), CampaignProgram.campaign_program_id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [_program_payload(session, program, include_occurrences=False) for program in programs]


@router.get("/{program_id}")
def get_program(
    program_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    program = get_campaign_program(session, program_id)
    return _program_payload(session, program, include_occurrences=True)


def _change_program_state(
    *,
    session: Session,
    audit: AuditStore,
    principal: Principal,
    program_id: uuid.UUID,
    body: ProgramStateChange,
    state: dm.CampaignProgramState,
) -> dict[str, Any]:
    rationale = body.rationale.strip()
    if not rationale:
        raise ValidationError_("campaign program state-change rationale cannot be blank")
    program, changed = set_campaign_program_state(
        session,
        program_id=program_id,
        state=state,
        expected_version=body.expected_version,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"campaign_program.{state.value}",
        object_type="campaign_program",
        object_id=str(program_id),
        detail={
            "expected_version": body.expected_version,
            "resulting_version": program.version,
            "changed": changed,
            "rationale": rationale,
        },
    )
    session.commit()
    return {"changed": changed, **_program_payload(session, program, include_occurrences=True)}


@router.post("/{program_id}/pause")
def pause_program(
    program_id: uuid.UUID,
    body: ProgramStateChange,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    return _change_program_state(
        session=session,
        audit=audit,
        principal=principal,
        program_id=program_id,
        body=body,
        state=dm.CampaignProgramState.PAUSED,
    )


@router.post("/{program_id}/resume")
def resume_program(
    program_id: uuid.UUID,
    body: ProgramStateChange,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SCHEDULE_CAMPAIGN)),
) -> dict[str, Any]:
    return _change_program_state(
        session=session,
        audit=audit,
        principal=principal,
        program_id=program_id,
        body=body,
        state=dm.CampaignProgramState.ACTIVE,
    )
