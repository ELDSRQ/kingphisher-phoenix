"""Small, governed, text-only security-awareness resource library."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import TrainingResource
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError_
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1", tags=["training-library"])
_COLLECTION_MAX_OFFSET = 10_000


class TrainingResourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=20_000)
    source_ref: str | None = Field(default=None, max_length=500)

    @field_validator("title", "content")
    @classmethod
    def _required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("value must contain bounded text")
        return normalized

    @field_validator("title", "source_ref")
    @classmethod
    def _single_line_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if "\x00" in normalized or "\r" in normalized or "\n" in normalized:
            raise ValueError("value must be a single line")
        return normalized or None


class TrainingResourceDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected", "superseded"]
    rationale: str = Field(min_length=1, max_length=1_000)

    @field_validator("rationale")
    @classmethod
    def _bounded_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("rationale is required")
        return normalized


def _principal_uuid(principal: Principal) -> uuid.UUID:
    try:
        return uuid.UUID(principal.principal_id)
    except ValueError as exc:
        raise ValidationError_("authenticated principal identifier is invalid") from exc


def _summary(resource: TrainingResource, principal: Principal) -> dict[str, object]:
    principal_id = _principal_uuid(principal)
    is_creator = resource.created_by == principal_id
    can_submit = bool(
        principal.can(Capability.CREATE_CAMPAIGN)
        and is_creator
        and resource.approval_state == dm.TemplateApprovalState.DRAFT
    )
    can_review = bool(
        principal.can(Capability.APPROVE_TEMPLATE)
        and not is_creator
        and resource.approval_state in {dm.TemplateApprovalState.PENDING, dm.TemplateApprovalState.APPROVED}
    )
    return {
        "training_resource_id": str(resource.training_resource_id),
        "title": resource.title,
        "version": resource.version,
        "source_ref": resource.source_ref,
        "approval_state": resource.approval_state.value,
        "requires_completion": resource.requires_completion,
        "can_submit": can_submit,
        "can_review": can_review,
    }


@router.get("/training-resources")
def list_training_resources(
    approval_state: dm.TemplateApprovalState | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_TEMPLATE)),
) -> list[dict[str, object]]:
    statement = select(TrainingResource)
    if approval_state is not None:
        statement = statement.where(TrainingResource.approval_state == approval_state)
    resources = session.scalars(
        statement.order_by(TrainingResource.created_at.desc(), TrainingResource.training_resource_id)
        .offset(offset)
        .limit(limit)
    ).all()
    return [_summary(resource, principal) for resource in resources]


@router.get("/training-resources/{training_resource_id}/preview")
def preview_training_resource(
    training_resource_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_any_capability(Capability.CREATE_CAMPAIGN, Capability.APPROVE_TEMPLATE)),
) -> dict[str, object]:
    resource = session.get(TrainingResource, training_resource_id)
    if resource is None:
        raise NotFoundError("training resource not found")
    return {
        **_summary(resource, principal),
        "content": resource.content,
        "content_type": "text/plain",
        "html_execution": False,
    }


@router.post("/training-resources", status_code=status.HTTP_201_CREATED)
def create_training_resource(
    body: TrainingResourceCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, object]:
    resource = TrainingResource(
        training_resource_id=uuid.uuid4(),
        title=body.title,
        kind="article",
        content=body.content,
        version=1,
        requires_completion=True,
        source_ref=body.source_ref,
        approval_state=dm.TemplateApprovalState.DRAFT,
        created_by=_principal_uuid(principal),
        created_at=datetime.now(UTC),
    )
    session.add(resource)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="training_resource.create",
        object_type="training_resource",
        object_id=str(resource.training_resource_id),
        detail={"source_ref": resource.source_ref, "content_type": "text/plain"},
    )
    session.commit()
    return _summary(resource, principal)


@router.post("/training-resources/{training_resource_id}/submit")
def submit_training_resource(
    training_resource_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, object]:
    resource = session.get(TrainingResource, training_resource_id, with_for_update=True)
    if resource is None:
        raise NotFoundError("training resource not found")
    if resource.created_by != _principal_uuid(principal):
        raise PermissionDeniedError("only the resource author may submit it for review")
    if resource.approval_state != dm.TemplateApprovalState.DRAFT:
        raise ConflictError(f"training resource is already {resource.approval_state.value}")
    resource.approval_state = dm.TemplateApprovalState.PENDING
    resource.submitted_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="training_resource.submit",
        object_type="training_resource",
        object_id=str(training_resource_id),
        detail={},
    )
    session.commit()
    return _summary(resource, principal)


@router.post("/training-resources/{training_resource_id}/decision")
def decide_training_resource(
    training_resource_id: uuid.UUID,
    body: TrainingResourceDecision,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> dict[str, object]:
    resource = session.get(TrainingResource, training_resource_id, with_for_update=True)
    if resource is None:
        raise NotFoundError("training resource not found")
    reviewer_id = _principal_uuid(principal)
    if resource.created_by == reviewer_id:
        raise PermissionDeniedError("resource authors cannot review their own resource")
    if body.decision == "superseded":
        if resource.approval_state != dm.TemplateApprovalState.APPROVED:
            raise ConflictError("only an approved training resource can be superseded")
        next_state = dm.TemplateApprovalState.SUPERSEDED
    else:
        if resource.approval_state != dm.TemplateApprovalState.PENDING:
            raise ConflictError("only a pending training resource can be approved or rejected")
        next_state = (
            dm.TemplateApprovalState.APPROVED if body.decision == "approved" else dm.TemplateApprovalState.REJECTED
        )
    resource.approval_state = next_state
    resource.reviewed_by = reviewer_id
    resource.reviewed_at = datetime.now(UTC)
    resource.review_rationale = body.rationale
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"training_resource.{body.decision}",
        object_type="training_resource",
        object_id=str(training_resource_id),
        detail={"rationale": body.rationale},
    )
    session.commit()
    return _summary(resource, principal)
