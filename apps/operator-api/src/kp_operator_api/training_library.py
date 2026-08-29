"""Small, governed, text-only security-awareness resource library."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import Campaign, CampaignPattern, TemplateVersion, TrainingResource
from kp_database.training_builder import build_knowledge_check_draft
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, NotFoundError, PermissionDeniedError, ValidationError_
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.deps import get_audit_store, get_session

router = APIRouter(prefix="/api/v1", tags=["training-library"])
_COLLECTION_MAX_OFFSET = 10_000
_KNOWLEDGE_QUESTION_MAX = 500
_KNOWLEDGE_OPTION_MAX = 200
_KNOWLEDGE_OPTIONS_MIN = 2
_KNOWLEDGE_OPTIONS_MAX = 5


class TrainingResourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=20_000)
    source_ref: str | None = Field(default=None, max_length=500)
    knowledge_question: str | None = Field(default=None, min_length=1, max_length=_KNOWLEDGE_QUESTION_MAX)
    knowledge_options: list[str] | None = Field(
        default=None,
        min_length=_KNOWLEDGE_OPTIONS_MIN,
        max_length=_KNOWLEDGE_OPTIONS_MAX,
    )
    knowledge_answer_index: int | None = Field(default=None, ge=0)

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

    @field_validator("knowledge_question")
    @classmethod
    def _knowledge_question_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or "\x00" in normalized:
            raise ValueError("knowledge question must contain bounded text")
        return normalized

    @field_validator("knowledge_options")
    @classmethod
    def _knowledge_options_text(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized: list[str] = []
        seen: set[str] = set()
        for option in value:
            cleaned = option.strip()
            if not cleaned or "\x00" in cleaned:
                raise ValueError("knowledge options must contain bounded text")
            if len(cleaned) > _KNOWLEDGE_OPTION_MAX:
                raise ValueError("knowledge option exceeds the length bound")
            folded = cleaned.casefold()
            if folded in seen:
                raise ValueError("knowledge options must be distinct")
            seen.add(folded)
            normalized.append(cleaned)
        return normalized

    @field_validator("knowledge_options")
    @classmethod
    def _knowledge_options_minimum(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(value) < _KNOWLEDGE_OPTIONS_MIN:
            raise ValueError("at least two knowledge options are required")
        return value

    @model_validator(mode="after")
    def _knowledge_check_all_or_nothing(self) -> TrainingResourceCreate:
        present = [
            self.knowledge_question is not None,
            self.knowledge_options is not None,
            self.knowledge_answer_index is not None,
        ]
        if any(present) and not all(present):
            raise ValueError("knowledge question, options, and answer index must be provided together")
        if (
            self.knowledge_answer_index is not None
            and self.knowledge_options is not None
            and self.knowledge_answer_index >= len(self.knowledge_options)
        ):
            raise ValueError("knowledge answer index is out of range")
        return self


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
        "has_knowledge_check": resource.knowledge_question is not None,
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
    view: dict[str, object] = {
        **_summary(resource, principal),
        "content": resource.content,
        "content_type": "text/plain",
        "html_execution": False,
    }
    if resource.knowledge_question is not None:
        # The operator preview is capability-gated and reviewer-facing; it may
        # show the correct-answer index so the independent reviewer can verify
        # the check. The public tracking page never receives it.
        view["knowledge_check"] = {
            "question": resource.knowledge_question,
            "options": resource.knowledge_options or [],
            "answer_index": resource.knowledge_answer_index,
        }
    return view


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
        knowledge_question=body.knowledge_question,
        knowledge_options=body.knowledge_options,
        knowledge_answer_index=body.knowledge_answer_index,
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
        detail={
            "source_ref": resource.source_ref,
            "content_type": "text/plain",
            "has_knowledge_check": resource.knowledge_question is not None,
        },
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


class TrainingDraftFromCampaign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: uuid.UUID


def _campaign_evidence(
    session: Session,
    campaign_id: uuid.UUID,
) -> tuple[Campaign, TemplateVersion, CampaignPattern]:
    """Load a campaign and its reviewed template/pattern, or fail closed.

    A knowledge check may only be drafted from evidence that already passed
    the content review gate. A campaign without an approved template is not
    evidence of anything, so the draft is refused rather than guessed.
    """

    campaign = session.get(Campaign, campaign_id)
    if campaign is None:
        raise NotFoundError("campaign not found")
    template = (
        session.get(TemplateVersion, campaign.current_template_id) if campaign.current_template_id is not None else None
    )
    pattern = session.get(CampaignPattern, campaign.pattern_id)
    if template is None or template.approval_state is not dm.TemplateApprovalState.APPROVED:
        raise ConflictError("campaign has no approved template to draft from")
    if pattern is None:
        raise ConflictError("campaign pattern is unavailable")
    return campaign, template, pattern


def _draft_lesson_payload(
    template: TemplateVersion,
    pattern: CampaignPattern,
) -> dict[str, object]:
    """Deterministically derive one bounded lesson + knowledge check draft.

    The lesson title and content are composed from the approved template's
    bounded training evidence; the knowledge check is built by the shared
    deterministic builder. Everything is bounded and sanitized before it is
    offered to the operator for review.
    """

    check = build_knowledge_check_draft(
        requested_action=pattern.requested_action,
        lure_category=pattern.lure_category.value if pattern.lure_category is not None else None,
        emotional_triggers=pattern.emotional_triggers or [],
        training_explanation=template.training_explanation,
    )
    title = f"Responding to {check.question}"[:160]
    explanation = (template.training_explanation or "").strip()[:8000]
    cues = "; ".join(
        str(cue).strip()[:200] for cue in (template.warning_cues or [])[:5] if isinstance(cue, str) and cue.strip()
    )[:4000]
    content_parts = [part for part in (explanation, cues) if part]
    fallback = (
        "Pause before acting on an unexpected request. Verify it through a trusted, independent channel, "
        "and report suspicious messages to your security team."
    )
    content = ("\n\n".join(content_parts) if content_parts else fallback)[:20_000]
    return {
        "title": title,
        "content": content,
        "content_type": "text/plain",
        "knowledge_check": check.as_dict(),
        "basis": {
            "template_version_id": str(template.template_version_id),
            "pattern_id": str(pattern.campaign_pattern_id),
            "builder": "deterministic-training-builder-v1",
        },
    }


@router.post("/campaigns/{campaign_id}/training-draft", status_code=status.HTTP_200_OK)
def draft_campaign_training(
    campaign_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, object]:
    """Return a deterministic lesson + knowledge-check draft from evidence.

    Read-only and advisory: the draft is offered to the operator for review
    and must be saved through the normal create/submit/approve flow. Nothing
    is created, bound, or approved here, and the answer index is only ever
    returned to this capability-gated operator endpoint.
    """
    del principal
    _, template, pattern = _campaign_evidence(session, campaign_id)
    return _draft_lesson_payload(template, pattern)
