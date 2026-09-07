"""Campaign-pattern and template approval routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.audit_store import AuditStore
from kp_database.campaign_service import (
    template_content_approval_hash,
)
from kp_database.models import (
    CampaignPattern,
    Source,
    SourceItem,
    SourceTerms,
    TemplateVersion,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_domain_models import models as dm
from kp_domain_models.source_governance import source_governance_is_current
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    SafetyRejectionError,
    ValidationError_,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.routes.shared import (
    _principal_uuid,
)
from kp_operator_api.sending_domains_roe import (
    _GUI_COLLECTION_MAX_OFFSET,
)

router = APIRouter(prefix="/api/v1")


def _pattern_source_item_id(pattern: CampaignPattern) -> uuid.UUID | None:
    """Return validated source provenance without acquiring database locks."""

    attack_mapping = pattern.attack_mapping
    if not isinstance(attack_mapping, dict) or "source_item_id" not in attack_mapping:
        return None
    raw_source_item_id = attack_mapping.get("source_item_id")
    if not isinstance(raw_source_item_id, str):
        raise SafetyRejectionError("pattern source evidence is unavailable or not active")
    try:
        return uuid.UUID(raw_source_item_id)
    except ValueError as exc:
        raise SafetyRejectionError("pattern source evidence is unavailable or not active") from exc


def _require_active_pattern_source(session: Session, pattern: CampaignPattern) -> uuid.UUID | None:
    """Fail closed when a source-backed pattern no longer has curated evidence.

    Manually authored patterns have no ``source_item_id`` provenance and retain
    their existing review path. Ingested and cloned source-backed patterns keep
    that identifier in ``attack_mapping``; approval rechecks the authoritative
    source row so a later quarantine, rejection, or duplicate decision cannot
    be bypassed through an older draft.
    """

    source_item_id = _pattern_source_item_id(pattern)
    if source_item_id is None:
        return None
    source_item = session.get(SourceItem, source_item_id, with_for_update=True)
    if (
        source_item is None
        or source_item.quarantine_state != dm.QuarantineState.ACTIVE
        or source_item.duplicate_of is not None
    ):
        raise SafetyRejectionError("pattern source evidence is unavailable or not active")
    source = session.get(Source, source_item.source_id, with_for_update=True, populate_existing=True)
    terms = (
        session.get(
            SourceTerms,
            source.license_state_id,
            with_for_update=True,
            populate_existing=True,
        )
        if source is not None and source.license_state_id is not None
        else None
    )
    if source is None or not source_governance_is_current(
        source,
        terms,
        evidence_license_state_id=source_item.license_state_id,
        as_of=datetime.now(UTC),
    ):
        raise SafetyRejectionError("pattern source governance is not current")
    return source_item_id


@router.post("/patterns/{pattern_id}/approve", status_code=status.HTTP_200_OK)
def approve_pattern(
    pattern_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_PATTERN)),
) -> dict[str, Any]:
    # Source-backed review and threat curation use the same source-then-pattern
    # lock order. The initial read discovers provenance only; the locked reload
    # below is authoritative and must still match it.
    pattern_snapshot = session.get(CampaignPattern, pattern_id)
    if pattern_snapshot is None:
        raise NotFoundError("pattern not found")
    source_item_id = _require_active_pattern_source(session, pattern_snapshot)
    pattern = session.get(
        CampaignPattern,
        pattern_id,
        with_for_update=True,
        populate_existing=True,
    )
    if pattern is None:
        raise NotFoundError("pattern not found")
    if _pattern_source_item_id(pattern) != source_item_id:
        raise ConflictError("pattern source evidence changed; review again")
    principal_id = _principal_uuid(principal)
    if pattern.created_by == principal_id:
        raise PermissionDeniedError("self-approval of your own pattern is prohibited")
    if pattern.approval_state not in {dm.PatternApprovalState.DRAFT, dm.PatternApprovalState.PENDING}:
        raise ConflictError("pattern is not awaiting approval")
    if pattern.prohibited_content_indicators:
        raise SafetyRejectionError("pattern contains prohibited-content indicators and cannot be approved")
    pattern.approval_state = dm.PatternApprovalState.APPROVED
    pattern.approved_by = principal_id
    pattern.approved_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="pattern.approve",
        object_type="campaign_pattern",
        object_id=str(pattern_id),
    )
    # Nothing published to the generate topic, so the generation worker idled
    # forever and approved patterns never became draft templates (P-1). Approval
    # is the trigger: a pattern a human has vouched for is what we are willing
    # to build training content from. `requested_by` lets the template record who
    # set generation in motion, so that person cannot also approve the result.
    enqueue_queue(
        session,
        topic="generate",
        payload={"pattern_id": str(pattern_id), "requested_by": principal.principal_id},
        idempotency_key=f"generate:{pattern_id}:{pattern.pattern_version}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    session.commit()
    return {
        "campaign_pattern_id": str(pattern_id),
        "approval_state": pattern.approval_state.value,
        # This response describes the durable fact established by this
        # transaction. Queue dispatch and provider execution are asynchronous;
        # claiming either completed here hid missing managed generation roles.
        "generation_request_recorded": True,
    }


class TemplateDecision(BaseModel):
    decision: dm.ApprovalDecision
    rationale: str = Field(min_length=1, max_length=2000)


_INCOMPLETE_TEMPLATE_CONTENT = "template content is incomplete or not recipient-bound"


def _require_approvable_template_content(template: TemplateVersion) -> None:
    """Reject canonical content that cannot bind a recipient training route."""

    subject = template.subject
    plain_text = template.plain_text
    safe_html = template.safe_html
    if not isinstance(subject, str) or not subject.strip():
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if not isinstance(plain_text, str) or not plain_text.strip() or TRAINING_URL_PLACEHOLDER not in plain_text:
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if safe_html is not None and not isinstance(safe_html, str):
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)
    if isinstance(safe_html, str) and safe_html.strip() and TRAINING_URL_PLACEHOLDER not in safe_html:
        raise ValidationError_(_INCOMPLETE_TEMPLATE_CONTENT)


@router.post("/templates/{template_version_id}/decision", status_code=status.HTTP_200_OK)
def decide_template(
    template_version_id: uuid.UUID,
    body: TemplateDecision,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> dict[str, Any]:
    """Approve or reject AI-generated content before it can be used.

    This is the human gate on the generation pipeline. Until a template leaves
    DRAFT nothing can schedule it, so an unreviewed model output cannot reach a
    recipient.
    """
    template = session.get(TemplateVersion, template_version_id)
    if template is None:
        raise NotFoundError("template not found")
    if template.approval_state != dm.TemplateApprovalState.DRAFT:
        raise ConflictError(f"template is already {template.approval_state.value}")

    # Whoever asked for the content must not be the one who signs it off. The
    # requester is recorded at generation time; when it is unknown (older rows,
    # or a self-published job) we cannot check, and say so in the audit trail.
    requested_by = (template.raw_proposal or {}).get("requested_by")
    if requested_by and str(requested_by) == principal.principal_id:
        raise PermissionDeniedError(
            "you requested this generation; approval of AI-generated content must come from someone else"
        )

    approved = body.decision == dm.ApprovalDecision.APPROVED
    if approved:
        # Only canonical reviewed columns are deliverable. Legacy rows that
        # carry usable-looking raw proposals but no canonical content remain
        # rejectable, but cannot be promoted into the delivery path.
        _require_approvable_template_content(template)
        template.approval_hash = template_content_approval_hash(template)
    template.approval_state = dm.TemplateApprovalState.APPROVED if approved else dm.TemplateApprovalState.REJECTED
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"template.{'approve' if approved else 'reject'}",
        object_type="template",
        object_id=str(template_version_id),
        detail={
            "rationale": body.rationale,
            "requester_known": bool(requested_by),
        },
    )
    session.commit()
    return {
        "template_version_id": str(template_version_id),
        "approval_state": template.approval_state.value,
    }


@router.get("/templates/pending", status_code=status.HTTP_200_OK)
def list_pending_templates(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> list[dict[str, Any]]:
    """Drafts awaiting human review, newest first."""
    rows = session.scalars(
        select(TemplateVersion)
        .where(TemplateVersion.approval_state == dm.TemplateApprovalState.DRAFT)
        .order_by(TemplateVersion.template_version_id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        {
            "template_version_id": str(row.template_version_id),
            "model_id": row.model_id,
            "subject": (row.raw_proposal or {}).get("subject", ""),
            "plain_text": (row.raw_proposal or {}).get("plain_text", ""),
            "requested_by": (row.raw_proposal or {}).get("requested_by"),
            "context_untrusted": bool((row.raw_proposal or {}).get("context_untrusted")),
            "neutralization_reasons": (row.raw_proposal or {}).get("neutralization_reasons", []),
        }
        for row in rows
    ]
