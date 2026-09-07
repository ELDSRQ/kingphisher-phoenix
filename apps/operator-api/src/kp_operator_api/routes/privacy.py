"""Privacy-request lifecycle routes and recipient erasure."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import (
    PrivacyNotice,
    PrivacyRequest,
    Recipient,
    TrackingEvent,
)
from kp_database.privacy import (
    VERIFIED_PRIVACY_STATES,
    PrivacyRequestStatus,
    erase_recipient_data,
    hash_mailbox,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
)
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.routes.shared import (
    _normalize_mailbox,
)

router = APIRouter(prefix="/api/v1")

_PRIVACY_SLA_DAYS = 45


class PrivacyRequestCreate(BaseModel):
    request_type: dm.PrivacyRequestType
    requester_mailbox: str = Field(min_length=3, max_length=320)
    campaign_id: uuid.UUID | None = None

    @field_validator("requester_mailbox")
    @classmethod
    def normalize_requester_mailbox(cls, value: str) -> str:
        return _normalize_mailbox(value, max_length=320)


class PrivacyVerification(BaseModel):
    method: str = Field(min_length=1, max_length=64)
    evidence_ref: str = Field(min_length=1, max_length=255)


class PrivacyFulfillment(BaseModel):
    note: str = Field(default="", max_length=2000)
    corrections: dict[str, str | None] | None = None

    @field_validator("corrections")
    @classmethod
    def validate_corrections(cls, value: dict[str, str | None] | None) -> dict[str, str | None] | None:
        if value is None:
            return None
        allowed = {"employee_key", "mailbox", "display_name", "department"}
        if not value or not set(value).issubset(allowed):
            raise ValueError("corrections must contain only supported recipient fields")
        normalized: dict[str, str | None] = {}
        for field_name, field_value in value.items():
            if field_name == "mailbox":
                if field_value is None:
                    raise ValueError("mailbox cannot be empty")
                normalized[field_name] = _normalize_mailbox(field_value, max_length=320)
                continue
            if field_name == "employee_key":
                if field_value is None or not field_value.strip() or len(field_value.strip()) > 256:
                    raise ValueError("employee_key must contain at most 256 characters")
                normalized[field_name] = field_value.strip()
                continue
            if field_value is not None and len(field_value.strip()) > 256:
                raise ValueError(f"{field_name} must contain at most 256 characters")
            normalized[field_name] = field_value.strip() or None if field_value is not None else None
        return normalized


@router.get("/privacy/notice")
def get_privacy_notice(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    notice = session.scalar(select(PrivacyNotice).where(PrivacyNotice.is_current.is_(True)).limit(1))
    if notice is None:
        raise NotFoundError("no current privacy notice")
    return {
        "version": notice.version,
        "notice_text": notice.notice_text,
        "effective_at": notice.effective_at,
    }


@router.get("/privacy/requests")
def list_privacy_requests(
    response: Response,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> list[dict[str, Any]]:
    # This response includes requester mailboxes and case notes.  Prevent
    # browser and intermediary caches from retaining that personal data.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    rows = (
        session.execute(
            select(PrivacyRequest)
            .order_by(PrivacyRequest.opened_at.desc(), PrivacyRequest.privacy_request_id)
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return [
        {
            "privacy_request_id": str(r.privacy_request_id),
            "request_type": r.request_type.value,
            "requester_mailbox": r.requester_key,
            "status": r.status,
            "opened_at": r.opened_at,
            "sla_deadline": r.sla_deadline,
            "completed_at": r.completed_at,
            "completion_note": r.completion_note,
        }
        for r in rows
    ]


@router.post("/privacy/requests", status_code=status.HTTP_201_CREATED)
def submit_privacy_request(
    body: PrivacyRequestCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    opened_at = datetime.now(UTC)
    request = PrivacyRequest(
        privacy_request_id=uuid.uuid4(),
        request_type=body.request_type,
        requester_key=body.requester_mailbox,
        campaign_id=body.campaign_id,
        status="opened",
        opened_at=opened_at,
        sla_deadline=opened_at + timedelta(days=_PRIVACY_SLA_DAYS),
    )
    session.add(request)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="privacy_request.submit",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "request_type": body.request_type.value,
            "campaign_id": str(body.campaign_id) if body.campaign_id else None,
            "sla_deadline": request.sla_deadline.isoformat(),
        },
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "sla_deadline": request.sla_deadline,
    }


@router.post("/privacy/requests/{request_id}/verify")
def verify_privacy_request(
    request_id: uuid.UUID,
    body: PrivacyVerification,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status != PrivacyRequestStatus.OPENED.value:
        raise ConflictError("only an opened privacy request can be verified")
    request.status = PrivacyRequestStatus.VERIFIED.value
    request.verified_at = datetime.now(UTC)
    request.verification_method = body.method
    request.verification_evidence_ref = body.evidence_ref
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="privacy_request.verify",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "verified_at": request.verified_at,
    }


def _recipients_for_request(
    session: Session,
    settings: OperatorApiSettings,
    request: PrivacyRequest,
    *,
    max_rows: int | None = None,
) -> list[Recipient]:
    salt = settings.require_recipient_hash_salt()
    mailbox = request.requester_key
    if not mailbox:
        return []
    digest = hash_mailbox(mailbox, salt)
    statement = select(Recipient).where(Recipient.mailbox_sha256 == digest)
    if max_rows is not None:
        statement = statement.limit(max_rows + 1)
    rows = list(session.execute(statement).scalars().all())
    if max_rows is not None and len(rows) > max_rows:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="privacy export recipients exceed the supported single-response boundary",
        )
    return rows


_PRIVACY_EXPORT_RECORD_LIMIT = 10_000


def _bounded_privacy_export_rows(session: Session, statement: Any, *, label: str) -> list[Any]:
    """Materialize one export collection without allowing unbounded JSON."""

    rows = list(session.scalars(statement.limit(_PRIVACY_EXPORT_RECORD_LIMIT + 1)))
    if len(rows) > _PRIVACY_EXPORT_RECORD_LIMIT:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"privacy export {label} exceed the supported single-response boundary",
        )
    return rows


@router.post("/privacy/requests/{request_id}/export")
def export_privacy_request(
    request_id: uuid.UUID,
    response: Response,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.HANDLE_PRIVACY)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status not in VERIFIED_PRIVACY_STATES:
        raise ConflictError("privacy request must be verified before export")
    recipients = _recipients_for_request(
        session,
        settings,
        request,
        max_rows=_PRIVACY_EXPORT_RECORD_LIMIT,
    )
    from kp_database.models import RecipientAssignment, RecipientExclusion, TrackingToken, TrainingAssignment

    recipient_ids = [recipient.recipient_id for recipient in recipients]
    assignments = (
        _bounded_privacy_export_rows(
            session,
            select(RecipientAssignment).where(RecipientAssignment.recipient_id.in_(recipient_ids)),
            label="assignments",
        )
        if recipient_ids
        else []
    )
    assignment_ids = [assignment.recipient_assignment_id for assignment in assignments]
    tokens = (
        _bounded_privacy_export_rows(
            session,
            select(TrackingToken).where(TrackingToken.recipient_assignment_id.in_(assignment_ids)),
            label="tracking tokens",
        )
        if assignment_ids
        else []
    )
    token_ids = [token.token_id for token in tokens]
    events = (
        _bounded_privacy_export_rows(
            session,
            select(TrackingEvent).where(
                (TrackingEvent.recipient_id.in_(recipient_ids)) | (TrackingEvent.token_id.in_(token_ids))
            ),
            label="tracking events",
        )
        if recipient_ids or token_ids
        else []
    )
    training = (
        _bounded_privacy_export_rows(
            session,
            select(TrainingAssignment).where(TrainingAssignment.recipient_id.in_(recipient_ids)),
            label="training assignments",
        )
        if recipient_ids
        else []
    )
    exclusions = (
        _bounded_privacy_export_rows(
            session,
            select(RecipientExclusion).where(RecipientExclusion.recipient_id.in_(recipient_ids)),
            label="recipient exclusions",
        )
        if recipient_ids
        else []
    )
    request.exported_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="privacy_request.export",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "recipients": len(recipients),
            "assignments": len(assignments),
            "events": len(events),
            "training_assignments": len(training),
            "exclusions": len(exclusions),
        },
    )
    session.commit()
    # This response contains the data subject's identity and activity history.
    # Keep it out of browser, proxy, and intermediary caches even when a
    # deployment later introduces an otherwise cache-friendly API gateway.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "request_type": request.request_type.value,
        "records": [
            {
                "recipient_id": str(r.recipient_id),
                "mailbox": r.mailbox,
                "employee_key": r.employee_key,
                "display_name": r.display_name,
                "department": r.department,
                "is_test_account": r.is_test_account,
            }
            for r in recipients
        ],
        "assignments": [
            {
                "recipient_assignment_id": str(row.recipient_assignment_id),
                "recipient_id": str(row.recipient_id),
                "campaign_id": str(row.campaign_id),
                "send_state": row.send_state.value,
                "created_at": row.created_at,
            }
            for row in assignments
        ],
        "events": [
            {
                "event_id": str(row.event_id),
                "recipient_id": str(row.recipient_id) if row.recipient_id else None,
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "event_type": row.event_type.value,
                "confidence": row.confidence.value,
                "occurred_at": row.occurred_at,
                "payload": row.payload,
            }
            for row in events
        ],
        "training_assignments": [
            {
                "training_assignment_id": str(row.training_assignment_id),
                "recipient_id": str(row.recipient_id),
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "status": row.status.value,
                "assigned_at": row.assigned_at,
                "completed_at": row.completed_at,
            }
            for row in training
        ],
        "exclusions": [
            {
                "recipient_exclusion_id": str(row.recipient_exclusion_id),
                "recipient_id": str(row.recipient_id),
                "exclusion_type": row.exclusion_type.value,
                "campaign_id": str(row.campaign_id) if row.campaign_id else None,
                "reason": row.reason,
                "created_by": str(row.created_by) if row.created_by else None,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "revoked_at": row.revoked_at,
                "revoked_by": str(row.revoked_by) if row.revoked_by else None,
                "revoke_reason": row.revoke_reason,
            }
            for row in exclusions
        ],
    }


@router.post("/privacy/requests/{request_id}/fulfill")
def fulfill_privacy_request(
    request_id: uuid.UUID,
    body: PrivacyFulfillment,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    request = session.get(PrivacyRequest, request_id)
    if request is None:
        raise NotFoundError("privacy request not found")
    if request.status not in VERIFIED_PRIVACY_STATES:
        raise ConflictError("privacy request must be verified before fulfillment")
    if request.request_type == dm.PrivacyRequestType.EXCEPTION:
        raise HTTPException(status_code=422, detail="exception requests require documented legal review")
    if request.request_type == dm.PrivacyRequestType.ACCESS_EXPORT and request.exported_at is None:
        raise ConflictError("access export must be generated before fulfillment")
    note = body.note
    deleted = 0
    corrected = 0
    recipients = _recipients_for_request(session, settings, request)
    request.status = PrivacyRequestStatus.IN_PROGRESS.value
    if request.request_type == dm.PrivacyRequestType.DELETION:
        for recipient in recipients:
            deleted += int(erase_recipient_data(session, recipient.recipient_id, erased_at=datetime.now(UTC)))
        request.requester_key = f"erased-request-{request.privacy_request_id}"
    elif request.request_type == dm.PrivacyRequestType.CORRECTION:
        allowed = {"employee_key", "mailbox", "display_name", "department"}
        corrections = body.corrections or {}
        if not corrections or not set(corrections).issubset(allowed):
            raise HTTPException(status_code=422, detail="corrections must contain only supported recipient fields")
        for recipient in recipients:
            for field_name, value in corrections.items():
                if field_name == "mailbox":
                    if not value:
                        raise HTTPException(status_code=422, detail="mailbox cannot be empty")
                    recipient.mailbox = value
                    recipient.mailbox_sha256 = hash_mailbox(value, settings.require_recipient_hash_salt())
                else:
                    setattr(recipient, field_name, value)
            corrected += 1
    request.status = PrivacyRequestStatus.COMPLETED.value
    request.completed_at = datetime.now(UTC)
    request.completion_note = note
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="privacy_request.fulfill",
        object_type="privacy_request",
        object_id=str(request.privacy_request_id),
        detail={
            "request_type": request.request_type.value,
            "deleted": deleted,
            "corrected": corrected,
            "completion_note_provided": bool(note),
        },
    )
    session.commit()
    return {
        "privacy_request_id": str(request.privacy_request_id),
        "status": request.status,
        "deleted": deleted,
        "corrected": corrected,
        "matched": len(recipients),
        "sla_deadline": request.sla_deadline,
    }


@router.delete("/recipients/{recipient_id}", status_code=status.HTTP_200_OK)
def delete_recipient(
    recipient_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    erase_recipient_data(session, recipient.recipient_id, erased_at=datetime.now(UTC))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.delete",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
    )
    session.commit()
    return {"recipient_id": str(recipient.recipient_id), "deleted_at": recipient.deleted_at}
