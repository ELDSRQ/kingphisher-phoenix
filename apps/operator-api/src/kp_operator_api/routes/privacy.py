"""Privacy-request lifecycle routes and recipient erasure."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.awareness_ledger import LedgerRecipientHistoryEntry, ledger_recipient_history
from kp_database.models import (
    PrivacyNotice,
    PrivacyRequest,
    Recipient,
    TrackingEvent,
)
from kp_database.personal_data import exported_store_names
from kp_database.privacy import (
    VERIFIED_PRIVACY_STATES,
    PrivacyRequestStatus,
    erase_recipient_data,
    hash_mailbox,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
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


#: Marker reason when the governed awareness-ledger pseudonym key is unset or
#: malformed (managed mode). The export stays 200 and fails closed: the ledger
#: section is flagged unavailable rather than crashing the whole DSR export.
LEDGER_UNAVAILABLE_PSEUDONYM_CONFIG = "ledger_pseudonym_key_unavailable"


@dataclass
class _PrivacyExportData:
    """Collected, subject-scoped rows for one DSR access export.

    One field per exported personal-data store (see
    :mod:`kp_database.personal_data`). ``awareness_ledger`` holds the subject's
    own pseudonymous ledger outcomes resolved via :func:`ledger_recipient_history`;
    it carries no recipient attribute and never the raw pseudonym. The ledger is
    pseudonymous, not anonymous (see the registry note in
    :mod:`kp_database.personal_data`).

    ``awareness_ledger_available`` is False when the governed pseudonym key could
    not be resolved; ``awareness_ledger_truncated`` is True when any recipient's
    history hit the per-recipient cap so the disclosed entries are incomplete.
    """

    recipients: Sequence[Recipient] = field(default_factory=list)
    assignments: Sequence[Any] = field(default_factory=list)
    events: Sequence[Any] = field(default_factory=list)
    training: Sequence[Any] = field(default_factory=list)
    exclusions: Sequence[Any] = field(default_factory=list)
    reported_receipts: Sequence[Any] = field(default_factory=list)
    reply_receipts: Sequence[Any] = field(default_factory=list)
    awareness_ledger: Sequence[LedgerRecipientHistoryEntry] = field(default_factory=list)
    awareness_ledger_available: bool = True
    awareness_ledger_truncated: bool = False
    awareness_ledger_unavailable_reason: str | None = None


def _serialize_receipt(row: Any) -> dict[str, Any]:
    """Minimized view of one mail receipt for the subject's own export.

    The encrypted external message id, its hash, provider scope, and evidence
    blob are operational/replay-boundary fields, not subject-facing content, so
    only the assignment linkage, disposition, and timestamp are disclosed.
    """

    return {
        "recipient_assignment_id": (str(row.recipient_assignment_id) if row.recipient_assignment_id else None),
        "disposition": row.disposition,
        "received_at": row.received_at,
    }


def _serialize_ledger_entry(entry: LedgerRecipientHistoryEntry) -> dict[str, Any]:
    return {
        "campaign_id": str(entry.campaign_id),
        "campaign_date": entry.campaign_date,
        "campaign_date_basis": entry.campaign_date_basis,
        "delivered": entry.delivered,
        "observed_open": entry.observed_open,
        "observed_click": entry.observed_click,
        "confirmed_interaction": entry.confirmed_interaction,
        "reported": entry.reported,
        "training_started": entry.training_started,
        "training_completed": entry.training_completed,
        "no_activity_at_close": entry.no_activity_at_close,
    }


def build_privacy_export_payload(
    *,
    privacy_request_id: str,
    request_type: str,
    data: _PrivacyExportData,
) -> dict[str, Any]:
    """Assemble the DSR access-export response from collected rows.

    Pure and database-free so the registry/export coverage invariant can be
    asserted hermetically: the returned dict carries one section per exported
    personal-data store registered in :mod:`kp_database.personal_data`.
    """

    payload: dict[str, Any] = {
        "privacy_request_id": privacy_request_id,
        "request_type": request_type,
        "records": [
            {
                "recipient_id": str(r.recipient_id),
                "mailbox": r.mailbox,
                "employee_key": r.employee_key,
                "display_name": r.display_name,
                "department": r.department,
                "is_test_account": r.is_test_account,
            }
            for r in data.recipients
        ],
        "assignments": [
            {
                "recipient_assignment_id": str(row.recipient_assignment_id),
                "recipient_id": str(row.recipient_id),
                "campaign_id": str(row.campaign_id),
                "send_state": row.send_state.value,
                "created_at": row.created_at,
            }
            for row in data.assignments
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
            for row in data.events
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
            for row in data.training
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
            for row in data.exclusions
        ],
        "reported_receipts": [_serialize_receipt(row) for row in data.reported_receipts],
        "reply_receipts": [_serialize_receipt(row) for row in data.reply_receipts],
        # Object (not a bare list) so the export can distinguish "no ledger
        # entries" from "ledger could not be resolved" and can flag truncation
        # instead of silently under-disclosing. ``entries`` carries only the
        # subject's pseudonymous outcomes, never the raw pseudonym.
        "awareness_ledger": {
            "available": data.awareness_ledger_available,
            "truncated": data.awareness_ledger_truncated,
            "unavailable_reason": data.awareness_ledger_unavailable_reason,
            "entries": [_serialize_ledger_entry(entry) for entry in data.awareness_ledger],
        },
    }
    # Fail closed if a newly registered exported store was not wired into this
    # payload (the coverage invariant behind KP-AUD-003). The hermetic test
    # catches this first; this assertion keeps production honest with -O off.
    missing = exported_store_names() - payload.keys()
    assert not missing, f"privacy export is missing registered personal-data stores: {sorted(missing)}"
    return payload


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
    from kp_database.models import (
        RecipientAssignment,
        RecipientExclusion,
        ReplyMailReceipt,
        ReportedMailReceipt,
        TrackingToken,
        TrainingAssignment,
    )

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
    # Reply and reported receipts link to the subject only through their
    # assignments; before KP-AUD-003 neither appeared in the export.
    reported_receipts = (
        _bounded_privacy_export_rows(
            session,
            select(ReportedMailReceipt).where(ReportedMailReceipt.recipient_assignment_id.in_(assignment_ids)),
            label="reported mail receipts",
        )
        if assignment_ids
        else []
    )
    reply_receipts = (
        _bounded_privacy_export_rows(
            session,
            select(ReplyMailReceipt).where(ReplyMailReceipt.recipient_assignment_id.in_(assignment_ids)),
            label="reply mail receipts",
        )
        if assignment_ids
        else []
    )
    # The awareness ledger holds no recipient/assignment foreign key; it is
    # resolved through the governed pseudonym key and returns only the subject's
    # pseudonymous campaign-level outcomes (never a recipient attribute or the
    # raw pseudonym). The ledger is pseudonymous, not anonymous.
    awareness_ledger: list[LedgerRecipientHistoryEntry] = []
    awareness_ledger_available = True
    awareness_ledger_truncated = False
    awareness_ledger_unavailable_reason: str | None = None
    if recipients:
        try:
            # Managed mode raises here when the pseudonym key is unset or
            # malformed. Fail closed on just the ledger section rather than
            # 500-ing the whole DSR access export: the subject still receives
            # every other store, and the ledger section is flagged unavailable.
            pseudonym_key, pseudonym_key_version = settings.require_awareness_pseudonym_config()
        except RuntimeError:
            awareness_ledger_available = False
            awareness_ledger_unavailable_reason = LEDGER_UNAVAILABLE_PSEUDONYM_CONFIG
        else:
            for recipient in recipients:
                history = ledger_recipient_history(
                    session,
                    tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
                    recipient_id=recipient.recipient_id,
                    pseudonym_key=pseudonym_key,
                    pseudonym_key_version=pseudonym_key_version,
                )
                awareness_ledger.extend(history.entries)
                # Surface under-disclosure: if any recipient's history hit the
                # per-recipient cap, the disclosed entries are incomplete.
                awareness_ledger_truncated = awareness_ledger_truncated or history.truncated
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
            "reported_receipts": len(reported_receipts),
            "reply_receipts": len(reply_receipts),
            "awareness_ledger": len(awareness_ledger),
            "awareness_ledger_available": awareness_ledger_available,
            "awareness_ledger_truncated": awareness_ledger_truncated,
        },
    )
    session.commit()
    # This response contains the data subject's identity and activity history.
    # Keep it out of browser, proxy, and intermediary caches even when a
    # deployment later introduces an otherwise cache-friendly API gateway.
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return build_privacy_export_payload(
        privacy_request_id=str(request.privacy_request_id),
        request_type=request.request_type.value,
        data=_PrivacyExportData(
            recipients=recipients,
            assignments=assignments,
            events=events,
            training=training,
            exclusions=exclusions,
            reported_receipts=reported_receipts,
            reply_receipts=reply_receipts,
            awareness_ledger=awareness_ledger,
            awareness_ledger_available=awareness_ledger_available,
            awareness_ledger_truncated=awareness_ledger_truncated,
            awareness_ledger_unavailable_reason=awareness_ledger_unavailable_reason,
        ),
    )


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
        # Fail closed before erasing: erasure must also purge the keyed-pseudonym
        # awareness ledger, which requires the active governed key. Resolving it
        # first means a missing/malformed key aborts the deletion rather than
        # leaving re-identifiable ledger rows behind (KP-AUD-003, Option A).
        pseudonym_key, pseudonym_key_version = settings.require_awareness_pseudonym_config()
        for recipient in recipients:
            deleted += int(
                erase_recipient_data(
                    session,
                    recipient.recipient_id,
                    erased_at=datetime.now(UTC),
                    pseudonym_key=pseudonym_key,
                    pseudonym_key_version=pseudonym_key_version,
                )
            )
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
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.DELETE_DATA)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    # Resolve the governed ledger key first so a missing key fails the delete
    # closed rather than leaving re-identifiable ledger rows (KP-AUD-003).
    pseudonym_key, pseudonym_key_version = settings.require_awareness_pseudonym_config()
    erase_recipient_data(
        session,
        recipient.recipient_id,
        erased_at=datetime.now(UTC),
        pseudonym_key=pseudonym_key,
        pseudonym_key_version=pseudonym_key_version,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.delete",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
    )
    session.commit()
    return {"recipient_id": str(recipient.recipient_id), "deleted_at": recipient.deleted_at}
