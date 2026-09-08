"""Recipient roster routes: listing, test-account designation, exclusions,
CSV import, and Microsoft 365 directory/reported-mail integration."""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.campaign_service import (
    _masked_mailbox,
)
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    Microsoft365IntegrationState,
    Recipient,
    RecipientAssignment,
    RecipientDeliverySuppression,
    RecipientExclusion,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_database.privacy import (
    hash_mailbox,
)
from kp_domain_models import models as dm
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_any_capability, require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.recipient_import_planning import (
    RecipientImportApplyRequest,
    RecipientImportPreviewRequest,
    RecipientsImport,
    _apply_recipient_import_plan,
    _recipient_import_audit_detail,
    _recipient_import_issues,
    _recipient_import_options,
    _recipient_import_plan,
    _recipient_import_preview_payload,
    _recipient_import_retryable_db_conflict,
    _rollback_recipient_import_conflict,
    _serialize_recipient_import_write,
)
from kp_operator_api.routes.shared import (
    _normalize_mailbox,
)

router = APIRouter(prefix="/api/v1")

_RECIPIENT_IMPORT_REPREVIEW_CONFLICT = "recipient state changed concurrently; preview the import again"


class DirectoryApply(BaseModel):
    preview_id: uuid.UUID


class ExclusionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    exclusion_type: dm.ExclusionType
    campaign_id: uuid.UUID | None = None
    reason: str = Field(min_length=1, max_length=500)
    expires_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("exclusion reason cannot be blank")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def require_future_aware_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("exclusion expiry must include a timezone offset")
        normalized = value.astimezone(UTC)
        if normalized <= datetime.now(UTC):
            raise ValueError("exclusion expiry must be in the future")
        return normalized


class ExclusionRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("exclusion revocation rationale cannot be blank")
        return normalized


@router.get("/recipients")
def list_recipients(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    mailbox: str | None = Query(default=None, max_length=320),
    session: Session = Depends(get_session),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_any_capability(Capability.VIEW_NAMED_RESULTS, Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    # Names appear ONLY for the capability literally named ``view_named:results``.
    # A ``manage:recipients`` holder (the campaign operator) sees the unchanged
    # department/uuid/status shape it was always meant to see. The mailbox is
    # never returned raw — only the same masked form the audience preview uses.
    can_view_named = principal.can(Capability.VIEW_NAMED_RESULTS)

    if mailbox is not None:
        # Exact-address lookup: hash the full address with the deployment salt
        # and match the indexed digest. No wildcard, no prefix, no LIKE — a
        # reader can only confirm an address they already typed in full.
        digest = hash_mailbox(_normalize_mailbox(mailbox, max_length=320), settings.require_recipient_hash_salt())
        rows = list(session.scalars(select(Recipient).where(Recipient.mailbox_sha256 == digest).limit(1)))
        total = len(rows)
        truncated = False
    else:
        total = int(session.scalar(select(func.count()).select_from(Recipient)) or 0)
        rows = list(session.scalars(select(Recipient).order_by(Recipient.recipient_id).offset(offset).limit(limit)))
        truncated = offset + len(rows) < total

    items: list[dict[str, Any]] = []
    for r in rows:
        item: dict[str, Any] = {
            "recipient_id": str(r.recipient_id),
            "department": r.department,
            "status": r.status.value,
            "is_test_account": r.is_test_account,
        }
        if can_view_named:
            item["display_name"] = r.display_name
            item["masked_mailbox"] = _masked_mailbox(r.mailbox)
        items.append(item)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "truncated": truncated,
    }


class TestAccountDesignation(BaseModel):
    is_test_account: StrictBool
    confirm: StrictBool = False
    reason: str = Field(min_length=1, max_length=500)


_CANARY_ELIGIBILITY_TERMINAL_STATES = frozenset(
    {
        dm.CampaignState.RECALLED,
        dm.CampaignState.RECALL_IN_PROGRESS,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.COMPLETED,
        dm.CampaignState.STOPPED,
        dm.CampaignState.REJECTED,
    }
)


@router.put("/recipients/{recipient_id}/test-account", status_code=status.HTTP_200_OK)
def designate_test_account(
    recipient_id: uuid.UUID,
    body: TestAccountDesignation,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    """Explicitly opt a recipient into or out of canary/test-send eligibility."""
    if not body.confirm:
        raise ValidationError_("test-account designation requires explicit confirmation (confirm=true)")
    reason = body.reason.strip()
    if not reason:
        raise ValidationError_("test-account designation requires a reason")

    recipient = session.get(Recipient, recipient_id, with_for_update=True)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    previous = bool(recipient.is_test_account)
    requested = body.is_test_account
    changed = previous != requested
    if changed:
        protected_campaign_id = session.scalar(
            select(Campaign.campaign_id)
            .outerjoin(CampaignAudience, CampaignAudience.campaign_id == Campaign.campaign_id)
            .outerjoin(
                CampaignAudienceManifest,
                and_(
                    CampaignAudienceManifest.campaign_id == Campaign.campaign_id,
                    CampaignAudienceManifest.recipient_id == recipient.recipient_id,
                ),
            )
            .outerjoin(
                RecipientAssignment,
                and_(
                    RecipientAssignment.campaign_id == Campaign.campaign_id,
                    RecipientAssignment.recipient_id == recipient.recipient_id,
                ),
            )
            .where(
                Campaign.state.not_in(_CANARY_ELIGIBILITY_TERMINAL_STATES),
                or_(
                    and_(
                        CampaignAudience.frozen_at.is_not(None),
                        CampaignAudienceManifest.recipient_id.is_not(None),
                    ),
                    RecipientAssignment.recipient_assignment_id.is_not(None),
                ),
            )
            .limit(1)
            .with_for_update(of=Campaign)
        )
        if protected_campaign_id is not None:
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.test-account.blocked",
                object_type="recipient",
                object_id=str(recipient.recipient_id),
                detail={
                    "old_is_test_account": previous,
                    "new_is_test_account": requested,
                    "changed": False,
                    "reason": reason,
                    "protected_campaign": True,
                },
            )
            session.commit()
            raise ConflictError(
                "test-account designation is locked while the recipient belongs to a frozen or assigned "
                "nonterminal campaign"
            )
        recipient.is_test_account = requested

    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.test-account.update",
        object_type="recipient",
        object_id=str(recipient.recipient_id),
        detail={
            "old_is_test_account": previous,
            "new_is_test_account": requested,
            "changed": changed,
            "reason": reason,
        },
    )
    session.commit()
    return {
        "recipient_id": str(recipient.recipient_id),
        "is_test_account": recipient.is_test_account,
        "changed": changed,
    }


@router.post("/recipients/{recipient_id}/exclusions", status_code=status.HTTP_201_CREATED)
def add_exclusion(
    recipient_id: uuid.UUID,
    body: ExclusionCreate,
    response: Response,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> dict[str, Any]:
    recipient = session.get(Recipient, recipient_id, with_for_update=True)
    if recipient is None or recipient.deleted_at is not None or recipient.status is not dm.RecipientStatus.ACTIVE:
        raise NotFoundError("recipient not found")
    campaign_specific = body.exclusion_type is dm.ExclusionType.CAMPAIGN_SPECIFIC
    if campaign_specific != (body.campaign_id is not None):
        raise ValidationError_("campaign-specific exclusions require exactly one campaign")
    if body.campaign_id is not None and session.get(Campaign, body.campaign_id) is None:
        raise NotFoundError("campaign not found")
    now = datetime.now(UTC)
    if body.expires_at is not None and body.expires_at <= now:
        raise ValidationError_("exclusion expiry must be in the future")
    scope = (
        RecipientExclusion.campaign_id == body.campaign_id
        if body.campaign_id is not None
        else RecipientExclusion.campaign_id.is_(None)
    )
    existing = session.scalar(
        select(RecipientExclusion)
        .where(
            RecipientExclusion.recipient_id == recipient.recipient_id,
            RecipientExclusion.exclusion_type == body.exclusion_type,
            scope,
            RecipientExclusion.revoked_at.is_(None),
            RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > now),
        )
        .order_by(RecipientExclusion.created_at.desc())
        .limit(1)
        .with_for_update()
    )
    created = existing is None
    if existing is not None:
        exclusion = existing
        response.status_code = status.HTTP_200_OK
    else:
        exclusion = RecipientExclusion(
            recipient_exclusion_id=uuid.uuid4(),
            recipient_id=recipient.recipient_id,
            exclusion_type=body.exclusion_type,
            campaign_id=body.campaign_id,
            reason=body.reason,
            created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
            expires_at=body.expires_at,
        )
        session.add(exclusion)
    # Expire any still-QUEUED assignments for this recipient so an exclusion
    # added after publication actually prevents the send. A campaign-specific
    # exclusion only retires that campaign's queue; a global one retires every
    # campaign's. Claimed (SENDING) or terminal assignments are left untouched:
    # the delivery worker owns an in-flight attempt, and re-checks the active
    # exclusion set itself before contacting the provider.
    expiry_scope = [
        RecipientAssignment.recipient_id == recipient.recipient_id,
        RecipientAssignment.send_state == dm.SendState.QUEUED,
    ]
    if body.campaign_id is not None:
        expiry_scope.append(RecipientAssignment.campaign_id == body.campaign_id)
    expiring_assignments = list(session.scalars(select(RecipientAssignment).where(*expiry_scope)))
    for expiring in expiring_assignments:
        expiring.send_state = dm.SendState.EXPIRED
        expiring.failure_reason = "recipient_excluded"
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.exclude",
        object_type="recipient",
        object_id=str(recipient_id),
        detail={
            "exclusion_type": body.exclusion_type.value,
            "campaign_id": str(body.campaign_id) if body.campaign_id else None,
            "created": created,
            "expired_queued": len(expiring_assignments),
        },
    )
    session.commit()
    return {"recipient_exclusion_id": str(exclusion.recipient_exclusion_id), "created": created}


def _recipient_exclusion_payload(exclusion: RecipientExclusion, *, now: datetime) -> dict[str, Any]:
    active = exclusion.revoked_at is None and (exclusion.expires_at is None or exclusion.expires_at > now)
    return {
        "recipient_exclusion_id": str(exclusion.recipient_exclusion_id),
        "recipient_id": str(exclusion.recipient_id),
        "exclusion_type": exclusion.exclusion_type.value,
        "campaign_id": str(exclusion.campaign_id) if exclusion.campaign_id else None,
        "reason": exclusion.reason[:500] if exclusion.reason else None,
        "created_by": str(exclusion.created_by) if exclusion.created_by else None,
        "created_at": exclusion.created_at,
        "expires_at": exclusion.expires_at,
        "active": active,
        "revoked_at": exclusion.revoked_at,
        "revoked_by": str(exclusion.revoked_by) if exclusion.revoked_by else None,
        "revoke_reason": exclusion.revoke_reason[:500] if exclusion.revoke_reason else None,
    }


@router.get("/recipients/{recipient_id}/exclusions", status_code=status.HTTP_200_OK)
def list_recipient_exclusions(
    recipient_id: uuid.UUID,
    include_inactive: bool = False,
    limit: int = Query(default=50, ge=1, le=100),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> list[dict[str, Any]]:
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.deleted_at is not None:
        raise NotFoundError("recipient not found")
    now = datetime.now(UTC)
    active_predicate = and_(
        RecipientExclusion.revoked_at.is_(None),
        RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > now),
    )
    active = list(
        session.scalars(
            select(RecipientExclusion)
            .where(RecipientExclusion.recipient_id == recipient_id, active_predicate)
            .order_by(RecipientExclusion.created_at.desc())
            .limit(limit)
        )
    )
    rows = active
    if include_inactive and len(rows) < limit:
        inactive = list(
            session.scalars(
                select(RecipientExclusion)
                .where(RecipientExclusion.recipient_id == recipient_id, ~active_predicate)
                .order_by(RecipientExclusion.created_at.desc())
                .limit(limit - len(rows))
            )
        )
        rows = [*active, *inactive]
    return [_recipient_exclusion_payload(row, now=now) for row in rows]


@router.post(
    "/recipients/{recipient_id}/exclusions/{exclusion_id}/revoke",
    status_code=status.HTTP_200_OK,
)
def revoke_recipient_exclusion(
    recipient_id: uuid.UUID,
    exclusion_id: uuid.UUID,
    body: ExclusionRevoke,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_EXCLUSIONS)),
) -> dict[str, Any]:
    if not body.confirm:
        raise ValidationError_("exclusion revocation requires explicit confirmation (confirm=true)")
    exclusion = session.scalar(
        select(RecipientExclusion)
        .where(
            RecipientExclusion.recipient_exclusion_id == exclusion_id,
            RecipientExclusion.recipient_id == recipient_id,
        )
        .with_for_update()
    )
    if exclusion is None:
        raise NotFoundError("recipient exclusion not found")
    changed = exclusion.revoked_at is None
    if changed:
        exclusion.revoked_at = datetime.now(UTC)
        exclusion.revoked_by = uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None
        exclusion.revoke_reason = body.rationale
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.exclusion.revoke",
        object_type="recipient",
        object_id=str(recipient_id),
        detail={
            "recipient_exclusion_id": str(exclusion_id),
            "exclusion_type": exclusion.exclusion_type.value,
            "campaign_id": str(exclusion.campaign_id) if exclusion.campaign_id else None,
            "changed": changed,
        },
    )
    session.commit()
    return {
        "recipient_exclusion_id": str(exclusion.recipient_exclusion_id),
        "active": False,
        "changed": changed,
        "revoked_at": exclusion.revoked_at,
    }


# --- Delivery suppression admin override ---


class SuppressionDeactivate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: StrictBool
    rationale: str = Field(min_length=1, max_length=500)

    @field_validator("rationale")
    @classmethod
    def normalize_rationale(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("suppression deactivation rationale cannot be blank")
        return normalized


@router.get(
    "/recipients/{recipient_id}/suppression",
    status_code=status.HTTP_200_OK,
)
def get_recipient_suppression(
    recipient_id: uuid.UUID,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.MANAGE_SUPPRESSIONS)),
) -> dict[str, Any]:
    suppression = session.scalar(
        select(RecipientDeliverySuppression).where(
            RecipientDeliverySuppression.recipient_id == recipient_id,
        )
    )
    if suppression is None:
        raise NotFoundError("no delivery suppression recorded for this recipient")
    return {
        "recipient_id": str(suppression.recipient_id),
        "provider": suppression.provider,
        "reason": suppression.reason,
        "active": suppression.active,
        "source_event_hash": suppression.source_event_hash,
        "created_at": suppression.created_at.isoformat(),
        "updated_at": suppression.updated_at.isoformat(),
    }


@router.post(
    "/recipients/{recipient_id}/suppression/deactivate",
    status_code=status.HTTP_200_OK,
)
def deactivate_recipient_suppression(
    recipient_id: uuid.UUID,
    body: SuppressionDeactivate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SUPPRESSIONS)),
) -> dict[str, Any]:
    if not body.confirm:
        raise ValidationError_("suppression deactivation requires explicit confirmation (confirm=true)")
    recipient = session.get(Recipient, recipient_id)
    if recipient is None or recipient.status == dm.RecipientStatus.DEPARTED:
        raise NotFoundError("recipient not found")
    suppression = session.scalar(
        select(RecipientDeliverySuppression)
        .where(RecipientDeliverySuppression.recipient_id == recipient_id)
        .with_for_update()
    )
    if suppression is None:
        raise NotFoundError("no delivery suppression recorded for this recipient")
    changed = suppression.active
    if changed:
        suppression.active = False
        suppression.updated_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.suppression.deactivate",
        object_type="recipient",
        object_id=str(recipient_id),
        detail={
            "provider": suppression.provider,
            "reason": suppression.reason,
            "changed": changed,
            "rationale_length": len(body.rationale),
        },
    )
    session.commit()
    return {
        "recipient_id": str(suppression.recipient_id),
        "active": False,
        "changed": changed,
        "deactivated_at": suppression.updated_at.isoformat() if changed else None,
    }


@router.post("/recipients/import/preview", status_code=status.HTTP_200_OK)
def preview_recipients_csv(
    body: RecipientImportPreviewRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    plan = _recipient_import_plan(body, session, settings, lock_rows=False)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="recipient.import.preview",
        object_type="recipients",
        object_id="csv",
        detail=_recipient_import_audit_detail(body, plan),
    )
    session.commit()
    return _recipient_import_preview_payload(body, plan)


@router.post("/recipients/import/apply", status_code=status.HTTP_200_OK)
def apply_recipients_csv(
    body: RecipientImportApplyRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    if body.deactivate_missing and not body.deactivate_missing_confirm:
        raise ValidationError_("deactivate-missing requires a second explicit confirmation")
    try:
        with _serialize_recipient_import_write(session):
            plan = _recipient_import_plan(body, session, settings, lock_rows=True)
            if not hmac.compare_digest(body.preview_digest, plan.digest):
                raise ConflictError(
                    "CSV, import options, recipient state, or domain policy changed; preview the import again"
                )
            if not plan.can_apply:
                raise ConflictError(
                    "deactivate-missing requires a clean preview with no blocked, invalid, or duplicate rows"
                )
            _apply_recipient_import_plan(plan, session)
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.import.apply",
                object_type="recipients",
                object_id="csv",
                detail=_recipient_import_audit_detail(body, plan),
            )
            session.commit()
    except DBAPIError as exc:
        if not _recipient_import_retryable_db_conflict(exc):
            raise
        _rollback_recipient_import_conflict(session)
        raise ConflictError(_RECIPIENT_IMPORT_REPREVIEW_CONFLICT) from None
    return {
        "preview_digest": plan.digest,
        "counts": plan.counts,
        "errors": _recipient_import_issues(plan),
        "applied": True,
    }


@router.post("/recipients/import", status_code=status.HTTP_201_CREATED)
def import_recipients_csv(
    body: RecipientsImport,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    preview_body = RecipientImportPreviewRequest(csv_text=body.csv_text, department=body.department)
    try:
        with _serialize_recipient_import_write(session):
            plan = _recipient_import_plan(preview_body, session, settings, lock_rows=True)
            _apply_recipient_import_plan(plan, session)
            audit.record(
                session=session,
                actor=principal.principal_id,
                action="recipient.import",
                object_type="recipients",
                object_id="csv",
                detail={
                    **_recipient_import_audit_detail(preview_body, plan),
                    "options": {**_recipient_import_options(preview_body, plan), "legacy_skip_only": True},
                },
            )
            session.commit()
    except DBAPIError as exc:
        if not _recipient_import_retryable_db_conflict(exc):
            raise
        _rollback_recipient_import_conflict(session)
        raise ConflictError(_RECIPIENT_IMPORT_REPREVIEW_CONFLICT) from None
    return {
        "created": plan.counts["created"],
        "skipped": plan.counts["existing"] + plan.counts["duplicate"],
        "blocked": plan.counts["blocked"],
        "errors": [f"row {issue.row}: {issue.code}" for issue in plan.parsed.errors],
    }


@router.post("/recipients/sync-directory", status_code=status.HTTP_202_ACCEPTED)
def sync_recipients_from_directory(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    """Compatibility alias: queue a preview, never an implicit apply."""
    _require_integration_action(session, kind="directory")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={"action": "preview", "requested_by": principal.principal_id, "job_id": job_id},
        idempotency_key=f"directory:preview:{job_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.preview.request",
        object_type="system",
        object_id=job_id,
        detail={},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "action": "preview"}


_INTEGRATION_PROVIDERS = {
    "directory": frozenset({"microsoft365"}),
    "mailbox": frozenset({"microsoft365", "mailpit"}),
}


_UNCONFIGURED_INTEGRATION_STATES = frozenset({"unconfigured", "configuration_error"})


_UNAVAILABLE_INTEGRATION_STATES = frozenset({"disabled", "unavailable"})


def _is_durable_fingerprint(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _integration_configuration_reason(state: Microsoft365IntegrationState | None, *, kind: str) -> str | None:
    label = "directory" if kind == "directory" else "reported mailbox"
    if state is None:
        return f"The {label} worker has not registered a durable configuration."
    if state.kind != kind or state.provider not in _INTEGRATION_PROVIDERS[kind]:
        return f"The selected {label} provider is not supported."
    if not _is_durable_fingerprint(state.scope_hash) or not _is_durable_fingerprint(state.config_fingerprint):
        return f"The {label} integration has not completed durable configuration."
    if state.status in _UNCONFIGURED_INTEGRATION_STATES:
        return f"The {label} integration reports an invalid or incomplete configuration."
    return None


def _integration_action_reason(state: Microsoft365IntegrationState | None, *, kind: str) -> str | None:
    reason = _integration_configuration_reason(state, kind=kind)
    if reason is not None:
        return reason
    if state is not None and state.status in _UNAVAILABLE_INTEGRATION_STATES:
        label = "directory" if kind == "directory" else "reported mailbox"
        return f"The {label} worker or provider is currently unavailable."
    return None


def _latest_integration_state(session: Session, *, kind: str) -> Microsoft365IntegrationState | None:
    return session.scalar(
        select(Microsoft365IntegrationState)
        .where(Microsoft365IntegrationState.kind == kind)
        .order_by(
            Microsoft365IntegrationState.updated_at.desc(),
            Microsoft365IntegrationState.last_attempt_at.desc().nullslast(),
        )
        .limit(1)
    )


def _require_integration_action(session: Session, *, kind: str) -> Microsoft365IntegrationState:
    state = _latest_integration_state(session, kind=kind)
    reason = _integration_action_reason(state, kind=kind)
    if reason is not None:
        raise ConflictError(reason)
    if state is None:
        # Keep this invariant fail-closed even under optimized Python, and
        # defend against future drift in the readiness-reason helper.
        raise ConflictError("Microsoft 365 integration state is unavailable")
    return state


def _integration_state_payload(
    state: Microsoft365IntegrationState | None,
    *,
    kind: str,
) -> dict[str, Any]:
    configuration_reason = _integration_configuration_reason(state, kind=kind)
    action_reason = _integration_action_reason(state, kind=kind)
    if state is None:
        return {
            "configured": False,
            "configuration_reason": configuration_reason,
            "provider": None,
            "status": "never",
            "last_attempt_at": None,
            "last_success_at": None,
            "last_applied_at": None,
            "cursor_present": False,
            "cursor_age_seconds": None,
            "counts": {},
            "last_error": None,
            "preview_id": None,
            "preview_expires_at": None,
            "apply_available": False,
            "discard_available": False,
            "action_available": False,
            "action_unavailable_reason": action_reason,
        }
    age = None
    if state.last_success_at is not None:
        last_success = state.last_success_at
        if last_success.tzinfo is None:
            last_success = last_success.replace(tzinfo=UTC)
        age = max(0, int((datetime.now(UTC) - last_success).total_seconds()))
    preview_current = False
    if state.pending_preview_id is not None and state.pending_expires_at is not None:
        expires_at = state.pending_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        preview_current = expires_at > datetime.now(UTC)
    return {
        "configured": configuration_reason is None,
        "configuration_reason": configuration_reason,
        "provider": state.provider,
        "status": state.status,
        "last_attempt_at": state.last_attempt_at,
        "last_success_at": state.last_success_at,
        "last_applied_at": state.last_applied_at,
        "cursor_present": state.cursor is not None,
        "cursor_age_seconds": age,
        "counts": state.last_counts or {},
        "last_error": state.last_error,
        "preview_id": str(state.pending_preview_id) if state.pending_preview_id else None,
        "preview_hash": state.pending_preview_hash,
        "preview_expires_at": state.pending_expires_at,
        "apply_available": bool(action_reason is None and state.status == "preview_ready" and preview_current),
        "discard_available": bool(action_reason is None and state.pending_preview_id),
        "action_available": action_reason is None,
        "action_unavailable_reason": action_reason,
    }


@router.get("/integrations/microsoft365/status")
def microsoft365_integration_status(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    states: dict[str, Microsoft365IntegrationState] = {}
    for state in session.scalars(
        select(Microsoft365IntegrationState).order_by(
            Microsoft365IntegrationState.updated_at.desc(),
            Microsoft365IntegrationState.last_attempt_at.desc().nullslast(),
        )
    ):
        states.setdefault(state.kind, state)
    directory = _integration_state_payload(states.get("directory"), kind="directory")
    mailbox = _integration_state_payload(states.get("mailbox"), kind="mailbox")
    return {
        "directory": directory,
        "reported_mailbox": mailbox,
        "directory_preview_available": directory["action_available"],
        "directory_preview_unavailable_reason": directory["action_unavailable_reason"],
        "mailbox_poll_available": mailbox["action_available"],
        "mailbox_poll_unavailable_reason": mailbox["action_unavailable_reason"],
    }


@router.post("/recipients/directory/preview", status_code=status.HTTP_202_ACCEPTED)
def preview_recipients_from_directory(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    return sync_recipients_from_directory(request, session, audit, principal)


@router.post("/recipients/directory/apply", status_code=status.HTTP_202_ACCEPTED)
def apply_recipients_from_directory(
    body: DirectoryApply,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    state = _require_integration_action(session, kind="directory")
    expires_at = state.pending_expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if (
        state.pending_preview_id != body.preview_id
        or state.status != "preview_ready"
        or expires_at is None
        or expires_at <= datetime.now(UTC)
    ):
        raise ConflictError("directory preview is missing, stale or already applied")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={
            "action": "apply",
            "preview_id": str(body.preview_id),
            "requested_by": principal.principal_id,
            "job_id": job_id,
        },
        idempotency_key=f"directory:apply:{body.preview_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.apply.request",
        object_type="system",
        object_id=job_id,
        detail={"preview_id": str(body.preview_id)},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "preview_id": str(body.preview_id)}


@router.post("/recipients/directory/discard", status_code=status.HTTP_202_ACCEPTED)
def discard_directory_preview(
    body: DirectoryApply,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    state = _require_integration_action(session, kind="directory")
    if state.pending_preview_id != body.preview_id:
        raise ConflictError("directory preview is missing, stale or already discarded")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="directory",
        payload={
            "action": "discard",
            "preview_id": str(body.preview_id),
            "requested_by": principal.principal_id,
            "job_id": job_id,
        },
        idempotency_key=f"directory:discard:{body.preview_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="directory.discard.request",
        object_type="system",
        object_id=job_id,
        detail={"preview_id": str(body.preview_id)},
    )
    session.commit()
    return {"queued": True, "job_id": job_id, "preview_id": str(body.preview_id)}


@router.post("/integrations/reported-mail/poll", status_code=status.HTTP_202_ACCEPTED)
def poll_reported_mailbox(
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_RECIPIENTS)),
) -> dict[str, Any]:
    _require_integration_action(session, kind="mailbox")
    job_id = str(uuid.uuid4())
    enqueue_queue(
        session,
        topic="mailbox",
        payload={"requested_by": principal.principal_id, "job_id": job_id},
        idempotency_key=f"mailbox:poll:{job_id}",
    )
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="mailbox.poll.request",
        object_type="system",
        object_id=job_id,
        detail={},
    )
    session.commit()
    return {"queued": True, "job_id": job_id}
