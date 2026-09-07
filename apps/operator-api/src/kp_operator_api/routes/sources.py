"""Threat-source registration, terms acknowledgement, and ingestion routes."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import (
    SourceTerms,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_domain_models import models as dm
from kp_domain_verification.verification import (
    normalize_domain,
)
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.deps import get_audit_store, get_session
from kp_operator_api.sending_domains_roe import (
    _GUI_COLLECTION_MAX_LIMIT,
    _GUI_COLLECTION_MAX_OFFSET,
)

router = APIRouter(prefix="/api/v1")


class SourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    source_type: dm.SourceType
    base_domain: str = Field(min_length=1, max_length=253)
    fetch_path: str = Field(default="/", max_length=1024)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source name cannot be blank")
        return normalized

    @field_validator("base_domain")
    @classmethod
    def normalize_base_domain(cls, value: str) -> str:
        normalized = normalize_domain(value)
        if normalized is None or "." not in normalized:
            raise ValueError("source base domain is malformed")
        return normalized


class SourceTermsAcknowledgement(BaseModel):
    """Explicit operator attestation for one bounded terms reference."""

    model_config = ConfigDict(extra="forbid")

    terms_reference: str = Field(min_length=1, max_length=2048)
    terms_hash: str = Field(min_length=64, max_length=64)
    commercial_use_ok: StrictBool
    automation_ok: StrictBool
    redistribution_ok: StrictBool
    retention_ok: StrictBool
    next_review_at: datetime

    @field_validator("terms_reference")
    @classmethod
    def normalize_terms_reference(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("terms_reference must be a non-empty single-line reference")
        return normalized

    @field_validator("terms_hash")
    @classmethod
    def normalize_terms_hash(cls, value: str) -> str:
        normalized = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", normalized) is None:
            raise ValueError("terms_hash must be a SHA-256 hexadecimal digest")
        return normalized

    @field_validator("commercial_use_ok", "automation_ok", "redistribution_ok", "retention_ok")
    @classmethod
    def require_permission_confirmation(cls, value: bool) -> bool:
        if not value:
            raise ValueError("every source-use permission must be explicitly confirmed")
        return value

    @field_validator("next_review_at")
    @classmethod
    def require_aware_next_review(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("next_review_at must include a timezone offset")
        return value


def _source_terms_at(
    session: Session,
    source: Any,
) -> SourceTerms | None:
    """Return only the acknowledgement selected by and belonging to ``source``."""
    if source.license_state_id is None:
        return None
    terms = session.get(SourceTerms, source.license_state_id)
    if terms is None or terms.source_id != source.source_id:
        return None
    return terms


def _as_utc(value: datetime) -> datetime:
    # PostgreSQL returns aware values for these timestamp-with-time-zone
    # columns. Treat SQLite's naive test representation as UTC so the predicate
    # remains identical in focused lifecycle tests.
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _source_terms_are_current(terms: SourceTerms | None, *, as_of: datetime) -> bool:
    """Fail-closed source-use predicate mirrored at the worker boundary."""
    if terms is None or not terms.enabled:
        return False
    if not all(
        (
            terms.commercial_use_ok,
            terms.automation_ok,
            terms.redistribution_ok,
            terms.retention_ok,
        )
    ):
        return False
    reviewed_at = _as_utc(terms.terms_reviewed_at)
    next_review_at = _as_utc(terms.next_review_at)
    now = _as_utc(as_of)
    return reviewed_at <= now < next_review_at and reviewed_at < next_review_at


def _source_terms_payload(source: Any, terms: SourceTerms | None, *, as_of: datetime) -> dict[str, Any]:
    acknowledgement = None
    if terms is not None:
        acknowledgement = {
            "source_terms_id": str(terms.source_terms_id),
            "terms_reference": terms.terms_reference,
            "terms_hash": terms.terms_hash,
            "commercial_use_ok": terms.commercial_use_ok,
            "automation_ok": terms.automation_ok,
            "redistribution_ok": terms.redistribution_ok,
            "retention_ok": terms.retention_ok,
            "reviewed_at": terms.terms_reviewed_at,
            "next_review_at": terms.next_review_at,
            "enabled": terms.enabled,
        }
    return {
        "source_id": str(source.source_id),
        "license_state_id": str(source.license_state_id) if source.license_state_id else None,
        "governance_ready": _source_terms_are_current(terms, as_of=as_of),
        "acknowledgement": acknowledgement,
    }


def _block_source_without_current_terms(
    *,
    session: Session,
    audit: AuditStore,
    principal: Principal,
    source: Any,
) -> None:
    was_enabled = bool(source.enabled)
    source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.governance.blocked",
        object_type="source",
        object_id=str(source.source_id),
        detail={"reason": "source_terms_not_current", "source_disabled": was_enabled},
    )
    session.commit()
    raise ConflictError("current source terms acknowledgement is required")


@router.post("/sources", status_code=status.HTTP_201_CREATED)
def create_source(
    body: SourceCreate,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBMIT_SOURCE)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    if body.source_type != dm.SourceType.RSS and body.source_type not in (
        dm.SourceType.STIX,
        dm.SourceType.BULK_DOWNLOAD,
    ):
        raise ValidationError_(f"source type {body.source_type.value} is not implemented")
    if not body.fetch_path.startswith("/") or body.fetch_path.startswith("//"):
        raise ValidationError_("fetch_path must be an absolute path, not a URL")
    source = SourceRow(
        source_id=uuid.uuid4(),
        source_key=str(uuid.uuid4())[:8],
        name=body.name,
        source_type=body.source_type,
        base_domain=body.base_domain,
        fetch_path=body.fetch_path,
        enabled=False,
    )
    session.add(source)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.create",
        object_type="source",
        object_id=str(source.source_id),
        detail={"base_domain": body.base_domain},
    )
    session.commit()
    return {"source_id": str(source.source_id), "enabled": source.enabled}


@router.get("/sources")
def list_sources(
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> list[dict[str, Any]]:
    from kp_database.models import Source as SourceRow

    rows = list(
        session.scalars(select(SourceRow).order_by(SourceRow.name, SourceRow.source_id).offset(offset).limit(limit))
    )
    return [
        {
            "source_id": str(row.source_id),
            "name": row.name,
            "source_type": row.source_type.value,
            "base_domain": row.base_domain,
            "fetch_path": row.fetch_path,
            "enabled": row.enabled,
            "last_success_at": row.last_success_at,
            "last_attempt_at": row.last_attempt_at,
            "consecutive_failures": row.consecutive_failures,
        }
        for row in rows
    ]


@router.post("/sources/{source_id}/terms", status_code=status.HTTP_201_CREATED)
def acknowledge_source_terms(
    source_id: uuid.UUID,
    body: SourceTermsAcknowledgement,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    reviewed_at = datetime.now(UTC)
    if body.next_review_at.astimezone(UTC) <= reviewed_at:
        raise ValidationError_("next_review_at must be in the future")

    # Locking the source serializes acknowledgements for one source. Keeping
    # prior rows disabled preserves provenance while ensuring only the selected
    # current row can authorize future ingestion.
    prior_terms = session.scalars(select(SourceTerms).where(SourceTerms.source_id == source_id)).all()
    for prior in prior_terms:
        prior.enabled = False
    terms = SourceTerms(
        source_terms_id=uuid.uuid4(),
        source_id=source_id,
        terms_reference=body.terms_reference,
        terms_hash=body.terms_hash,
        commercial_use_ok=body.commercial_use_ok,
        automation_ok=body.automation_ok,
        redistribution_ok=body.redistribution_ok,
        retention_ok=body.retention_ok,
        terms_reviewed_at=reviewed_at,
        next_review_at=body.next_review_at.astimezone(UTC),
        enabled=True,
    )
    session.add(terms)
    source.license_state_id = terms.source_terms_id
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.terms.acknowledge",
        object_type="source",
        object_id=str(source_id),
        detail={"source_terms_id": str(terms.source_terms_id), "permissions_confirmed": True},
    )
    session.commit()
    return _source_terms_payload(source, terms, as_of=reviewed_at)


@router.get("/sources/{source_id}/terms/current")
def current_source_terms(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    return _source_terms_payload(source, terms, as_of=datetime.now(UTC))


@router.post("/sources/{source_id}/terms/revoke")
def revoke_source_terms(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    terms_changed = bool(terms is not None and terms.enabled)
    source_changed = bool(source.enabled)
    if terms is not None:
        terms.enabled = False
    source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.terms.revoke" if terms_changed or source_changed else "source.terms.revoke.noop",
        object_type="source",
        object_id=str(source_id),
        detail={"terms_changed": terms_changed, "source_disabled": source_changed},
    )
    session.commit()
    return _source_terms_payload(source, terms, as_of=datetime.now(UTC))


@router.post("/sources/{source_id}/enable")
def enable_source(
    source_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    if source.source_type not in (dm.SourceType.RSS, dm.SourceType.STIX, dm.SourceType.BULK_DOWNLOAD):
        raise ValidationError_("source adapter is not implemented")
    terms = _source_terms_at(session, source)
    if not _source_terms_are_current(terms, as_of=datetime.now(UTC)):
        _block_source_without_current_terms(session=session, audit=audit, principal=principal, source=source)
    if source.enabled:
        audit.record(
            session=session,
            actor=principal.principal_id,
            action="source.enable.noop",
            object_type="source",
            object_id=str(source_id),
            detail={"changed": False, "ingestion_queued": False},
        )
        session.commit()
        return {
            "source_id": str(source_id),
            "enabled": True,
            "changed": False,
            "ingestion_queued": False,
            "job_id": None,
        }

    source.enabled = True
    job_id = _queue_source_ingestion(session, source_id)
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.enable",
        object_type="source",
        object_id=str(source_id),
        detail={"changed": True, "ingestion_queued": True, "job_id": str(job_id)},
    )
    session.commit()
    return {
        "source_id": str(source_id),
        "enabled": True,
        "changed": True,
        "ingestion_queued": True,
        "job_id": str(job_id),
    }


def _queue_source_ingestion(session: Session, source_id: uuid.UUID) -> uuid.UUID:
    job_id = uuid.uuid4()
    enqueue_queue(
        session,
        topic="ingest",
        payload={"source_id": str(source_id), "job_id": str(job_id)},
        idempotency_key=f"ingest:{source_id}:{job_id}",
    )
    return job_id


@router.post("/sources/{source_id}/disable")
def disable_source(
    source_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    changed = bool(source.enabled)
    if changed:
        source.enabled = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.disable" if changed else "source.disable.noop",
        object_type="source",
        object_id=str(source_id),
        detail={"changed": changed},
    )
    session.commit()
    return {"source_id": str(source_id), "enabled": False, "changed": changed}


@router.post("/sources/{source_id}/ingest", status_code=status.HTTP_202_ACCEPTED)
def ingest_source_now(
    source_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    from kp_database.models import Source as SourceRow

    source = session.get(SourceRow, source_id, with_for_update=True)
    if source is None:
        raise NotFoundError("source not found")
    terms = _source_terms_at(session, source)
    if not _source_terms_are_current(terms, as_of=datetime.now(UTC)):
        _block_source_without_current_terms(session=session, audit=audit, principal=principal, source=source)
    if not source.enabled:
        raise ConflictError("source must be enabled before ingestion can be queued")
    if source.source_type not in (dm.SourceType.RSS, dm.SourceType.STIX, dm.SourceType.BULK_DOWNLOAD):
        raise ValidationError_("source adapter is not implemented")
    job_id = _queue_source_ingestion(session, source_id)
    dispatch_after_commit(session, lambda: audit.dispatch_pending_queue(request.app.state.queue))
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="source.ingest.queue",
        object_type="source",
        object_id=str(source_id),
        detail={"job_id": str(job_id)},
    )
    session.commit()
    return {
        "source_id": str(source_id),
        "enabled": True,
        "ingestion_queued": True,
        "job_id": str(job_id),
    }
