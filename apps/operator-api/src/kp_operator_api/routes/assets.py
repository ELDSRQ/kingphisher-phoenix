"""Reusable image-asset library: upload, review/approve, apply to templates.

Operators build a vetted library of raster images (FLUX-generated banners, brand
logos) and apply approved ones to DRAFT templates. An applied asset is inlined
into the template's ``safe_html`` as a ``data:image`` URI (see
:mod:`kp_operator_api.asset_service`), so it is covered by the template approval
hash and the same sanitizer + SafetyValidator as all other content. Assets are
themselves vetted (DRAFT -> APPROVED with separation of duties); only an APPROVED
asset may be applied. Nothing is hard-deleted — an asset is retired by moving it
to SUPERSEDED/REJECTED (preservation).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Response, status
from kp_authorization.rbac import Capability, Principal
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.audit_store import AuditStore
from kp_database.models import TemplateAsset, TemplateVersion
from kp_domain_models import models as dm
from kp_safety_validation.validator import SafetyValidator
from kp_sanitization.image_asset import ImageAssetError, inspect_raster_image
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

from kp_operator_api.asset_service import AssetApplyError, apply_assets, asset_data_uri, slot_for_kind
from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.routes.patterns import _single_operator
from kp_operator_api.routes.shared import _principal_uuid

router = APIRouter(prefix="/api/v1")

# A 512 KB raster base64-encodes to ≈700 KB; allow headroom for the JSON field.
_MAX_CONTENT_B64 = 1_000_000


def _asset_approval_hash(asset: TemplateAsset) -> str:
    """Bind the approval to this exact asset's identity, bytes and role."""

    return hashlib.sha256(f"asset:{asset.asset_id}:{asset.sha256}:{asset.kind.value}".encode()).hexdigest()


def _asset_metadata(asset: TemplateAsset) -> dict[str, Any]:
    """Serialise an asset WITHOUT its raw bytes."""

    return {
        "asset_id": str(asset.asset_id),
        "kind": asset.kind.value,
        "brand": asset.brand,
        "name": asset.name,
        "media_type": asset.media_type,
        "width": asset.width,
        "height": asset.height,
        "byte_size": asset.byte_size,
        "sha256": asset.sha256,
        "provenance": asset.provenance or {},
        "approval_state": asset.approval_state.value,
        "created_at": asset.created_at.isoformat() if asset.created_at else None,
        "updated_at": asset.updated_at.isoformat() if asset.updated_at else None,
    }


class AssetUploadRequest(BaseModel):
    """An operator-supplied raster image to add to the library (DRAFT)."""

    kind: dm.AssetKind
    name: str = Field(min_length=1, max_length=255)
    brand: str | None = Field(default=None, max_length=64)
    content_base64: str = Field(min_length=1, max_length=_MAX_CONTENT_B64)
    provenance: dict[str, Any] = Field(default_factory=dict)


@router.post("/assets", status_code=status.HTTP_201_CREATED)
def upload_asset(
    body: AssetUploadRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    """Add a raster image to the library as a DRAFT asset.

    The bytes are validated as an accepted raster (png/jpeg/gif/webp — svg and
    non-images are rejected) before storage. The asset is DRAFT and cannot be
    applied to a template until a (different) operator approves it.
    """
    try:
        content = base64.b64decode(body.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise ValidationError_("content_base64 is not valid base64") from None
    try:
        info = inspect_raster_image(content)
    except ImageAssetError as error:
        raise ValidationError_(str(error)) from None

    provenance = dict(body.provenance)
    provenance.setdefault("uploaded_by", principal.principal_id)
    asset = TemplateAsset(
        asset_id=uuid.uuid4(),
        kind=body.kind,
        brand=(body.brand or None),
        name=body.name,
        media_type=info.media_type,
        width=info.width,
        height=info.height,
        byte_size=info.byte_size,
        sha256=info.sha256,
        content=content,
        provenance=provenance,
        approval_state=dm.AssetApprovalState.DRAFT,
        requested_by=_principal_uuid(principal),
    )
    session.add(asset)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="asset.upload",
        object_type="asset",
        object_id=str(asset.asset_id),
        detail={"kind": asset.kind.value, "media_type": asset.media_type, "byte_size": asset.byte_size},
    )
    session.commit()
    session.refresh(asset)
    return _asset_metadata(asset)


@router.get("/assets", status_code=status.HTTP_200_OK)
def list_assets(
    kind: dm.AssetKind | None = Query(default=None),
    brand: str | None = Query(default=None, max_length=64),
    approval_state: dm.AssetApprovalState | None = Query(default=None),
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    """List asset metadata (never the bytes), newest first, with optional filters."""

    stmt = select(TemplateAsset)
    if kind is not None:
        stmt = stmt.where(TemplateAsset.kind == kind)
    if brand is not None:
        stmt = stmt.where(TemplateAsset.brand == brand)
    if approval_state is not None:
        stmt = stmt.where(TemplateAsset.approval_state == approval_state)
    stmt = stmt.order_by(TemplateAsset.created_at.desc())
    assets = session.execute(stmt).scalars().all()
    return {"assets": [_asset_metadata(a) for a in assets]}


@router.get("/assets/{asset_id}", status_code=status.HTTP_200_OK)
def get_asset(
    asset_id: uuid.UUID,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    asset = session.get(TemplateAsset, asset_id)
    if asset is None:
        raise NotFoundError("asset not found")
    return _asset_metadata(asset)


@router.get("/assets/{asset_id}/content")
def get_asset_content(
    asset_id: uuid.UUID,
    session: Session = Depends(get_session),
    _principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> Response:
    """Return the raw asset bytes for operator-UI preview (not used for delivery)."""

    asset = session.get(TemplateAsset, asset_id)
    if asset is None:
        raise NotFoundError("asset not found")
    return Response(
        content=asset.content,
        media_type=asset.media_type,
        headers={"Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff"},
    )


class AssetApprovalRequest(BaseModel):
    decision: dm.ApprovalDecision
    rationale: str | None = Field(default=None, max_length=2000)


@router.post("/assets/{asset_id}/approve", status_code=status.HTTP_200_OK)
def approve_asset(
    asset_id: uuid.UUID,
    body: AssetApprovalRequest,
    settings: OperatorApiSettings = Depends(get_settings),
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.APPROVE_TEMPLATE)),
) -> dict[str, Any]:
    """Approve or reject a DRAFT asset. Only an APPROVED asset may be applied.

    The uploader must not be the approver unless this is a one-operator
    deployment (mirrors template approval); every decision is audited.
    """
    asset = session.get(TemplateAsset, asset_id)
    if asset is None:
        raise NotFoundError("asset not found")
    if asset.approval_state != dm.AssetApprovalState.DRAFT:
        raise ConflictError(f"asset is already {asset.approval_state.value}")

    requested_by = asset.requested_by
    self_reviewed = requested_by is not None and requested_by == _principal_uuid(principal)
    if self_reviewed and not _single_operator(settings):
        raise PermissionDeniedError("you uploaded this asset; approval must come from someone else")

    approved = body.decision == dm.ApprovalDecision.APPROVED
    if approved:
        asset.approval_hash = _asset_approval_hash(asset)
        asset.approved_by = _principal_uuid(principal)
    asset.approval_state = dm.AssetApprovalState.APPROVED if approved else dm.AssetApprovalState.REJECTED
    asset.updated_at = datetime.now(UTC)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action=f"asset.{'approve' if approved else 'reject'}",
        object_type="asset",
        object_id=str(asset_id),
        detail={"rationale": body.rationale, "self_reviewed": self_reviewed},
    )
    session.commit()
    return {"asset_id": str(asset_id), "approval_state": asset.approval_state.value}


class ApplyAssetRequest(BaseModel):
    asset_id: uuid.UUID


@router.post("/templates/{template_version_id}/apply-asset", status_code=status.HTTP_200_OK)
def apply_asset_to_template(
    template_version_id: uuid.UUID,
    body: ApplyAssetRequest,
    settings: OperatorApiSettings = Depends(get_settings),
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    """Inline an APPROVED asset into a DRAFT template's HTML as a data:image.

    The asset occupies the ``banner`` or ``logo`` slot (by its kind); the header
    is rebuilt from the recorded slots so re-applying never stacks. The result is
    re-run through the sanitizer and SafetyValidator fail-closed before it is
    persisted; approved templates are immutable.
    """
    template = session.get(TemplateVersion, template_version_id)
    if template is None:
        raise NotFoundError("template not found")
    if template.approval_state != dm.TemplateApprovalState.DRAFT:
        raise ConflictError(f"template is already {template.approval_state.value}; only DRAFT templates can be branded")
    if not isinstance(template.safe_html, str) or not template.safe_html.strip():
        raise ValidationError_("template has no HTML body to brand")

    asset = session.get(TemplateAsset, body.asset_id)
    if asset is None:
        raise NotFoundError("asset not found")
    if asset.approval_state != dm.AssetApprovalState.APPROVED:
        raise ConflictError("asset is not approved; only approved assets can be applied")

    edited = dict(template.edited_content) if isinstance(template.edited_content, dict) else {}
    stored_slots = edited.get("assets")
    prior_slots = dict(stored_slots) if isinstance(stored_slots, dict) else {}
    previous_srcs = [s for s in prior_slots.values() if isinstance(s, str)]

    new_uri = asset_data_uri(asset.media_type, asset.content)
    slots = dict(prior_slots)
    slots[slot_for_kind(asset.kind)] = new_uri

    try:
        result = apply_assets(
            template.safe_html,
            slots=slots,
            previous_srcs=previous_srcs,
            training_placeholder=TRAINING_URL_PLACEHOLDER,
        )
    except AssetApplyError as error:
        raise ValidationError_(str(error)) from None

    # Fail-closed re-validation (data:image needs no host allow-list).
    training_domains = {d.strip() for d in settings.training_domains.split(",") if d.strip()}
    validator = SafetyValidator(training_domains=training_domains, allowed_image_hosts=settings.image_host_set())
    validation_html = result.safe_html.replace(TRAINING_URL_PLACEHOLDER, "/recipient-training-link")
    validation_plain = (template.plain_text or "").replace(TRAINING_URL_PLACEHOLDER, "/recipient-training-link")
    verdict = validator.validate(template.subject, validation_plain, validation_html, content_checks=False)
    if not verdict.allowed:
        raise SafetyRejectionError(f"applying the asset failed safety validation: {verdict.reasons}")

    template.safe_html = result.safe_html
    edited["assets"] = result.slots
    template.edited_content = edited or None
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="template.apply_asset",
        object_type="template",
        object_id=str(template_version_id),
        detail={"asset_id": str(asset.asset_id), "slot": slot_for_kind(asset.kind), "kind": asset.kind.value},
    )
    session.commit()
    return {
        "template_version_id": str(template_version_id),
        "applied_slots": sorted(result.slots.keys()),
        "asset_id": str(asset.asset_id),
    }
