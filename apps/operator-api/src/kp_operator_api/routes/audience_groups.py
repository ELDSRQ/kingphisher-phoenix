"""Reusable audience-group (saved recipient list) routes."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.campaign_service import (
    invalidate_campaign_audience,
)
from kp_database.models import (
    AudienceGroup,
    AudienceGroupMember,
    Campaign,
    CampaignAudience,
    Microsoft365IntegrationState,
    Recipient,
)
from kp_telemetry.errors import (
    ConflictError,
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings

router = APIRouter(prefix="/api/v1")


class AudienceGroupUpsert(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    recipient_ids: list[uuid.UUID] = Field(default_factory=list, max_length=10_000)
    directory_group_ref: str | None = Field(default=None, max_length=256)


@router.get("/audience-groups")
def list_audience_groups(
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.VIEW_AGGREGATE)),
) -> dict[str, Any]:
    del principal
    groups = list(session.scalars(select(AudienceGroup).order_by(AudienceGroup.name).limit(10_001)))
    if len(groups) > 10_000:
        raise ConflictError("static audience groups exceed the supported 10,000-group boundary")
    # Count in Python from a bounded two-column query; this avoids a separate
    # query per group while keeping the response simple.
    member_counts: dict[uuid.UUID, int] = {}
    member_ids: dict[uuid.UUID, list[str]] = {}
    if groups:
        member_rows = list(
            session.execute(
                select(AudienceGroupMember.audience_group_id, AudienceGroupMember.recipient_id)
                .where(AudienceGroupMember.audience_group_id.in_([item.audience_group_id for item in groups]))
                .limit(10_001)
            )
        )
        if len(member_rows) > 10_000:
            raise ConflictError("static group memberships exceed the supported 10,000-recipient boundary")
        for group_id, _ in member_rows:
            member_counts[group_id] = member_counts.get(group_id, 0) + 1
        for group_id, recipient_id in member_rows:
            member_ids.setdefault(group_id, []).append(str(recipient_id))
    directory_healthy = (
        session.scalar(
            select(Microsoft365IntegrationState.integration_state_id).where(
                Microsoft365IntegrationState.kind == "directory",
                Microsoft365IntegrationState.status == "healthy",
            )
        )
        is not None
    )
    return {
        "groups": [
            {
                "audience_group_id": str(item.audience_group_id),
                "name": item.name,
                "member_count": member_counts.get(item.audience_group_id, 0),
                "recipient_ids": sorted(member_ids.get(item.audience_group_id, [])),
                "directory_group_ref": item.directory_group_ref,
                "directory_group_resolved": bool(item.directory_group_ref and directory_healthy),
            }
            for item in groups
        ]
    }


def _replace_group_members(session: Session, group: AudienceGroup, recipient_ids: list[uuid.UUID]) -> None:
    unique_ids = sorted(set(recipient_ids), key=str)
    if unique_ids:
        known = set(
            session.scalars(select(Recipient.recipient_id).where(Recipient.recipient_id.in_(unique_ids)).limit(10_001))
        )
        if known != set(unique_ids):
            raise ValidationError_("static audience group contains an unknown recipient")
    session.execute(delete(AudienceGroupMember).where(AudienceGroupMember.audience_group_id == group.audience_group_id))
    session.add_all(
        [
            AudienceGroupMember(
                audience_group_member_id=uuid.uuid4(),
                audience_group_id=group.audience_group_id,
                recipient_id=recipient_id,
            )
            for recipient_id in unique_ids
        ]
    )


def _directory_group_reference(value: str | None, settings: OperatorApiSettings) -> tuple[str | None, str | None]:
    if not value:
        return None, None
    normalized = value.strip().lower()
    digest = hmac.new(
        settings.require_recipient_hash_salt(),
        b"kp-directory-group-v1\0microsoft365\0" + normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return normalized, digest


@router.post("/audience-groups", status_code=status.HTTP_201_CREATED)
def create_audience_group(
    body: AudienceGroupUpsert,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    name = body.name.strip()
    if session.scalar(select(AudienceGroup).where(AudienceGroup.name == name)) is not None:
        raise ConflictError("an audience group with that name already exists")
    directory_ref, directory_ref_hash = _directory_group_reference(body.directory_group_ref, settings)
    if directory_ref_hash and session.scalar(
        select(AudienceGroup).where(AudienceGroup.directory_group_ref_hash == directory_ref_hash)
    ):
        raise ConflictError("that Entra directory group is already connected")
    group = AudienceGroup(
        audience_group_id=uuid.uuid4(),
        name=name,
        directory_group_ref=directory_ref,
        directory_group_ref_hash=directory_ref_hash,
        created_by=uuid.UUID(principal.principal_id) if principal.principal_id != "anonymous" else None,
    )
    session.add(group)
    session.flush()
    _replace_group_members(session, group, body.recipient_ids)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="audience-group.create",
        object_type="audience_group",
        object_id=str(group.audience_group_id),
        detail={"name": name, "member_count": len(set(body.recipient_ids))},
    )
    session.commit()
    return {"audience_group_id": str(group.audience_group_id), "member_count": len(set(body.recipient_ids))}


@router.put("/audience-groups/{group_id}")
def update_audience_group(
    group_id: uuid.UUID,
    body: AudienceGroupUpsert,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.CREATE_CAMPAIGN)),
) -> dict[str, Any]:
    group = session.get(AudienceGroup, group_id, with_for_update=True)
    if group is None:
        raise NotFoundError("audience group not found")
    duplicate = session.scalar(
        select(AudienceGroup).where(
            AudienceGroup.name == body.name.strip(),
            AudienceGroup.audience_group_id != group.audience_group_id,
        )
    )
    if duplicate is not None:
        raise ConflictError("an audience group with that name already exists")
    directory_ref, directory_ref_hash = _directory_group_reference(body.directory_group_ref, settings)
    duplicate_ref = (
        session.scalar(
            select(AudienceGroup).where(
                AudienceGroup.directory_group_ref_hash == directory_ref_hash,
                AudienceGroup.audience_group_id != group.audience_group_id,
            )
        )
        if directory_ref_hash
        else None
    )
    if duplicate_ref is not None:
        raise ConflictError("that Entra directory group is already connected")
    group.name = body.name.strip()
    group.directory_group_ref = directory_ref
    group.directory_group_ref_hash = directory_ref_hash
    group.updated_at = datetime.now(UTC)
    _replace_group_members(session, group, body.recipient_ids)
    impacted = list(
        session.scalars(
            select(CampaignAudience).where(CampaignAudience.group_ids.contains([str(group.audience_group_id)]))
        )
    )
    invalidated = 0
    for audience in impacted:
        campaign = session.get(Campaign, audience.campaign_id, with_for_update=True)
        if campaign is not None and audience.frozen_at is not None:
            invalidate_campaign_audience(session, campaign, audience)
            invalidated += 1
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="audience-group.update",
        object_type="audience_group",
        object_id=str(group.audience_group_id),
        detail={"member_count": len(set(body.recipient_ids)), "campaigns_invalidated": invalidated},
    )
    session.commit()
    return {
        "audience_group_id": str(group_id),
        "member_count": len(set(body.recipient_ids)),
        "invalidated": invalidated,
    }
