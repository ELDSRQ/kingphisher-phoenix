"""Forwarded-phish curation ingestion.

A designated mailbox (or a mail-forwarding rule, a manual submit, or the
scheduled poller) hands a forwarded real phishing email to this endpoint; it is
auto-cloned — payload neutralized — into a dated, deduplicated DRAFT template
the operator reviews in the library. Nothing here approves or sends anything.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, status
from kp_authorization.rbac import Capability, Principal
from kp_curation.curation_service import curate_forwarded_message
from kp_database.audit_store import AuditStore
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings

router = APIRouter(prefix="/api/v1")


class ForwardedPhishRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=998)
    html: str = Field(min_length=1, max_length=400_000)
    plain_text: str | None = Field(default=None, max_length=400_000)
    source: str = Field(default="forwarded-mailbox", min_length=1, max_length=64)


@router.post("/curation/forwarded", status_code=status.HTTP_201_CREATED)
def curate_forwarded(
    body: ForwardedPhishRequest,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.MANAGE_SOURCES)),
) -> dict[str, Any]:
    """Auto-clone a forwarded real phishing email into a dated DRAFT template."""
    result = curate_forwarded_message(
        session,
        subject=body.subject,
        raw_html=body.html,
        plain_text=body.plain_text,
        source=body.source,
        allowed_image_hosts=settings.image_host_set(),
        requested_by=principal.principal_id,
    )
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="template.auto-curate",
        object_type="template",
        object_id=result.template_version_id or "",
        detail={
            "created": result.created,
            "deduplicated": result.deduplicated,
            "source": body.source,
            "reason": result.reason,
        },
    )
    session.commit()
    return {
        "created": result.created,
        "deduplicated": result.deduplicated,
        "template_version_id": result.template_version_id,
        "reason": result.reason,
    }
