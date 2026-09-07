"""Operator alert-subscription routes and the campaign alert fan-out helper."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, Request, status
from kp_authorization.rbac import Capability, Principal
from kp_database.audit_store import AuditStore
from kp_database.models import (
    AlertSubscription,
    Campaign,
)
from kp_database.outbox import dispatch_after_commit, enqueue_queue
from kp_telemetry.errors import (
    NotFoundError,
    ValidationError_,
)
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_operator_api.auth import require_capability
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.deps import get_audit_store, get_session, get_settings
from kp_operator_api.routes.shared import (
    _get_campaign,
)
from kp_operator_api.sending_domains_roe import (
    _GUI_COLLECTION_MAX_LIMIT,
    _GUI_COLLECTION_MAX_OFFSET,
)

router = APIRouter(prefix="/api/v1")


class AlertSubscribe(BaseModel):
    campaign_id: uuid.UUID
    channel: str = Field(default="web", pattern="^(web|webhook|ntfy)$")
    destination_url: str | None = Field(default=None, max_length=2048)


def _alert_destination_is_allowlisted(host: str, allowlist: frozenset[str]) -> bool:
    """Mirror the worker's exact host-or-www policy before persistence."""

    normalized_host = host.lower().removeprefix("www.")
    return any(normalized_host == domain.lower().removeprefix("www.") for domain in allowlist)


@router.post("/alerts/subscriptions", status_code=status.HTTP_201_CREATED)
def subscribe_alerts(
    body: AlertSubscribe,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    settings: OperatorApiSettings = Depends(get_settings),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    campaign = _get_campaign(session, body.campaign_id)
    if body.channel != "web":
        parsed = urlparse(body.destination_url or "")
        try:
            port = parsed.port
        except ValueError:
            port = -1
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or port not in (None, 443)
            or parsed.fragment
        ):
            raise ValidationError_("outbound alert destinations require an HTTPS URL without embedded credentials")
        if not _alert_destination_is_allowlisted(
            parsed.hostname,
            settings.alert_webhook_domain_allowlist(),
        ):
            raise ValidationError_("outbound alert destination is not in the configured domain allowlist")
        if body.channel == "ntfy" and (
            not parsed.path.strip("/") or "/" in parsed.path.strip("/") or parsed.query or parsed.fragment
        ):
            raise ValidationError_("ntfy destinations must be an HTTPS topic URL with one path segment")
    elif body.destination_url is not None:
        raise ValidationError_("web subscriptions do not accept a destination URL")
    new_secret: str | None = None
    existing = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
            AlertSubscription.campaign_id == campaign.campaign_id,
            AlertSubscription.channel == body.channel,
        )
    )
    if existing is not None:
        existing.active = True
        if body.destination_url and body.destination_url != existing.destination_url:
            existing.destination_url = body.destination_url
            new_secret = secrets.token_hex(32)
            existing.signing_secret = new_secret
        sub = existing
    else:
        if body.channel != "web":
            new_secret = secrets.token_hex(32)
        sub = AlertSubscription(
            alert_subscription_id=uuid.uuid4(),
            user_id=uuid.UUID(principal.principal_id),
            campaign_id=campaign.campaign_id,
            channel=body.channel,
            destination_url=body.destination_url,
            signing_secret=new_secret,
            active=True,
        )
        session.add(sub)
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="alerts.subscribe",
        object_type="campaign",
        object_id=str(campaign.campaign_id),
        detail={"channel": body.channel},
    )
    session.commit()
    return {
        "alert_subscription_id": str(sub.alert_subscription_id),
        "active": sub.active,
        "signing_secret": new_secret,
    }


@router.get("/alerts/subscriptions", status_code=status.HTTP_200_OK)
def list_alert_subscriptions(
    campaign_id: uuid.UUID | None = None,
    limit: int = Query(default=100, ge=1, le=_GUI_COLLECTION_MAX_LIMIT),
    offset: int = Query(default=0, ge=0, le=_GUI_COLLECTION_MAX_OFFSET),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> list[dict[str, Any]]:
    stmt = select(AlertSubscription).where(AlertSubscription.user_id == uuid.UUID(principal.principal_id))
    if campaign_id:
        stmt = stmt.where(AlertSubscription.campaign_id == campaign_id)
    rows = (
        session.execute(
            stmt.order_by(AlertSubscription.campaign_id, AlertSubscription.alert_subscription_id)
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    return [
        {
            "alert_subscription_id": str(s.alert_subscription_id),
            "campaign_id": str(s.campaign_id),
            "channel": s.channel,
            "destination_configured": bool(s.destination_url),
            "last_delivery_at": s.last_delivery_at,
            "consecutive_failures": s.consecutive_failures,
            "active": s.active,
        }
        for s in rows
    ]


@router.delete("/alerts/subscriptions/{subscription_id}", status_code=status.HTTP_200_OK)
def unsubscribe_alerts(
    subscription_id: uuid.UUID,
    session: Session = Depends(get_session),
    audit: AuditStore = Depends(get_audit_store),
    principal: Principal = Depends(require_capability(Capability.SUBSCRIBE_ALERTS)),
) -> dict[str, Any]:
    sub = session.scalar(
        select(AlertSubscription).where(
            AlertSubscription.alert_subscription_id == subscription_id,
            AlertSubscription.user_id == uuid.UUID(principal.principal_id),
        )
    )
    if sub is None:
        raise NotFoundError("subscription not found")
    sub.active = False
    audit.record(
        session=session,
        actor=principal.principal_id,
        action="alerts.unsubscribe",
        object_type="campaign",
        object_id=str(sub.campaign_id),
        detail={"channel": sub.channel},
    )
    session.commit()
    return {"alert_subscription_id": str(subscription_id), "active": False}


def _queue_campaign_alert(session: Session, request: Request, campaign: Campaign, event_type: str) -> int:
    subscriptions = list(
        session.scalars(
            select(AlertSubscription).where(
                AlertSubscription.campaign_id == campaign.campaign_id,
                AlertSubscription.active.is_(True),
                AlertSubscription.channel != "web",
            )
        )
    )
    for subscription in subscriptions:
        enqueue_queue(
            session,
            topic="alert",
            payload={
                "subscription_id": str(subscription.alert_subscription_id),
                "campaign_id": str(campaign.campaign_id),
                "event_type": event_type,
                "occurred_at": datetime.now(UTC).isoformat(),
            },
            idempotency_key=f"alert:{subscription.alert_subscription_id}:{event_type}:{campaign.campaign_id}",
        )
    dispatch_after_commit(
        session,
        lambda: request.app.state.audit_store.dispatch_pending_queue(request.app.state.queue),
    )
    return len(subscriptions)
