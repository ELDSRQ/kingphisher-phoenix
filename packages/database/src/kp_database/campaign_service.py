"""Campaign launch preparation.

Creates the recipient assignments and tracking tokens for a scheduled
campaign and returns per-recipient tracking URLs. Ports the launch/tracking
mechanics of the original King Phisher (`mailer.py` uid generation, `uid`
template variable, `tracking_dot` image) into Phoenix's safe model:

- the raw token is generated, immediately hashed, and **only the hash is
  stored** (token_hash is what URLs carry and what the tracking API looks up)
- every assignment carries a deterministic idempotency key so re-launching a
  campaign (even after a queue retry) never duplicates sends
- tokens expire at campaign end and are revocable via the kill switch
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import NamedTuple

from kp_domain_models import models as dm
from sqlalchemy import select
from sqlalchemy.orm import Session

from kp_database.models import (
    Campaign,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    TrackingToken,
)

TOKEN_EXPIRY_BUFFER_SECONDS = 7 * 24 * 60 * 60


class PreparedRecipient(NamedTuple):
    assignment_id: str
    token_hash: str
    token_prefix: str
    open_url: str
    click_url: str


def _excluded_recipient_ids(session: Session, campaign_id: uuid.UUID) -> set[uuid.UUID]:
    rows = session.execute(
        select(RecipientExclusion.recipient_id).where(
            RecipientExclusion.recipient_id.is_not(None),
            RecipientExclusion.expires_at.is_(None) | (RecipientExclusion.expires_at > datetime.now(UTC)),
            (RecipientExclusion.campaign_id == campaign_id)
            | (RecipientExclusion.campaign_id.is_(None)),
        )
    ).scalars().all()
    return set(rows)


def prepare_campaign(
    session: Session,
    campaign: Campaign,
    *,
    tracking_base_url: str,
    include_test_accounts: bool = False,
    test_only: bool = False,
) -> list[PreparedRecipient]:
    """Create assignments + tokens for eligible recipients of `campaign`.

    Returns tracking URLs per recipient so the caller can publish the deliver
    job. Safe to call once; idempotency keys prevent duplicates on retry.
    """
    if campaign.state not in (dm.CampaignState.APPROVED, dm.CampaignState.SCHEDULED, dm.CampaignState.SENDING):
        raise ValueError(f"campaign is not launchable (state={campaign.state.value})")

    excluded = _excluded_recipient_ids(session, campaign.campaign_id)
    recipients = list(session.execute(
        select(Recipient).where(Recipient.status == dm.RecipientStatus.ACTIVE)
    ).scalars().all())

    now = datetime.now(UTC)
    expires_at = campaign.expires_at
    if expires_at is None:
        expires_at = campaign.schedule_end
    if expires_at is None:
        expires_at = now
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    expires_at = expires_at + timedelta(seconds=TOKEN_EXPIRY_BUFFER_SECONDS)

    tracking_base_url = tracking_base_url.rstrip("/")
    prepared: list[PreparedRecipient] = []

    for recipient in recipients:
        if recipient.recipient_id in excluded:
            continue
        if recipient.is_test_account and not include_test_accounts:
            continue
        if test_only and not recipient.is_test_account:
            continue

        assignment = session.scalar(
            select(RecipientAssignment).where(
                RecipientAssignment.campaign_id == campaign.campaign_id,
                RecipientAssignment.recipient_id == recipient.recipient_id,
            )
        )
        if assignment is not None:
            prepared.append(_urls_for(session, tracking_base_url, assignment))
            continue

        assignment = RecipientAssignment(
            recipient_assignment_id=uuid.uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            snapshot_version=1,
            send_state=dm.SendState.QUEUED,
            idempotency_key=f"{campaign.campaign_id}:{recipient.recipient_id}:1",
        )
        session.add(assignment)
        session.flush()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        session.add(TrackingToken(
            token_id=uuid.uuid4(),
            token_hash=token_hash,
            token_prefix=raw_token[:6],
            campaign_id=campaign.campaign_id,
            recipient_assignment_id=assignment.recipient_assignment_id,
            pepper_version=1,
            status=dm.TokenStatus.ACTIVE,
            expires_at=expires_at,
        ))
        session.flush()
        assignment.token_id = session.execute(
            select(TrackingToken).where(TrackingToken.token_hash == token_hash)
        ).scalar_one().token_id
        prepared.append(_urls_for(session, tracking_base_url, assignment))

    session.commit()
    return prepared


def _urls_for(session: Session, tracking_base_url: str, assignment: RecipientAssignment) -> PreparedRecipient:
    token = session.execute(
        select(TrackingToken).where(TrackingToken.recipient_assignment_id == assignment.recipient_assignment_id)
    ).scalar_one()
    return PreparedRecipient(
        assignment_id=str(assignment.recipient_assignment_id),
        token_hash=token.token_hash,
        token_prefix=token.token_prefix,
        open_url=f"{tracking_base_url}/v1/track/open/{token.token_hash}",
        click_url=f"{tracking_base_url}/v1/track/click/{token.token_hash}",
    )
