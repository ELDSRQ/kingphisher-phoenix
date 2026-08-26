"""Two-person rule: the security and privacy approvals must be distinct people.

Blocking only the campaign author is not enough. One approver could otherwise
supply BOTH decisions and satisfy the gate alone, which is exactly the outcome
requiring two approvals exists to prevent. Runs against the disposable dev
Postgres; skipped when it is not reachable.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from kp_database.base import Base
from kp_database.models import Campaign, CampaignApproval, CampaignPattern, CipherText, TemplateVersion
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from sqlalchemy import select

load_dotenv(Path(__file__).resolve().parents[3] / ".env", override=False)

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="dev Postgres not reachable")


def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    CipherText.configure_key(b"0" * 32)


def _session():
    return make_session_factory(create_db_engine(TEST_URL))()


def _campaign(session, author) -> Campaign:  # noqa: ANN001
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        pattern_version=1,
        lure_category=dm.LureCategory.INVOICE,
        approval_state=dm.PatternApprovalState.APPROVED,
        confidence=dm.Confidence.HIGH,
    )
    session.add(pattern)
    template = TemplateVersion(
        template_version_id=uuid4(),
        version=1,
        idempotency_key=f"approval-separation-{uuid4()}",
        generator_version="0.1.0",
        prompt_template_version="0.1.0",
        model_id="test",
        input_hash=hashlib.sha256(b"approval-separation").hexdigest(),
        raw_proposal={"subject": "s", "plain_text": "p", "safe_html": "<p>p</p>"},
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    session.add(template)
    session.commit()
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        current_template_id=template.template_version_id,
        title="Approval separation drill",
        state=dm.CampaignState.PENDING_APPROVAL,
        sender_mailbox="drills@example.com",
        training_domain="training.local",
        schedule_start=now + timedelta(hours=1),
        schedule_end=now + timedelta(days=7),
        timezone="UTC",
        max_recipients=10,
        manifest_hash=hashlib.sha256(b"approval-separation").hexdigest(),
        created_by=author,
        expires_at=now + timedelta(days=8),
    )
    session.add(campaign)
    session.commit()
    return campaign


def _approve(session, campaign, approver, approval_type) -> None:  # noqa: ANN001
    session.add(
        CampaignApproval(
            campaign_approval_id=uuid4(),
            campaign_id=campaign.campaign_id,
            approval_type=approval_type,
            approver_id=approver,
            decision=dm.ApprovalDecision.APPROVED,
            rationale="test",
            decided_at=datetime.now(UTC),
            template_version_id=campaign.current_template_id,
        )
    )
    session.commit()


def _other_approval_by(session, campaign, approver, approval_type):  # noqa: ANN001
    """The query the router uses to detect a same-person second approval."""
    return session.scalar(
        select(CampaignApproval).where(
            CampaignApproval.campaign_id == campaign.campaign_id,
            CampaignApproval.approval_type != approval_type,
            CampaignApproval.approver_id == approver,
            CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
        )
    )


@requires_db
def test_same_approver_is_detected_across_approval_types() -> None:
    _setup()
    session = _session()
    try:
        author, approver = uuid4(), uuid4()
        campaign = _campaign(session, author)
        _approve(session, campaign, approver, dm.ApprovalType.SECURITY)

        # The same person coming back for the privacy decision must be found.
        assert _other_approval_by(session, campaign, approver, dm.ApprovalType.PRIVACY) is not None
    finally:
        session.close()


@requires_db
def test_a_different_approver_is_not_blocked() -> None:
    _setup()
    session = _session()
    try:
        author, first, second = uuid4(), uuid4(), uuid4()
        campaign = _campaign(session, author)
        _approve(session, campaign, first, dm.ApprovalType.SECURITY)

        # A genuinely separate reviewer must be able to give the other approval.
        assert _other_approval_by(session, campaign, second, dm.ApprovalType.PRIVACY) is None
    finally:
        session.close()


@requires_db
def test_a_rejected_decision_does_not_count_as_the_other_approval() -> None:
    _setup()
    session = _session()
    try:
        author, approver = uuid4(), uuid4()
        campaign = _campaign(session, author)
        session.add(
            CampaignApproval(
                campaign_approval_id=uuid4(),
                campaign_id=campaign.campaign_id,
                approval_type=dm.ApprovalType.SECURITY,
                approver_id=approver,
                decision=dm.ApprovalDecision.REJECTED,
                rationale="test",
                decided_at=datetime.now(UTC),
                template_version_id=campaign.current_template_id,
            )
        )
        session.commit()

        # Only APPROVED decisions consume a person's one slot.
        assert _other_approval_by(session, campaign, approver, dm.ApprovalType.PRIVACY) is None
    finally:
        session.close()
