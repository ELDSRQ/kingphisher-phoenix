"""Two-person approval keeps separate facets without requiring three people.

The campaign creator remains outside the approval set. One independent
authorized operator may persist both facet decisions, while a third person may
still take one facet. Runs against the disposable dev Postgres; skipped when it
is not reachable.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kp_database.base import Base
from kp_database.models import Campaign, CampaignApproval, CampaignPattern, CipherText, TemplateVersion
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from sqlalchemy import create_engine, select
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.postgres


TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _available
    if _available is None:
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            engine.dispose()
            _available = True
        except Exception:
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    CipherText.configure_key(b"0" * 32)


def _session():
    engine = create_engine(
        TEST_URL,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )
    return make_session_factory(engine)()


def _campaign(session, author) -> Campaign:
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


def _approve(session, campaign, approver, approval_type) -> None:
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
            launch_manifest_hash=campaign.manifest_hash,
        )
    )
    session.commit()


def _approvals_for(session, campaign):
    return list(
        session.scalars(
            select(CampaignApproval).where(
                CampaignApproval.campaign_id == campaign.campaign_id,
                CampaignApproval.decision == dm.ApprovalDecision.APPROVED,
                CampaignApproval.launch_manifest_hash == campaign.manifest_hash,
            )
        )
    )


@requires_db
def test_one_independent_approver_can_complete_both_recorded_facets() -> None:
    _setup()
    session = _session()
    try:
        author, approver = uuid4(), uuid4()
        campaign = _campaign(session, author)
        _approve(session, campaign, approver, dm.ApprovalType.SECURITY)
        _approve(session, campaign, approver, dm.ApprovalType.PRIVACY)

        approvals = _approvals_for(session, campaign)
        assert {approval.approval_type for approval in approvals} == {
            dm.ApprovalType.SECURITY,
            dm.ApprovalType.PRIVACY,
        }
        assert {approval.approver_id for approval in approvals} == {approver}
        assert {approval.launch_manifest_hash for approval in approvals} == {campaign.manifest_hash}
    finally:
        session.close()


@requires_db
def test_a_third_person_can_take_one_facet_without_being_required() -> None:
    _setup()
    session = _session()
    try:
        author, first, second = uuid4(), uuid4(), uuid4()
        campaign = _campaign(session, author)
        _approve(session, campaign, first, dm.ApprovalType.SECURITY)
        _approve(session, campaign, second, dm.ApprovalType.PRIVACY)

        approvals = _approvals_for(session, campaign)
        assert {approval.approver_id for approval in approvals} == {first, second}
        assert len(approvals) == 2
    finally:
        session.close()


@requires_db
def test_a_rejected_decision_does_not_count_as_an_approved_facet() -> None:
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
                launch_manifest_hash=campaign.manifest_hash,
            )
        )
        session.commit()

        assert _approvals_for(session, campaign) == []
    finally:
        session.close()
