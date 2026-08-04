"""WS-10 campaign lifecycle tests against a disposable Postgres.

Require the local dev stack (`docker compose up -d postgres`) and the
`kingphisher_test` database (created by `make db-init`); skipped otherwise.
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
from kp_database.campaign_service import prepare_campaign
from kp_database.models import Campaign, CampaignPattern, CipherText, Recipient, RecipientAssignment, TrackingToken
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError
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


def _pattern(session) -> CampaignPattern:  # noqa: ANN001
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        pattern_version=1,
        lure_category=dm.LureCategory.INVOICE,
        approval_state=dm.PatternApprovalState.APPROVED,
        confidence=dm.Confidence.HIGH,
    )
    session.add(pattern)
    session.commit()
    return pattern


def _campaign(session, *, state: dm.CampaignState, max_recipients: int = 10) -> Campaign:  # noqa: ANN001
    pattern = _pattern(session)
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        title="test campaign",
        state=state,
        sender_mailbox="drills@example.com",
        training_domain="training.local",
        schedule_start=now - timedelta(days=1),
        schedule_end=now + timedelta(days=13),
        timezone="UTC",
        max_recipients=max_recipients,
        created_by=uuid4(),
        expires_at=now + timedelta(days=14),
    )
    session.add(campaign)
    session.commit()
    return campaign


def _recipient(session, mailbox: str, *, is_test: bool = False) -> Recipient:  # noqa: ANN001
    recipient = Recipient(
        recipient_id=uuid4(),
        employee_key=mailbox.lower(),
        mailbox=mailbox,
        mailbox_sha256=hashlib.sha256(mailbox.lower().encode("utf-8")).hexdigest(),
        display_name="N",
        department="QA",
        is_test_account=is_test,
        status=dm.RecipientStatus.ACTIVE,
    )
    session.add(recipient)
    session.commit()
    return recipient


@requires_db
def test_max_recipients_cap_is_enforced() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED, max_recipients=1)
    for i in range(3):
        _recipient(session, f"user{i}@example.com")
    try:
        with pytest.raises(ConflictError, match="max_recipients"):
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
    finally:
        session.close()


@requires_db
def test_terminal_state_blocks_both_launch_and_test_send() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.RECALLED)
    try:
        with pytest.raises(ConflictError, match="terminal"):
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
        with pytest.raises(ConflictError, match="terminal"):
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001", test_only=True)
    finally:
        session.close()


@requires_db
def test_draft_state_requires_test_only() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.DRAFT)
    _recipient(session, "test+batch@example.com", is_test=True)
    try:
        with pytest.raises(ConflictError, match="not launchable"):
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
        prepared = prepare_campaign(
            session, campaign, tracking_base_url="http://t:8001", include_test_accounts=True, test_only=True
        )
        assert len(prepared) == 1
    finally:
        session.close()


@requires_db
def test_test_only_prepares_only_test_accounts() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED)
    _recipient(session, "real@example.com")
    _recipient(session, "test+batch@example.com", is_test=True)
    try:
        prepared = prepare_campaign(
            session, campaign, tracking_base_url="http://t:8001", include_test_accounts=True, test_only=True
        )
        assert len(prepared) == 1
    finally:
        session.close()


@requires_db
def test_token_prefix_derived_from_hash_not_raw_token() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED)
    _recipient(session, "user0@example.com")
    try:
        prepared = prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
        assert len(prepared) == 1
        token = session.execute(select(TrackingToken)).scalar_one()
        assert token.token_prefix == token.token_hash[:6]
        assert prepared[0].token_prefix == token.token_hash[:6]
    finally:
        session.close()


@requires_db
def test_prepare_is_idempotent() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED)
    _recipient(session, "user0@example.com")
    try:
        first = prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
        second = prepare_campaign(session, campaign, tracking_base_url="http://t:8001")
        assert len(first) == len(second) == 1
        assignments = session.execute(select(RecipientAssignment)).scalars().all()
        assert len(assignments) == 1
    finally:
        session.close()
