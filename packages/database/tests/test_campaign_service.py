"""WS-10 campaign lifecycle tests against a disposable Postgres.

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles.
"""

from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kp_database.base import Base
from kp_database.campaign_service import (
    bind_campaign_training_resource,
    empty_audience,
    prepare_campaign,
    tracking_token_verifier,
)
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    TrackingToken,
    TrainingResource,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError
from sqlalchemy import create_engine, func, select
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
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")
TOKEN_KEY = b"t" * 32


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
    resource = TrainingResource(
        training_resource_id=uuid4(),
        title="Reviewed awareness lesson",
        kind="article",
        content="Pause and verify an unexpected request through a trusted channel.",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    # Campaign stores only the resource UUID, so the ORM cannot infer the FK
    # insert order.  Persist the approved parent before binding the campaign.
    session.add(resource)
    session.flush()
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
    bind_campaign_training_resource(campaign, resource)
    session.add_all([campaign, empty_audience(campaign.campaign_id)])
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
    session.flush()
    campaign = session.scalar(select(Campaign).order_by(Campaign.campaign_id).limit(1))
    if campaign is not None:
        audience = session.get(CampaignAudience, campaign.campaign_id)
        assert audience is not None
        ordinal = session.scalar(
            select(func.count())
            .select_from(CampaignAudienceManifest)
            .where(CampaignAudienceManifest.campaign_id == campaign.campaign_id)
        )
        recipient_hash = hashlib.sha256(
            f"campaign-audience-v1:{campaign.campaign_id}:{recipient.recipient_id}:{recipient.mailbox_sha256}".encode(
                "ascii"
            )
        ).hexdigest()
        session.add(
            CampaignAudienceManifest(
                campaign_id=campaign.campaign_id,
                recipient_id=recipient.recipient_id,
                audience_version=audience.version,
                ordinal=int(ordinal or 0),
                recipient_hash=recipient_hash,
            )
        )
        audience.frozen_at = datetime.now(UTC)
        audience.preview_hash = "p" * 64
        audience.manifest_hash = "m" * 64
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
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
    finally:
        session.close()


@requires_db
def test_terminal_state_blocks_both_launch_and_test_send() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.RECALLED)
    try:
        with pytest.raises(ConflictError, match="terminal"):
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
        with pytest.raises(ConflictError, match="terminal"):
            prepare_campaign(
                session, campaign, tracking_base_url="http://t:8001", test_only=True, token_hmac_key=TOKEN_KEY
            )
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
            prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
        prepared = prepare_campaign(
            session,
            campaign,
            tracking_base_url="http://t:8001",
            include_test_accounts=True,
            test_only=True,
            token_hmac_key=TOKEN_KEY,
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
            session,
            campaign,
            tracking_base_url="http://t:8001",
            include_test_accounts=True,
            test_only=True,
            token_hmac_key=TOKEN_KEY,
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
        prepared = prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
        assert len(prepared) == 1
        token = session.execute(select(TrackingToken)).scalar_one()
        assert token.token_prefix == token.token_hash[:6]
        assert prepared[0].token_prefix == token.token_hash[:6]
        assert token.token_hash == tracking_token_verifier(prepared[0].bearer_token, TOKEN_KEY)
        assert token.token_hash not in prepared[0].open_url
        assert prepared[0].bearer_token in prepared[0].open_url
    finally:
        session.close()


@requires_db
def test_prepare_is_idempotent() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED)
    _recipient(session, "user0@example.com")
    try:
        first = prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
        second = prepare_campaign(session, campaign, tracking_base_url="http://t:8001", token_hmac_key=TOKEN_KEY)
        assert len(first) == len(second) == 1
        assert first[0].bearer_token != second[0].bearer_token
        assert first[0].token_verifier != second[0].token_verifier
        assignments = session.execute(select(RecipientAssignment)).scalars().all()
        assert len(assignments) == 1
    finally:
        session.close()


@requires_db
def test_prepare_leaves_commit_ownership_to_caller_and_rolls_back_cleanly() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, state=dm.CampaignState.APPROVED)
    _recipient(session, "rollback@example.com")
    try:
        prepared = prepare_campaign(
            session,
            campaign,
            tracking_base_url="http://t:8001",
            token_hmac_key=TOKEN_KEY,
        )
        assert len(prepared) == 1
        session.rollback()
    finally:
        session.close()

    verification = _session()
    try:
        assert verification.scalar(select(RecipientAssignment)) is None
        assert verification.scalar(select(TrackingToken)) is None
    finally:
        verification.close()
