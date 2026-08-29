from __future__ import annotations

import hashlib
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from kp_database.base import Base
from kp_database.campaign_service import (
    AudienceDefinition,
    audience_matches_preview,
    bind_campaign_training_resource,
    configure_campaign_audience,
    empty_audience,
    freeze_campaign_audience,
    prepare_campaign,
    preview_campaign_audience,
)
from kp_database.models import (
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    RulesOfEngagement,
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
TOKEN_KEY = b"a" * 32
_available: bool | None = None


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
        except Exception:  # noqa: BLE001
            _available = False
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    now = datetime.now(UTC)
    with make_session_factory(engine)() as session:
        session.add_all(
            RulesOfEngagement(
                roe_id=uuid.UUID(int=index),
                signer="test-operator@example.com",
                authorizing_party="Test organization",
                terms_text="Authorized test engagement",
                terms_hash="1" * 64,
                signature="2" * 64,
                signed_at=now,
                window_start=now - timedelta(days=1),
                window_end=now + timedelta(days=30),
                target_domains=["example.com"],
            )
            for index in range(1, 4)
        )
        session.commit()
    engine.dispose()
    CipherText.configure_key(b"c" * 32)


def _session():
    engine = create_engine(
        TEST_URL,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5},
    )
    return make_session_factory(engine)()


def _campaign(session, *, max_recipients: int = 10) -> Campaign:  # noqa: ANN001
    pattern = CampaignPattern(
        campaign_pattern_id=uuid.uuid4(),
        lure_category=dm.LureCategory.CONFERENCE,
        confidence=dm.Confidence.HIGH,
        approval_state=dm.PatternApprovalState.APPROVED,
    )
    # Campaign only stores the FK value (there is no ORM relationship for the
    # unit-of-work to use when ordering these inserts), so make the parent row
    # durable before inserting the campaign.
    session.add(pattern)
    session.flush()
    now = datetime.now(UTC)
    resource = TrainingResource(
        training_resource_id=uuid.uuid4(),
        title="Reviewed awareness lesson",
        kind="article",
        content="Pause and verify an unexpected request through a trusted channel.",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    session.add(resource)
    session.flush()
    campaign = Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        title="RSA pilot",
        state=dm.CampaignState.DRAFT,
        sender_mailbox="security@example.com",
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        max_recipients=max_recipients,
        expires_at=now + timedelta(days=2),
        created_by=uuid.uuid4(),
    )
    bind_campaign_training_resource(campaign, resource)
    session.add_all([campaign, empty_audience(campaign.campaign_id)])
    session.commit()
    return campaign


def _recipient(
    session,
    mailbox: str,
    *,
    department: str = "Security",
    status: dm.RecipientStatus = dm.RecipientStatus.ACTIVE,
) -> Recipient:  # noqa: ANN001
    recipient = Recipient(
        recipient_id=uuid.uuid4(),
        employee_key=mailbox,
        mailbox=mailbox,
        mailbox_sha256=hashlib.sha256(mailbox.lower().encode()).hexdigest(),
        display_name="Masked Person",
        department=department,
        status=status,
        is_test_account=False,
    )
    session.add(recipient)
    session.commit()
    return recipient


@requires_db
def test_seeded_preview_freeze_and_prepare_use_only_exact_manifest() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session, max_recipients=2)
    recipients = [_recipient(session, f"person-{index}@example.com") for index in range(4)]
    departed = _recipient(session, "departed@example.com", status=dm.RecipientStatus.DEPARTED)
    outside = _recipient(session, "outside@elsewhere.com")
    definition = AudienceDefinition(
        include_recipient_ids=tuple(item.recipient_id for item in [*recipients, departed, outside]),
        statuses=(dm.RecipientStatus.ACTIVE,),
        sample_size=2,
        sample_seed="rsa-pilot-seed",
    )
    configure_campaign_audience(session, campaign, definition)
    session.commit()

    first = preview_campaign_audience(
        session,
        campaign,
        allowed_domains=frozenset({"example.com"}),
        roe_options=[(uuid.UUID(int=1), frozenset({"example.com"}))],
    )
    second = preview_campaign_audience(
        session,
        campaign,
        allowed_domains=frozenset({"example.com"}),
        roe_options=[(uuid.UUID(int=1), frozenset({"example.com"}))],
    )
    assert first.preview_hash == second.preview_hash
    assert [item.recipient_id for item in first.included] == [item.recipient_id for item in second.included]
    assert len(first.included) == 2
    assert first.excluded_counts == {"domain_not_allowed": 1, "status_filter": 1, "sampled_out": 2}

    freeze_campaign_audience(session, campaign, first, expected_preview_hash=first.preview_hash)
    campaign.state = dm.CampaignState.APPROVED
    session.commit()
    assert audience_matches_preview(session, campaign, second)

    # A new active directory recipient after approval is not in the manifest
    # and must never silently join this campaign.
    _recipient(session, "late-joiner@example.com")
    prepared = prepare_campaign(
        session,
        campaign,
        tracking_base_url="https://tracking.example.com",
        token_hmac_key=TOKEN_KEY,
    )
    assert len(prepared) == 2
    assigned_ids = set(
        session.scalars(
            select(RecipientAssignment.recipient_id).where(RecipientAssignment.campaign_id == campaign.campaign_id)
        )
    )
    assert assigned_ids == {item.recipient_id for item in first.included}
    session.close()


@requires_db
def test_only_active_matching_scope_exclusions_filter_preview_and_prepare() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session)
    recipient = _recipient(session, "exclusion-lifecycle@example.com")
    configure_campaign_audience(
        session,
        campaign,
        AudienceDefinition(include_recipient_ids=(recipient.recipient_id,)),
    )
    now = datetime.now(UTC)
    session.add_all(
        [
            RecipientExclusion(
                recipient_exclusion_id=uuid.uuid4(),
                recipient_id=recipient.recipient_id,
                exclusion_type=dm.ExclusionType.GLOBAL,
                reason="expired",
                expires_at=now - timedelta(minutes=1),
            ),
            RecipientExclusion(
                recipient_exclusion_id=uuid.uuid4(),
                recipient_id=recipient.recipient_id,
                exclusion_type=dm.ExclusionType.ACCOMMODATION,
                reason="revoked",
                revoked_at=now,
                revoked_by=uuid.uuid4(),
                revoke_reason="review complete",
            ),
            RecipientExclusion(
                recipient_exclusion_id=uuid.uuid4(),
                recipient_id=recipient.recipient_id,
                exclusion_type=dm.ExclusionType.CAMPAIGN_SPECIFIC,
                campaign_id=uuid.uuid4(),
                reason="different campaign",
            ),
        ]
    )
    session.commit()

    preview = preview_campaign_audience(
        session,
        campaign,
        allowed_domains=frozenset({"example.com"}),
        roe_options=[(uuid.UUID(int=1), frozenset({"example.com"}))],
    )
    assert [item.recipient_id for item in preview.included] == [recipient.recipient_id]
    assert preview.excluded_counts == {}
    freeze_campaign_audience(session, campaign, preview, expected_preview_hash=preview.preview_hash)
    campaign.state = dm.CampaignState.APPROVED
    session.commit()

    active = RecipientExclusion(
        recipient_exclusion_id=uuid.uuid4(),
        recipient_id=recipient.recipient_id,
        exclusion_type=dm.ExclusionType.GLOBAL,
        reason="current global exclusion",
    )
    session.add(active)
    session.commit()
    with pytest.raises(ConflictError, match="excluded recipient"):
        prepare_campaign(
            session,
            campaign,
            tracking_base_url="https://tracking.example.com",
            token_hmac_key=TOKEN_KEY,
        )
    session.rollback()

    active.revoked_at = datetime.now(UTC)
    active.revoked_by = uuid.uuid4()
    active.revoke_reason = "operator restored eligibility"
    session.commit()
    prepared = prepare_campaign(
        session,
        campaign,
        tracking_base_url="https://tracking.example.com",
        token_hmac_key=TOKEN_KEY,
    )
    assert len(prepared) == 1
    assignment = session.get(RecipientAssignment, uuid.UUID(prepared[0].assignment_id))
    assert assignment is not None and assignment.recipient_id == recipient.recipient_id
    session.close()


@requires_db
def test_configuration_change_invalidates_manifest_approvals_and_state_with_rollback() -> None:
    _setup()
    session = _session()
    campaign = _campaign(session)
    recipient = _recipient(session, "person@example.com")
    definition = AudienceDefinition(include_recipient_ids=(recipient.recipient_id,))
    configure_campaign_audience(session, campaign, definition)
    preview = preview_campaign_audience(
        session,
        campaign,
        allowed_domains=frozenset({"example.com"}),
        roe_options=[(uuid.UUID(int=2), frozenset({"example.com"}))],
    )
    freeze_campaign_audience(session, campaign, preview, expected_preview_hash=preview.preview_hash)
    campaign.state = dm.CampaignState.APPROVED
    session.add(
        CampaignApproval(
            campaign_approval_id=uuid.uuid4(),
            campaign_id=campaign.campaign_id,
            approval_type=dm.ApprovalType.SECURITY,
            approver_id=uuid.uuid4(),
            decision=dm.ApprovalDecision.APPROVED,
            decided_at=datetime.now(UTC),
            template_version_id=uuid.uuid4(),
        )
    )
    session.commit()

    configure_campaign_audience(
        session,
        campaign,
        AudienceDefinition(include_recipient_ids=(recipient.recipient_id,), sample_size=1, sample_seed="changed"),
    )
    assert campaign.state == dm.CampaignState.DRAFT
    assert session.scalar(select(CampaignApproval)) is None
    assert session.scalar(select(CampaignAudienceManifest)) is None
    session.rollback()

    session.expire_all()
    assert session.get(Campaign, campaign.campaign_id).state == dm.CampaignState.APPROVED
    assert session.scalar(select(func.count()).select_from(CampaignApproval)) == 1
    assert session.scalar(select(func.count()).select_from(CampaignAudienceManifest)) == 1
    session.close()


@requires_db
def test_concurrent_prepare_serializes_to_one_assignment() -> None:
    _setup()
    seed = _session()
    campaign = _campaign(seed)
    recipient = _recipient(seed, "concurrent@example.com")
    configure_campaign_audience(seed, campaign, AudienceDefinition(include_recipient_ids=(recipient.recipient_id,)))
    preview = preview_campaign_audience(
        seed,
        campaign,
        allowed_domains=frozenset({"example.com"}),
        roe_options=[(uuid.UUID(int=3), frozenset({"example.com"}))],
    )
    freeze_campaign_audience(seed, campaign, preview, expected_preview_hash=preview.preview_hash)
    campaign.state = dm.CampaignState.APPROVED
    seed.commit()
    campaign_id = campaign.campaign_id
    seed.close()

    def launch() -> int:
        session = _session()
        try:
            row = session.get(Campaign, campaign_id)
            assert row is not None
            prepared = prepare_campaign(
                session,
                row,
                tracking_base_url="https://tracking.example.com",
                token_hmac_key=TOKEN_KEY,
            )
            session.commit()
            return len(prepared)
        finally:
            session.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: launch(), range(2))) == [1, 1]
    verify = _session()
    try:
        assert verify.scalar(select(func.count()).select_from(RecipientAssignment)) == 1
        audience = verify.get(CampaignAudience, campaign_id)
        assert audience is not None and audience.frozen_at is not None
    finally:
        verify.close()
