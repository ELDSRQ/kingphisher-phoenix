from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from kp_database.base import Base
from kp_database.campaign_service import AudienceDefinition, audience_definition_hash, bind_campaign_training_resource
from kp_database.models import (
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignPattern,
    CampaignProgram,
    CampaignProgramOccurrence,
    CipherText,
    RulesOfEngagement,
    TemplateVersion,
    TrainingResource,
)
from kp_database.program_service import (
    campaign_program_is_complete,
    materialize_campaign_program,
    require_program_active_for_schedule,
    set_campaign_program_state,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, ValidationError_
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.postgres

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST",
    "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test",
)
TEST_SCHEMA = f"campaign_program_{uuid4().hex}"


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(TEST_URL)
        with engine.connect():
            pass
        engine.dispose()
        return True
    except Exception:  # noqa: BLE001 - local integration dependency gate
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


def _setup() -> None:
    admin_engine = create_db_engine(TEST_URL)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{TEST_SCHEMA}" CASCADE')
        connection.exec_driver_sql(f'CREATE SCHEMA "{TEST_SCHEMA}"')
    admin_engine.dispose()
    engine = _test_engine()
    Base.metadata.create_all(bind=engine)
    engine.dispose()
    CipherText.configure_key(b"p" * 32)


def _test_engine():
    return create_engine(
        TEST_URL,
        pool_pre_ping=True,
        poolclass=NullPool,
        connect_args={"connect_timeout": 5, "options": f"-csearch_path={TEST_SCHEMA}"},
    )


def _session():
    return make_session_factory(_test_engine())()


@pytest.fixture(scope="module", autouse=True)
def _cleanup_isolated_schema():
    yield
    engine = create_db_engine(TEST_URL)
    with engine.begin() as connection:
        connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{TEST_SCHEMA}" CASCADE')
    engine.dispose()


def _source_campaign(session, *, starts_in_days: int = 2) -> Campaign:  # noqa: ANN001
    now = datetime.now(UTC)
    pattern = CampaignPattern(
        campaign_pattern_id=uuid4(),
        pattern_version=1,
        lure_category=dm.LureCategory.CONFERENCE,
        confidence=dm.Confidence.HIGH,
        approval_state=dm.PatternApprovalState.APPROVED,
    )
    roe = RulesOfEngagement(
        roe_id=uuid4(),
        signer="Security",
        authorizing_party="RSA Conference",
        terms_text="Authorized awareness simulation",
        terms_hash="t" * 64,
        signature="s" * 64,
        signature_version=2,
        signed_at=now,
        window_start=now,
        window_end=now + timedelta(days=400),
        target_domains=["example.com"],
    )
    start = now + timedelta(days=starts_in_days)
    end = start + timedelta(hours=8)
    template = TemplateVersion(
        template_version_id=uuid4(),
        version=1,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="i" * 64,
        subject="Initial subject",
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    campaign = Campaign(
        campaign_id=uuid4(),
        pattern_id=pattern.campaign_pattern_id,
        current_template_id=template.template_version_id,
        title="RSA Conference awareness exercise",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="awareness@example.com",
        sender_display_name="Conference Security",
        roe_id=roe.roe_id,
        training_domain="training.example.com",
        schedule_start=start,
        schedule_end=end,
        timezone="UTC",
        max_recipients=500,
        difficulty={"legacy_note": "copied but not interpreted"},
        manifest_hash="c" * 64,
        created_by=uuid4(),
        expires_at=end,
    )
    resource = TrainingResource(
        training_resource_id=uuid4(),
        title="Conference warning-sign review",
        kind="article",
        content="Pause, inspect the sender, and verify independently.",
        version=1,
        requires_completion=True,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    bind_campaign_training_resource(campaign, resource)
    definition = AudienceDefinition(
        departments=("security",),
        statuses=(dm.RecipientStatus.ACTIVE,),
        sample_size=25,
        sample_seed="program-test",
    )
    audience = CampaignAudience(
        campaign_id=campaign.campaign_id,
        version=3,
        group_ids=[],
        departments=list(definition.departments),
        statuses=[dm.RecipientStatus.ACTIVE.value],
        include_recipient_ids=[],
        exclude_recipient_ids=[],
        sample_size=definition.sample_size,
        sample_seed=definition.sample_seed,
        configuration_hash=audience_definition_hash(definition),
        preview_hash="p" * 64,
        manifest_hash="m" * 64,
        frozen_at=now,
        legacy_requires_configuration=False,
    )
    approval = CampaignApproval(
        campaign_approval_id=uuid4(),
        campaign_id=campaign.campaign_id,
        approval_type=dm.ApprovalType.SECURITY,
        approver_id=uuid4(),
        decision=dm.ApprovalDecision.APPROVED,
        decided_at=now,
        template_version_id=campaign.current_template_id,
    )
    session.add_all([pattern, template, roe, resource])
    session.flush()
    session.add(campaign)
    session.flush()
    session.add_all([audience, approval])
    session.commit()
    return campaign


@requires_db
def test_materialization_creates_finite_independent_drafts_without_evidence() -> None:
    _setup()
    with _session() as session:
        source = _source_campaign(session)
        actor_id = uuid4()
        result = materialize_campaign_program(
            session,
            source_campaign_id=source.campaign_id,
            cadence_days=28,
            occurrence_count=4,
            created_by=actor_id,
        )
        session.commit()

        assert result.created is True
        assert [item.occurrence_number for item in result.occurrences] == [1, 2, 3, 4]
        assert result.occurrences[0].campaign_id == source.campaign_id
        campaigns = list(
            session.scalars(
                select(Campaign)
                .join(CampaignProgramOccurrence, CampaignProgramOccurrence.campaign_id == Campaign.campaign_id)
                .where(CampaignProgramOccurrence.campaign_program_id == result.program.campaign_program_id)
                .order_by(Campaign.schedule_start)
            )
        )
        assert len(campaigns) == 4
        for index, campaign in enumerate(campaigns[1:], start=1):
            assert campaign.state is dm.CampaignState.DRAFT
            assert campaign.roe_id is None
            assert campaign.manifest_signed_at is None
            assert campaign.recall_of is None
            assert campaign.training_resource_id == source.training_resource_id
            assert campaign.training_resource_version == source.training_resource_version
            assert campaign.training_resource_digest == source.training_resource_digest
            assert campaign.schedule_start == source.schedule_start + timedelta(days=28 * index)
            copied_audience = session.get(CampaignAudience, campaign.campaign_id)
            assert copied_audience is not None
            assert (
                copied_audience.configuration_hash
                == session.get(CampaignAudience, source.campaign_id).configuration_hash
            )
            assert copied_audience.frozen_at is None
            assert copied_audience.preview_hash is None
            assert copied_audience.manifest_hash is None
            approval_count = session.scalar(
                select(func.count())
                .select_from(CampaignApproval)
                .where(CampaignApproval.campaign_id == campaign.campaign_id)
            )
            assert approval_count == 0


@requires_db
def test_materialization_is_idempotent_and_body_drift_fails_closed() -> None:
    _setup()
    with _session() as session:
        source = _source_campaign(session)
        first = materialize_campaign_program(
            session,
            source_campaign_id=source.campaign_id,
            cadence_days=14,
            occurrence_count=3,
            created_by=uuid4(),
        )
        session.commit()
        replay = materialize_campaign_program(
            session,
            source_campaign_id=source.campaign_id,
            cadence_days=14,
            occurrence_count=3,
            created_by=uuid4(),
        )
        assert replay.created is False
        assert replay.program.campaign_program_id == first.program.campaign_program_id
        assert [item.campaign_id for item in replay.occurrences] == [item.campaign_id for item in first.occurrences]
        with pytest.raises(ConflictError, match="different program configuration"):
            materialize_campaign_program(
                session,
                source_campaign_id=source.campaign_id,
                cadence_days=28,
                occurrence_count=3,
                created_by=uuid4(),
            )

        template = session.get(TemplateVersion, source.current_template_id)
        assert template is not None
        template.subject = "Changed after program creation"
        session.flush()
        with pytest.raises(ConflictError, match="configuration changed"):
            materialize_campaign_program(
                session,
                source_campaign_id=source.campaign_id,
                cadence_days=14,
                occurrence_count=3,
                created_by=uuid4(),
            )


@requires_db
def test_concurrent_materialization_produces_one_program() -> None:
    _setup()
    with _session() as session:
        source_id = _source_campaign(session).campaign_id

    def create() -> tuple[UUID, bool]:
        with _session() as thread_session:
            result = materialize_campaign_program(
                thread_session,
                source_campaign_id=source_id,
                cadence_days=28,
                occurrence_count=3,
                created_by=uuid4(),
            )
            thread_session.commit()
            return result.program.campaign_program_id, result.created

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: create(), range(2)))
    assert len({program_id for program_id, _created in results}) == 1
    assert sorted(created for _program_id, created in results) == [False, True]
    with _session() as session:
        assert session.scalar(select(func.count()).select_from(CampaignProgram)) == 1
        assert session.scalar(select(func.count()).select_from(CampaignProgramOccurrence)) == 3


@requires_db
def test_program_bounds_and_pause_guard_fail_closed_without_partial_rows() -> None:
    _setup()
    with _session() as session:
        source = _source_campaign(session)
        with pytest.raises(ValidationError_, match="cadence_days"):
            materialize_campaign_program(
                session,
                source_campaign_id=source.campaign_id,
                cadence_days=30,
                occurrence_count=3,
                created_by=uuid4(),
            )
        assert session.scalar(select(func.count()).select_from(CampaignProgram)) == 0

        result = materialize_campaign_program(
            session,
            source_campaign_id=source.campaign_id,
            cadence_days=28,
            occurrence_count=3,
            created_by=uuid4(),
        )
        program, changed = set_campaign_program_state(
            session,
            program_id=result.program.campaign_program_id,
            state=dm.CampaignProgramState.PAUSED,
            expected_version=1,
        )
        assert changed is True
        assert program.version == 2
        with pytest.raises(ConflictError, match="paused"):
            require_program_active_for_schedule(session, result.occurrences[1].campaign_id)
        with pytest.raises(ConflictError, match="reload"):
            set_campaign_program_state(
                session,
                program_id=program.campaign_program_id,
                state=dm.CampaignProgramState.ACTIVE,
                expected_version=1,
            )
        session.commit()
        assert campaign_program_is_complete(session, program.campaign_program_id) is False
