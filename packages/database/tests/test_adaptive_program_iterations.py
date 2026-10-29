"""W4-03: adaptive-program iteration generation against a MIGRATED Postgres.

Proves the non-negotiable safety invariants end to end on the real schema:

* An adaptive program materializes ONLY the source occurrence up front; later
  iterations are generated over time, as DRAFTS, and never self-approve/self-send.
* Generation is idempotent across a restart: re-running it creates no duplicate,
  and the occurrence/adaptation unique keys are the enforced backstop.
* A scanner-only (suspected-automation) recipient is never enrolled, and opt-out
  / suppression is honored at enrollment.
* A paused program, or one whose prior iteration has not completed, generates
  nothing.

These require the isolated-migrated-database profile (``KP_TEST_PROFILE=postgres``)
and skip otherwise.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from _migrate_schema import isolated_migrated_database
from kp_database.campaign_service import AudienceDefinition, audience_definition_hash, bind_campaign_training_resource
from kp_database.models import (
    Campaign,
    CampaignApproval,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignLaunchGate,
    CampaignPattern,
    CampaignProgramAdaptation,
    CampaignProgramOccurrence,
    CipherText,
    Recipient,
    RecipientAssignment,
    RecipientExclusion,
    RulesOfEngagement,
    TemplateVersion,
    TrackingEvent,
    TrainingResource,
)
from kp_database.program_service import (
    materialize_campaign_program,
    materialize_next_program_iteration,
    set_campaign_program_state,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.postgres

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST",
    "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test",
)

_DATABASE_URL: str | None = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    try:
        engine = create_db_engine(TEST_URL)
        try:
            with engine.connect() as connection:
                from sqlalchemy import text

                return bool(
                    connection.scalar(text("SELECT rolsuper OR rolcreatedb FROM pg_roles WHERE rolname = current_user"))
                )
        finally:
            engine.dispose()
    except Exception:
        return False


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL isolated-database profile is not reachable")


@pytest.fixture(autouse=True)
def _migrated_database() -> Iterator[str]:
    global _DATABASE_URL
    with isolated_migrated_database(TEST_URL, prefix="kp_adaptive_program") as database_url:
        _DATABASE_URL = database_url
        CipherText.configure_key(b"p" * 32)
        try:
            yield database_url
        finally:
            _DATABASE_URL = None


def _test_engine():
    assert _DATABASE_URL is not None, "the migrated-database fixture is not active"
    return create_engine(_DATABASE_URL, pool_pre_ping=True, poolclass=NullPool, connect_args={"connect_timeout": 5})


def _session():
    return make_session_factory(_test_engine())()


def _recipient(mailbox: str) -> Recipient:
    return Recipient(
        recipient_id=uuid4(),
        employee_key=f"emp-{mailbox}",
        mailbox=mailbox,
        mailbox_sha256=hashlib.sha256(mailbox.encode()).hexdigest(),
        display_name="Test Person",
        department="security",
        status=dm.RecipientStatus.ACTIVE,
    )


def _adaptive_source(session, recipients: list[Recipient], *, occurrence_count: int = 3) -> UUID:
    """Create a scheduled, reviewed source campaign and its adaptive program.

    Returns the program id. The source occurrence (iteration 1) is the only
    occurrence materialized; the frozen audience manifest pins the reviewed
    population used by later adaptive iterations.
    """

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
    start = now + timedelta(days=2)
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
        difficulty={"adaptive_level": 3},
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
    recipient_ids = tuple(sorted((r.recipient_id for r in recipients), key=str))
    definition = AudienceDefinition(include_recipient_ids=recipient_ids)
    audience = CampaignAudience(
        campaign_id=campaign.campaign_id,
        version=1,
        group_ids=[],
        departments=[],
        statuses=[],
        include_recipient_ids=[str(item) for item in recipient_ids],
        exclude_recipient_ids=[],
        sample_size=None,
        sample_seed=None,
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
    session.add_all([pattern, template, roe, resource, *recipients])
    session.flush()
    session.add(campaign)
    session.flush()
    session.add_all([audience, approval])
    for ordinal, recipient_id in enumerate(recipient_ids):
        session.add(
            CampaignAudienceManifest(
                campaign_id=campaign.campaign_id,
                recipient_id=recipient_id,
                audience_version=1,
                ordinal=ordinal,
                recipient_hash=hashlib.sha256(str(recipient_id).encode()).hexdigest(),
            )
        )
    session.flush()
    result = materialize_campaign_program(
        session,
        source_campaign_id=campaign.campaign_id,
        cadence_days=28,
        occurrence_count=occurrence_count,
        generation_mode="adaptive",
        created_by=uuid4(),
    )
    session.commit()
    return result.program.campaign_program_id


def _accepted_assignment(session, campaign_id: UUID, recipient_id: UUID) -> RecipientAssignment:
    assignment = RecipientAssignment(
        recipient_assignment_id=uuid4(),
        campaign_id=campaign_id,
        recipient_id=recipient_id,
        provider_accepted_at=datetime.now(UTC),
        send_state=dm.SendState.ACCEPTED,
        idempotency_key=f"assign-{uuid4()}",
    )
    session.add(assignment)
    session.flush()
    return assignment


def _clicked(session, assignment: RecipientAssignment, *, automation: bool) -> None:
    session.add(
        TrackingEvent(
            event_id=uuid4(),
            event_type=dm.EventType.CLICKED,
            token_id=None,
            recipient_assignment_id=assignment.recipient_assignment_id,
            recipient_id=assignment.recipient_id,
            campaign_id=assignment.campaign_id,
            occurred_at=datetime.now(UTC),
            payload={"automation_suspected": True} if automation else {},
        )
    )
    session.flush()


def _complete_source(session, program_id: UUID) -> UUID:
    """Mark the source iteration COMPLETED and return its campaign id."""
    source_campaign_id = session.scalar(
        select(CampaignProgramOccurrence.campaign_id).where(
            CampaignProgramOccurrence.campaign_program_id == program_id,
            CampaignProgramOccurrence.occurrence_number == 1,
        )
    )
    assert source_campaign_id is not None
    source = session.get(Campaign, source_campaign_id)
    assert source is not None
    source.state = dm.CampaignState.COMPLETED
    session.flush()
    return source_campaign_id


@requires_db
def test_adaptive_create_materializes_only_the_source() -> None:
    with _session() as session:
        recipients = [_recipient(f"r{i}@example.com") for i in range(3)]
        program_id = _adaptive_source(session, recipients, occurrence_count=4)
    with _session() as session:
        occurrences = list(
            session.scalars(
                select(CampaignProgramOccurrence).where(CampaignProgramOccurrence.campaign_program_id == program_id)
            )
        )
        # Only iteration 1 (the human-made source) exists up front; iterations
        # 2..4 are generated over time, never eagerly.
        assert [o.occurrence_number for o in occurrences] == [1]


@requires_db
def test_generation_produces_draft_iteration_excluding_scanner_and_opt_out() -> None:
    with _session() as session:
        human, scanner, opted_out = (_recipient(f"{name}@example.com") for name in ("human", "scanner", "optout"))
        recipients = [human, scanner, opted_out]
        human_id, scanner_id, opt_out_id = human.recipient_id, scanner.recipient_id, opted_out.recipient_id
        program_id = _adaptive_source(session, recipients, occurrence_count=3)

    with _session() as session:
        source_campaign_id = _complete_source(session, program_id)
        # Prior-iteration signals: a genuine human click, and a scanner whose
        # ONLY click is suspected automation.
        _clicked(session, _accepted_assignment(session, source_campaign_id, human_id), automation=False)
        _clicked(session, _accepted_assignment(session, source_campaign_id, scanner_id), automation=True)
        # An active global opt-out/suppression for the third recipient.
        session.add(
            RecipientExclusion(
                recipient_exclusion_id=uuid4(),
                recipient_id=opt_out_id,
                exclusion_type=dm.ExclusionType.GLOBAL,
                campaign_id=None,
                created_by=uuid4(),
            )
        )
        session.commit()

    with _session() as session:
        result = materialize_next_program_iteration(session, program_id=program_id, created_by=uuid4())
        session.commit()
        assert result.created is True
        assert result.occurrence is not None
        assert result.occurrence.occurrence_number == 2

        iteration = session.get(Campaign, result.occurrence.campaign_id)
        assert iteration is not None
        # INVARIANT: the iteration is a DRAFT with no authorization of its own.
        assert iteration.state is dm.CampaignState.DRAFT
        assert iteration.roe_id is None
        assert iteration.manifest_signed_at is None
        assert session.get(CampaignLaunchGate, iteration.campaign_id) is None
        assert (
            session.scalar(
                select(func.count())
                .select_from(CampaignApproval)
                .where(CampaignApproval.campaign_id == iteration.campaign_id)
            )
            == 0
        )

        # Enrollment: scanner-only and opt-out are both excluded; only the human
        # remains. The audience is left unfrozen for the normal review path.
        audience = session.get(CampaignAudience, iteration.campaign_id)
        assert audience is not None
        assert audience.frozen_at is None
        excluded = {UUID(x) for x in audience.exclude_recipient_ids}
        assert scanner_id in excluded
        assert opt_out_id in excluded
        assert human_id not in excluded

        adaptation = session.scalar(
            select(CampaignProgramAdaptation).where(
                CampaignProgramAdaptation.campaign_program_id == program_id,
                CampaignProgramAdaptation.iteration_number == 2,
            )
        )
        assert adaptation is not None
        assert adaptation.enrollment["excluded_scanner_only"] == 1
        assert adaptation.enrollment["excluded_opt_out"] == 1
        assert adaptation.enrollment["enrolled"] == 1
        assert str(scanner_id) in adaptation.enrollment["excluded_scanner_only_ids"]
        assert str(opt_out_id) in adaptation.enrollment["excluded_opt_out_ids"]
        # Adaptation is explainable: the signals and the driver are recorded.
        assert adaptation.signals["human_clicked"] == 1
        assert adaptation.signals["automation_suspected_clicked"] == 1
        assert adaptation.changes["drivers"]


@requires_db
def test_generation_is_idempotent_across_restart() -> None:
    with _session() as session:
        recipients = [_recipient(f"r{i}@example.com") for i in range(2)]
        program_id = _adaptive_source(session, recipients, occurrence_count=3)
    with _session() as session:
        source_campaign_id = _complete_source(session, program_id)
        _clicked(
            session, _accepted_assignment(session, source_campaign_id, recipients[0].recipient_id), automation=False
        )
        session.commit()

    # First run generates iteration 2 and commits.
    with _session() as session:
        first = materialize_next_program_iteration(session, program_id=program_id, created_by=uuid4())
        session.commit()
        assert first.created is True

    # A restart re-runs generation; the prior (new) iteration is a DRAFT, not
    # COMPLETED, so nothing new is produced -- no duplicate iteration 2.
    with _session() as session:
        second = materialize_next_program_iteration(session, program_id=program_id, created_by=uuid4())
        session.commit()
        assert second.created is False
        assert second.reason == "prior_not_complete"
        count = session.scalar(
            select(func.count())
            .select_from(CampaignProgramOccurrence)
            .where(CampaignProgramOccurrence.campaign_program_id == program_id)
        )
        assert count == 2

    # The unique (program, occurrence_number) key is the enforced backstop a
    # racing worker would hit.
    with _session() as session:
        iteration_campaign_id = session.scalar(
            select(CampaignProgramOccurrence.campaign_id).where(
                CampaignProgramOccurrence.campaign_program_id == program_id,
                CampaignProgramOccurrence.occurrence_number == 1,
            )
        )
        session.add(
            CampaignProgramOccurrence(
                campaign_program_occurrence_id=uuid4(),
                campaign_program_id=program_id,
                occurrence_number=2,
                campaign_id=iteration_campaign_id,
                schedule_start=datetime.now(UTC),
                schedule_end=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        with pytest.raises(IntegrityError):
            session.flush()


@requires_db
def test_paused_program_generates_nothing() -> None:
    with _session() as session:
        recipients = [_recipient(f"r{i}@example.com") for i in range(2)]
        program_id = _adaptive_source(session, recipients, occurrence_count=3)
    with _session() as session:
        # Complete the source so an iteration WOULD otherwise be due, then pause.
        _complete_source(session, program_id)
        from kp_database.program_service import get_campaign_program

        current = get_campaign_program(session, program_id)
        set_campaign_program_state(
            session,
            program_id=program_id,
            state=dm.CampaignProgramState.PAUSED,
            expected_version=current.version,
        )
        session.commit()
    with _session() as session:
        result = materialize_next_program_iteration(session, program_id=program_id, created_by=uuid4())
        session.commit()
        assert result.created is False
        assert result.reason == "paused"


@requires_db
def test_prior_not_complete_generates_nothing() -> None:
    with _session() as session:
        recipients = [_recipient(f"r{i}@example.com") for i in range(2)]
        program_id = _adaptive_source(session, recipients, occurrence_count=3)
    with _session() as session:
        # Source is still SCHEDULED (never completed): nothing to adapt from yet.
        result = materialize_next_program_iteration(session, program_id=program_id, created_by=uuid4())
        session.commit()
        assert result.created is False
        assert result.reason == "prior_not_complete"
