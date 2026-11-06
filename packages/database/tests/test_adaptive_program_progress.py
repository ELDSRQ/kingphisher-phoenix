from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock
from uuid import uuid4

import pytest
from kp_database import program_service
from kp_database.models import Campaign, CampaignProgram, CampaignProgramOccurrence
from kp_domain_models import models as dm
from kp_telemetry.errors import ConflictError, ValidationError_

NOW = datetime(2026, 11, 6, 12, tzinfo=UTC)


def fixture(monkeypatch, *, prior_state=dm.CampaignState.COMPLETED, late=False):
    source = Campaign(
        campaign_id=uuid4(),
        state=prior_state,
        schedule_start=NOW - timedelta(days=29 if late else 1),
        schedule_end=NOW - timedelta(days=29 if late else 1) + timedelta(hours=2),
        created_by=uuid4(),
    )
    program = CampaignProgram(
        campaign_program_id=uuid4(),
        source_campaign_id=source.campaign_id,
        state=dm.CampaignProgramState.ACTIVE,
        generation_mode="adaptive",
        occurrence_count=3,
        cadence_days=28,
        created_by=uuid4(),
    )
    occurrence = CampaignProgramOccurrence(
        campaign_program_id=program.campaign_program_id, campaign_id=source.campaign_id, occurrence_number=1
    )
    session = Mock()
    session.get.return_value = source
    monkeypatch.setattr(program_service, "_program_occurrences", lambda *_a: (occurrence,))
    monkeypatch.setattr(program_service, "get_campaign_program", lambda *_a, **_kw: program)
    return session, program


@pytest.mark.parametrize(
    "state",
    [
        dm.CampaignState.REJECTED,
        dm.CampaignState.CANCELLED,
        dm.CampaignState.EXPIRED,
        dm.CampaignState.RECALLED,
        dm.CampaignState.STOPPED,
    ],
)
def test_terminal_failed_prior_campaign_has_explicit_stalled_state(monkeypatch, state) -> None:
    session, program = fixture(monkeypatch, prior_state=state)
    progress = program_service.program_iteration_status(session, program, now=NOW)
    assert progress.reason == f"stalled_prior_{state.value}"
    assert progress.prior_state == state.value
    result = program_service.materialize_next_program_iteration(
        session, program_id=program.campaign_program_id, now=NOW
    )
    assert not result.created and result.reason == progress.reason
    session.add_all.assert_not_called()


def test_late_window_is_not_silently_shifted_or_materialized(monkeypatch) -> None:
    session, program = fixture(monkeypatch, late=True)
    progress = program_service.program_iteration_status(session, program, now=NOW)
    assert progress.reason == "late" and progress.late
    assert progress.schedule_start == NOW - timedelta(days=1)
    result = program_service.materialize_next_program_iteration(
        session, program_id=program.campaign_program_id, now=NOW
    )
    assert not result.created and result.reason == "late"
    session.add_all.assert_not_called()


def test_unfinished_prior_with_late_window_is_truthfully_visible(monkeypatch) -> None:
    session, program = fixture(monkeypatch, prior_state=dm.CampaignState.DRAFT, late=True)
    assert program_service.program_iteration_status(session, program, now=NOW).reason == "late_prior_not_complete"


def test_iteration_precondition_prevents_stale_or_invalid_create(monkeypatch) -> None:
    session, program = fixture(monkeypatch)
    for expected in (3, True, "2"):
        with pytest.raises(ConflictError, match="iteration changed"):
            program_service.materialize_next_program_iteration(
                session, program_id=program.campaign_program_id, expected_iteration=expected, now=NOW
            )
    session.add_all.assert_not_called()


def test_adaptation_pagination_is_validated_before_reading_data() -> None:
    session = Mock()
    for limit, offset in ((0, 0), (101, 0), (True, 0), (1, -1), (1, 10_001)):
        with pytest.raises(ValidationError_):
            program_service.list_program_adaptations(session, uuid4(), limit=limit, offset=offset)
    session.scalar.assert_not_called()
