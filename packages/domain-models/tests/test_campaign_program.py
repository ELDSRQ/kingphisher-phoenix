from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from kp_domain_models.models import CampaignProgram, CampaignProgramOccurrence, CampaignProgramState
from pydantic import ValidationError


def test_campaign_program_domain_shape_is_bounded() -> None:
    now = datetime.now(UTC)
    program = CampaignProgram(
        source_campaign_id=uuid4(),
        cadence_days=28,
        occurrence_count=12,
        configuration_hash="a" * 64,
        created_at=now,
        updated_at=now,
    )
    assert program.state is CampaignProgramState.ACTIVE

    with pytest.raises(ValidationError):
        CampaignProgram(
            source_campaign_id=uuid4(),
            cadence_days=30,
            occurrence_count=12,
            configuration_hash="a" * 64,
            created_at=now,
            updated_at=now,
        )
    with pytest.raises(ValidationError):
        CampaignProgram(
            source_campaign_id=uuid4(),
            cadence_days=28,
            occurrence_count=4,
            configuration_hash="Z" * 64,
            created_at=now,
            updated_at=now,
        )
    with pytest.raises(ValidationError):
        CampaignProgram(
            source_campaign_id=uuid4(),
            cadence_days=28,
            occurrence_count=13,
            configuration_hash="a" * 64,
            created_at=now,
            updated_at=now,
        )


def test_campaign_program_occurrence_requires_positive_number() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        CampaignProgramOccurrence(
            campaign_program_id=uuid4(),
            occurrence_number=0,
            campaign_id=uuid4(),
            schedule_start=now,
            schedule_end=now + timedelta(hours=1),
        )


def test_campaign_program_timestamps_are_ordered_and_timezone_aware() -> None:
    now = datetime.now(UTC)
    common = {
        "source_campaign_id": uuid4(),
        "cadence_days": 28,
        "occurrence_count": 4,
        "configuration_hash": "a" * 64,
    }
    with pytest.raises(ValidationError, match="updated_at"):
        CampaignProgram(created_at=now, updated_at=now - timedelta(seconds=1), **common)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timezone"):
        CampaignProgram(
            created_at=now.replace(tzinfo=None),
            updated_at=now,
            **common,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("duration", [timedelta(0), timedelta(seconds=-1)])
def test_campaign_program_occurrence_requires_ordered_aware_window(duration: timedelta) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="schedule_end"):
        CampaignProgramOccurrence(
            campaign_program_id=uuid4(),
            occurrence_number=1,
            campaign_id=uuid4(),
            schedule_start=now,
            schedule_end=now + duration,
        )
    with pytest.raises(ValidationError, match="timezone"):
        CampaignProgramOccurrence(
            campaign_program_id=uuid4(),
            occurrence_number=1,
            campaign_id=uuid4(),
            schedule_start=now.replace(tzinfo=None),
            schedule_end=now,
        )
