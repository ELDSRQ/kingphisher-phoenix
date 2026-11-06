"""Real coverage-gate SQL rejects unverifiable legacy review identities."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_database.models import CampaignCueCoverageException, TrainingCueCoverage
from kp_operator_api.training_library import enforce_cue_coverage_gate
from kp_telemetry.errors import ConflictError
from sqlalchemy import Column, MetaData, Table, create_engine
from sqlalchemy.orm import Session


@pytest.mark.parametrize("invalid", ["author_missing", "reviewer_missing", "self_review", "timestamp_missing", None])
def test_launch_coverage_requires_known_distinct_author_and_reviewer(invalid: str | None) -> None:
    engine = create_engine("sqlite://")
    metadata = MetaData()
    # Reproduce legacy/imported rows without today's all-or-nothing check. The
    # production gate runs its actual ORM SELECT against these persisted rows;
    # no production database or legacy data is rewritten by this regression.
    tables = {}
    for model in (TrainingCueCoverage, CampaignCueCoverageException):
        tables[model] = Table(
            model.__tablename__,
            metadata,
            *(Column(column.name, column.type, primary_key=column.primary_key) for column in model.__table__.columns),
        )
    metadata.create_all(engine)
    resource_id, author_id, reviewer_id = uuid4(), uuid4(), uuid4()
    campaign = SimpleNamespace(campaign_id=uuid4())
    resource = SimpleNamespace(training_resource_id=resource_id, version=1)
    template = SimpleNamespace(cue_manifest={"cues": [{"cue_type": "urgency"}]}, warning_cues=[])
    with Session(engine) as session:
        session.execute(
            tables[TrainingCueCoverage]
            .insert()
            .values(
                coverage_id=uuid4(),
                training_resource_id=resource_id,
                resource_version=1,
                cue_id="urgency",
                lesson_section="Urgency section",
                quiz_item="Urgency quiz",
                reviewed=True,
                created_by=None if invalid == "author_missing" else author_id,
                reviewed_by=None
                if invalid == "reviewer_missing"
                else author_id
                if invalid == "self_review"
                else reviewer_id,
                reviewed_at=None if invalid == "timestamp_missing" else datetime.now(UTC),
                created_at=datetime.now(UTC),
            )
        )
        if invalid:
            with pytest.raises(ConflictError, match="reviewed training coverage"):
                enforce_cue_coverage_gate(session, campaign, template, resource)
        else:
            assessment = enforce_cue_coverage_gate(session, campaign, template, resource)
            assert assessment is not None and assessment.satisfied and assessment.covered == ("urgency",)
    engine.dispose()
