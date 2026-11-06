"""Bounded cue-review/reauthor races on a fresh, preserved task database."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from uuid import uuid4

import pytest
from kp_authorization.rbac import Principal, Role
from kp_database.models import (
    Campaign,
    CampaignApproval,
    CampaignLaunchGate,
    CampaignPattern,
    TrainingCueCoverage,
    TrainingResource,
)
from kp_domain_models import models as dm
from kp_operator_api.routes import campaigns as routes
from kp_telemetry.errors import ConflictError
from psycopg import sql
from sqlalchemy import Table, create_engine, event, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def engine():  # type: ignore[no-untyped-def]
    explicit = os.environ.get("KP_CUE_COVERAGE_TEST_URL")
    if explicit:
        url = make_url(explicit)
    else:
        assert os.environ.get("KP_TEST_PROFILE") == "postgres"
        source = make_url(os.environ["DATABASE_URL_TEST"])
        assert source.database == "kingphisher_test" or (source.database or "").startswith(
            ("kp_reconcile_qualification_", "kp_hold_qualification_", "kp_cue_qualification_")
        )
        name = f"kp_cue_qualification_{uuid4().hex}"
        admin = create_engine(source.set(database="postgres"), isolation_level="AUTOCOMMIT")
        with admin.connect() as connection:
            connection.connection.driver_connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        admin.dispose()
        url = source.set(database=name)
    assert (url.database or "").startswith("kp_cue_qualification_")
    engine = create_engine(url, connect_args={"options": "-c statement_timeout=15000 -c lock_timeout=5000"})
    # Only these ORM tables and their FK dependencies are created. No schema
    # replacement, migration/role changes, cleanup, or normal database access.
    tables = {
        cast(Table, model.__table__)
        for model in (
            Campaign,
            CampaignApproval,
            CampaignLaunchGate,
            TrainingResource,
            TrainingCueCoverage,
        )
    }
    while dependencies := {fk.column.table for table in tables for fk in table.foreign_keys} - tables:
        tables.update(dependencies)
    Campaign.metadata.create_all(engine, tables=sorted(tables, key=lambda table: table.name))
    yield engine
    engine.dispose()


class _Audit:
    def __init__(self) -> None:
        self.actions: list[str] = []

    def record(self, **kwargs: Any) -> None:
        self.actions.append(kwargs["action"])


@pytest.mark.parametrize("winner", ["review", "reauthor"])
def test_review_and_reauthor_serialize_without_inverted_campaign_locks(engine, winner: str) -> None:
    author = Principal(str(uuid4()), {Role.ADMINISTRATOR})
    reviewer = Principal(str(uuid4()), {Role.ADMINISTRATOR})
    with Session(engine) as session:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            pattern_version=1,
            lure_category=dm.LureCategory.CONFERENCE,
            confidence=dm.Confidence.HIGH,
            approval_state=dm.PatternApprovalState.APPROVED,
        )
        resource = TrainingResource(
            training_resource_id=uuid4(),
            title="Synthetic lesson",
            kind="article",
            content="Synthetic lesson.",
            version=1,
            approval_state=dm.TemplateApprovalState.APPROVED,
        )
        session.add_all([pattern, resource])
        session.flush()
        campaign = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Synthetic cue race",
            delivery_mode="reviewed_direct",
            state=dm.CampaignState.APPROVED,
            sender_mailbox="qualification@example.invalid",
            training_domain="training.example.invalid",
            max_recipients=1,
            expires_at=datetime.now(UTC) + timedelta(days=1),
            training_resource_id=resource.training_resource_id,
            training_resource_version=1,
        )
        coverage = TrainingCueCoverage(
            coverage_id=uuid4(),
            training_resource_id=resource.training_resource_id,
            resource_version=1,
            cue_id="urgency",
            lesson_section="original",
            quiz_item="original",
            reviewed=False,
            created_by=uuid4(),
        )
        session.add_all([campaign, coverage])
        session.flush()
        session.add(
            CampaignApproval(
                campaign_approval_id=uuid4(),
                campaign_id=campaign.campaign_id,
                approval_type=dm.ApprovalType.SECURITY,
                approver_id=uuid4(),
                decision=dm.ApprovalDecision.APPROVED,
                decided_at=datetime.now(UTC),
                template_version_id=uuid4(),
                launch_manifest_hash="a" * 64,
            )
        )
        session.commit()
        campaign_id, coverage_id = campaign.campaign_id, coverage.coverage_id

    first_locked = threading.Event()
    second_attempted = threading.Event()
    thread_role = threading.local()

    def is_coverage_lock(statement: str) -> bool:
        return "FROM training_cue_coverage" in statement and "FOR UPDATE" in statement

    def before(_conn: Any, _cursor: Any, statement: str, _params: Any, _context: Any, _many: bool) -> None:
        if is_coverage_lock(statement) and thread_role.role != winner:
            second_attempted.set()

    def after(_conn: Any, _cursor: Any, statement: str, _params: Any, _context: Any, _many: bool) -> None:
        if is_coverage_lock(statement) and thread_role.role == winner:
            first_locked.set()
            assert second_attempted.wait(5), "second transaction did not attempt the coverage lock"

    event.listen(engine, "before_cursor_execute", before)
    event.listen(engine, "after_cursor_execute", after)

    def run(role: str):  # type: ignore[no-untyped-def]
        thread_role.role = role
        audit = _Audit()
        with Session(engine) as session:
            if role == "review":
                result = routes.decide_campaign_cue_coverage(
                    campaign_id,
                    coverage_id,
                    routes.CueCoverageDecision(decision="reviewed"),
                    session=session,
                    audit=audit,
                    principal=reviewer,
                )
            else:
                try:
                    result = routes.create_campaign_cue_coverage(
                        campaign_id,
                        routes.CueCoverageCreate(cue_id="urgency", lesson_section="revised", quiz_item="revised"),
                        session=session,
                        audit=audit,
                        principal=author,
                    )
                except ConflictError:
                    assert winner == "review"
                    session.rollback()
                    return "conflict", audit.actions
            return result, audit.actions

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(run, winner)
            assert first_locked.wait(5), "first transaction did not acquire the coverage lock"
            second = executor.submit(run, "reauthor" if winner == "review" else "review")
            first_result, first_actions = first.result(timeout=25)
            second_result, second_actions = second.result(timeout=25)
        assert isinstance(first_result, dict)
        if winner == "review":
            assert second_result == "conflict" and not second_actions
            assert first_actions == ["campaign.cue_coverage.reviewed"]
        else:
            assert isinstance(second_result, dict) and second_result["reviewed"] is True
            assert first_actions == ["campaign.cue_coverage.reauthor"]
            assert second_actions == ["campaign.cue_coverage.reviewed"]
        with Session(engine) as session:
            row = session.get(TrainingCueCoverage, coverage_id)
            assert row is not None and row.reviewed
            assert row.lesson_section == ("original" if winner == "review" else "revised")
            assert session.get(Campaign, campaign_id).state == dm.CampaignState.DRAFT
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(CampaignApproval)
                    .where(
                        CampaignApproval.campaign_id == campaign_id,
                    )
                )
                == 0
            )
    finally:
        event.remove(engine, "before_cursor_execute", before)
        event.remove(engine, "after_cursor_execute", after)
