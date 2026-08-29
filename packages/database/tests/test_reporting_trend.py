from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from kp_database.reporting import (
    SINGLE_TENANT_DATABASE_SCOPE,
    CampaignSelectionWindow,
    campaign_trend,
    campaign_trend_csv_rows,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _id(value: int) -> uuid.UUID:
    return uuid.UUID(int=value)


@pytest.fixture
def session() -> Iterator[Session]:
    sqlite3.register_adapter(
        datetime,
        lambda value: value.astimezone(UTC).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f"),
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE campaigns (campaign_id CHAR(32) PRIMARY KEY, schedule_start DATETIME, "
            "schedule_end DATETIME, state VARCHAR(32) NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE recipient_assignments ("
            "recipient_assignment_id CHAR(32) PRIMARY KEY, campaign_id CHAR(32) NOT NULL, "
            "send_state VARCHAR(32) NOT NULL, delivery_attempt_id CHAR(32), "
            "provider_accepted_at DATETIME, delivery_confirmed_at DATETIME)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE tracking_tokens (token_id CHAR(32) PRIMARY KEY, recipient_assignment_id CHAR(32) NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE events (event_id CHAR(32) PRIMARY KEY, event_type VARCHAR(64) NOT NULL, token_id CHAR(32), "
            "recipient_assignment_id CHAR(32), occurred_at DATETIME NOT NULL)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE training_assignments (training_assignment_id CHAR(32) PRIMARY KEY, "
            "recipient_assignment_id CHAR(32), completed_at DATETIME)"
        )
    with Session(engine) as database_session:
        yield database_session
    engine.dispose()


def _campaign(session: Session, value: int, *, days_ago: int, state: str, assignments: int) -> uuid.UUID:
    campaign_id = _id(value)
    start = NOW - timedelta(days=days_ago)
    session.execute(
        text(
            "INSERT INTO campaigns (campaign_id, schedule_start, schedule_end, state) "
            "VALUES (:id, :start, :end, :state)"
        ),
        {"id": campaign_id.hex, "start": start, "end": start + timedelta(hours=1), "state": state},
    )
    for ordinal in range(assignments):
        assignment_id = _id(value * 100 + ordinal + 1)
        attempt_id = _id(value * 1000 + ordinal + 1)
        session.execute(
            text(
                "INSERT INTO recipient_assignments (recipient_assignment_id, campaign_id, send_state, "
                "delivery_attempt_id, provider_accepted_at, delivery_confirmed_at) "
                "VALUES (:assignment, :campaign, 'ACCEPTED', :attempt, :accepted, NULL)"
            ),
            {
                "assignment": assignment_id.hex,
                "campaign": campaign_id.hex,
                "attempt": attempt_id.hex,
                "accepted": start + timedelta(minutes=5),
            },
        )
    return campaign_id


def _seed_weighting_fixture(session: Session) -> tuple[uuid.UUID, uuid.UUID]:
    older = _campaign(session, 1, days_ago=20, state="COMPLETED", assignments=2)
    newer = _campaign(session, 2, days_ago=10, state="STOPPED", assignments=8)
    # In-progress campaigns and terminal campaigns without assignments are not
    # final assignment-exposure trend points.
    _campaign(session, 3, days_ago=5, state="ACTIVE", assignments=3)
    _campaign(session, 4, days_ago=4, state="COMPLETED", assignments=0)
    for event_id, assignment_id in ((_id(9001), _id(101)), (_id(9002), _id(201))):
        session.execute(
            text(
                "INSERT INTO events (event_id, event_type, token_id, recipient_assignment_id, occurred_at) "
                "VALUES (:event, 'CLICKED', NULL, :assignment, :occurred)"
            ),
            {"event": event_id.hex, "assignment": assignment_id.hex, "occurred": NOW - timedelta(days=2)},
        )
    session.commit()
    return older, newer


def test_trend_reuses_canonical_funnels_and_weights_assignment_exposures(session: Session) -> None:
    older, newer = _seed_weighting_fixture(session)
    report = campaign_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        schedule_window=CampaignSelectionWindow(NOW - timedelta(days=30), NOW),
        generated_at=NOW,
    )

    assert [point.campaign_id for point in report.points] == [older, newer]
    assert [point.state.value for point in report.points] == ["completed", "stopped"]
    assert all(point.funnel.generated_at == NOW for point in report.points)
    assert all(point.funnel.evidence_window is None for point in report.points)
    assert report.portfolio.targeted == 10
    assert report.portfolio.accepted == 10
    assert report.portfolio.clicked == 2
    clicked = dict(report.portfolio.rates)["clicked"]
    assert clicked.numerator == 2
    assert clicked.denominator == 10
    assert clicked.denominator_name == "provider_accepted_handoff_exposures"
    assert clicked.value == 0.2  # not the unweighted mean of 1/2 and 1/8


def test_trend_is_stably_bounded_and_reports_truncation(session: Session) -> None:
    for offset in range(5):
        _campaign(session, 20 + offset, days_ago=20 - offset, state="COMPLETED", assignments=1)
    session.commit()

    report = campaign_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        schedule_window=CampaignSelectionWindow(NOW - timedelta(days=30), NOW),
        limit=2,
        generated_at=NOW,
    )

    assert report.truncated is True
    assert [point.campaign_id for point in report.points] == [_id(23), _id(24)]
    assert [point.schedule_start for point in report.points] == sorted(point.schedule_start for point in report.points)


def test_empty_trend_has_null_weighted_rates_and_safe_csv(session: Session) -> None:
    report = campaign_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        schedule_window=CampaignSelectionWindow(NOW - timedelta(days=30), NOW),
        generated_at=NOW,
    )

    assert report.points == ()
    assert report.truncated is False
    assert report.portfolio.targeted == 0
    assert all(rate.value is None for _, rate in report.portfolio.rates)
    rows = campaign_trend_csv_rows(report)
    assert rows[0][0:3] == ("scope", "campaign_id", "schedule_start")
    assert any(row[0] == "portfolio_assignment_exposures" and row[9:11] == ("rate", "clicked") for row in rows)
    assert all(not (isinstance(cell, str) and cell.startswith(("=", "+", "-", "@"))) for row in rows for cell in row)
    serialized = repr(rows).lower()
    for forbidden in ("title", "mailbox", "recipient_id", "department", "display_name", "employee_key"):
        assert forbidden not in serialized


def test_trend_scope_window_limit_and_generated_at_fail_closed(session: Session) -> None:
    window = CampaignSelectionWindow(NOW - timedelta(days=30), NOW)
    with pytest.raises(ValueError, match="single-tenant"):
        campaign_trend(session, scope="tenant-a", schedule_window=window, generated_at=NOW)
    with pytest.raises(ValueError, match="between 1 and 12"):
        campaign_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            schedule_window=window,
            limit=13,
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="timezone"):
        CampaignSelectionWindow(datetime(2026, 1, 1), datetime(2026, 1, 2))
    with pytest.raises(ValueError, match="precede"):
        CampaignSelectionWindow(NOW, NOW)
    with pytest.raises(ValueError, match="366 days"):
        CampaignSelectionWindow(NOW - timedelta(days=367), NOW)
    with pytest.raises(ValueError, match="generated_at"):
        campaign_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            schedule_window=window,
            generated_at=datetime(2026, 8, 27),
        )
