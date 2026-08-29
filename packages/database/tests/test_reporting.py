from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from kp_database.reporting import (
    SINGLE_TENANT_DATABASE_SCOPE,
    CampaignReportNotFound,
    EvidenceWindow,
    campaign_funnel,
    campaign_funnel_csv_rows,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _id(value: int) -> uuid.UUID:
    return uuid.UUID(int=value)


@pytest.fixture
def session() -> Session:
    sqlite3.register_adapter(
        datetime,
        lambda value: value.astimezone(UTC).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f"),
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE campaigns (campaign_id CHAR(32) PRIMARY KEY)")
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


def _insert_fixture(session: Session) -> tuple[uuid.UUID, uuid.UUID]:
    campaign_id = _id(1)
    other_campaign_id = _id(2)
    session.execute(
        text("INSERT INTO campaigns (campaign_id) VALUES (:first), (:second)"),
        {"first": campaign_id.hex, "second": other_campaign_id.hex},
    )
    assignments = (
        (_id(11), campaign_id, "DELIVERED", _id(101), NOW - timedelta(hours=4), NOW - timedelta(hours=3)),
        (_id(12), campaign_id, "ACCEPTED", _id(102), NOW - timedelta(hours=2), None),
        (_id(13), campaign_id, "FAILED", None, None, None),
        (_id(14), campaign_id, "INDETERMINATE", _id(104), None, None),
        (_id(15), campaign_id, "QUEUED", None, None, None),
        (_id(21), other_campaign_id, "DELIVERED", _id(201), NOW - timedelta(hours=2), NOW - timedelta(hours=1)),
    )
    for assignment_id, owner, state, attempt, accepted, delivered in assignments:
        session.execute(
            text(
                "INSERT INTO recipient_assignments "
                "(recipient_assignment_id, campaign_id, send_state, delivery_attempt_id, "
                "provider_accepted_at, delivery_confirmed_at) "
                "VALUES (:assignment, :campaign, :state, :attempt, :accepted, :delivered)"
            ),
            {
                "assignment": assignment_id.hex,
                "campaign": owner.hex,
                "state": state,
                "attempt": attempt.hex if attempt else None,
                "accepted": accepted,
                "delivered": delivered,
            },
        )
    session.execute(
        text(
            "INSERT INTO tracking_tokens (token_id, recipient_assignment_id) VALUES "
            "(:token1, :assignment1), (:token2, :assignment2), (:token5, :assignment5), (:other, :other_assignment)"
        ),
        {
            "token1": _id(301).hex,
            "assignment1": _id(11).hex,
            "token2": _id(302).hex,
            "assignment2": _id(12).hex,
            "token5": _id(305).hex,
            "assignment5": _id(15).hex,
            "other": _id(321).hex,
            "other_assignment": _id(21).hex,
        },
    )
    events = (
        (_id(401), "OPENED", _id(301), None, NOW - timedelta(hours=2)),
        (_id(402), "OPENED", _id(301), None, NOW - timedelta(hours=1)),
        (_id(403), "CLICKED", _id(301), None, NOW - timedelta(minutes=45)),
        (_id(404), "MESSAGE_REPORTED", None, _id(12), NOW - timedelta(minutes=30)),
        # A queued assignment cannot inflate accepted-handoff engagement rates.
        (_id(405), "CLICKED", _id(305), None, NOW - timedelta(minutes=15)),
        # Another campaign in the same database must never leak into this report.
        (_id(406), "OPENED", _id(321), None, NOW - timedelta(minutes=10)),
        # Authenticated evidence delayed into storage is still available all-time.
        (_id(407), "MESSAGE_REPORTED", None, _id(11), NOW - timedelta(days=10)),
        # Future timestamps are excluded even from an all-retained-evidence report.
        (_id(408), "OPENED", _id(302), None, NOW + timedelta(hours=1)),
    )
    for event_id, event_type, token_id, assignment_id, occurred_at in events:
        session.execute(
            text(
                "INSERT INTO events (event_id, event_type, token_id, recipient_assignment_id, occurred_at) "
                "VALUES (:event, :kind, :token, :assignment, :occurred)"
            ),
            {
                "event": event_id.hex,
                "kind": event_type,
                "token": token_id.hex if token_id else None,
                "assignment": assignment_id.hex if assignment_id else None,
                "occurred": occurred_at,
            },
        )
    training = (
        (_id(501), _id(11), NOW - timedelta(minutes=20)),
        (_id(502), _id(12), NOW - timedelta(days=5)),
        (_id(503), _id(15), None),
        (_id(504), _id(21), NOW - timedelta(minutes=5)),
    )
    for training_id, assignment_id, completed_at in training:
        session.execute(
            text(
                "INSERT INTO training_assignments "
                "(training_assignment_id, recipient_assignment_id, completed_at) "
                "VALUES (:training, :assignment, :completed)"
            ),
            {"training": training_id.hex, "assignment": assignment_id.hex, "completed": completed_at},
        )
    session.commit()
    return campaign_id, other_campaign_id


def test_campaign_funnel_uses_distinct_accepted_assignments_and_explicit_denominators(session: Session) -> None:
    campaign_id, _ = _insert_fixture(session)

    report = campaign_funnel(
        session,
        campaign_id,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        generated_at=NOW,
    )

    assert (report.targeted, report.sent, report.accepted, report.delivered) == (5, 3, 2, 1)
    assert (report.failed, report.indeterminate) == (1, 1)
    assert (report.opened, report.clicked, report.reported) == (1, 1, 2)
    assert (report.training_assigned, report.training_completed) == (3, 2)
    rates = dict(report.rates)
    assert rates["opened"].denominator_name == "provider_accepted_handoffs"
    assert rates["opened"].value == 0.5
    assert rates["delivered"].value == 0.5
    assert rates["training_completed"].denominator == 3


def test_evidence_window_does_not_rewrite_current_send_snapshot(session: Session) -> None:
    campaign_id, _ = _insert_fixture(session)
    window = EvidenceWindow(NOW - timedelta(hours=3), NOW)

    report = campaign_funnel(
        session,
        campaign_id,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        evidence_window=window,
        generated_at=NOW,
    )

    assert (report.targeted, report.sent, report.accepted, report.delivered) == (5, 3, 2, 1)
    assert (report.opened, report.clicked, report.reported) == (1, 1, 1)
    assert report.training_assigned == 3
    assert report.training_completed == 1


def test_empty_campaign_rates_are_undefined_instead_of_fake_zero(session: Session) -> None:
    empty_campaign = _id(900)
    session.execute(text("INSERT INTO campaigns (campaign_id) VALUES (:id)"), {"id": empty_campaign.hex})
    session.commit()

    report = campaign_funnel(
        session,
        empty_campaign,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        generated_at=NOW,
    )

    assert report.targeted == 0
    assert all(rate.value is None for _, rate in report.rates)
    rows = dict(campaign_funnel_csv_rows(report))
    assert rows["rate.opened.value"] == ""
    assert rows["semantics.delivered"] == "destination_mta_handoff_not_inbox_or_read"


def test_scope_campaign_and_time_inputs_fail_closed(session: Session) -> None:
    campaign_id, _ = _insert_fixture(session)
    with pytest.raises(ValueError, match="single-tenant"):
        campaign_funnel(session, campaign_id, scope="tenant-a", generated_at=NOW)
    with pytest.raises(CampaignReportNotFound):
        campaign_funnel(session, _id(999), scope=SINGLE_TENANT_DATABASE_SCOPE, generated_at=NOW)
    with pytest.raises(TypeError, match="UUID"):
        campaign_funnel(session, str(campaign_id), scope=SINGLE_TENANT_DATABASE_SCOPE, generated_at=NOW)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="timezone"):
        EvidenceWindow(datetime(2026, 1, 1), datetime(2026, 1, 2))
    with pytest.raises(ValueError, match="precede"):
        EvidenceWindow(NOW, NOW)
    with pytest.raises(ValueError, match="366 days"):
        EvidenceWindow(NOW - timedelta(days=367), NOW)


def test_csv_rows_are_primitive_privacy_safe_and_formula_safe(session: Session) -> None:
    campaign_id, _ = _insert_fixture(session)
    report = campaign_funnel(
        session,
        campaign_id,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        generated_at=NOW,
    )

    rows = campaign_funnel_csv_rows(report)

    assert rows[0] == ("metric", "value")
    assert all(isinstance(cell, str | int | float) for row in rows for cell in row)
    assert not any(isinstance(cell, str) and cell.startswith(("=", "+", "-", "@")) for row in rows for cell in row)
    serialized = repr(rows)
    assert "mailbox" not in serialized
    assert "department" not in serialized
