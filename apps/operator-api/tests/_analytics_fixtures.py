"""Shared minimal in-memory funnel DB for W4-02 consistency tests.

Follows the project's established reporting-test pattern: hand-rolled sqlite
tables holding only the columns the reporting Core queries reference (never a
full ORM entity load, which would drag in Postgres-only DDL), seeded by raw
SQL. One event set feeds the single ``campaign_funnel`` computation that the
UI, CSV and evidence-ZIP surfaces all derive from.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
CAMPAIGN_ID = uuid.UUID("11111111-1111-4111-8111-111111111111")


def make_session() -> Session:
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
            "recipient_assignment_id CHAR(32), occurred_at DATETIME NOT NULL, payload TEXT)"
        )
        connection.exec_driver_sql(
            "CREATE TABLE training_assignments (training_assignment_id CHAR(32) PRIMARY KEY, "
            "recipient_assignment_id CHAR(32), completed_at DATETIME)"
        )
    return Session(engine)


def _assignment(session: Session, *, state: str, accepted: bool, delivered: bool = False) -> uuid.UUID:
    assignment_id = uuid.uuid4()
    session.execute(
        text(
            "INSERT INTO recipient_assignments (recipient_assignment_id, campaign_id, send_state, "
            "delivery_attempt_id, provider_accepted_at, delivery_confirmed_at) "
            "VALUES (:a, :c, :s, :attempt, :accepted, :delivered)"
        ),
        {
            "a": assignment_id.hex,
            "c": CAMPAIGN_ID.hex,
            "s": state,
            "attempt": uuid.uuid4().hex if accepted else None,
            "accepted": NOW - timedelta(hours=4) if accepted else None,
            "delivered": NOW - timedelta(hours=3) if delivered else None,
        },
    )
    return assignment_id


def _click(session: Session, assignment_id: uuid.UUID, *, automation: bool) -> None:
    token_id = uuid.uuid4()
    session.execute(
        text("INSERT INTO tracking_tokens (token_id, recipient_assignment_id) VALUES (:t, :a)"),
        {"t": token_id.hex, "a": assignment_id.hex},
    )
    payload = '{"automation_suspected": true, "automation_signals": ["scanner_user_agent"]}' if automation else "{}"
    session.execute(
        text(
            "INSERT INTO events (event_id, event_type, token_id, recipient_assignment_id, occurred_at, payload) "
            "VALUES (:e, 'CLICKED', :t, :a, :when, :payload)"
        ),
        {
            "e": uuid.uuid4().hex,
            "t": token_id.hex,
            "a": assignment_id.hex,
            "when": NOW - timedelta(hours=2),
            "payload": payload,
        },
    )


def seed(session: Session) -> dict[str, int]:
    """Seed one campaign's event set and return the human-interaction numbers.

    Contains one genuine human click, one scanner (automation) click, one
    correlated reply, and one INDETERMINATE (unknown) transport outcome.
    """

    session.execute(text("INSERT INTO campaigns (campaign_id) VALUES (:c)"), {"c": CAMPAIGN_ID.hex})
    human = _assignment(session, state="DELIVERED", accepted=True, delivered=True)
    scanner = _assignment(session, state="ACCEPTED", accepted=True)
    replied = _assignment(session, state="ACCEPTED", accepted=True)
    _assignment(session, state="INDETERMINATE", accepted=False)
    _click(session, human, automation=False)
    _click(session, scanner, automation=True)
    session.execute(
        text(
            "INSERT INTO events (event_id, event_type, token_id, recipient_assignment_id, occurred_at, payload) "
            "VALUES (:e, 'MESSAGE_REPLIED', NULL, :a, :when, '{}')"
        ),
        {"e": uuid.uuid4().hex, "a": replied.hex, "when": NOW - timedelta(hours=1)},
    )
    session.commit()
    return {
        "targeted": 4,
        "accepted": 3,
        "delivered": 1,
        "clicked": 1,
        "clicked_automation_suspected": 1,
        "reply_correlated": 1,
        "indeterminate": 1,
    }
