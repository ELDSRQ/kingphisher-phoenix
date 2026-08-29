from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from kp_database.awareness_ledger import (
    LOCAL_AWARENESS_PSEUDONYM_KEY,
    LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION,
    MAX_LEDGER_RECIPIENT_HISTORY,
    MIN_PSEUDONYM_KEY_BYTES,
    ledger_recipient_history,
    recipient_pseudonym,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE as SCOPE
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
KEY = bytes.fromhex(LOCAL_AWARENESS_PSEUDONYM_KEY)
VERSION = LOCAL_AWARENESS_PSEUDONYM_KEY_VERSION


@pytest.fixture
def session() -> Iterator[Session]:
    sqlite3.register_adapter(
        datetime,
        lambda value: value.astimezone(UTC).replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S.%f"),
    )
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE awareness_ledger_entries ("
            "awareness_ledger_entry_id CHAR(32) PRIMARY KEY, "
            "tenant_scope VARCHAR(64) NOT NULL, "
            "pseudonym_key_version VARCHAR(32) NOT NULL, "
            "recipient_pseudonym VARCHAR(64) NOT NULL, "
            "assignment_exposure_pseudonym VARCHAR(64) NOT NULL, "
            "campaign_id CHAR(32) NOT NULL, "
            "campaign_date DATE NOT NULL, "
            "campaign_date_basis VARCHAR(32) NOT NULL, "
            "targeted BOOLEAN NOT NULL, accepted BOOLEAN NOT NULL, delivered BOOLEAN NOT NULL, "
            "observed_open BOOLEAN NOT NULL, observed_click BOOLEAN NOT NULL, "
            "reported BOOLEAN NOT NULL, confirmed_interaction BOOLEAN NOT NULL, "
            "training_assigned BOOLEAN NOT NULL, training_started BOOLEAN NOT NULL, "
            "training_completed BOOLEAN NOT NULL, training_passed BOOLEAN NOT NULL, "
            "campaign_closed BOOLEAN NOT NULL, no_activity_at_close BOOLEAN, "
            "projected_at DATETIME NOT NULL, retain_until DATE NOT NULL)"
        )
    with Session(engine) as database_session:
        yield database_session
    engine.dispose()


def _entry(
    session: Session,
    *,
    pseudonym: str,
    day: date,
    clicked: bool = False,
    opened: bool = False,
    no_activity: bool = False,
) -> None:
    session.execute(
        text(
            "INSERT INTO awareness_ledger_entries ("
            "awareness_ledger_entry_id, tenant_scope, pseudonym_key_version, recipient_pseudonym, "
            "assignment_exposure_pseudonym, campaign_id, campaign_date, campaign_date_basis, "
            "targeted, accepted, delivered, observed_open, observed_click, reported, "
            "confirmed_interaction, training_assigned, training_started, training_completed, "
            "training_passed, campaign_closed, no_activity_at_close, projected_at, retain_until) "
            "VALUES (:id, :scope, :version, :recipient, :exposure, :campaign, :day, 'scheduled_start', "
            "true, true, true, :opened, :clicked, false, false, false, "
            "false, false, false, true, :no_activity, :projected, :retain)"
        ),
        {
            "id": uuid.uuid4().hex,
            "scope": SCOPE,
            "version": VERSION,
            "recipient": pseudonym,
            "exposure": uuid.uuid4().hex * 4,
            "campaign": uuid.uuid4().hex,
            "day": day,
            "opened": opened,
            "clicked": clicked,
            "no_activity": no_activity,
            "projected": NOW,
            "retain": day + timedelta(days=1826),
        },
    )


def test_ledger_recipient_history_resolves_one_pseudonym_only(session: Session) -> None:
    recipient_id = uuid.uuid4()
    other_id = uuid.uuid4()
    target = recipient_pseudonym(tenant_scope=SCOPE, recipient_id=recipient_id, key=KEY)
    other = recipient_pseudonym(tenant_scope=SCOPE, recipient_id=other_id, key=KEY)
    assert target != other

    _entry(session, pseudonym=target, day=date(2026, 1, 1), clicked=True)
    _entry(session, pseudonym=target, day=date(2026, 3, 1), opened=True)
    _entry(session, pseudonym=target, day=date(2026, 5, 1), no_activity=True)
    _entry(session, pseudonym=other, day=date(2026, 2, 1), clicked=True)

    history = ledger_recipient_history(
        session,
        tenant_scope=SCOPE,
        recipient_id=recipient_id,
        pseudonym_key=KEY,
        pseudonym_key_version=VERSION,
        generated_at=NOW,
    )

    assert history.recipient_pseudonym == target
    assert len(history.entries) == 3
    assert [entry.campaign_date for entry in history.entries] == [
        date(2026, 1, 1),
        date(2026, 3, 1),
        date(2026, 5, 1),
    ]
    assert history.exposures_total == 3
    assert history.delivered_total == 3
    assert history.engaged_total == 2
    assert history.no_activity_at_close_total == 1
    assert history.repeat_exposures == 2
    assert history.truncated is False
    assert all(entry.campaign_id for entry in history.entries)


def test_ledger_recipient_history_is_empty_and_bounded_for_unknown_recipient(session: Session) -> None:
    history = ledger_recipient_history(
        session,
        tenant_scope=SCOPE,
        recipient_id=uuid.uuid4(),
        pseudonym_key=KEY,
        pseudonym_key_version=VERSION,
        generated_at=NOW,
    )
    assert history.entries == ()
    assert history.exposures_total == 0
    assert history.repeat_exposures == 0
    assert history.truncated is False


def test_ledger_recipient_history_truncates_at_the_bounded_cap(session: Session) -> None:
    recipient_id = uuid.uuid4()
    target = recipient_pseudonym(tenant_scope=SCOPE, recipient_id=recipient_id, key=KEY)
    for index in range(MAX_LEDGER_RECIPIENT_HISTORY + 5):
        _entry(session, pseudonym=target, day=date(2026, 1, 1) + timedelta(days=index))

    history = ledger_recipient_history(
        session,
        tenant_scope=SCOPE,
        recipient_id=recipient_id,
        pseudonym_key=KEY,
        pseudonym_key_version=VERSION,
        generated_at=NOW,
    )

    assert history.truncated is True
    assert len(history.entries) == MAX_LEDGER_RECIPIENT_HISTORY


def test_ledger_recipient_history_rejects_invalid_inputs(session: Session) -> None:
    recipient_id = uuid.uuid4()
    with pytest.raises(ValueError, match="single-tenant"):
        ledger_recipient_history(
            session,
            tenant_scope="tenant-name",
            recipient_id=recipient_id,
            pseudonym_key=KEY,
            pseudonym_key_version=VERSION,
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="at least 32 bytes"):
        ledger_recipient_history(
            session,
            tenant_scope=SCOPE,
            recipient_id=recipient_id,
            pseudonym_key=b"short",
            pseudonym_key_version=VERSION,
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="key version is invalid"):
        ledger_recipient_history(
            session,
            tenant_scope=SCOPE,
            recipient_id=recipient_id,
            pseudonym_key=KEY,
            pseudonym_key_version="bad version!",
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="must include a timezone"):
        ledger_recipient_history(
            session,
            tenant_scope=SCOPE,
            recipient_id=recipient_id,
            pseudonym_key=KEY,
            pseudonym_key_version=VERSION,
            generated_at=datetime(2026, 8, 27, 12, 0),
        )
    assert MIN_PSEUDONYM_KEY_BYTES == 32
