from __future__ import annotations

import csv
import io
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from kp_database.reporting import (
    MAX_LEDGER_TREND_WINDOW,
    SINGLE_TENANT_DATABASE_SCOPE,
    LedgerTrendBucket,
    ledger_trend,
    ledger_trend_csv_rows,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


@pytest.fixture
def session() -> Iterator[Session]:
    # Explicit adapters: Python 3.12 deprecated sqlite3's implicit date/datetime
    # adapters. This date adapter reproduces the stdlib default (``val.isoformat()``)
    # byte for byte, so stored values and comparison semantics are unchanged.
    sqlite3.register_adapter(date, lambda value: value.isoformat())
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
    day: date,
    delivered: bool = True,
    clicked: bool = False,
    confirmed: bool = False,
    reported: bool = False,
    assigned: bool = True,
    completed: bool = False,
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
            "VALUES (:id, :scope, 'v1', :recipient, :exposure, :campaign, :day, 'scheduled_start', "
            "true, true, :delivered, false, :clicked, :reported, :confirmed, :assigned, "
            ":completed, :completed, :completed, true, :no_activity, :projected, :retain)"
        ),
        {
            "id": uuid.uuid4().hex,
            "scope": SINGLE_TENANT_DATABASE_SCOPE,
            "recipient": "a" * 64,
            "exposure": uuid.uuid4().hex * 4,
            "campaign": uuid.uuid4().hex,
            "day": day,
            "delivered": delivered,
            "clicked": clicked,
            "reported": reported,
            "confirmed": confirmed,
            "assigned": assigned,
            "completed": completed,
            "no_activity": no_activity,
            "projected": NOW,
            "retain": day + timedelta(days=1826),
        },
    )


def test_ledger_trend_buckets_by_month_with_explicit_click_and_no_click_denominators(
    session: Session,
) -> None:
    _entry(session, day=date(2026, 1, 5), clicked=True, confirmed=True)
    _entry(session, day=date(2026, 1, 20))
    _entry(session, day=date(2026, 3, 2), clicked=True, reported=True, completed=True)
    _entry(session, day=date(2026, 3, 15), delivered=False)

    report = ledger_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2026, 1, 1),
        window_end=date(2027, 1, 1),
        generated_at=NOW,
    )

    assert [bucket.month for bucket in report.buckets] == [date(2026, 1, 1), date(2026, 3, 1)]
    january, march = report.buckets
    assert january.targeted == 2 and january.delivered == 2
    assert january.clicked == 1 and january.no_click == 1
    assert january.confirmed_interaction == 1 and january.reported == 0
    assert march.targeted == 2 and march.delivered == 1
    assert march.clicked == 1 and march.no_click == 0
    assert march.training_completed == 1
    rates = dict(march.rates)
    assert rates["clicked"].numerator == 1 and rates["clicked"].denominator == 1
    assert rates["clicked"].value == 1.0
    assert rates["no_click"].denominator == 1 and rates["no_click"].numerator == 0
    assert rates["training_completed"].denominator == 2
    assert report.portfolio.clicked == 2
    assert report.portfolio.no_click == 1
    assert report.portfolio.delivered == 3


def test_ledger_trend_window_is_bounded_to_retention_and_ignores_out_of_window_rows(
    session: Session,
) -> None:
    _entry(session, day=date(2021, 1, 1), clicked=True)
    _entry(session, day=date(2022, 6, 15))
    _entry(session, day=date(2026, 8, 1), clicked=True)

    report = ledger_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2022, 1, 1),
        window_end=date(2023, 1, 1),
        generated_at=NOW,
    )

    assert [bucket.month for bucket in report.buckets] == [date(2022, 6, 1)]
    assert report.portfolio.targeted == 1
    assert report.portfolio.clicked == 0

    with pytest.raises(ValueError, match="cannot exceed 1826"):
        ledger_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=date(2021, 1, 1),
            window_end=date(2021, 1, 1) + MAX_LEDGER_TREND_WINDOW + timedelta(days=1),
            generated_at=NOW,
        )


def test_ledger_trend_rejects_wrong_scope_and_invalid_window(session: Session) -> None:
    with pytest.raises(ValueError, match="single-tenant"):
        ledger_trend(
            session,
            scope="tenant-name",
            window_start=date(2026, 1, 1),
            window_end=date(2027, 1, 1),
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="start must precede end"):
        ledger_trend(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=date(2026, 1, 1),
            window_end=date(2026, 1, 1),
            generated_at=NOW,
        )
    with pytest.raises(TypeError, match="must be dates"):
        ledger_trend(  # type: ignore[arg-type]
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start="2026-01-01",
            window_end=date(2027, 1, 1),
            generated_at=NOW,
        )


def test_ledger_trend_csv_is_formula_safe_and_pseudonym_free(session: Session) -> None:
    _entry(session, day=date(2026, 2, 3), clicked=True)
    _entry(session, day=date(2026, 2, 14))

    report = ledger_trend(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2026, 1, 1),
        window_end=date(2027, 1, 1),
        generated_at=NOW,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(ledger_trend_csv_rows(report))
    projection = output.getvalue()

    assert "awareness_ledger_entries" not in projection
    assert ("a" * 64) not in projection
    assert "pseudonym" not in projection
    assert "portfolio" in projection
    assert "2026-02-01" in projection
    assert "clicked" in projection
    assert "no_click" in projection
    assert not any(cell.startswith(("=", "+", "-", "@")) for cell in _cells(projection))
    assert isinstance(report.buckets, tuple) and all(isinstance(b, LedgerTrendBucket) for b in report.buckets)


def _cells(projection: str) -> list[str]:
    return [cell.strip() for row in csv.reader(io.StringIO(projection)) for cell in row if cell.strip()]
