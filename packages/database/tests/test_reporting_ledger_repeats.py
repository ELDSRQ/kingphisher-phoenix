from __future__ import annotations

import csv
import io
import sqlite3
import uuid
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from kp_database.reporting import (
    MAX_LEDGER_REPEAT_BUCKET,
    MAX_LEDGER_TREND_WINDOW,
    SINGLE_TENANT_DATABASE_SCOPE,
    LedgerRepeatBucket,
    LedgerRepeatDistribution,
    ledger_repeat_csv_rows,
    ledger_repeat_distribution,
)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


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
    delivered: bool = True,
    clicked: bool = False,
    opened: bool = False,
    confirmed: bool = False,
    reported: bool = False,
    assigned: bool = True,
    started: bool = False,
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
            "true, true, :delivered, :opened, :clicked, :reported, :confirmed, :assigned, "
            ":started, :completed, :completed, true, :no_activity, :projected, :retain)"
        ),
        {
            "id": uuid.uuid4().hex,
            "scope": SINGLE_TENANT_DATABASE_SCOPE,
            "recipient": pseudonym,
            "exposure": uuid.uuid4().hex * 4,
            "campaign": uuid.uuid4().hex,
            "day": day,
            "delivered": delivered,
            "opened": opened,
            "clicked": clicked,
            "reported": reported,
            "confirmed": confirmed,
            "assigned": assigned,
            "started": started,
            "completed": completed,
            "no_activity": no_activity,
            "projected": NOW,
            "retain": day + timedelta(days=1826),
        },
    )


def _buckets(report: LedgerRepeatDistribution, *, engaged: bool) -> dict[int, int]:
    source = report.engaged_buckets if engaged else report.exposure_buckets
    return {bucket.exposures: bucket.participants for bucket in source}


def test_ledger_repeats_buckets_distinct_pseudonyms_by_exposure_and_engagement(
    session: Session,
) -> None:
    # One pseudonym exposed three times (engaged twice), one exposed twice
    # (engaged once), one exposed once (engaged once), one exposed once with no
    # activity at close.
    _entry(session, pseudonym="a" * 64, day=date(2026, 1, 1), clicked=True)
    _entry(session, pseudonym="a" * 64, day=date(2026, 2, 1), clicked=True)
    _entry(session, pseudonym="a" * 64, day=date(2026, 3, 1))
    _entry(session, pseudonym="b" * 64, day=date(2026, 1, 15), opened=True, started=True)
    _entry(session, pseudonym="b" * 64, day=date(2026, 4, 1))
    _entry(session, pseudonym="c" * 64, day=date(2026, 5, 1), confirmed=True, completed=True)
    _entry(session, pseudonym="d" * 64, day=date(2026, 6, 1), no_activity=True)

    report = ledger_repeat_distribution(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2026, 1, 1),
        window_end=date(2027, 1, 1),
        generated_at=NOW,
    )

    exposure = _buckets(report, engaged=False)
    assert exposure[3] == 1  # "a" (three exposures)
    assert exposure[2] == 1  # "b"
    assert exposure[1] == 2  # "c", "d"
    assert sum(exposure.values()) == report.unique_exposed == 4
    assert report.exposures_total == 7

    engaged = _buckets(report, engaged=True)
    # "a" engaged in two campaigns, "b" engaged in one (opened/started),
    # "c" engaged in one (confirmed/completed), "d" never engaged.
    assert engaged[2] == 1
    assert engaged[1] == 2
    assert report.unique_engaged == 3
    assert report.engaged_exposures_total == 4
    assert report.no_activity_at_close == 1

    rates = dict(report.rates)
    # "a" and "b" have two or more exposures: 2 of 4 exposed pseudonyms.
    assert rates["repeat_exposure"].numerator == 2
    assert rates["repeat_exposure"].denominator == 4
    assert rates["repeat_exposure"].value == 0.5
    # Only "a" engaged in two or more campaigns: 1 of 3 engaged pseudonyms.
    assert rates["repeat_engagement"].numerator == 1
    assert rates["repeat_engagement"].denominator == 3


def test_ledger_repeats_caps_tail_bucket_and_ignores_out_of_window_rows(session: Session) -> None:
    for index in range(6):
        _entry(session, pseudonym="e" * 64, day=date(2026, 1, index + 1))
    _entry(session, pseudonym="f" * 64, day=date(2022, 1, 1), clicked=True)
    _entry(session, pseudonym="f" * 64, day=date(2026, 7, 1), clicked=True)

    report = ledger_repeat_distribution(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2026, 1, 1),
        window_end=date(2027, 1, 1),
        generated_at=NOW,
    )

    exposure = _buckets(report, engaged=False)
    assert exposure[MAX_LEDGER_REPEAT_BUCKET] == 1  # six exposures fall into the tail bucket
    assert exposure[1] == 1  # "f" has one in-window exposure
    assert report.unique_exposed == 2
    assert report.exposures_total == 7
    assert all(bucket.exposures <= MAX_LEDGER_REPEAT_BUCKET for bucket in report.exposure_buckets)
    assert all(isinstance(bucket, LedgerRepeatBucket) for bucket in report.exposure_buckets)


def test_ledger_repeats_rejects_wrong_scope_and_invalid_window(session: Session) -> None:
    with pytest.raises(ValueError, match="single-tenant"):
        ledger_repeat_distribution(
            session,
            scope="tenant-name",
            window_start=date(2026, 1, 1),
            window_end=date(2027, 1, 1),
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="start must precede end"):
        ledger_repeat_distribution(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=date(2026, 1, 1),
            window_end=date(2026, 1, 1),
            generated_at=NOW,
        )
    with pytest.raises(ValueError, match="cannot exceed 1826"):
        ledger_repeat_distribution(
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start=date(2021, 1, 1),
            window_end=date(2021, 1, 1) + MAX_LEDGER_TREND_WINDOW + timedelta(days=1),
            generated_at=NOW,
        )
    with pytest.raises(TypeError, match="must be dates"):
        ledger_repeat_distribution(  # type: ignore[arg-type]
            session,
            scope=SINGLE_TENANT_DATABASE_SCOPE,
            window_start="2026-01-01",
            window_end=date(2027, 1, 1),
            generated_at=NOW,
        )


def test_ledger_repeats_csv_is_formula_safe_and_pseudonym_free(session: Session) -> None:
    _entry(session, pseudonym="a" * 64, day=date(2026, 2, 1), clicked=True)
    _entry(session, pseudonym="a" * 64, day=date(2026, 3, 1), clicked=True)
    _entry(session, pseudonym="b" * 64, day=date(2026, 4, 1), no_activity=True)

    report = ledger_repeat_distribution(
        session,
        scope=SINGLE_TENANT_DATABASE_SCOPE,
        window_start=date(2026, 1, 1),
        window_end=date(2027, 1, 1),
        generated_at=NOW,
    )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(ledger_repeat_csv_rows(report))
    projection = output.getvalue()

    assert ("a" * 64) not in projection
    assert "recipient_pseudonym" not in projection
    assert "exposures_2" in projection
    assert "engaged_2" in projection
    assert "unique_exposed" in projection
    assert "repeat_exposure" in projection
    assert "no_activity_at_close" in projection
    assert not any(cell.startswith(("=", "+", "-", "@")) for cell in _cells(projection))
    assert isinstance(report.exposure_buckets, tuple) and len(report.exposure_buckets) == MAX_LEDGER_REPEAT_BUCKET


def _cells(projection: str) -> list[str]:
    return [cell.strip() for row in csv.reader(io.StringIO(projection)) for cell in row if cell.strip()]
