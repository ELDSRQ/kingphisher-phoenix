from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from kp_database.awareness_ledger import (
    AWARENESS_LEDGER_RETENTION_DAYS,
    MAX_LEDGER_PROJECTION_BATCH,
    AwarenessLedgerProjectionError,
    project_awareness_ledger_batch,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE
from kp_domain_models import models as dm
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

NOW = datetime(2026, 8, 29, 16, 0, tzinfo=UTC)


class _Result:
    def __init__(self, rows: Iterable[tuple[object, ...]]) -> None:
        self.rows = list(rows)

    def __iter__(self):  # noqa: ANN204
        return iter(self.rows)


class _Session:
    def __init__(self, results: list[_Result]) -> None:
        self.results = list(results)
        self.statements: list[object] = []

    def execute(self, statement: object) -> _Result:
        self.statements.append(statement)
        return self.results.pop(0) if self.results else _Result(())


def _params(statement: object) -> dict[str, object]:
    return dict(statement.compile(dialect=postgresql.dialect()).params)  # type: ignore[attr-defined]


def test_projection_is_bounded_pseudonymous_idempotent_and_denominator_complete() -> None:
    recipient_id = uuid.uuid4()
    active_assignment = uuid.uuid4()
    quiet_assignment = uuid.uuid4()
    active_campaign = uuid.uuid4()
    quiet_campaign = uuid.uuid4()
    active_start = NOW - timedelta(days=20)
    quiet_targeted_at = NOW - timedelta(days=10)
    fake = _Session(
        [
            _Result(
                [
                    (
                        active_assignment,
                        recipient_id,
                        active_campaign,
                        NOW - timedelta(days=21),
                        NOW - timedelta(days=20),
                        NOW - timedelta(days=20),
                        active_start,
                        dm.CampaignState.COMPLETED,
                    ),
                    (
                        quiet_assignment,
                        recipient_id,
                        quiet_campaign,
                        quiet_targeted_at,
                        None,
                        None,
                        None,
                        dm.CampaignState.COMPLETED,
                    ),
                ]
            ),
            _Result(
                [
                    (active_assignment, dm.EventType.CLICKED),
                    (active_assignment, dm.EventType.HUMAN_INTERACTION_CONFIRMED),
                    (active_assignment, dm.EventType.MESSAGE_REPORTED),
                ]
            ),
            _Result([(active_assignment, NOW - timedelta(days=19), NOW - timedelta(days=18))]),
            _Result([]),
        ]
    )

    result = project_awareness_ledger_batch(
        cast(Session, fake),
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
        pseudonym_key=b"p" * 32,
        pseudonym_key_version="v1",
        assignment_ids=[active_assignment, quiet_assignment],
        projected_at=NOW,
    )

    assert result.requested_assignments == result.projected_entries == 2
    assert len(set(result.entry_ids)) == 2
    assert len(fake.statements) == 4
    source_sql = " ".join(str(statement.compile(dialect=postgresql.dialect())) for statement in fake.statements[:3])
    assert "recipients" not in source_sql
    assert all(value not in source_sql for value in ("mailbox", "display_name", "department"))

    upsert = fake.statements[-1]
    upsert_sql = str(upsert.compile(dialect=postgresql.dialect()))
    params = _params(upsert)
    assert "ON CONFLICT ON CONSTRAINT uq_awareness_ledger_scope_campaign_exposure DO UPDATE" in upsert_sql
    assert "excluded.projected_at >= awareness_ledger_entries.projected_at" in upsert_sql
    assert "recipient_id" not in upsert_sql
    assert params["recipient_pseudonym_m0"] == params["recipient_pseudonym_m1"]
    assert params["recipient_pseudonym_m0"] != recipient_id.hex
    assert params["assignment_exposure_pseudonym_m0"] != params["assignment_exposure_pseudonym_m1"]
    assert params["targeted_m0"] is params["targeted_m1"] is True
    assert params["accepted_m0"] is params["delivered_m0"] is True
    assert params["observed_click_m0"] is True
    assert params["confirmed_interaction_m0"] is True
    assert params["reported_m0"] is True
    assert params["training_assigned_m0"] is True
    assert params["training_completed_m0"] is params["training_passed_m0"] is True
    assert params["campaign_closed_m0"] is True
    assert params["no_activity_at_close_m0"] is False
    assert params["no_activity_at_close_m1"] is True
    assert params["campaign_date_basis_m0"] == "scheduled_start"
    assert params["campaign_date_basis_m1"] == "targeted_at"
    assert params["retain_until_m0"] == active_start.date() + timedelta(days=AWARENESS_LEDGER_RETENTION_DAYS)


def test_projection_fails_closed_before_write_when_raw_batch_is_incomplete() -> None:
    fake = _Session([_Result([])])
    with pytest.raises(AwarenessLedgerProjectionError, match="incomplete"):
        project_awareness_ledger_batch(
            cast(Session, fake),
            tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
            pseudonym_key=b"p" * 32,
            pseudonym_key_version="v1",
            assignment_ids=[uuid.uuid4()],
            projected_at=NOW,
        )
    assert len(fake.statements) == 1


def test_projection_rejects_nonterminal_campaign_before_any_ledger_write() -> None:
    assignment_id = uuid.uuid4()
    fake = _Session(
        [
            _Result(
                [
                    (
                        assignment_id,
                        uuid.uuid4(),
                        uuid.uuid4(),
                        NOW - timedelta(days=400),
                        None,
                        None,
                        None,
                        dm.CampaignState.ACTIVE,
                    )
                ]
            ),
            _Result([]),
            _Result([]),
        ]
    )

    with pytest.raises(AwarenessLedgerProjectionError, match="terminal campaign"):
        project_awareness_ledger_batch(
            cast(Session, fake),
            tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
            pseudonym_key=b"p" * 32,
            pseudonym_key_version="v1",
            assignment_ids=[assignment_id],
            projected_at=NOW,
        )

    assert len(fake.statements) == 3
    assert "INSERT INTO awareness_ledger_entries" not in " ".join(map(str, fake.statements))


def test_projection_preserves_duplicate_campaign_recipient_assignment_denominators() -> None:
    recipient_id = uuid.uuid4()
    campaign_id = uuid.uuid4()
    first_assignment = uuid.uuid4()
    second_assignment = uuid.uuid4()
    assignment_row_tail = (
        recipient_id,
        campaign_id,
        NOW - timedelta(days=2),
        None,
        None,
        NOW - timedelta(days=2),
        dm.CampaignState.COMPLETED,
    )
    fake = _Session(
        [
            _Result(
                [
                    (first_assignment, *assignment_row_tail),
                    (second_assignment, *assignment_row_tail),
                ]
            ),
            _Result([]),
            _Result([]),
            _Result([]),
        ]
    )

    result = project_awareness_ledger_batch(
        cast(Session, fake),
        tenant_scope=SINGLE_TENANT_DATABASE_SCOPE,
        pseudonym_key=b"p" * 32,
        pseudonym_key_version="v1",
        assignment_ids=[first_assignment, second_assignment],
        projected_at=NOW,
    )

    assert result.projected_entries == 2
    params = _params(fake.statements[-1])
    assert params["recipient_pseudonym_m0"] == params["recipient_pseudonym_m1"]
    assert params["assignment_exposure_pseudonym_m0"] != params["assignment_exposure_pseudonym_m1"]


def test_projection_rejects_unscoped_weak_or_unbounded_inputs_without_database_use() -> None:
    fake = _Session([])
    arguments = {
        "session": cast(Session, fake),
        "tenant_scope": SINGLE_TENANT_DATABASE_SCOPE,
        "pseudonym_key": b"p" * 32,
        "pseudonym_key_version": "v1",
        "assignment_ids": [],
        "projected_at": NOW,
    }
    with pytest.raises(ValueError, match="single-tenant"):
        project_awareness_ledger_batch(**(arguments | {"tenant_scope": "tenant-name"}))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least 32"):
        project_awareness_ledger_batch(**(arguments | {"pseudonym_key": b"weak"}))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="cannot exceed"):
        project_awareness_ledger_batch(
            **(arguments | {"assignment_ids": [uuid.uuid4() for _ in range(MAX_LEDGER_PROJECTION_BATCH + 1)]})  # type: ignore[arg-type]
        )
    assert fake.statements == []
