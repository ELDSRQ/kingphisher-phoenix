"""WS-6 retention worker tests against a disposable Postgres.

These belong to the explicit ``make test-postgres`` profile and require its
migrated disposable database and roles.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from kp_database.audit_store import AuditStore
from kp_database.base import Base
from kp_database.models import (
    AwarenessLedgerEntry,
    Campaign,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    RetentionAction,
    RetentionPolicy,
)
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_workers import jobs as worker_jobs
from kp_workers.config import WorkerSettings
from kp_workers.jobs import (
    AwarenessLedgerRetentionError,
    WorkerContext,
    maybe_publish_retention,
    process_retention,
    reconcile_campaign_lifecycle,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

pytestmark = pytest.mark.postgres


HMAC = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
KEK = HMAC

TEST_URL = os.environ.get(
    "DATABASE_URL_TEST", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher_test"
)

_available = None


def _db_available() -> bool:
    if os.environ.get("KP_TEST_PROFILE") != "postgres":
        return False
    global _available
    if _available is None:
        engine = None
        try:
            engine = create_db_engine(TEST_URL)
            with engine.connect():
                pass
            _available = True
        except Exception:  # noqa: BLE001 - DB simply not up
            _available = False
        finally:
            if engine is not None:
                engine.dispose()
    return _available


requires_db = pytest.mark.skipif(not _db_available(), reason="PostgreSQL integration database is not reachable")


class StubQueue:
    def __init__(self) -> None:
        self.published: list[tuple[str, dict]] = []

    def publish(
        self,
        topic: str,
        message: dict,
        *,
        idempotency_key: str | None = None,
        available_at: float | None = None,
    ) -> None:
        del idempotency_key, available_at
        self.published.append((topic, message))


@contextmanager
def _test_session() -> Iterator[Session]:
    engine = create_db_engine(TEST_URL)
    try:
        with make_session_factory(engine)() as session:
            yield session
    finally:
        engine.dispose()


@contextmanager
def _make_ctx(queue: StubQueue) -> Iterator[WorkerContext]:
    session_engine = create_db_engine(TEST_URL)
    audit_engine = None
    try:
        audit_engine = create_db_engine(TEST_URL)
        session_factory = make_session_factory(session_engine)
        audit_store = AuditStore(audit_engine, hmac_key=bytes.fromhex(HMAC))
        settings = WorkerSettings(
            _env_file=None,
            audit_hmac_key=HMAC,
            ciphertext_kek=KEK,
            database_url=TEST_URL,
            audit_database_url=TEST_URL,
            reported_mailbox_url="http://localhost:8025",
        )
        yield WorkerContext(settings, session_factory, audit_store, queue)
    finally:
        session_engine.dispose()
        if audit_engine is not None:
            audit_engine.dispose()


def _seed_assignments(
    *,
    campaign_state: dm.CampaignState = dm.CampaignState.COMPLETED,
) -> tuple[str, str, str]:
    """Seed one campaign with two DELIVERED assignments (old + recent) and one
    QUEUED old assignment. Returns all three assignment identifiers."""
    with _test_session() as session:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.INVOICE,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        campaign = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Retention Drill",
            state=campaign_state,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            timezone="UTC",
            max_recipients=10,
            created_by=uuid4(),
            expires_at=datetime.now(UTC) + timedelta(days=14),
        )
        session.add(campaign)
        # Each seeding call needs its own mailbox_sha256: the module shares one
        # schema (drop_all runs once), and uq_recipients_mailbox_sha256_active
        # must not collide with rows left by an earlier test.
        mailbox_sha256 = hashlib.sha256(f"retention-seed-{uuid4()}".encode("ascii")).hexdigest()
        recipient = Recipient(
            recipient_id=uuid4(),
            employee_key="u1",
            mailbox="u1@example.com",
            mailbox_sha256=mailbox_sha256,
            display_name="U One",
        )
        session.add(recipient)
        session.flush()

        old_delivered = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"old-delivered-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=400),
        )
        recent_delivered = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.DELIVERED,
            idempotency_key=f"recent-delivered-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=10),
        )
        old_queued = RecipientAssignment(
            recipient_assignment_id=uuid4(),
            campaign_id=campaign.campaign_id,
            recipient_id=recipient.recipient_id,
            send_state=dm.SendState.QUEUED,
            idempotency_key=f"old-queued-{uuid4()}",
            created_at=datetime.now(UTC) - timedelta(days=400),
        )
        session.add_all([old_delivered, recent_delivered, old_queued])
        session.commit()
        return (
            str(old_delivered.recipient_assignment_id),
            str(recent_delivered.recipient_assignment_id),
            str(old_queued.recipient_assignment_id),
        )


def _remaining_assignments() -> set[str]:
    with _test_session() as session:
        rows = session.execute(select(RecipientAssignment.recipient_assignment_id)).scalars().all()
        return {str(r) for r in rows}


@pytest.fixture(scope="module", autouse=True)
def _setup() -> None:
    engine = create_db_engine(TEST_URL)
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
    finally:
        engine.dispose()
    CipherText.configure_key(bytes.fromhex(KEK))


@requires_db
def test_retention_projects_exact_batch_before_deleting_old_assignments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_id, recent_id, old_queued_id = _seed_assignments()
    with _test_session() as session:
        session.add(
            RetentionPolicy(
                retention_policy_id=uuid4(),
                name="Default",
                data_category="recipient_assignments",
                retention_days=365,
                is_default=True,
            )
        )
        session.commit()

    with _test_session() as session:
        ledger_count_before = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0

    projected_batches: list[tuple[str, ...]] = []
    real_project = worker_jobs.project_awareness_ledger_batch

    def observing_project(session: Session, **arguments: Any) -> Any:  # noqa: ANN401
        assignment_ids = arguments["assignment_ids"]
        assert isinstance(assignment_ids, list)
        assert all(session.get(RecipientAssignment, assignment_id) is not None for assignment_id in assignment_ids)
        projected_batches.append(tuple(str(assignment_id) for assignment_id in assignment_ids))
        return real_project(session, **arguments)  # type: ignore[arg-type]

    monkeypatch.setattr(worker_jobs, "project_awareness_ledger_batch", observing_project)
    queue = StubQueue()
    with _make_ctx(queue) as ctx:
        process_retention(ctx, {"payload": {}, "idempotency_key": f"run-{uuid4()}"})

    assert len(projected_batches) == 1
    assert set(projected_batches[0]) == {old_id, old_queued_id}
    remaining = _remaining_assignments()
    assert old_id not in remaining
    assert old_queued_id not in remaining
    assert recent_id in remaining

    with _test_session() as session:
        action = session.scalar(select(RetentionAction).order_by(RetentionAction.executed_at.desc()).limit(1))
        assert action is not None
        assert action.target_table == "linked_campaign_data"
        assert action.row_count_deleted == 2
        ledger_count_after = session.scalar(select(func.count()).select_from(AwarenessLedgerEntry)) or 0
        assert ledger_count_after == ledger_count_before + 2
        projected = list(
            session.scalars(select(AwarenessLedgerEntry).order_by(AwarenessLedgerEntry.projected_at.desc()).limit(2))
        )
        assert all(entry.campaign_closed is True for entry in projected)
        assert all(entry.no_activity_at_close is True for entry in projected)


@requires_db
def test_retention_does_not_purge_old_assignments_from_nonterminal_campaigns() -> None:
    old_id, recent_id, old_queued_id = _seed_assignments(campaign_state=dm.CampaignState.ACTIVE)

    with _make_ctx(StubQueue()) as ctx:
        process_retention(ctx, {"payload": {}, "idempotency_key": f"nonterminal-{uuid4()}"})

    assert {old_id, recent_id, old_queued_id} <= _remaining_assignments()


@requires_db
def test_projection_failure_rolls_back_and_surfaces_stable_non_secret_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_id, recent_id, old_queued_id = _seed_assignments()
    secret = "private.person@example.com pseudonym-key=do-not-render"

    def fail_projection(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(secret)

    monkeypatch.setattr(worker_jobs, "project_awareness_ledger_batch", fail_projection)
    queue = StubQueue()
    with (
        _make_ctx(queue) as ctx,
        pytest.raises(
            AwarenessLedgerRetentionError,
            match="awareness ledger projection failed; raw retention was not applied",
        ) as captured,
    ):
        process_retention(ctx, {"payload": {}, "idempotency_key": f"failed-{uuid4()}"})

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    remaining = _remaining_assignments()
    assert {old_id, recent_id, old_queued_id} <= remaining


def _ledger_entry(*, entry_id: UUID, campaign_date: date) -> AwarenessLedgerEntry:
    return AwarenessLedgerEntry(
        awareness_ledger_entry_id=entry_id,
        tenant_scope="single_tenant_database",
        pseudonym_key_version="test-v1",
        recipient_pseudonym="a" * 64,
        assignment_exposure_pseudonym=str(entry_id).replace("-", "") * 2,
        campaign_id=uuid4(),
        campaign_date=campaign_date,
        campaign_date_basis="targeted_at",
        targeted=True,
        accepted=False,
        delivered=False,
        observed_open=False,
        observed_click=False,
        reported=False,
        confirmed_interaction=False,
        training_assigned=False,
        training_started=False,
        training_completed=False,
        training_passed=False,
        campaign_closed=False,
        no_activity_at_close=None,
        projected_at=datetime.now(UTC),
        retain_until=campaign_date + timedelta(days=1826),
    )


@requires_db
def test_retention_prunes_bounded_ledger_entries_only_after_retain_until() -> None:
    expired_id = uuid4()
    boundary_id = uuid4()
    today = datetime.now(UTC).date()
    with _test_session() as session:
        session.add_all(
            [
                _ledger_entry(entry_id=expired_id, campaign_date=today - timedelta(days=1827)),
                _ledger_entry(entry_id=boundary_id, campaign_date=today - timedelta(days=1826)),
            ]
        )
        session.commit()

    with _make_ctx(StubQueue()) as ctx:
        process_retention(ctx, {"payload": {}, "idempotency_key": f"prune-{uuid4()}"})

    with _test_session() as session:
        assert session.get(AwarenessLedgerEntry, expired_id) is None
        assert session.get(AwarenessLedgerEntry, boundary_id) is not None


@requires_db
def test_maybe_publish_retention_self_publishes() -> None:
    queue = StubQueue()
    now = datetime.now(UTC)
    with _make_ctx(queue) as ctx:
        maybe_publish_retention(ctx, now)
    assert len(queue.published) == 1
    topic, message = queue.published[0]
    assert topic == "retention"
    assert message == {
        "retention_policy_id": "default",
        "scheduled_at": now.isoformat(),
        "idempotency_key": f"retention-self-{int(now.timestamp()) // 86400}",
    }


@requires_db
def test_reconcile_campaign_lifecycle_closes_elapsed_windows() -> None:
    with _test_session() as session:
        pattern = CampaignPattern(
            campaign_pattern_id=uuid4(),
            lure_category=dm.LureCategory.INVOICE,
            confidence=dm.Confidence.HIGH,
        )
        session.add(pattern)
        session.flush()
        now = datetime.now(UTC)
        active = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Active elapsed",
            state=dm.CampaignState.ACTIVE,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            schedule_end=now - timedelta(minutes=1),
            timezone="UTC",
            max_recipients=1,
            expires_at=now - timedelta(minutes=1),
        )
        scheduled = Campaign(
            campaign_id=uuid4(),
            pattern_id=pattern.campaign_pattern_id,
            title="Never launched",
            state=dm.CampaignState.SCHEDULED,
            sender_mailbox="drills@example.com",
            training_domain="training.local",
            schedule_end=now - timedelta(minutes=1),
            timezone="UTC",
            max_recipients=1,
            expires_at=now - timedelta(minutes=1),
        )
        session.add_all([active, scheduled])
        session.flush()
        assert reconcile_campaign_lifecycle(session, now) == {
            "completed": 1,
            "expired": 1,
            "stale_queued": 0,
            "indeterminate": 0,
        }
        session.commit()
        assert active.state == dm.CampaignState.COMPLETED
        assert scheduled.state == dm.CampaignState.EXPIRED
