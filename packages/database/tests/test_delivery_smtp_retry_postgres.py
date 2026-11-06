"""Durable SMTP DATA-refusal retries with actual managed delivery logins.

Runs the production claim/correlation/provider-result loop in a fresh preserved
synthetic database. Only the provider callback is synthetic; audit and retry
intents use real PostgreSQL transactions. No external SMTP/Redis is contacted.
"""

from __future__ import annotations

import copy
import smtplib
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from kp_database.audit_store import AuditStore
from kp_database.models import (
    AuditEvent,
    Campaign,
    CampaignApproval,
    DeliveryReportCorrelation,
    Recipient,
    RecipientAssignment,
    RulesOfEngagement,
    TemplateVersion,
    TrainingResource,
    TransactionalOutbox,
)
from kp_domain_models import models as dm
from kp_workers import jobs
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.exc import DBAPIError
from test_delivery_live_authority_races import authority as _authority
from test_delivery_live_authority_races import managed_database as _managed_database
from test_delivery_live_authority_races import mutate
from test_delivery_live_authority_races import prepared as _prepared
from test_delivery_live_authority_races import subject as _subject
from test_delivery_recipient_races import receipt

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _subject.__wrapped__(managed_database)


@pytest.fixture
def prepared(subject, monkeypatch):
    return _prepared.__wrapped__(subject, monkeypatch)


@pytest.fixture
def authority(prepared, managed_database, monkeypatch):
    value = _authority.__wrapped__(prepared, monkeypatch)
    url, _, _, audit_password = managed_database
    audit_engine = create_engine(url.set(username="audit_writer", password=audit_password))
    value.ctx.audit_store = AuditStore(audit_engine, intent_engine=value.delivery_factory.kw["bind"])
    # Preserve the production after-commit dispatcher without connecting to a
    # Redis service. Replayed durable payloads below drive the actual worker.
    value.published = []
    value.ctx.queue = SimpleNamespace(
        publish=lambda *args, **kwargs: value.published.append(copy.deepcopy((args, kwargs)))
    )
    value.ctx.settings.email_provider = "smtp"
    value.original_payload = copy.deepcopy(value.payload)
    try:
        yield value
    finally:
        audit_engine.dispose()


def _assignment(authority):
    with authority.admin_factory() as session:
        row = session.get(RecipientAssignment, authority.assignment_ids[0])
        return SimpleNamespace(
            state=row.send_state,
            reason=row.failure_reason,
            attempt_id=row.delivery_attempt_id,
            count=row.delivery_attempt_count,
            claimed_at=row.delivery_claimed_at,
        )


def _correlations(authority):
    with authority.admin_factory() as session:
        return session.execute(
            select(
                DeliveryReportCorrelation.delivery_attempt_id,
                DeliveryReportCorrelation.message_id,
                DeliveryReportCorrelation.verifier_hash,
            ).where(DeliveryReportCorrelation.recipient_assignment_id == authority.assignment_ids[0])
        ).all()


def _queue_intents(authority):
    attempt = _assignment(authority).attempt_id
    with authority.admin_factory() as session:
        rows = session.scalars(
            select(TransactionalOutbox)
            .where(
                TransactionalOutbox.kind == "queue",
                TransactionalOutbox.topic == "deliver",
                TransactionalOutbox.idempotency_key.like(f"deliver:smtp-data:{attempt}:%"),
            )
            .order_by(TransactionalOutbox.created_at, TransactionalOutbox.idempotency_key)
        ).all()
        return [
            SimpleNamespace(
                payload=copy.deepcopy(row.payload),
                key=row.idempotency_key,
                available_at=row.available_at,
                origin=row.origin_role,
            )
            for row in rows
        ]


def _rejection_intents(authority):
    row = _assignment(authority)
    with authority.admin_factory() as session:
        return session.scalars(
            select(TransactionalOutbox)
            .where(
                TransactionalOutbox.kind == "audit",
                TransactionalOutbox.idempotency_key.like(f"deliver:smtp-rejected:{row.attempt_id}:%"),
            )
            .order_by(TransactionalOutbox.created_at, TransactionalOutbox.idempotency_key)
        ).all()


def _rejection_audit(authority):
    row = _assignment(authority)
    with authority.admin_factory() as session:
        return session.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.action == "campaign.deliver.smtp_rejected",
                AuditEvent.object_id.in_(
                    [str(authority.campaign_id), str(authority.assignment_ids[0]), str(row.attempt_id)]
                ),
            )
            .order_by(AuditEvent.occurred_at)
        ).all()


def _await_rejection_audit(authority, expected):
    assert expected > 0
    intents = _rejection_intents(authority)
    assert len(intents) == expected  # missing durable evidence is never a projection-timing excuse
    deadline = time.monotonic() + 5
    while True:
        # The real worker dispatches committed audit intents periodically. Its
        # server-clock eligibility can lag the caller's occurred_at briefly.
        with authority.admin_factory() as session:
            now = session.scalar(text("SELECT clock_timestamp()"))
        if intents and all(intent.available_at <= now for intent in intents):
            authority.ctx.audit_store.dispatch_pending_audit()
        events = _rejection_audit(authority)
        if len(events) == expected:
            assert {event.outbox_id for event in events} == {intent.outbox_id for intent in intents}
            return events
        if time.monotonic() >= deadline:
            pytest.fail("committed SMTP rejection audit intents did not project within the bounded worker-loop poll")
        time.sleep(0.05)


def _marker(intent):
    return intent.payload["smtp_data_retry"]


def _due(intent):
    return datetime.fromisoformat(_marker(intent)["not_before"].replace("Z", "+00:00"))


def _wait_until_due(authority, intent):
    # Use the actual server clock; payload time alone cannot authorize a retry.
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        with authority.admin_factory() as session:
            if session.scalar(text("SELECT clock_timestamp()")) >= _due(intent):
                return
        time.sleep(0.05)
    pytest.fail("bounded SMTP retry did not become eligible within its declared 5/10-second policy")


def _run(authority, payload):
    authority.payload = copy.deepcopy(payload)
    with authority.delivery_factory() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_worker_delivery"
        assert not session.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
        campaign = session.get(Campaign, authority.campaign_id)
        # Keep real cached authority across the production claim/correlation
        # commits, as the normal expire_on_commit=False worker session does.
        cached = [
            session.get(RulesOfEngagement, campaign.roe_id),
            session.get(TrainingResource, campaign.training_resource_id),
            session.get(TemplateVersion, campaign.current_template_id),
        ]
        approvals = list(
            session.scalars(select(CampaignApproval).where(CampaignApproval.campaign_id == authority.campaign_id))
        )
        assert all(cached) and len(approvals) == 2
        authority.plan.template = cached[2]
        outcome = jobs._deliver_assignments(
            authority.ctx,
            session,
            campaign,
            authority.plan,
            authority.payload,
            [str(authority.assignment_ids[0])],
            campaign_id=str(authority.campaign_id),
            test_send=False,
        )
        # process_delivery's summary owns this final commit, including branches
        # intentionally returned with recipient_unavailable(commit=False).
        session.commit()
        return outcome


def _provider_calls(monkeypatch, *, accepted_after=None):
    calls = []

    def provider(*args, correlation, **_kwargs):
        assignment = args[4]
        calls.append((assignment.delivery_attempt_id, correlation.operation_id, correlation.message_id))
        if accepted_after is not None and len(calls) >= accepted_after:
            return receipt()
        raise smtplib.SMTPDataError(451, b"synthetic pre-acceptance DATA refusal")

    monkeypatch.setattr(jobs, "_send_email", provider)
    return calls


def test_real_delivery_refusal_is_durable_and_only_due_matching_retry_accepts_once(authority, monkeypatch):
    calls = _provider_calls(monkeypatch, accepted_after=2)
    outcome = _run(authority, authority.original_payload)
    first = _assignment(authority)
    assert outcome.retry_deferred == 1
    assert first.state == dm.SendState.QUEUED and first.reason == "smtp_data_retry_pending" and first.count == 1
    correlations = _correlations(authority)
    assert len(correlations) == 1 and correlations[0][0] == first.attempt_id
    intents = _queue_intents(authority)
    assert len(intents) == 1 and intents[0].origin == "kp_worker_delivery"
    intent = intents[0]
    marker = _marker(intent)
    assert marker["assignment_id"] == str(authority.assignment_ids[0])
    assert marker["attempt_id"] == str(first.attempt_id) and marker["after_attempt"] == 1
    assert _due(intent) == first.claimed_at + timedelta(seconds=5) == intent.available_at
    assert intent.payload["recipient_assignment_ids"] == [str(authority.assignment_ids[0])]
    assert set(intent.payload["tracking_bearers"]) == {str(authority.assignment_ids[0])}
    assert len(_rejection_intents(authority)) == 1
    with authority.admin_factory() as session:
        assert session.get(DeliveryReportCorrelation, first.attempt_id).provider_status == "smtp_data_rejected_451"

    _run(authority, authority.original_payload)
    _run(authority, intent.payload)  # correctly signed marker, but still too early
    forged = copy.deepcopy(intent.payload)
    forged["smtp_data_retry"]["not_before"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    _run(authority, forged)
    assert len(calls) == 1 and _assignment(authority).count == 1
    assert len(_queue_intents(authority)) == 1
    # Finish all early/original/forged marker proofs before a projection wait
    # can consume the five-second retry eligibility interval.
    evidence = _await_rejection_audit(authority, expected=1)
    assert len(evidence) == 1 and evidence[0].detail["smtp_code"] == 451 and evidence[0].detail["attempt"] == 1

    _wait_until_due(authority, intent)
    assert _run(authority, intent.payload).sent == 1
    accepted = _assignment(authority)
    assert accepted.state == dm.SendState.ACCEPTED and accepted.count == 2 and accepted.attempt_id == first.attempt_id
    assert _correlations(authority) == correlations
    assert len(calls) == 2 and len(set(calls)) == 1  # attempt, correlation and Message-ID are retry-stable
    _run(authority, intent.payload)
    _run(authority, authority.original_payload)
    assert len(calls) == 2 and len(_await_rejection_audit(authority, expected=1)) == 1


def test_refusal_exhaustion_persists_across_jobs_and_stale_marker_cannot_reset_count(authority, monkeypatch):
    calls = _provider_calls(monkeypatch)
    _run(authority, authority.original_payload)
    first = _queue_intents(authority)[0]
    initial_id = _assignment(authority).attempt_id
    _wait_until_due(authority, first)
    _run(authority, first.payload)
    second = _queue_intents(authority)[1]
    pending = _assignment(authority)
    assert pending.count == 2 and _marker(second)["after_attempt"] == 2
    assert _due(second) == pending.claimed_at + timedelta(seconds=10)
    _run(authority, first.payload)
    _run(authority, authority.original_payload)
    assert len(calls) == 2 and _assignment(authority).count == 2
    _wait_until_due(authority, second)
    _run(authority, second.payload)
    exhausted = _assignment(authority)
    assert exhausted.state == dm.SendState.FAILED and exhausted.reason == "smtp_data_retry_exhausted"
    assert exhausted.count == 3 and exhausted.attempt_id == initial_id
    assert len(_queue_intents(authority)) == 2
    committed = _rejection_intents(authority)
    assert len(committed) == 3
    assert [intent.payload["detail"]["attempt"] for intent in committed] == [1, 2, 3]
    assert [intent.idempotency_key for intent in committed] == [
        f"deliver:smtp-rejected:{initial_id}:{count}" for count in (1, 2, 3)
    ]
    assert all(intent.origin_role == "kp_worker_delivery" for intent in committed)
    assert all(intent.payload["action"] == "campaign.deliver.smtp_rejected" for intent in committed)
    assert all(intent.payload["detail"]["delivery_attempt_id"] == str(initial_id) for intent in committed)
    assert all(intent.payload["detail"]["smtp_code"] == 451 for intent in committed)
    assert [intent.payload["detail"]["retry_scheduled"] for intent in committed] == [True, True, False]
    audit = _await_rejection_audit(authority, expected=3)
    assert len(audit) == 3
    assert all(row.origin_role == "kp_worker_delivery" and row.detail["smtp_code"] == 451 for row in audit)
    assert [row.detail["attempt"] for row in audit] == [1, 2, 3]
    assert [row.detail["retry_scheduled"] for row in audit] == [True, True, False]
    _run(authority, second.payload)
    _run(authority, first.payload)
    _run(authority, authority.original_payload)
    assert len(calls) == 3 and len(set(calls)) == 1 and _assignment(authority).count == 3
    assert len(_correlations(authority)) == 1


def test_sql_failure_in_retry_intent_rolls_back_reset_and_audit_without_another_provider_call(authority, monkeypatch):
    calls = _provider_calls(monkeypatch)
    engine = authority.delivery_factory.kw["bind"]

    def fail_retry_queue_insert(connection, _cursor, statement, parameters, _context, _executemany):
        if (
            statement.startswith("INSERT INTO transactional_outbox")
            and isinstance(parameters, dict)
            and parameters.get("topic") == "deliver"
            and str(parameters.get("key", "")).startswith("deliver:smtp-data:")
        ):
            connection.exec_driver_sql("SELECT 1/0")  # genuine PostgreSQL transaction failure, synthetic DB only

    event.listen(engine, "before_cursor_execute", fail_retry_queue_insert)
    try:
        with pytest.raises(DBAPIError):
            _run(authority, authority.original_payload)
    finally:
        event.remove(engine, "before_cursor_execute", fail_retry_queue_insert)
    stopped = _assignment(authority)
    assert stopped.state == dm.SendState.SENDING and stopped.count == 1 and stopped.attempt_id is not None
    assert len(calls) == 1 and len(_correlations(authority)) == 1
    assert _queue_intents(authority) == [] and _rejection_intents(authority) == [] and _rejection_audit(authority) == []
    _run(authority, authority.original_payload)
    assert len(calls) == 1 and _assignment(authority).state == dm.SendState.SENDING


@pytest.mark.parametrize("change", ("recipient", "roe"))
def test_due_retry_still_obeys_current_recipient_and_signed_authorization(authority, monkeypatch, change):
    calls = _provider_calls(monkeypatch)
    _run(authority, authority.original_payload)
    intent = _queue_intents(authority)[0]
    _wait_until_due(authority, intent)
    if change == "roe":
        mutate(authority, "roe")
    else:
        with authority.operator_factory() as operator:
            operator.get(
                Recipient, authority.recipient_ids[0], with_for_update=True
            ).status = dm.RecipientStatus.DEPARTED
            operator.commit()
    outcome = _run(authority, intent.payload)
    assert outcome.sent == 0 and len(calls) == 1
    assert _assignment(authority).state in {dm.SendState.FAILED, dm.SendState.EXPIRED}
    assert len(_queue_intents(authority)) == len(_await_rejection_audit(authority, expected=1)) == 1
