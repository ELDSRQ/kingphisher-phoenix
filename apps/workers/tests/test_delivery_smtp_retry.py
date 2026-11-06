"""Transport-to-worker classification and retry-intent boundaries, no network."""

from __future__ import annotations

import copy
import smtplib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_domain_models import models as dm
from kp_workers import jobs
from kp_workers.providers.smtp import SmtpSender
from test_delivery_recipient_fence import batch as _recipient_batch
from test_smtp_known_negative import ScriptedSMTP, message

PRODUCTION_CLAIM = jobs._claim_delivery


@pytest.fixture
def delivery(monkeypatch):
    value = _recipient_batch.__wrapped__(monkeypatch)
    value.ctx.settings.email_provider = "smtp"
    value.ctx.settings.email_provider_kind = SimpleNamespace(is_acs=False)
    value.intent, value.audit, value.dispatch_registered, value.dispatches = [], [], [], []
    value.ctx.audit_store = SimpleNamespace(
        record=lambda **entry: value.audit.append(entry),
        dispatch_pending_queue=lambda queue: value.dispatches.append(queue),
    )
    value.ctx.queue = SimpleNamespace()
    monkeypatch.setattr(jobs, "enqueue_queue", lambda session, **entry: value.intent.append((session, entry)))
    monkeypatch.setattr(
        jobs, "dispatch_after_commit", lambda session, callback: value.dispatch_registered.append((session, callback))
    )
    original = jobs._claim_delivery

    def claim(session, assignment, campaign_id, *, claimed_at, **kwargs):
        result = original(session, assignment, campaign_id, claimed_at=claimed_at, **kwargs)
        assignment.delivery_attempt_count = (assignment.delivery_attempt_count or 0) + 1
        assignment.delivery_claimed_at = claimed_at
        return result

    monkeypatch.setattr(jobs, "_claim_delivery", claim)
    first, second = (str(row.recipient_assignment_id) for row in value.assignments)
    value.payload = {
        "campaign_id": str(value.campaign.campaign_id),
        "template_hash": "reviewed",
        "delivery_phase": "reviewed_direct",
        "launch_manifest_hash": "reviewed-launch",
        "recipient_assignment_ids": [first, second],
        "tracking_bearers": {first: {"bearer": "first opaque bearer"}, second: {"bearer": "other opaque bearer"}},
    }
    value.correlations = []

    def correlation(_session, assignment, **kwargs):
        row = SimpleNamespace(delivery_attempt_id=assignment.delivery_attempt_id, provider_status=None)
        value.correlations.append(row)
        return row, SimpleNamespace()

    monkeypatch.setattr(jobs, "_durable_delivery_correlation", correlation)

    def run():
        return jobs._deliver_assignments(
            value.ctx,
            value.session,
            value.campaign,
            value.plan,
            value.payload,
            [first],
            campaign_id=str(value.campaign.campaign_id),
            test_send=False,
        )

    value.run_one = run
    return value


def test_real_data451_stages_singleton_delayed_intent_with_atomic_session_audit(delivery, monkeypatch):
    protocol = ScriptedSMTP((451, b"temporary failure"))
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: SmtpSender("smtp.example.test:25").send(message()))
    outcome = delivery.run_one()
    assignment = delivery.assignments[0]
    assert outcome.retry_deferred == 1 and outcome.failed == outcome.indeterminate == outcome.sent == 0
    assert assignment.send_state == dm.SendState.QUEUED and assignment.failure_reason == "smtp_data_retry_pending"
    assert assignment.delivery_attempt_count == 1 and assignment.delivery_attempt_id is not None
    assert delivery.correlations[0].delivery_attempt_id == assignment.delivery_attempt_id
    assert delivery.correlations[0].provider_status == "smtp_data_rejected_451"
    assert len(delivery.intent) == len(delivery.audit) == len(delivery.dispatch_registered) == 1
    assert delivery.dispatches == []  # callback registration cannot publish pre-commit
    session, intent = delivery.intent[0]
    assert session is delivery.session and delivery.audit[0]["session"] is session
    assert intent["topic"] == "deliver"
    identifier = str(assignment.recipient_assignment_id)
    assert intent["payload"]["recipient_assignment_ids"] == [identifier]
    assert intent["payload"]["tracking_bearers"] == {identifier: delivery.payload["tracking_bearers"][identifier]}
    assert intent["payload"]["launch_manifest_hash"] == "reviewed-launch"
    marker = intent["payload"]["smtp_data_retry"]
    assert marker == {
        "assignment_id": identifier,
        "attempt_id": str(assignment.delivery_attempt_id),
        "after_attempt": 1,
        "not_before": intent["available_at"].isoformat(),
    }
    assert intent["available_at"] == assignment.delivery_claimed_at + timedelta(seconds=5)
    assert delivery.audit[0]["detail"]["retry_scheduled"] is True
    assert len(protocol.bodies) == 1


@pytest.mark.parametrize(
    "failure,expected",
    [
        (smtplib.SMTPDataError(550, b"permanent"), dm.SendState.FAILED),
        (smtplib.SMTPResponseException(451, b"unclassified phase"), dm.SendState.INDETERMINATE),
        (TimeoutError("lost response"), dm.SendState.INDETERMINATE),
    ],
)
def test_permanent_unclassified_or_unknown_result_never_enqueues_retry(delivery, monkeypatch, failure, expected):
    def provider(*_, **__):
        raise failure

    monkeypatch.setattr(jobs, "_send_email", provider)
    delivery.run_one()
    assert delivery.assignments[0].send_state == expected
    assert delivery.intent == [] and delivery.dispatch_registered == []


def test_acs_never_enters_smtp_retry_policy(delivery, monkeypatch):
    delivery.ctx.settings.email_provider = "azure_communication_services"
    delivery.ctx.settings.email_provider_kind.is_acs = True

    def provider(*_, **__):
        raise smtplib.SMTPDataError(451, b"not an SMTP transport")

    monkeypatch.setattr(jobs, "_send_email", provider)
    delivery.run_one()
    assert delivery.assignments[0].send_state == dm.SendState.INDETERMINATE and delivery.intent == []


@pytest.mark.parametrize(
    "tamper", ["missing_generation", "stale_count", "earlier_time", "wrong_attempt", "boolean_count"]
)
def test_invalid_retry_marker_does_not_reach_claim_sql_or_mutate_durable_state(delivery, tamper):
    assignment = delivery.assignments[0]
    assignment.delivery_attempt_id = uuid4()
    assignment.delivery_attempt_count = 1
    assignment.delivery_claimed_at = datetime.now(UTC)
    assignment.failure_reason = "smtp_data_retry_pending"
    marker = {
        "assignment_id": str(assignment.recipient_assignment_id),
        "attempt_id": str(assignment.delivery_attempt_id),
        "after_attempt": 1,
        "not_before": jobs._smtp_retry_not_before(assignment).isoformat(),
    }
    if tamper == "stale_count":
        marker["after_attempt"] = 0
    elif tamper == "earlier_time":
        marker["not_before"] = assignment.delivery_claimed_at.isoformat()
    elif tamper == "wrong_attempt":
        marker["attempt_id"] = str(uuid4())
    elif tamper == "boolean_count":
        marker["after_attempt"] = True
    else:
        marker = {"not_before": marker["not_before"]}

    class NoClaimSQL:
        rolled_back = False

        def scalar(self, *_):
            pytest.fail("invalid marker reached claim SQL")

        def rollback(self):
            self.rolled_back = True

    session = NoClaimSQL()
    before = copy.copy(assignment.__dict__)
    assert (
        PRODUCTION_CLAIM(
            session, assignment, delivery.campaign.campaign_id, claimed_at=datetime.now(UTC), retry_marker=marker
        )
        is None
    )
    assert session.rolled_back and assignment.__dict__ == before
