"""SMTP transport changes retain reminder/proof no-retry contracts."""

from __future__ import annotations

import smtplib

import pytest
from kp_workers import jobs
from kp_workers.providers.reminders import ProviderReminderSender
from kp_workers.providers.smtp import DeliveryIndeterminateError, SmtpSender
from provider_jobs_test import _add_due_assignment, _context, _Session
from test_proof_send_job import _campaign, _recipient, _run, _template
from test_smtp_known_negative import ScriptedSMTP


@pytest.mark.parametrize(
    "reply,expected",
    [
        ((451, b"synthetic rejected DATA"), smtplib.SMTPDataError),
        (TimeoutError("lost final reply"), DeliveryIndeterminateError),
    ],
)
def test_reminder_retains_durable_no_retry_claim_for_negative_or_unknown_transport(monkeypatch, reply, expected):
    protocol = ScriptedSMTP(reply)
    monkeypatch.setattr(SmtpSender, "_connect", lambda _: protocol)
    monkeypatch.setattr(
        jobs,
        "_reminder_sender",
        lambda _: ProviderReminderSender(SmtpSender("smtp.example.test:25"), sender="sender@example.test"),
    )
    monkeypatch.setattr(
        jobs, "enqueue_queue", lambda *_, **__: pytest.fail("reminder must not enqueue delivery retries")
    )
    monkeypatch.setattr("kp_workers.followup_jobs._excluded_recipient_ids", lambda *_: set())
    session = _Session()
    assignment = _add_due_assignment(session, mailbox="synthetic@example.com")
    context, audit = _context(session)
    session.scalar_results = [assignment]
    with pytest.raises(expected):
        jobs.process_reminder(context, {"payload": {}})
    claimed_at = assignment.followup_sent_at
    assert claimed_at is not None and session.commits == 1 and len(protocol.bodies) == 1
    assert audit.records[0]["action"] == "training.remind.failed"
    session.scalar_results = [assignment, None]  # stale/redelivered reminder still cannot send again
    jobs.process_reminder(context, {"payload": {}})
    assert assignment.followup_sent_at == claimed_at and len(protocol.bodies) == 1


@pytest.mark.parametrize(
    "failure",
    [
        smtplib.SMTPDataError(451, b"explicit negative"),
        DeliveryIndeterminateError(message_id="<synthetic@example.test>"),
    ],
)
def test_proof_failure_is_audited_without_assignment_or_automatic_retry(monkeypatch, failure):
    monkeypatch.setattr(jobs, "enqueue_queue", lambda *_, **__: pytest.fail("proof must not enqueue delivery retries"))
    audit, sent = _run(
        monkeypatch, campaign=_campaign(), template=_template(), recipient=_recipient(), send_error=failure
    )
    assert sent == [] and audit.actions == ["campaign.proof-send.failed"]
