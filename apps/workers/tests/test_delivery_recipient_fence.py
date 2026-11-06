"""Recipient changes at delivery boundaries, without transport or databases."""

from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_database.models import Campaign, Recipient, RecipientAssignment
from kp_domain_models import models as dm
from kp_workers import jobs
from kp_workers.providers.smtp import DeliveryReceipt


@pytest.fixture
def batch(monkeypatch):
    campaign = Campaign(campaign_id=uuid4(), state=dm.CampaignState.SCHEDULED)
    recipients = [
        Recipient(recipient_id=uuid4(), mailbox=f"synthetic-{i}@example.test", status=dm.RecipientStatus.ACTIVE)
        for i in range(2)
    ]
    assignments = [
        RecipientAssignment(
            recipient_assignment_id=uuid4(),
            recipient_id=row.recipient_id,
            campaign_id=campaign.campaign_id,
            send_state=dm.SendState.QUEUED,
        )
        for row in recipients
    ]
    rows = {(Campaign, campaign.campaign_id): campaign}
    rows.update({(Recipient, row.recipient_id): row for row in recipients})
    rows.update({(RecipientAssignment, row.recipient_assignment_id): row for row in assignments})
    excluded = set()
    calls = []
    claims = []
    gap = [lambda assignment: None]
    after_send = [lambda recipient: None]

    class Session:
        def get(self, model, identifier, **kwargs):
            calls.append((model, identifier, kwargs))
            return rows.get((model, identifier))

        def scalar(self, statement):
            return SimpleNamespace(
                status=dm.TokenStatus.ACTIVE, token_hash="ab" * 32, expires_at=datetime.now(UTC) + timedelta(days=1)
            )

        def commit(self):
            pass

    session = Session()
    plan = SimpleNamespace(
        unrestricted=True,
        allowlist=frozenset(),
        roe_targets=frozenset({"example.test"}),
        sender_address="synthetic@example.test",
        template=None,
        pattern=None,
    )
    ctx = SimpleNamespace(settings=SimpleNamespace(), audit_store=SimpleNamespace(record=lambda **_: None))
    monkeypatch.setattr(jobs, "_excluded_recipient_ids", lambda *_: set(excluded))
    monkeypatch.setattr(jobs, "_delivery_recipient_is_excluded", lambda _s, recipient_id, _c: recipient_id in excluded)
    monkeypatch.setattr(jobs, "_delivery_tracking_bearer", lambda *_: ("A" * 43, "ok"))
    monkeypatch.setattr(jobs, "_make_batch_sender", lambda _: nullcontext())
    monkeypatch.setattr(jobs, "_launch_delivery_gate_reason", lambda *_: (None, None))
    monkeypatch.setattr(jobs, "_live_delivery_authorization_reason", lambda *_: None)
    monkeypatch.setattr(jobs, "_delivery_safety_state", lambda *_, **__: SimpleNamespace(emergency_stop_engaged=False))

    def claim(_session, assignment, _campaign_id, **kwargs):
        claims.append(assignment.recipient_assignment_id)
        assignment.send_state = dm.SendState.SENDING
        assignment.delivery_attempt_id = uuid4()
        return assignment.delivery_attempt_id

    def correlation(_session, assignment, **kwargs):
        gap[0](assignment)
        return SimpleNamespace(), SimpleNamespace()

    sends = []

    def provider(_ctx, _campaign, _template, _pattern, assignment, recipient, _token, **kwargs):
        sends.append(assignment.recipient_assignment_id)
        after_send[0](recipient)
        return DeliveryReceipt(message_id="<synthetic@example.test>", provider_id="synthetic")

    monkeypatch.setattr(jobs, "_claim_delivery", claim)
    monkeypatch.setattr(jobs, "_durable_delivery_correlation", correlation)
    monkeypatch.setattr(jobs, "_send_email", provider)

    def run():
        return jobs._deliver_assignments(
            ctx,
            session,
            campaign,
            plan,
            {},
            [str(row.recipient_assignment_id) for row in assignments],
            campaign_id=str(campaign.campaign_id),
            test_send=False,
        )

    return SimpleNamespace(
        run=run,
        ctx=ctx,
        session=session,
        plan=plan,
        campaign=campaign,
        recipients=recipients,
        assignments=assignments,
        excluded=excluded,
        sends=sends,
        claims=claims,
        gap=gap,
        after_send=after_send,
        calls=calls,
    )


def test_exclusion_committed_while_earlier_batch_recipient_sends_is_seen_before_next_claim(batch):
    batch.after_send[0] = lambda _: batch.excluded.add(batch.recipients[1].recipient_id)
    outcome = batch.run()
    assert batch.sends == batch.claims == [batch.assignments[0].recipient_assignment_id]
    assert batch.assignments[1].send_state == dm.SendState.EXPIRED
    assert batch.assignments[1].delivery_attempt_id is None
    assert outcome.sent == 1 and outcome.blocked == 1


def test_exclusion_committed_in_claim_to_provider_gap_blocks_that_claim(batch):
    batch.gap[0] = lambda assignment: batch.excluded.add(assignment.recipient_id)
    outcome = batch.run()
    assert batch.sends == [] and len(batch.claims) == 2
    assert all(row.send_state == dm.SendState.EXPIRED for row in batch.assignments)
    assert all(row.failure_reason == "recipient_excluded" for row in batch.assignments)
    assert outcome.blocked == 2 and outcome.sent == 0


@pytest.mark.parametrize("change", ["departed", "deleted", "outside_domain"])
def test_recipient_is_refreshed_and_revalidated_after_correlation_before_provider(batch, change):
    def mutate(assignment):
        recipient = next(row for row in batch.recipients if row.recipient_id == assignment.recipient_id)
        if change == "departed":
            recipient.status = dm.RecipientStatus.DEPARTED
        elif change == "deleted":
            recipient.deleted_at = datetime.now(UTC)
        else:
            recipient.mailbox = "synthetic@outside.test"

    batch.gap[0] = mutate
    batch.run()
    assert batch.sends == []
    assert all(row.send_state == dm.SendState.EXPIRED for row in batch.assignments)
    shared = [(model, kwargs) for model, _, kwargs in batch.calls if kwargs.get("with_for_update")]
    assert all(model is Recipient for model, _ in shared)
    assert all(kwargs == {"with_for_update": {"read": True}, "populate_existing": True} for _, kwargs in shared)


def test_final_recipient_shared_lock_precedes_campaign_shared_lock_for_each_send(batch):
    outcome = batch.run()
    assert outcome.sent == 2
    locks = [model for model, _, kwargs in batch.calls if kwargs.get("with_for_update")]
    assert locks == [Recipient, Campaign, Recipient, Campaign]
