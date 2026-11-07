"""Actual-role delivery/exclusion barriers on a fresh preserved synthetic DB.

The production claim/correlation/send loop and exclusion endpoint execute.
Campaign/provider-policy gates are isolated; the provider records a synthetic
receipt without opening any transport. No normal database or queue is used.
"""

from __future__ import annotations

import hashlib
import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import Response
from kp_authorization import Principal, Role
from kp_database.models import Campaign, Recipient, RecipientAssignment, TrackingToken
from kp_database.session import make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.routes.recipients import ExclusionCreate, add_exclusion
from kp_workers import jobs
from kp_workers.providers.smtp import DeliveryReceipt
from sqlalchemy import select, text
from test_runtime_feature_role_effects import managed_database as _managed_database
from test_runtime_feature_role_effects import subject as _subject

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _subject.__wrapped__(managed_database)


@pytest.fixture
def prepared(subject, monkeypatch):
    campaign_id, assignment_ids, factory, engines, audit = subject
    payload = {"tracking_bearers": {}}
    with factory() as session:
        session.get(Campaign, campaign_id).state = dm.CampaignState.SCHEDULED
        recipient_ids = []
        for index, identity in enumerate(assignment_ids):
            assignment = session.get(RecipientAssignment, identity)
            recipient_ids.append(assignment.recipient_id)
            verifier = uuid4().hex + uuid4().hex
            bearer = ("A" if index == 0 else "B") * 43
            session.add(
                TrackingToken(
                    token_id=uuid4(),
                    token_hash=verifier,
                    token_prefix=uuid4().hex[:6],
                    campaign_id=campaign_id,
                    recipient_assignment_id=identity,
                    status=dm.TokenStatus.ACTIVE,
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                )
            )
            payload["tracking_bearers"][str(identity)] = {
                "bearer": bearer,
                "verifier": verifier,
                "checksum": hashlib.sha256(bearer.encode()).hexdigest(),
            }
        session.commit()
    monkeypatch.setattr(jobs, "_make_batch_sender", lambda _: nullcontext())
    monkeypatch.setattr(jobs, "_launch_delivery_gate_reason", lambda *_: (None, None))
    # Recipient serialization is isolated from the independent live RoE,
    # training and approval gates, which have their own actual-role proofs.
    monkeypatch.setattr(jobs, "_live_delivery_authorization_reason", lambda *_: None)
    monkeypatch.setattr(jobs, "_delivery_safety_state", lambda *_, **__: SimpleNamespace(emergency_stop_engaged=False))
    ctx = SimpleNamespace(settings=SimpleNamespace(), audit_store=SimpleNamespace(record=lambda **_: None))
    plan = SimpleNamespace(
        unrestricted=True,
        allowlist=frozenset(),
        roe_targets=frozenset({"example.test"}),
        sender_address="qualification@example.test",
        template=None,
        pattern=None,
    )
    value = SimpleNamespace(
        campaign_id=campaign_id,
        assignment_ids=assignment_ids,
        recipient_ids=recipient_ids,
        admin_factory=factory,
        operator_factory=make_session_factory(engines["operator"]),
        delivery_factory=make_session_factory(engines["delivery"]),
        admin=engines["operator"],
        audit=audit,
        principal=Principal(str(uuid4()), {Role.ADMINISTRATOR}),
        ctx=ctx,
        plan=plan,
        payload=payload,
    )
    # The real admin engine is needed solely to observe pg_stat_activity waits.
    value.observer = managed_observer = factory.kw["bind"]
    assert managed_observer is not None
    return value


def deliver(prepared, count=1):
    with prepared.delivery_factory() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_worker_delivery"
        assert not session.scalar(text("SELECT rolinherit FROM pg_roles WHERE rolname=session_user"))
        # Retain identity-map entries across the production claim/correlation
        # commits, proving populate_existing defeats a stale pre-claim read.
        assignments = list(
            session.scalars(
                select(RecipientAssignment).where(
                    RecipientAssignment.recipient_assignment_id.in_(prepared.assignment_ids)
                )
            )
        )
        recipients = list(session.scalars(select(Recipient).where(Recipient.recipient_id.in_(prepared.recipient_ids))))
        assert assignments and recipients
        campaign = session.get(Campaign, prepared.campaign_id)
        return jobs._deliver_assignments(
            prepared.ctx,
            session,
            campaign,
            prepared.plan,
            prepared.payload,
            [str(identity) for identity in prepared.assignment_ids[:count]],
            campaign_id=str(prepared.campaign_id),
            test_send=False,
        )


def exclude(prepared, index=0, session=None):
    if session is None:
        with prepared.operator_factory() as owned:
            return exclude(prepared, index=index, session=owned)
    return add_exclusion(
        prepared.recipient_ids[index],
        ExclusionCreate(
            exclusion_type=dm.ExclusionType.CAMPAIGN_SPECIFIC,
            campaign_id=prepared.campaign_id,
            reason="synthetic delivery-boundary qualification",
        ),
        response=Response(),
        session=session,
        audit=prepared.audit,
        principal=prepared.principal,
    )


def receipt():
    identity = uuid4().hex
    return DeliveryReceipt(message_id=f"<{identity}@example.test>", provider_id=f"synthetic-{identity}")


def wait_for_lock(prepared, pid, future):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if future.done():
            pytest.fail("competing recipient operation completed without waiting for the held recipient row")
        with prepared.observer.connect() as connection:
            if connection.scalar(
                text("SELECT wait_event_type='Lock' FROM pg_stat_activity WHERE pid=:pid"), {"pid": pid}
            ):
                return
        time.sleep(0.02)
    pytest.fail("competing recipient operation did not enter the expected bounded PostgreSQL lock wait")


def test_exclusion_owner_blocks_final_delivery_then_commits_before_any_provider_call(prepared, monkeypatch):
    backend = queue.Queue()
    original = jobs._lock_delivery_recipient
    sends = []

    def boundary(session, *args, **kwargs):
        session.execute(text("SET LOCAL statement_timeout='8s'"))
        backend.put(session.scalar(text("SELECT pg_backend_pid()")))
        return original(session, *args, **kwargs)

    monkeypatch.setattr(jobs, "_lock_delivery_recipient", boundary)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: sends.append("sent") or receipt())
    with ThreadPoolExecutor(max_workers=1) as executor, prepared.operator_factory() as operator:
        operator.get(Recipient, prepared.recipient_ids[0], with_for_update=True)
        future = executor.submit(deliver, prepared)
        try:
            wait_for_lock(prepared, backend.get(timeout=3), future)
            assert operator.get(RecipientAssignment, prepared.assignment_ids[0]).send_state == dm.SendState.SENDING
            assert exclude(prepared, session=operator)["created"]
        finally:
            operator.rollback()
        outcome = future.result(timeout=8)
    assert sends == [] and outcome.sent == 0 and outcome.blocked == 1
    with prepared.admin_factory() as session:
        row = session.get(RecipientAssignment, prepared.assignment_ids[0])
        assert row.send_state == dm.SendState.EXPIRED and row.failure_reason == "recipient_excluded"
        assert row.delivery_attempt_id is not None


def test_delivery_owner_prevents_exclusion_confirmation_until_provider_result_commits(prepared, monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    backend = queue.Queue()

    def provider(*_, **__):
        entered.set()
        assert release.wait(5), "test controller did not release bounded synthetic provider"
        return receipt()

    def operator():
        with prepared.operator_factory() as session:
            session.execute(text("SET LOCAL statement_timeout='8s'"))
            backend.put(session.scalar(text("SELECT pg_backend_pid()")))
            return exclude(prepared, session=session)

    monkeypatch.setattr(jobs, "_send_email", provider)
    with ThreadPoolExecutor(max_workers=2) as executor:
        delivery = executor.submit(deliver, prepared)
        try:
            assert entered.wait(3), "worker did not reach the synthetic provider"
            exclusion = executor.submit(operator)
            wait_for_lock(prepared, backend.get(timeout=3), exclusion)
        finally:
            release.set()
        assert delivery.result(timeout=8).sent == 1
        assert exclusion.result(timeout=8)["created"]
    with prepared.admin_factory() as session:
        assert session.get(RecipientAssignment, prepared.assignment_ids[0]).send_state == dm.SendState.ACCEPTED


def test_exclusion_committed_between_claim_and_final_lock_is_rechecked(prepared, monkeypatch):
    original = jobs._durable_delivery_correlation
    sends = []

    def gap(session, assignment, **kwargs):
        result = original(session, assignment, **kwargs)
        assert exclude(prepared)["created"]
        return result

    monkeypatch.setattr(jobs, "_durable_delivery_correlation", gap)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: sends.append("sent") or receipt())
    outcome = deliver(prepared)
    assert sends == [] and outcome.blocked == 1
    with prepared.admin_factory() as session:
        row = session.get(RecipientAssignment, prepared.assignment_ids[0])
        assert row.send_state == dm.SendState.EXPIRED and row.failure_reason == "recipient_excluded"


def test_exclusion_committed_during_earlier_send_blocks_later_preclaim_with_cached_assignments(prepared, monkeypatch):
    sends = []
    claims = []
    original = jobs._claim_delivery

    def claim(session, assignment, *args, **kwargs):
        claims.append(assignment.recipient_assignment_id)
        return original(session, assignment, *args, **kwargs)

    def provider(*_, **__):
        sends.append("sent")
        assert exclude(prepared, index=1)["created"]
        return receipt()

    monkeypatch.setattr(jobs, "_claim_delivery", claim)
    monkeypatch.setattr(jobs, "_send_email", provider)
    outcome = deliver(prepared, count=2)
    assert len(sends) == len(claims) == outcome.sent == outcome.blocked == 1
    with prepared.admin_factory() as session:
        row = session.get(RecipientAssignment, prepared.assignment_ids[1])
        assert row.send_state == dm.SendState.EXPIRED and row.delivery_attempt_id is None


@pytest.mark.parametrize("change", ["departed", "deleted"])
def test_recipient_status_or_deletion_committed_in_claim_gap_refreshes_before_provider(prepared, monkeypatch, change):
    original = jobs._durable_delivery_correlation
    sends = []

    def gap(session, assignment, **kwargs):
        result = original(session, assignment, **kwargs)
        with prepared.operator_factory() as operator:
            row = operator.get(Recipient, prepared.recipient_ids[0], with_for_update=True)
            if change == "departed":
                row.status = dm.RecipientStatus.DEPARTED
            else:
                row.deleted_at = datetime.now(UTC)
            operator.commit()
        return result

    monkeypatch.setattr(jobs, "_durable_delivery_correlation", gap)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: sends.append("sent") or receipt())
    outcome = deliver(prepared)
    assert sends == [] and outcome.blocked == 1
    with prepared.admin_factory() as session:
        row = session.get(RecipientAssignment, prepared.assignment_ids[0])
        assert row.send_state == dm.SendState.EXPIRED and row.failure_reason == "recipient_unavailable"
