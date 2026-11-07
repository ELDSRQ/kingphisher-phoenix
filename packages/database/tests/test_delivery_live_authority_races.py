"""Mutable authority ordering with real roles and cached SQLAlchemy entities.

Fresh preserved task databases only. Real claim/correlation/send loop and
revoke/supersede endpoints execute; provider transport is a bounded receipt stub.
The independent launch-manifest gate is isolated to focus these authority locks.
"""

from __future__ import annotations

import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_database.models import (
    Campaign,
    CampaignApproval,
    RecipientAssignment,
    RulesOfEngagement,
    TemplateVersion,
    TrainingResource,
)
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_domain_models.roe import roe_signature_hex
from kp_operator_api.sending_domains_roe import RoeRevoke, revoke_roe
from kp_operator_api.training_library import TrainingResourceDecision, decide_training_resource
from kp_workers import jobs
from sqlalchemy import select, text
from test_delivery_recipient_races import managed_database as _managed_database
from test_delivery_recipient_races import prepared as _recipient_prepared
from test_delivery_recipient_races import receipt, wait_for_lock
from test_delivery_recipient_races import subject as _recipient_subject

pytestmark = pytest.mark.postgres
SIGNING_KEY = b"w" * 32
REAL_AUTHORITY = jobs._live_delivery_authorization_reason


@pytest.fixture(scope="module")
def managed_database():
    yield from _managed_database.__wrapped__()


@pytest.fixture
def subject(managed_database):
    yield from _recipient_subject.__wrapped__(managed_database)


@pytest.fixture
def prepared(subject, monkeypatch):
    return _recipient_prepared.__wrapped__(subject, monkeypatch)


@pytest.fixture
def authority(prepared, monkeypatch):
    now = datetime.now(UTC)
    with prepared.admin_factory() as session:
        campaign = session.get(Campaign, prepared.campaign_id)
        roe = session.get(RulesOfEngagement, campaign.roe_id)
        roe.target_domains = ["example.test"]
        roe.signed_at = now
        roe.window_start = now - timedelta(days=1)
        roe.window_end = now + timedelta(days=1)
        roe.signature = roe_signature_hex(
            roe.terms_hash,
            roe.signer,
            roe.signed_at,
            authorizing_party=roe.authorizing_party,
            target_domains=roe.target_domains,
            window_start=roe.window_start,
            window_end=roe.window_end,
            signing_key=SIGNING_KEY,
        )
        prepared.payload["template_hash"] = campaign.manifest_hash
        prepared.payload["launch_manifest_hash"] = "f" * 64
        prepared.roe_id, prepared.training_id = campaign.roe_id, campaign.training_resource_id
        approval = session.scalar(select(CampaignApproval).where(CampaignApproval.campaign_id == campaign.campaign_id))
        approval.launch_manifest_hash = prepared.payload["launch_manifest_hash"]
        session.add(
            CampaignApproval(
                campaign_approval_id=uuid4(),
                campaign_id=campaign.campaign_id,
                approval_type=dm.ApprovalType.PRIVACY,
                approver_id=uuid4(),
                decision=dm.ApprovalDecision.APPROVED,
                launch_manifest_hash=prepared.payload["launch_manifest_hash"],
                template_version_id=campaign.current_template_id,
                decided_at=now,
            )
        )
        session.commit()
    prepared.ctx.settings = SimpleNamespace(
        approval_policy=ApprovalPolicy.ENFORCE, require_roe_signing_key=lambda: SIGNING_KEY
    )
    monkeypatch.setattr(jobs, "_live_delivery_authorization_reason", REAL_AUTHORITY)
    monkeypatch.setattr(jobs, "check_spf_for_mailbox", lambda *_: pytest.fail("per-recipient DNS is forbidden"))
    return prepared


def deliver(authority):
    with authority.delivery_factory() as session:
        assert session.scalar(text("SELECT session_user")) == "kp_worker_delivery"
        campaign = session.get(Campaign, authority.campaign_id)
        # Keep strong references across expire_on_commit=False claim commits.
        cached = [
            session.get(RulesOfEngagement, campaign.roe_id),
            session.get(TrainingResource, campaign.training_resource_id),
            session.get(TemplateVersion, campaign.current_template_id),
        ]
        approvals = list(
            session.scalars(select(CampaignApproval).where(CampaignApproval.campaign_id == campaign.campaign_id))
        )
        assert all(cached) and len(approvals) == 2
        authority.plan.template = cached[2]
        return jobs._deliver_assignments(
            authority.ctx,
            session,
            campaign,
            authority.plan,
            authority.payload,
            [str(authority.assignment_ids[0])],
            campaign_id=str(authority.campaign_id),
            test_send=False,
        )


def mutate(authority, kind, session=None):
    if session is None:
        with authority.operator_factory() as owned:
            return mutate(authority, kind, session=owned)
    if kind == "roe":
        return revoke_roe(
            authority.roe_id,
            RoeRevoke(reason="synthetic immediate revocation"),
            session=session,
            audit=authority.audit,
            principal=authority.principal,
        )
    if kind == "training":
        return decide_training_resource(
            authority.training_id,
            TrainingResourceDecision(decision="superseded", rationale="synthetic lesson replacement"),
            session=session,
            audit=authority.audit,
            principal=authority.principal,
        )
    # Approval changes share the campaign boundary, matching the real route.
    session.get(Campaign, authority.campaign_id, with_for_update=True)
    approval = session.scalar(
        select(CampaignApproval).where(
            CampaignApproval.campaign_id == authority.campaign_id,
            CampaignApproval.approval_type == dm.ApprovalType.PRIVACY,
        )
    )
    approval.decision = dm.ApprovalDecision.REJECTED
    session.commit()


def test_current_signed_authority_accepts_with_select_only_approvals_and_no_dns(authority, monkeypatch):
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: receipt())
    assert deliver(authority).sent == 1


@pytest.mark.parametrize(
    "kind,reason",
    [("roe", "roe_not_active"), ("training", "training_manifest_drift"), ("approval", "missing_approvals")],
)
def test_change_committed_after_claim_refreshes_cached_authority_before_provider(authority, monkeypatch, kind, reason):
    original = jobs._durable_delivery_correlation
    sends = []

    def gap(session, assignment, **kwargs):
        result = original(session, assignment, **kwargs)
        mutate(authority, kind)
        return result

    monkeypatch.setattr(jobs, "_durable_delivery_correlation", gap)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: sends.append("sent") or receipt())
    outcome = deliver(authority)
    assert sends == [] and outcome.blocked == 1
    with authority.admin_factory() as session:
        row = session.get(RecipientAssignment, authority.assignment_ids[0])
        assert row.send_state == dm.SendState.EXPIRED and row.failure_reason == reason


@pytest.mark.parametrize(
    "kind,model,reason",
    [("roe", RulesOfEngagement, "roe_not_active"), ("training", TrainingResource, "training_manifest_drift")],
)
def test_authority_change_owner_orders_before_delivery_and_prevents_provider(
    authority, monkeypatch, kind, model, reason
):
    original = jobs._live_delivery_authorization_reason
    backend = queue.Queue()
    sends = []

    def final(session, *args, **kwargs):
        session.execute(text("SET LOCAL statement_timeout='8s'"))
        backend.put(session.scalar(text("SELECT pg_backend_pid()")))
        return original(session, *args, **kwargs)

    monkeypatch.setattr(jobs, "_live_delivery_authorization_reason", final)
    monkeypatch.setattr(jobs, "_send_email", lambda *_, **__: sends.append("sent") or receipt())
    with ThreadPoolExecutor(max_workers=1) as executor, authority.operator_factory() as operator:
        identity = authority.roe_id if kind == "roe" else authority.training_id
        operator.get(model, identity, with_for_update=True)
        future = executor.submit(deliver, authority)
        try:
            wait_for_lock(authority, backend.get(timeout=3), future)
            mutate(authority, kind, session=operator)
        finally:
            operator.rollback()
        outcome = future.result(timeout=8)
    assert sends == [] and outcome.blocked == 1
    with authority.admin_factory() as session:
        assert session.get(RecipientAssignment, authority.assignment_ids[0]).failure_reason == reason


@pytest.mark.parametrize("kind", ["roe", "training"])
def test_delivery_authority_locks_hold_through_provider_result_before_change_confirmation(authority, monkeypatch, kind):
    entered, release = threading.Event(), threading.Event()
    backend = queue.Queue()

    def provider(*_, **__):
        entered.set()
        assert release.wait(5), "test controller did not release bounded synthetic provider"
        return receipt()

    def operator():
        with authority.operator_factory() as session:
            session.execute(text("SET LOCAL statement_timeout='8s'"))
            backend.put(session.scalar(text("SELECT pg_backend_pid()")))
            return mutate(authority, kind, session=session)

    monkeypatch.setattr(jobs, "_send_email", provider)
    with ThreadPoolExecutor(max_workers=2) as executor:
        delivery = executor.submit(deliver, authority)
        try:
            assert entered.wait(3), "worker did not reach synthetic provider"
            change = executor.submit(operator)
            wait_for_lock(authority, backend.get(timeout=3), change)
        finally:
            release.set()
        assert delivery.result(timeout=8).sent == 1
        change.result(timeout=8)
    with authority.admin_factory() as session:
        assert session.get(RecipientAssignment, authority.assignment_ids[0]).send_state == dm.SendState.ACCEPTED
