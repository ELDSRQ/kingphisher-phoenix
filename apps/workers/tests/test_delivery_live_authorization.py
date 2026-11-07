"""Mutable authorization refresh at the final provider boundary."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_database.campaign_service import bind_campaign_training_resource
from kp_database.models import (
    CampaignApproval,
    CampaignAudience,
    CampaignLaunchGate,
    RulesOfEngagement,
    TemplateVersion,
    TrainingResource,
)
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_workers import jobs
from kp_workers.config import WorkerSettings
from test_delivery_recipient_fence import batch as _recipient_batch
from test_delivery_roe import _KEY_HEX, _make_campaign, _make_recipient, _make_roe, _make_template

REAL_AUTHORITY = jobs._live_delivery_authorization_reason


@pytest.fixture
def recipient_batch(monkeypatch):
    return _recipient_batch.__wrapped__(monkeypatch)


@pytest.fixture
def authority():
    roe = _make_roe(target_domains=["example.test"])
    campaign = _make_campaign(roe)
    template = _make_template()
    campaign.current_template_id = template.template_version_id
    training = TrainingResource(
        training_resource_id=uuid4(),
        title="Reviewed lesson",
        kind="article",
        content="Verify independently",
        version=1,
        approval_state=dm.TemplateApprovalState.APPROVED,
        requires_completion=True,
    )
    bind_campaign_training_resource(campaign, training)
    recipient = _make_recipient("synthetic@example.test")
    settings = WorkerSettings(
        _env_file=None,
        runtime_mode="development",
        dev_stack=True,
        approval_policy="single-admin",
        roe_signing_key=_KEY_HEX,
    )
    payload = {
        "template_hash": campaign.manifest_hash,
        "launch_manifest_hash": "reviewed-launch",
        "delivery_phase": "reviewed_direct",
    }
    cached = {
        TemplateVersion: template,
        TrainingResource: training,
        RulesOfEngagement: roe,
        CampaignAudience: SimpleNamespace(version=1),
        CampaignLaunchGate: SimpleNamespace(),
    }
    fresh = copy.deepcopy(cached)

    class Session:
        def __init__(self):
            self.calls = []
            self.approvals = []

        def get(self, model, identifier, **kwargs):
            self.calls.append((model, kwargs))
            return (fresh if kwargs.get("populate_existing") else cached).get(model)

        def scalars(self, statement):
            assert statement.get_execution_options().get("populate_existing") is True
            params = statement.compile().params
            assert campaign.campaign_id in params.values() and "reviewed-launch" in params.values()
            return SimpleNamespace(all=lambda: self.approvals)

    session = Session()
    return SimpleNamespace(
        session=session,
        campaign=campaign,
        recipient=recipient,
        settings=settings,
        payload=payload,
        fresh=fresh,
        cached=cached,
        check=lambda: jobs._live_delivery_authorization_reason(session, campaign, recipient, payload, settings),
    )


def test_valid_authority_refreshes_without_dns_and_holds_training_and_roe_shared(authority, monkeypatch):
    monkeypatch.setattr(jobs, "check_spf_for_mailbox", lambda *_: pytest.fail("DNS must not repeat per recipient"))
    assert authority.check() is None
    assert authority.session.calls == [
        (TemplateVersion, {"populate_existing": True}),
        (TrainingResource, {"with_for_update": {"read": True}, "populate_existing": True}),
        (RulesOfEngagement, {"with_for_update": {"read": True}, "populate_existing": True}),
    ]


@pytest.mark.parametrize(
    "change", ["revoked", "expired", "tampered_signature", "superseded_training", "unapproved_template"]
)
def test_stale_cached_approval_and_roe_cannot_authorize_changed_rows(authority, change):
    if change == "revoked":
        authority.fresh[RulesOfEngagement].revoked_at = authority.fresh[RulesOfEngagement].signed_at
        expected = "roe_not_active"
    elif change == "expired":
        authority.fresh[RulesOfEngagement] = _make_roe(
            target_domains=["example.test"], window_days_ago=3, window_days_ahead=-1
        )
        expected = "roe_not_active"
    elif change == "tampered_signature":
        authority.fresh[RulesOfEngagement].signature = "0" * 64
        expected = "roe_signature_invalid"
    elif change == "superseded_training":
        authority.fresh[TrainingResource].approval_state = dm.TemplateApprovalState.SUPERSEDED
        expected = "training_manifest_drift"
    else:
        authority.fresh[TemplateVersion].approval_state = dm.TemplateApprovalState.REJECTED
        expected = "template_not_approved"
    assert authority.cached[TrainingResource].approval_state == dm.TemplateApprovalState.APPROVED
    assert authority.cached[RulesOfEngagement].revoked_at is None
    assert authority.check() == expected


def test_live_approvals_are_refreshed_against_exact_launch_manifest_and_policy(authority):
    authority.settings.approval_policy = ApprovalPolicy.ENFORCE
    author = uuid4()
    authority.session.approvals = [
        CampaignApproval(approval_type=kind, approver_id=author)
        for kind in (dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY)
    ]
    assert authority.check() == "insufficient_distinct_approvers"
    authority.session.approvals[1].approver_id = uuid4()
    assert authority.check() is None
    authority.session.approvals = []
    assert authority.check() == "missing_approvals"


def test_launch_gate_uses_fresh_audience_template_and_training(authority, monkeypatch):
    authority.fresh[CampaignAudience].version = 2
    authority.fresh[TrainingResource].approval_state = dm.TemplateApprovalState.SUPERSEDED
    observed = []
    monkeypatch.setattr(
        jobs, "campaign_launch_gate_error", lambda _c, a, t, _g: observed.append((a.version, t)) or None
    )
    _, reason = jobs._launch_delivery_gate_reason(
        authority.session, authority.campaign, authority.payload, [], authority.settings
    )
    assert observed[0][0] == 2
    assert observed[0][1] is authority.fresh[TemplateVersion]
    assert reason == "training_manifest_drift"


def test_signed_target_domain_is_rechecked_from_refreshed_roe(authority):
    authority.fresh[RulesOfEngagement] = _make_roe(target_domains=["other.test"])
    assert authority.check() == "target_domain_not_roe_covered"


@pytest.mark.parametrize("waiting_gate", ["launch", "safety"])
def test_roe_clock_is_checked_after_blocking_gates_immediately_before_provider(
    authority, recipient_batch, monkeypatch, waiting_gate
):
    batch = recipient_batch
    real = REAL_AUTHORITY
    end = authority.fresh[RulesOfEngagement].window_end
    clock = [end - timedelta(seconds=1)]

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return clock[0].astimezone(tz or UTC)

    monkeypatch.setattr(jobs, "datetime", Clock)
    monkeypatch.setattr(
        jobs,
        "_live_delivery_authorization_reason",
        lambda *_: real(
            authority.session, authority.campaign, authority.recipient, authority.payload, authority.settings
        ),
    )

    def release_launch(*_):
        if waiting_gate == "launch":
            clock[0] = end + timedelta(seconds=1)
        return None, None

    def release_safety(*_, **__):
        if waiting_gate == "safety":
            clock[0] = end + timedelta(seconds=1)
        return SimpleNamespace(emergency_stop_engaged=False)

    monkeypatch.setattr(jobs, "_launch_delivery_gate_reason", release_launch)
    monkeypatch.setattr(jobs, "_delivery_safety_state", release_safety)
    outcome = batch.run()
    assert batch.sends == [] and outcome.blocked == 1 and outcome.stop_observed
    assert batch.assignments[0].failure_reason == "roe_not_active"
