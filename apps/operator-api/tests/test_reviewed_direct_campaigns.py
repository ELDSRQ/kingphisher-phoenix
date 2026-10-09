"""Exact review and one whole-roster send remain transaction and policy bound."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_authorization import Principal, Role
from kp_database.models import Campaign, CampaignAudience, CampaignLaunchGate, TemplateVersion
from kp_domain_models import models as dm
from kp_domain_models.policy import ApprovalPolicy
from kp_operator_api.routes import campaigns as routes
from kp_telemetry.errors import ConflictError


def _case(monkeypatch):  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid4(),
        delivery_mode="reviewed_direct",
        pattern_id=uuid4(),
        title="Whole roster",
        state=dm.CampaignState.APPROVED,
        current_template_id=uuid4(),
        sender_mailbox="awareness@example.com",
        training_domain="training.example.com",
        schedule_start=now - timedelta(minutes=1),
        schedule_end=now + timedelta(hours=1),
        max_recipients=2,
        expires_at=now + timedelta(hours=1),
    )
    gate = SimpleNamespace(
        state="reviewed",
        review_manifest_hash="a" * 64,
        roe_id=uuid4(),
        canary_evidence_hash=None,
        canary_succeeded_at=None,
    )
    calls = []

    class Session:
        commits = 0

        def scalar(self, statement):  # type: ignore[no-untyped-def]
            assert "FOR UPDATE" in str(statement)
            return campaign

        def get(self, model, identifier, **kwargs):  # type: ignore[no-untyped-def]
            if model is CampaignLaunchGate:
                return gate
            if model in {CampaignAudience, TemplateVersion}:
                return SimpleNamespace()
            raise AssertionError(model)

        def commit(self):  # type: ignore[no-untyped-def]
            self.commits += 1

    class Audit:
        def record(self, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(("audit", kwargs))

    settings = SimpleNamespace(
        approval_policy=ApprovalPolicy.SINGLE_OPERATOR,
        tracking_base_url="https://track.example.com",
        require_tracking_token_hmac_key=lambda: b"a" * 32,
    )
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    monkeypatch.setattr(routes, "require_program_active_for_schedule", lambda *_a: None)
    monkeypatch.setattr(routes, "_system_safety_state", lambda *_a, **_k: SimpleNamespace(emergency_stop_engaged=False))
    monkeypatch.setattr(routes, "require_bound_training_resource", lambda *_a: SimpleNamespace())
    monkeypatch.setattr(routes, "_require_current_frozen_audience", lambda *_a: None)
    monkeypatch.setattr(routes, "campaign_launch_gate_error", lambda *_a: None)
    monkeypatch.setattr(routes, "_roe_signing_key", lambda *_a: b"s" * 32)
    monkeypatch.setattr(routes, "_covering_roes", lambda *_a, **_k: [SimpleNamespace(roe_id=gate.roe_id)])
    monkeypatch.setattr(routes, "_queue_campaign_alert", lambda *_a: None)

    def prepare(*args, **kwargs):  # type: ignore[no-untyped-def]
        assert "recipient_scope" not in kwargs and "omit_recipient_ids" not in kwargs
        calls.append(("prepare", kwargs))
        return [
            SimpleNamespace(
                assignment_id=str(uuid4()), bearer_token="synthetic", token_verifier="v", bearer_checksum="c"
            )
            for _ in range(2)
        ]

    def queue(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(("queue", kwargs))
        return 1

    monkeypatch.setattr(routes, "prepare_campaign", prepare)
    monkeypatch.setattr(routes, "_publish_delivery_batches", queue)
    return campaign, gate, Session(), Audit(), request, Principal(str(uuid4()), frozenset({Role.ADMINISTRATOR})), calls


def test_send_queues_whole_roster_once_and_does_not_assert_canary_success(monkeypatch):  # type: ignore[no-untyped-def]
    campaign, gate, session, audit, request, principal, calls = _case(monkeypatch)
    result = routes.send_reviewed_campaign(campaign.campaign_id, request, session, audit, principal)
    assert result["queued"] == 2
    assert campaign.state is dm.CampaignState.SCHEDULED
    assert gate.state == "direct_published" and gate.full_published_at is not None
    assert gate.canary_evidence_hash is None and gate.canary_succeeded_at is None
    queue = next(kwargs for action, kwargs in calls if action == "queue")
    assert queue["delivery_phase"] == "reviewed_direct" and queue["test_send"] is False
    assert session.commits == 1
    with pytest.raises(ConflictError):
        routes.send_reviewed_campaign(campaign.campaign_id, request, session, audit, principal)
    assert len([action for action, _ in calls if action == "queue"]) == 1


@pytest.mark.parametrize("blocker", ["roe", "emergency_stop", "review", "approval", "expired", "legacy"])
def test_send_never_prepares_or_queues_when_a_current_gate_fails(monkeypatch, blocker):  # type: ignore[no-untyped-def]
    campaign, _gate, session, audit, request, principal, calls = _case(monkeypatch)
    if blocker == "roe":
        monkeypatch.setattr(routes, "_covering_roes", lambda *_a, **_k: [])
    elif blocker == "emergency_stop":
        monkeypatch.setattr(
            routes, "_system_safety_state", lambda *_a, **_k: SimpleNamespace(emergency_stop_engaged=True)
        )
    elif blocker == "review":
        monkeypatch.setattr(routes, "campaign_launch_gate_error", lambda *_a: "review changed")
    elif blocker == "approval":
        request.app.state.settings.approval_policy = ApprovalPolicy.ENFORCE
        monkeypatch.setattr(routes, "_missing_campaign_approvals", lambda *_a: {dm.ApprovalType.PRIVACY})
    elif blocker == "expired":
        campaign.schedule_end = datetime.now(UTC) - timedelta(seconds=1)
    elif blocker == "legacy":
        campaign.delivery_mode = "canary"
    with pytest.raises(ConflictError):
        routes.send_reviewed_campaign(campaign.campaign_id, request, session, audit, principal)
    assert not calls and session.commits == 0


def test_changed_recipient_confirmation_never_commits_a_partial_review(monkeypatch):  # type: ignore[no-untyped-def]
    campaign, _gate, session, audit, request, principal, calls = _case(monkeypatch)
    campaign.state = dm.CampaignState.DRAFT
    monkeypatch.setattr(routes, "_audience_preview_for_request", lambda *_a: SimpleNamespace())

    def changed(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise ConflictError("recipient list changed")

    monkeypatch.setattr(routes, "freeze_campaign_audience", changed)
    with pytest.raises(ConflictError, match="recipient list changed"):
        routes.confirm_campaign(
            campaign.campaign_id,
            routes.CampaignAudienceFreeze(preview_hash="b" * 64),
            request,
            session,
            audit,
            principal,
        )
    assert session.commits == 0 and not calls and campaign.state is dm.CampaignState.DRAFT
