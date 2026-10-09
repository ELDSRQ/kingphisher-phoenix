"""Whole-roster publication keeps scope and configuration checks without a canary."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from kp_database.models import CampaignAudience, CampaignLaunchGate
from kp_workers import jobs
from kp_workers.config import WorkerSettings


def _case(monkeypatch):  # type: ignore[no-untyped-def]
    campaign = SimpleNamespace(
        campaign_id=uuid4(), current_template_id=uuid4(), training_resource_id=None, delivery_mode="reviewed_direct"
    )
    gate = SimpleNamespace(
        state="direct_published",
        full_published_at=datetime.now(UTC),
        review_manifest_hash="a" * 64,
        canary_evidence_hash=None,
        canary_succeeded_at=None,
        provider=None,
        provider_config_hash=None,
    )
    assignment_id = uuid4()
    settings = WorkerSettings(_env_file=None, email_provider="smtp", smtp_address="localhost:1025")
    monkeypatch.setattr(jobs, "campaign_launch_gate_error", lambda *_a: None)
    monkeypatch.setattr(jobs, "training_binding_error", lambda *_a: None)

    class Session:
        rows = [SimpleNamespace(recipient_assignment_id=assignment_id)]

        def get(self, model, identifier, **kwargs):  # type: ignore[no-untyped-def]
            if model is CampaignLaunchGate:
                return gate
            if model is CampaignAudience:
                return SimpleNamespace(version=7)
            return SimpleNamespace()

        def scalars(self, statement):  # type: ignore[no-untyped-def]
            # Scope must be checked in the database, against the reviewed version
            # and the campaign of each assignment. No client recipient subset.
            sql = str(statement)
            params = statement.compile().params
            assert "campaign_audience_manifest" in sql
            assert campaign.campaign_id in params.values()
            assert 7 in params.values()
            return self.rows

    session = Session()
    payload = {"delivery_phase": "reviewed_direct", "launch_manifest_hash": gate.review_manifest_hash}
    return session, campaign, gate, payload, [str(assignment_id)], settings


def test_direct_send_binds_provider_and_validates_ordinary_assignments_without_canary(monkeypatch):  # type: ignore[no-untyped-def]
    session, campaign, gate, payload, ids, settings = _case(monkeypatch)
    assert jobs._launch_delivery_gate_reason(session, campaign, payload, ids, settings) == (gate, None)
    assert (gate.provider, gate.provider_config_hash) == jobs._delivery_provider_binding(settings)
    assert gate.canary_evidence_hash is None
    assert gate.canary_succeeded_at is None


@pytest.mark.parametrize(
    "change,reason",
    [
        ("phase", "delivery_mode_mismatch"),
        ("hash", "launch_manifest_mismatch"),
        ("state", "direct_campaign_not_published"),
        ("evidence", "direct_campaign_has_canary_evidence"),
        ("provider", "provider_configuration_drift"),
        ("assignment", "assignment_binding_invalid"),
    ],
)
def test_direct_send_refuses_unreviewed_or_mismatched_delivery(monkeypatch, change, reason):  # type: ignore[no-untyped-def]
    session, campaign, gate, payload, ids, settings = _case(monkeypatch)
    if change == "phase":
        payload["delivery_phase"] = "full"
    elif change == "hash":
        payload["launch_manifest_hash"] = "b" * 64
    elif change == "state":
        gate.state = "reviewed"
    elif change == "evidence":
        gate.canary_evidence_hash = "c" * 64
    elif change == "provider":
        gate.provider, gate.provider_config_hash = "smtp", "d" * 64
    elif change == "assignment":
        session.rows = []
    assert jobs._launch_delivery_gate_reason(session, campaign, payload, ids, settings)[1] == reason


def test_direct_send_refuses_duplicate_assignment_ids(monkeypatch):  # type: ignore[no-untyped-def]
    session, campaign, _gate, payload, ids, settings = _case(monkeypatch)
    assert (
        jobs._launch_delivery_gate_reason(session, campaign, payload, ids + ids, settings)[1]
        == "assignment_binding_invalid"
    )
