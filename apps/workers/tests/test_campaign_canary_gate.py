from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from kp_database.models import Campaign, RecipientAssignment
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, _delivery_provider_binding, _refresh_canary_evidence

JOBS = (Path(__file__).resolve().parents[1] / "src" / "kp_workers" / "jobs.py").read_text(encoding="utf-8")


def _settings(**overrides: object) -> WorkerSettings:
    values: dict[str, object] = {
        "_env_file": None,
        "email_provider": "smtp",
        "smtp_address": "smtp.example.com:587",
        "smtp_username": "canary-user",
        "smtp_password": "secret-a",
        "smtp_starttls": True,
        "smtp_sender": "awareness@example.com",
        "sending_domains": "example.com",
        "allowed_recipient_domains": "example.com",
        "tracking_base_url": "https://track.example.com",
        "training_base_url": "https://train.example.com/lesson",
    }
    values.update(overrides)
    return WorkerSettings(**values)  # type: ignore[arg-type]


def test_provider_binding_is_stable_secret_free_and_detects_material_drift() -> None:
    provider, first = _delivery_provider_binding(_settings())
    assert provider == "smtp"
    assert len(first) == 64
    assert "secret-a" not in first
    assert _delivery_provider_binding(_settings())[1] == first
    assert _delivery_provider_binding(_settings(smtp_password="secret-b"))[1] != first
    assert _delivery_provider_binding(_settings(smtp_address="smtp2.example.com:587"))[1] != first
    assert _delivery_provider_binding(_settings(allowed_recipient_domains="other.example"))[1] != first


def test_worker_rechecks_gate_before_initial_and_per_assignment_provider_boundaries() -> None:
    process = JOBS[JOBS.index("def process_delivery(") : JOBS.index("def process_retention(")]
    assert process.count("_launch_delivery_gate_reason(") >= 2
    assert process.index("_launch_delivery_gate_reason(") < process.index("_make_batch_sender(ctx)")
    boundary = process[process.index("attempt_id = _claim_delivery(") : process.index("receipt = _send_email(")]
    assert "_launch_delivery_gate_reason(" in boundary
    assert "_delivery_safety_state(session, shared_lock=True)" in boundary


def test_worker_requires_phase_manifest_provider_and_evidence_bindings() -> None:
    gate = JOBS[JOBS.index("def _launch_delivery_gate_reason(") : JOBS.index("def _refresh_canary_evidence(")]
    for required in (
        'phase not in {"canary", "full"}',
        'payload.get("launch_manifest_hash") != gate.review_manifest_hash',
        'payload.get("canary_evidence_hash") != gate.canary_evidence_hash',
        'payload.get("provider_config_hash") != gate.provider_config_hash',
        'return gate, "provider_configuration_drift"',
        'return gate, "canary_manifest_drift"',
        'return gate, "training_manifest_drift"',
    ):
        assert required in gate


def test_canary_success_is_derived_from_provider_rows_not_operator_input() -> None:
    refresh = JOBS[JOBS.index("def _refresh_canary_evidence(") : JOBS.index("def _delivery_tracking_bearer(")]
    assert "dm.SendState.DELIVERED" in refresh
    assert "delivery_confirmed_at is not None" in refresh
    assert "provider_accepted_at is not None" in refresh
    assert 'gate.state = "canary_succeeded"' in refresh
    assert 'action="campaign.canary.succeeded"' in refresh
    # Guard against accidental serialization of provider credentials into
    # evidence or logs; only the digest may leave the binding helper.
    assert json.dumps("smtp_password") not in refresh


class _EvidenceSession:
    def __init__(self, gate: object, recipient_ids: list[object], assignments: list[RecipientAssignment]) -> None:
        self.gate = gate
        self.results = [recipient_ids, assignments]

    def get(self, model: object, identifier: object, **kwargs: object) -> object:
        return self.gate

    def scalars(self, statement: object) -> list[object]:
        return self.results.pop(0)


class _EvidenceAudit:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def record(self, **kwargs: object) -> None:
        self.records.append(kwargs)


def _campaign_and_evidence(state: dm.SendState) -> tuple[Campaign, object, RecipientAssignment]:
    now = datetime.now(UTC)
    campaign_id = uuid4()
    recipient_id = uuid4()
    campaign = Campaign(
        campaign_id=campaign_id,
        pattern_id=uuid4(),
        title="Canary evidence",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="awareness@example.com",
        training_domain="training.example.com",
        max_recipients=2,
        expires_at=now + timedelta(days=1),
    )
    provider, config_hash = _delivery_provider_binding(_settings())
    gate = SimpleNamespace(
        state="canary_queued",
        canary_expires_at=now + timedelta(hours=1),
        provider=provider,
        provider_config_hash=config_hash,
        review_manifest_hash="a" * 64,
        canary_evidence_hash=None,
        canary_succeeded_at=None,
        updated_at=now,
    )
    assignment = RecipientAssignment(
        recipient_assignment_id=uuid4(),
        campaign_id=campaign_id,
        recipient_id=recipient_id,
        send_state=state,
        provider_accepted_at=now if state in {dm.SendState.ACCEPTED, dm.SendState.DELIVERED} else None,
        provider_message_id="provider-evidence" if state in {dm.SendState.ACCEPTED, dm.SendState.DELIVERED} else None,
        idempotency_key=f"{campaign_id}:{recipient_id}:1",
    )
    return campaign, gate, assignment


def test_refresh_promotes_only_complete_provider_evidence() -> None:
    campaign, gate, assignment = _campaign_and_evidence(dm.SendState.ACCEPTED)
    session = _EvidenceSession(gate, [assignment.recipient_id], [assignment])
    audit = _EvidenceAudit()
    ctx = WorkerContext(_settings(), lambda: session, audit, SimpleNamespace())  # type: ignore[arg-type]

    _refresh_canary_evidence(session, ctx, campaign)  # type: ignore[arg-type]

    assert gate.state == "canary_succeeded"
    assert gate.canary_succeeded_at is not None
    assert isinstance(gate.canary_evidence_hash, str) and len(gate.canary_evidence_hash) == 64
    assert audit.records[0]["action"] == "campaign.canary.succeeded"


def test_refresh_turns_definite_canary_failure_into_a_permanent_gate() -> None:
    campaign, gate, assignment = _campaign_and_evidence(dm.SendState.FAILED)
    session = _EvidenceSession(gate, [assignment.recipient_id], [assignment])
    audit = _EvidenceAudit()
    ctx = WorkerContext(_settings(), lambda: session, audit, SimpleNamespace())  # type: ignore[arg-type]

    _refresh_canary_evidence(session, ctx, campaign)  # type: ignore[arg-type]

    assert gate.state == "canary_failed"
    assert gate.canary_evidence_hash is None
    assert audit.records[0]["action"] == "campaign.canary.failed"
