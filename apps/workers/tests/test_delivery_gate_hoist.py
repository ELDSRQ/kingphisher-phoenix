"""Why the per-assignment launch-gate re-check stays inside the delivery loop.

ARC-002 Item 2 proposed hoisting ``_launch_delivery_gate_reason`` out of the
per-assignment loop in ``process_delivery`` because it re-reads and re-hashes
the canary manifest once per recipient. These tests pin the two halves of that
question:

* the **assignment-dependent** half is invariant. With the database state held
  still, the batch call and every singleton call agree on exactly which
  recipients are gated, in both the canary and the full phase. Whatever the
  batch call decides about a cohort, each singleton decides about its own
  member.
* the **gate-dependent** half is *not* invariant. ``process_delivery`` commits
  between recipients (the claim and the correlation row each commit), which
  releases the ``FOR UPDATE`` lock the gate is read under. A gate that is
  revoked, fails, or expires mid-batch therefore changes the verdict for later
  recipients — and the loop stops the batch there.

The second property is why the value cannot be hoisted: a value computed once
per run would keep sending to recipients the live gate refuses.

The two campaign-level drift helpers (``campaign_launch_gate_error`` and
``training_binding_error``) are stubbed here. Neither takes an assignment, so
neither can vary with the recipient set; they have their own contract tests.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.campaign_service import campaign_canary_manifest_hash
from kp_database.models import Campaign, CampaignLaunchGate, RecipientAssignment
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import _delivery_provider_binding, _launch_delivery_gate_reason

_NOW = datetime.now(UTC)
_REVIEW_HASH = "r" * 64


def _settings() -> WorkerSettings:
    return WorkerSettings(  # type: ignore[call-arg]
        _env_file=None,
        email_provider="smtp",
        smtp_address="smtp.example.com:587",
        smtp_username="canary-user",
        smtp_password="secret-a",
        smtp_starttls=True,
        smtp_sender="awareness@example.com",
        sending_domains="example.com",
        allowed_recipient_domains="example.com",
        tracking_base_url="https://track.example.com",
        training_base_url="https://train.example.com/lesson",
    )


class _GateSession:
    """The slice of ``Session`` the launch gate touches.

    ``scalars`` reproduces the real ``WHERE recipient_assignment_id IN (...)
    AND campaign_id = ...`` filter: the caller hands in only the rows the
    database would have returned for the requested batch.
    """

    def __init__(
        self,
        gate: object,
        canary_rows: list[tuple[uuid.UUID, str]],
        assignments: list[RecipientAssignment],
    ) -> None:
        self.gate = gate
        self.canary_rows = canary_rows
        self.assignments = assignments

    def get(self, model: object, _identifier: object, **_kwargs: object) -> object:
        return self.gate if model is CampaignLaunchGate else None

    def execute(self, _statement: object) -> list[tuple[uuid.UUID, str]]:
        return list(self.canary_rows)

    def scalars(self, _statement: object) -> list[RecipientAssignment]:
        return list(self.assignments)


def _campaign() -> Campaign:
    return Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.uuid4(),
        current_template_id=uuid.uuid4(),
        title="canary cohort",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="awareness@example.com",
        training_domain="example.com",
        max_recipients=10,
        manifest_hash="m" * 64,
        expires_at=_NOW + timedelta(days=30),
    )


def _assignment(campaign: Campaign, recipient_id: uuid.UUID) -> RecipientAssignment:
    return RecipientAssignment(
        recipient_assignment_id=uuid.uuid4(),
        campaign_id=campaign.campaign_id,
        recipient_id=recipient_id,
        send_state=dm.SendState.QUEUED,
        idempotency_key=f"{campaign.campaign_id}:{recipient_id}:1",
    )


def _gate(canary_rows: list[tuple[uuid.UUID, str]], *, phase: str) -> SimpleNamespace:
    provider, config_hash = _delivery_provider_binding(_settings())
    return SimpleNamespace(
        state="canary_queued" if phase == "canary" else "full_published",
        canary_expires_at=_NOW + timedelta(hours=1),
        provider=provider,
        provider_config_hash=config_hash,
        review_manifest_hash=_REVIEW_HASH,
        canary_manifest_hash=campaign_canary_manifest_hash(canary_rows),
        canary_evidence_hash="e" * 64 if phase == "full" else None,
        updated_at=_NOW,
    )


def _payload(gate: SimpleNamespace, *, phase: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "delivery_phase": phase,
        "launch_manifest_hash": gate.review_manifest_hash,
    }
    if phase == "full":
        payload["canary_evidence_hash"] = gate.canary_evidence_hash
        payload["provider"] = gate.provider
        payload["provider_config_hash"] = gate.provider_config_hash
    return payload


def _stub_campaign_level_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("kp_workers.jobs.campaign_launch_gate_error", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("kp_workers.jobs.training_binding_error", lambda *_args, **_kwargs: None)


def _verdict(
    gate: object,
    campaign: Campaign,
    payload: dict[str, Any],
    canary_rows: list[tuple[uuid.UUID, str]],
    by_id: dict[str, RecipientAssignment],
    ids: list[str],
) -> str | None:
    session = _GateSession(gate, canary_rows, [by_id[item] for item in ids if item in by_id])
    return _launch_delivery_gate_reason(session, campaign, payload, ids, _settings())[1]  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("phase", "expected_reason"),
    [
        ("canary", "canary_recipient_not_reviewed"),
        ("full", "canary_recipient_in_full_publication"),
    ],
)
def test_batch_and_singleton_gate_verdicts_agree_across_recipients(
    monkeypatch: pytest.MonkeyPatch, phase: str, expected_reason: str
) -> None:
    """The gated-recipient set is identical whether judged per batch or per recipient.

    Canary phase: the reviewed cohort passes and an unreviewed recipient is
    gated. Full phase: the mirror image — the reviewed canary recipient is the
    one gated out of the full publication.
    """

    _stub_campaign_level_drift(monkeypatch)
    campaign = _campaign()
    reviewed = [uuid.uuid4(), uuid.uuid4()]
    canary_rows = [(recipient_id, f"{index}" * 64) for index, recipient_id in enumerate(reviewed)]
    outsider = uuid.uuid4()
    gate = _gate(canary_rows, phase=phase)
    payload = _payload(gate, phase=phase)

    cohort = reviewed if phase == "canary" else [outsider, uuid.uuid4()]
    gated_recipient = outsider if phase == "canary" else reviewed[0]
    assignments = [_assignment(campaign, recipient_id) for recipient_id in [*cohort, gated_recipient]]
    by_id = {str(item.recipient_assignment_id): item for item in assignments}
    ungated_ids = [str(item.recipient_assignment_id) for item in assignments[:-1]]
    gated_id = str(assignments[-1].recipient_assignment_id)

    # The batch view: the clean cohort passes, adding the gated recipient fails.
    assert _verdict(gate, campaign, payload, canary_rows, by_id, ungated_ids) is None
    assert _verdict(gate, campaign, payload, canary_rows, by_id, [*ungated_ids, gated_id]) == expected_reason

    # The per-recipient view agrees, member for member: same gated set.
    per_recipient = {
        assignment_id: _verdict(gate, campaign, payload, canary_rows, by_id, [assignment_id])
        for assignment_id in [*ungated_ids, gated_id]
    }
    assert {key for key, value in per_recipient.items() if value is not None} == {gated_id}
    assert per_recipient[gated_id] == expected_reason


def test_gate_revoked_mid_batch_changes_the_verdict_for_later_recipients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The verdict is time- and lock-dependent, so it cannot be computed once.

    ``process_delivery`` commits between recipients, releasing the gate's
    ``FOR UPDATE`` lock. Expiry of the canary window — or any concurrent gate
    mutation — therefore lands between two recipients of the same batch, and
    the second recipient must be refused even though the first was allowed.
    """

    _stub_campaign_level_drift(monkeypatch)
    campaign = _campaign()
    reviewed = [uuid.uuid4(), uuid.uuid4()]
    canary_rows = [(recipient_id, f"{index}" * 64) for index, recipient_id in enumerate(reviewed)]
    gate = _gate(canary_rows, phase="canary")
    payload = _payload(gate, phase="canary")
    assignments = [_assignment(campaign, recipient_id) for recipient_id in reviewed]
    by_id = {str(item.recipient_assignment_id): item for item in assignments}
    first, second = (str(item.recipient_assignment_id) for item in assignments)

    assert _verdict(gate, campaign, payload, canary_rows, by_id, [first, second]) is None
    assert _verdict(gate, campaign, payload, canary_rows, by_id, [first]) is None

    # Between the two recipients the reviewed canary window lapses.
    gate.canary_expires_at = _NOW - timedelta(seconds=1)

    assert _verdict(gate, campaign, payload, canary_rows, by_id, [second]) == "canary_evidence_expired"
    assert gate.state == "expired"
