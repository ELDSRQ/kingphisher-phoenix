"""A golden verdict table for ``_launch_delivery_gate_reason``.

The launch gate is the middle member of the delivery stop-race trio (campaign
state -> launch gate -> emergency stop). Today its individual refusal reasons
are asserted only by *source-text grep* in
``test_campaign_canary_gate.py::test_worker_requires_phase_manifest_provider_and_evidence_bindings``;
``test_delivery_gate_hoist.py`` covers the three assignment- and time-dependent
reasons behaviourally. Nothing pins the rest to an actual call.

This module fixes that. Every branch of the function is exercised through the
real entry point and asserted against its exact reason string, plus the gate
mutations the caller depends on (``state`` flips and ``updated_at`` touches).
Branch *precedence* is asserted too, because several refusals can be true at
once and the reason that comes back is the one the audit log records.

It exists to be the equivalence oracle for the open cost work described in
``docs/design/ARC-002-ITEM2-WAVE.md`` ("The underlying cost is real and still
open"): up to 10,000 canary rows are read and hashed per recipient, and the
safe fix is to push the digest and the membership tests into Postgres. Any such
rewrite must reproduce this table exactly -- same reason string, same gate
mutation, same precedence -- not merely something similar.

Note for whoever does that work: the session double below is statement-blind,
like the one in ``test_delivery_gate_hoist.py``. It can only answer the
row-returning form of the manifest query. A server-side digest returns a single
aggregate row through the ``Result`` API instead, so it needs a
statement-*aware* double (or a ``postgres``-marked test); see the report that
accompanied this file.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from kp_database.campaign_service import campaign_canary_manifest_hash
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignLaunchGate,
    RecipientAssignment,
    TemplateVersion,
    TrainingResource,
)
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import _delivery_provider_binding, _launch_delivery_gate_reason

_NOW = datetime.now(UTC)
_REVIEW_HASH = "r" * 64
_EVIDENCE_HASH = "e" * 64


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


class _GateSession:
    """The slice of ``Session`` the launch gate touches.

    ``get`` is model-keyed so the campaign-level lookups can be steered
    independently. ``execute`` answers the canary-manifest query and ``scalars``
    the assignment query, and both record their call count so the per-call row
    cost stays visible.
    """

    def __init__(
        self,
        *,
        gate: object | None,
        canary_rows: list[tuple[uuid.UUID, str]],
        assignments: list[RecipientAssignment],
        audience: object | None = None,
        template: object | None = None,
        training_resource: object | None = None,
    ) -> None:
        self._by_model: dict[object, object | None] = {
            CampaignLaunchGate: gate,
            CampaignAudience: audience,
            TemplateVersion: template,
            TrainingResource: training_resource,
        }
        self.canary_rows = canary_rows
        self.assignments = assignments
        self.manifest_queries = 0
        self.manifest_rows_read = 0
        self.assignment_queries = 0

    def get(self, model: object, _identifier: object, **_kwargs: object) -> object | None:
        return self._by_model.get(model)

    def execute(self, _statement: object) -> list[tuple[uuid.UUID, str]]:
        self.manifest_queries += 1
        rows = list(self.canary_rows)
        self.manifest_rows_read += len(rows)
        return rows

    def scalars(self, _statement: object) -> list[RecipientAssignment]:
        self.assignment_queries += 1
        return list(self.assignments)


def _campaign(**overrides: object) -> Campaign:
    values: dict[str, Any] = {
        "campaign_id": uuid.uuid4(),
        "pattern_id": uuid.uuid4(),
        "current_template_id": uuid.uuid4(),
        "title": "canary cohort",
        "state": dm.CampaignState.SCHEDULED,
        "sender_mailbox": "awareness@example.com",
        "training_domain": "example.com",
        "max_recipients": 10,
        "manifest_hash": "m" * 64,
        "expires_at": _NOW + timedelta(days=30),
    }
    values.update(overrides)
    return Campaign(**values)


def _assignment(campaign: Campaign, recipient_id: uuid.UUID) -> RecipientAssignment:
    return RecipientAssignment(
        recipient_assignment_id=uuid.uuid4(),
        campaign_id=campaign.campaign_id,
        recipient_id=recipient_id,
        send_state=dm.SendState.QUEUED,
        idempotency_key=f"{campaign.campaign_id}:{recipient_id}:1",
    )


def _gate(canary_rows: list[tuple[uuid.UUID, str]], *, phase: str, **overrides: object) -> SimpleNamespace:
    provider, config_hash = _delivery_provider_binding(_settings())
    values: dict[str, Any] = {
        "state": "canary_queued" if phase == "canary" else "full_published",
        "canary_expires_at": _NOW + timedelta(hours=1),
        "provider": provider,
        "provider_config_hash": config_hash,
        "review_manifest_hash": _REVIEW_HASH,
        "canary_manifest_hash": campaign_canary_manifest_hash(canary_rows),
        "canary_evidence_hash": _EVIDENCE_HASH if phase == "full" else None,
        "updated_at": _NOW,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _payload(gate: SimpleNamespace, *, phase: str, **overrides: object) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "delivery_phase": phase,
        "launch_manifest_hash": gate.review_manifest_hash,
    }
    if phase == "full":
        payload["canary_evidence_hash"] = gate.canary_evidence_hash
        payload["provider"] = gate.provider
        payload["provider_config_hash"] = gate.provider_config_hash
    payload.update(overrides)
    return payload


def _stub_campaign_level_drift(
    monkeypatch: pytest.MonkeyPatch,
    *,
    gate_error: str | None = None,
    training_error: str | None = None,
) -> None:
    monkeypatch.setattr("kp_workers.jobs.campaign_launch_gate_error", lambda *_a, **_k: gate_error)
    monkeypatch.setattr("kp_workers.jobs.training_binding_error", lambda *_a, **_k: training_error)


def _cohort(size: int = 2) -> list[tuple[uuid.UUID, str]]:
    return [(uuid.uuid4(), f"{index % 10}" * 64) for index in range(size)]


def _run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase: str = "canary",
    canary_rows: list[tuple[uuid.UUID, str]] | None = None,
    gate_overrides: dict[str, Any] | None = None,
    payload_overrides: dict[str, Any] | None = None,
    assignment_recipients: list[uuid.UUID] | None = None,
    assignment_ids: list[str] | None = None,
    gate_error: str | None = None,
    training_error: str | None = None,
    training_resource_id: uuid.UUID | None = None,
    gate: object | None = ...,  # type: ignore[assignment]
    settings: WorkerSettings | None = None,
) -> tuple[Any, str | None, _GateSession, Campaign]:
    _stub_campaign_level_drift(monkeypatch, gate_error=gate_error, training_error=training_error)
    rows = _cohort() if canary_rows is None else canary_rows
    campaign = _campaign(training_resource_id=training_resource_id)
    resolved_gate = _gate(rows, phase=phase, **(gate_overrides or {})) if gate is ... else gate
    payload = _payload(
        resolved_gate if resolved_gate is not None else _gate(rows, phase=phase),
        phase=phase,
        **(payload_overrides or {}),
    )
    recipients = assignment_recipients if assignment_recipients is not None else [row[0] for row in rows]
    assignments = [_assignment(campaign, recipient_id) for recipient_id in recipients]
    ids = assignment_ids if assignment_ids is not None else [str(item.recipient_assignment_id) for item in assignments]
    session = _GateSession(gate=resolved_gate, canary_rows=rows, assignments=assignments)
    returned_gate, reason = _launch_delivery_gate_reason(
        session,  # type: ignore[arg-type]
        campaign,
        payload,
        ids,
        settings or _settings(),
    )
    return returned_gate, reason, session, campaign


# --------------------------------------------------------------------------
# Phase binding
# --------------------------------------------------------------------------


@pytest.mark.parametrize("phase", [None, "", "canary_queued", "FULL", "proof"])
def test_unknown_delivery_phase_is_refused_before_any_query(monkeypatch: pytest.MonkeyPatch, phase: object) -> None:
    returned_gate, reason, session, _ = _run(
        monkeypatch, payload_overrides={"delivery_phase": phase} if phase is not None else {"delivery_phase": None}
    )
    assert reason == "delivery_phase_missing"
    # The refusal precedes the gate lock, so no gate is returned to the caller.
    assert returned_gate is None
    assert session.manifest_queries == 0
    assert session.assignment_queries == 0


def test_missing_delivery_phase_key_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_campaign_level_drift(monkeypatch)
    rows = _cohort()
    campaign = _campaign()
    gate = _gate(rows, phase="canary")
    session = _GateSession(gate=gate, canary_rows=rows, assignments=[])
    assert _launch_delivery_gate_reason(session, campaign, {}, [], _settings())[1] == "delivery_phase_missing"  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Campaign-level manifest binding
# --------------------------------------------------------------------------


def test_campaign_level_gate_error_is_launch_manifest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, session, _ = _run(monkeypatch, gate_error="audience_manifest_changed")
    assert reason == "launch_manifest_drift"
    # The gate is still handed back even though it is refused: the caller
    # audits against it.
    assert returned_gate is not None
    assert session.manifest_queries == 0


def test_absent_gate_row_is_launch_manifest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, session, _ = _run(monkeypatch, gate=None)
    assert reason == "launch_manifest_drift"
    assert returned_gate is None
    assert session.manifest_queries == 0


def test_training_binding_error_is_training_manifest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    _, reason, session, _ = _run(
        monkeypatch, training_error="training_resource_superseded", training_resource_id=uuid.uuid4()
    )
    assert reason == "training_manifest_drift"
    assert session.manifest_queries == 0


def test_launch_manifest_hash_must_match_the_reviewed_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    _, reason, session, _ = _run(monkeypatch, payload_overrides={"launch_manifest_hash": "z" * 64})
    assert reason == "launch_manifest_mismatch"
    assert session.manifest_queries == 0


# --------------------------------------------------------------------------
# Canary window
# --------------------------------------------------------------------------


@pytest.mark.parametrize("phase", ["canary", "full"])
@pytest.mark.parametrize("expires_at", [None, _NOW - timedelta(seconds=1)])
def test_expired_or_unset_canary_window_expires_the_gate(
    monkeypatch: pytest.MonkeyPatch, phase: str, expires_at: datetime | None
) -> None:
    returned_gate, reason, session, _ = _run(monkeypatch, phase=phase, gate_overrides={"canary_expires_at": expires_at})
    assert reason == "canary_evidence_expired"
    assert returned_gate is not None
    assert returned_gate.state == "expired"
    assert returned_gate.updated_at > _NOW
    assert session.manifest_queries == 0


def test_a_window_expiring_exactly_now_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """``canary_expires_at <= now`` -- the boundary is closed, not open.

    The clock is frozen so ``canary_expires_at`` can equal ``now`` exactly;
    with a merely-past timestamp a ``<`` comparison would pass this too.
    """

    frozen = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
    monkeypatch.setattr("kp_workers.jobs.datetime", SimpleNamespace(now=lambda _tz: frozen))
    returned_gate, reason, _, _ = _run(monkeypatch, gate_overrides={"canary_expires_at": frozen})
    assert reason == "canary_evidence_expired"
    assert returned_gate.state == "expired"
    assert returned_gate.updated_at == frozen


def test_a_window_one_microsecond_wide_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other side of the same boundary: strictly-future is still open."""

    frozen = datetime(2026, 9, 7, 12, 0, 0, tzinfo=UTC)
    monkeypatch.setattr("kp_workers.jobs.datetime", SimpleNamespace(now=lambda _tz: frozen))
    rows = _cohort(2)
    _, reason, _, _ = _run(
        monkeypatch,
        canary_rows=rows,
        gate_overrides={"canary_expires_at": frozen + timedelta(microseconds=1)},
        assignment_recipients=[rows[0][0]],
    )
    assert reason is None


# --------------------------------------------------------------------------
# Provider binding, canary phase
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["reviewed", "approved", "canary_succeeded", "full_published", "canary_failed"])
def test_canary_phase_requires_the_queued_state(monkeypatch: pytest.MonkeyPatch, state: str) -> None:
    _, reason, session, _ = _run(monkeypatch, phase="canary", gate_overrides={"state": state})
    assert reason == "canary_not_queued"
    assert session.manifest_queries == 0


def test_canary_phase_adopts_an_unbound_provider_and_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, _, _ = _run(
        monkeypatch, phase="canary", gate_overrides={"provider": None, "provider_config_hash": None}
    )
    assert reason is None
    provider, config_hash = _delivery_provider_binding(_settings())
    assert returned_gate.provider == provider
    assert returned_gate.provider_config_hash == config_hash
    assert returned_gate.updated_at > _NOW


@pytest.mark.parametrize(
    "override",
    [
        {"provider": "acs"},
        {"provider_config_hash": "d" * 64},
        {"provider": "acs", "provider_config_hash": "d" * 64},
    ],
)
def test_canary_phase_provider_drift_fails_the_gate_permanently(
    monkeypatch: pytest.MonkeyPatch, override: dict[str, Any]
) -> None:
    returned_gate, reason, session, _ = _run(monkeypatch, phase="canary", gate_overrides=override)
    assert reason == "canary_provider_configuration_drift"
    assert returned_gate.state == "canary_failed"
    assert returned_gate.updated_at > _NOW
    assert session.manifest_queries == 0


def test_canary_phase_half_bound_provider_is_drift_not_adoption(monkeypatch: pytest.MonkeyPatch) -> None:
    """Adoption requires *both* fields unset; one set alone is drift."""

    returned_gate, reason, _, _ = _run(
        monkeypatch, phase="canary", gate_overrides={"provider": None, "provider_config_hash": "d" * 64}
    )
    assert reason == "canary_provider_configuration_drift"
    assert returned_gate.state == "canary_failed"


# --------------------------------------------------------------------------
# Provider and evidence binding, full phase
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("gate_overrides", "payload_overrides"),
    [
        ({"state": "canary_succeeded"}, {}),
        ({"state": "canary_queued"}, {}),
        ({"canary_evidence_hash": None}, {"canary_evidence_hash": None}),
        ({}, {"canary_evidence_hash": "f" * 64}),
        ({}, {"provider": "acs"}),
        ({}, {"provider_config_hash": "d" * 64}),
    ],
    ids=[
        "state_canary_succeeded",
        "state_canary_queued",
        "gate_evidence_absent",
        "payload_evidence_mismatch",
        "payload_provider_mismatch",
        "payload_provider_config_mismatch",
    ],
)
def test_full_phase_requires_published_state_and_matching_evidence(
    monkeypatch: pytest.MonkeyPatch, gate_overrides: dict[str, Any], payload_overrides: dict[str, Any]
) -> None:
    returned_gate, reason, session, _ = _run(
        monkeypatch, phase="full", gate_overrides=gate_overrides, payload_overrides=payload_overrides
    )
    assert reason == "canary_evidence_missing_or_mismatched"
    # This refusal is a mismatch, not a compromise: the gate is not failed.
    assert returned_gate.state == gate_overrides.get("state", "full_published")
    assert session.manifest_queries == 0


@pytest.mark.parametrize(
    "gate_overrides",
    [{"provider": "acs"}, {"provider_config_hash": "d" * 64}],
    ids=["provider", "provider_config_hash"],
)
def test_full_phase_live_provider_drift_fails_the_gate_permanently(
    monkeypatch: pytest.MonkeyPatch, gate_overrides: dict[str, Any]
) -> None:
    """The payload agrees with the gate, but the *running worker* does not.

    ``_payload`` is derived from the gate, so the evidence check passes and the
    refusal comes from the live ``_delivery_provider_binding`` comparison.
    """

    returned_gate, reason, session, _ = _run(
        monkeypatch, phase="full", gate_overrides=gate_overrides, assignment_recipients=[uuid.uuid4()]
    )
    assert reason == "provider_configuration_drift"
    assert returned_gate.state == "canary_failed"
    assert returned_gate.updated_at > _NOW
    assert session.manifest_queries == 0


# --------------------------------------------------------------------------
# Canary manifest: size, presence, drift
# --------------------------------------------------------------------------


def test_manifest_at_the_ten_thousand_row_boundary_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(10_000)
    _, reason, session, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[0][0]])
    assert reason is None
    assert session.manifest_rows_read == 10_000


def test_manifest_one_row_past_the_boundary_is_oversized(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(10_001)
    returned_gate, reason, _, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[0][0]])
    assert reason == "canary_manifest_oversized"
    # Oversize is a refusal, not a failure: the gate state is untouched.
    assert returned_gate.state == "canary_queued"


def test_empty_manifest_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, _, _ = _run(monkeypatch, canary_rows=[], assignment_recipients=[uuid.uuid4()])
    assert reason == "canary_manifest_missing"
    assert returned_gate.state == "canary_queued"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda rows: rows[::-1], id="reordered"),
        pytest.param(lambda rows: rows[:-1], id="row_removed"),
        pytest.param(lambda rows: [*rows, (uuid.uuid4(), "9" * 64)], id="row_added"),
        pytest.param(lambda rows: [(rows[0][0], "8" * 64), *rows[1:]], id="hash_changed"),
        pytest.param(lambda rows: [(uuid.uuid4(), rows[0][1]), *rows[1:]], id="recipient_changed"),
    ],
)
def test_any_manifest_mutation_is_drift(monkeypatch: pytest.MonkeyPatch, mutate: Any) -> None:
    """The digest covers order, membership and per-row hash alike."""

    _stub_campaign_level_drift(monkeypatch)
    reviewed = _cohort(3)
    gate = _gate(reviewed, phase="canary")  # hash pinned to the reviewed order
    live = mutate(reviewed)
    campaign = _campaign()
    assignments = [_assignment(campaign, live[0][0])]
    session = _GateSession(gate=gate, canary_rows=live, assignments=assignments)

    _, reason = _launch_delivery_gate_reason(
        session,  # type: ignore[arg-type]
        campaign,
        _payload(gate, phase="canary"),
        [str(assignments[0].recipient_assignment_id)],
        _settings(),
    )
    assert reason == "canary_manifest_drift"
    assert gate.state == "canary_queued"


# --------------------------------------------------------------------------
# Assignment binding
# --------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "", "12345", "00000000-0000-0000-0000-00000000000"])
def test_unparseable_assignment_id_is_binding_invalid(monkeypatch: pytest.MonkeyPatch, bad_id: str) -> None:
    rows = _cohort()
    _, reason, _, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[0][0]], assignment_ids=[bad_id])
    assert reason == "assignment_binding_invalid"


def test_assignment_not_owned_by_the_campaign_is_binding_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    """The database filters on ``campaign_id``; a short result is a refusal."""

    _stub_campaign_level_drift(monkeypatch)
    rows = _cohort()
    gate = _gate(rows, phase="canary")
    campaign = _campaign()
    # Two ids requested, one row returned.
    session = _GateSession(gate=gate, canary_rows=rows, assignments=[_assignment(campaign, rows[0][0])])
    _, reason = _launch_delivery_gate_reason(
        session,  # type: ignore[arg-type]
        campaign,
        _payload(gate, phase="canary"),
        [str(uuid.uuid4()), str(uuid.uuid4())],
        _settings(),
    )
    assert reason == "assignment_binding_invalid"


def test_an_empty_assignment_batch_passes_the_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """No recipients means no membership violation to find."""

    rows = _cohort()
    _, reason, _, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[], assignment_ids=[])
    assert reason is None


# --------------------------------------------------------------------------
# Cohort membership
# --------------------------------------------------------------------------


def test_canary_phase_accepts_a_single_reviewed_recipient(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(3)
    _, reason, _, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[1][0]])
    assert reason is None


def test_canary_phase_refuses_a_recipient_outside_the_cohort(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(3)
    _, reason, _, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[0][0], uuid.uuid4()])
    assert reason == "canary_recipient_not_reviewed"


def test_full_phase_accepts_a_recipient_outside_the_cohort(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(3)
    _, reason, _, _ = _run(
        monkeypatch, phase="full", canary_rows=rows, assignment_recipients=[uuid.uuid4(), uuid.uuid4()]
    )
    assert reason is None


def test_full_phase_refuses_a_recipient_inside_the_cohort(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(3)
    _, reason, _, _ = _run(
        monkeypatch, phase="full", canary_rows=rows, assignment_recipients=[uuid.uuid4(), rows[2][0]]
    )
    assert reason == "canary_recipient_in_full_publication"


def test_duplicate_recipients_do_not_change_the_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Membership is a set test; a repeated recipient is not a violation."""

    rows = _cohort(2)
    _stub_campaign_level_drift(monkeypatch)
    gate = _gate(rows, phase="canary")
    campaign = _campaign()
    assignments = [_assignment(campaign, rows[0][0]), _assignment(campaign, rows[0][0])]
    session = _GateSession(gate=gate, canary_rows=rows, assignments=assignments)
    _, reason = _launch_delivery_gate_reason(
        session,  # type: ignore[arg-type]
        campaign,
        _payload(gate, phase="canary"),
        [str(item.recipient_assignment_id) for item in assignments],
        _settings(),
    )
    assert reason is None


# --------------------------------------------------------------------------
# Precedence
# --------------------------------------------------------------------------


def test_expiry_outranks_provider_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, _, _ = _run(
        monkeypatch,
        phase="canary",
        gate_overrides={"canary_expires_at": _NOW - timedelta(seconds=1), "provider": "acs"},
    )
    assert reason == "canary_evidence_expired"
    assert returned_gate.state == "expired"


def test_manifest_drift_outranks_assignment_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    """Both are true; the manifest refusal is the one the audit log records."""

    _stub_campaign_level_drift(monkeypatch)
    reviewed = _cohort(2)
    gate = _gate(reviewed, phase="canary")
    campaign = _campaign()
    session = _GateSession(gate=gate, canary_rows=reviewed[::-1], assignments=[])
    _, reason = _launch_delivery_gate_reason(
        session,  # type: ignore[arg-type]
        campaign,
        _payload(gate, phase="canary"),
        ["not-a-uuid"],
        _settings(),
    )
    assert reason == "canary_manifest_drift"


def test_manifest_size_outranks_manifest_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _cohort(10_001)
    _, reason, _, _ = _run(
        monkeypatch,
        canary_rows=rows,
        gate_overrides={"canary_manifest_hash": "z" * 64},
        assignment_recipients=[rows[0][0]],
    )
    assert reason == "canary_manifest_oversized"


def test_launch_mismatch_outranks_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    returned_gate, reason, _, _ = _run(
        monkeypatch,
        gate_overrides={"canary_expires_at": _NOW - timedelta(seconds=1)},
        payload_overrides={"launch_manifest_hash": "z" * 64},
    )
    assert reason == "launch_manifest_mismatch"
    # Crucially the gate is *not* expired as a side effect of a mismatched payload.
    assert returned_gate.state == "canary_queued"


# --------------------------------------------------------------------------
# Cost, pinned so an optimisation is visible
# --------------------------------------------------------------------------


def test_each_call_reads_the_whole_manifest_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Today: one manifest query per call, returning every row.

    This is the cost ``ARC-002-ITEM2-WAVE.md`` leaves open. It is asserted, not
    merely described, so that pushing the digest into Postgres shows up here as
    a deliberate edit rather than passing unnoticed.
    """

    rows = _cohort(500)
    _, reason, session, _ = _run(monkeypatch, canary_rows=rows, assignment_recipients=[rows[0][0]])
    assert reason is None
    assert session.manifest_queries == 1
    assert session.manifest_rows_read == len(rows)
    assert session.assignment_queries == 1
