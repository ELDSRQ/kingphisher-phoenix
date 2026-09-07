"""UX-011 §2b — the delivery worker's proof-send path.

The worker is the component that actually talks to the mail provider, so it is
the last place the destination can be checked. These tests pin that it:

* re-derives the mailbox from the recipient row's server-set
  ``is_test_account`` designation — the queue payload never carries an address,
  and a payload whose recipient is not (or is no longer) designated sends
  nothing;
* honours the persistent emergency stop, the recipient-domain allowlist
  (fail-closed), exclusions, delivery suppression and a bound RoE's target
  domains;
* creates NO assignment, token, correlation or canary evidence and mutates no
  campaign/send state — a proof can never be mistaken for, or consumed as, a
  real send;
* is audited on success and on every refusal.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from types import SimpleNamespace
from typing import Any

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import (
    Campaign,
    CampaignPattern,
    Recipient,
    RecipientDeliverySuppression,
    RulesOfEngagement,
    SystemSafetyState,
    TemplateVersion,
)
from kp_domain_models import models as dm
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_delivery
from kp_workers.providers.smtp import DeliveryReceipt

DESIGNATED = "proof-mailbox@corp.example"
_NOW = datetime.now(UTC)


class _Audit:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(self, **kwargs: Any) -> None:
        self.records.append(kwargs)

    @property
    def actions(self) -> list[str]:
        return [record["action"] for record in self.records]

    @property
    def reasons(self) -> list[str]:
        return [record["detail"].get("reason") for record in self.records]


class _Session:
    def __init__(self) -> None:
        self.get_results: dict[tuple[Any, Any], Any] = {}
        self.added: list[Any] = []
        self.deleted: list[Any] = []
        self.commits = 0
        self.assignment_id: uuid.UUID | None = None

    def get(self, model: Any, identifier: Any, **_kwargs: Any) -> Any:
        return self.get_results.get((model, identifier))

    def scalar(self, _statement: Any) -> Any:
        return self.assignment_id

    def add(self, value: Any) -> None:  # pragma: no cover - must never happen
        self.added.append(value)

    def delete(self, value: Any) -> None:  # pragma: no cover - must never happen
        self.deleted.append(value)

    def commit(self) -> None:
        self.commits += 1


def _campaign(state: dm.CampaignState = dm.CampaignState.PENDING_APPROVAL, roe_id: uuid.UUID | None = None) -> Campaign:
    return Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.uuid4(),
        current_template_id=uuid.uuid4(),
        title="Quarterly drill",
        state=state,
        sender_mailbox="itsecurity@corp.example",
        sender_display_name="IT Security",
        training_domain="corp.example",
        max_recipients=100,
        manifest_hash="m" * 64,
        roe_id=roe_id,
        expires_at=_NOW + timedelta(days=30),
    )


def _template() -> TemplateVersion:
    return TemplateVersion(
        template_version_id=uuid.uuid4(),
        generator_version="0.1.0",
        prompt_template_version="0.1.0",
        model_id="mock",
        input_hash="i" * 64,
        subject="Action required on your account",
        plain_text=f"Please review your account: {TRAINING_URL_PLACEHOLDER}",
        # Deliberately a DRAFT: the whole point of a proof is to see the
        # message before approval. Content safety is still validated at render.
        approval_state=dm.TemplateApprovalState.DRAFT,
    )


def _recipient(
    mailbox: str = DESIGNATED,
    *,
    is_test_account: bool = True,
    status: dm.RecipientStatus = dm.RecipientStatus.ACTIVE,
    deleted: bool = False,
) -> Recipient:
    return Recipient(
        recipient_id=uuid.uuid4(),
        employee_key="ek",
        mailbox=mailbox,
        mailbox_sha256="b" * 64,
        display_name="Proof Mailbox",
        is_test_account=is_test_account,
        status=status,
        deleted_at=_NOW if deleted else None,
    )


def _settings(**overrides: Any) -> WorkerSettings:
    values: dict[str, Any] = {
        "_env_file": None,
        "runtime_mode": "development",
        "approval_policy": "single-admin",
        "dev_stack": True,
        "allowed_recipient_domains": "corp.example",
        "training_domains": "corp.example,localhost,127.0.0.1",
    }
    values.update(overrides)
    return WorkerSettings(**values)


def _run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    campaign: Campaign,
    template: TemplateVersion | None = None,
    recipient: Recipient | None = None,
    payload_recipient_id: uuid.UUID | None = None,
    stop_engaged: bool = False,
    excluded: set[uuid.UUID] | None = None,
    suppressed: bool = False,
    assignment_id: uuid.UUID | None = None,
    roe: Any = None,
    settings: WorkerSettings | None = None,
    template_hash: str | None = None,
    send_error: Exception | None = None,
) -> tuple[_Audit, list[EmailMessage]]:
    session = _Session()
    session.assignment_id = assignment_id
    session.get_results[(SystemSafetyState, 1)] = SimpleNamespace(emergency_stop_engaged=stop_engaged, generation=1)
    session.get_results[(Campaign, campaign.campaign_id)] = campaign
    if template is not None:
        session.get_results[(TemplateVersion, campaign.current_template_id)] = template
    session.get_results[(CampaignPattern, campaign.pattern_id)] = CampaignPattern(
        campaign_pattern_id=campaign.pattern_id,
        lure_category=dm.LureCategory.OTHER,
        confidence=dm.Confidence.HIGH,
    )
    if roe is not None:
        session.get_results[(RulesOfEngagement, campaign.roe_id)] = roe
    if recipient is not None:
        session.get_results[(Recipient, recipient.recipient_id)] = recipient
        if suppressed:
            session.get_results[(RecipientDeliverySuppression, recipient.recipient_id)] = SimpleNamespace(active=True)

    @contextmanager
    def factory() -> Any:
        yield session

    audit = _Audit()
    context = WorkerContext(settings or _settings(), factory, audit, SimpleNamespace())  # type: ignore[arg-type]
    sent: list[EmailMessage] = []

    class _Transport:
        def send(self, message: EmailMessage, **_kwargs: Any) -> DeliveryReceipt:
            if send_error is not None:
                raise send_error
            sent.append(message)
            return DeliveryReceipt(message_id="<proof@corp.example>", provider_id="provider-proof")

    monkeypatch.setattr("kp_workers.jobs._make_batch_sender", lambda _ctx: _Transport())
    monkeypatch.setattr(
        "kp_workers.jobs._excluded_recipient_ids", lambda *_args, **_kwargs: frozenset(excluded or set())
    )
    process_delivery(
        context,
        {
            "payload": {
                "job_type": "proof_send",
                "campaign_id": str(campaign.campaign_id),
                "proof_recipient_id": str(
                    payload_recipient_id
                    if payload_recipient_id is not None
                    else (recipient.recipient_id if recipient is not None else uuid.uuid4())
                ),
                "template_hash": campaign.manifest_hash if template_hash is None else template_hash,
                "requested_by": str(uuid.uuid4()),
            }
        },
    )
    # A proof never touches the ORM identity map beyond reads.
    assert session.added == []
    assert session.deleted == []
    return audit, sent


def test_a_proof_goes_only_to_the_designated_mailbox_and_is_marked_as_a_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign()
    recipient = _recipient()
    audit, sent = _run(monkeypatch, campaign=campaign, template=_template(), recipient=recipient)

    (message,) = sent
    assert message["To"] == DESIGNATED
    assert message["Subject"].startswith("[PROOF] ")
    assert message["X-KP-Proof-Send"] == "1"
    # No open-pixel / token-hash correlation headers: a proof produces no
    # evidence and cannot be correlated to a tracking token.
    assert message["X-KP-Token-Hash"] is None
    body = message.get_body(preferencelist=("plain",)).get_content()
    assert "/v1/track/click/proof-" in body

    assert audit.actions == ["campaign.proof-send"]
    detail = audit.records[0]["detail"]
    assert detail["destination"] == "server_designated_test_account"
    assert detail["proof_recipient_id"] == str(recipient.recipient_id)
    assert detail["creates_assignment"] is False
    assert detail["creates_tracking_token"] is False


def test_the_campaign_and_its_send_state_are_untouched(monkeypatch: pytest.MonkeyPatch) -> None:
    campaign = _campaign()
    before = (campaign.state, campaign.manifest_hash, campaign.roe_id, campaign.current_template_id)
    _run(monkeypatch, campaign=campaign, template=_template(), recipient=_recipient())
    assert (campaign.state, campaign.manifest_hash, campaign.roe_id, campaign.current_template_id) == before


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"is_test_account": False}, "not_a_designated_test_account"),
        ({"status": dm.RecipientStatus.EXCLUDED}, "not_a_designated_test_account"),
        ({"deleted": True}, "not_a_designated_test_account"),
    ],
)
def test_a_recipient_that_is_not_a_live_designated_test_account_is_refused(
    monkeypatch: pytest.MonkeyPatch, kwargs: dict[str, Any], reason: str
) -> None:
    recipient = _recipient(**kwargs)
    audit, sent = _run(monkeypatch, campaign=_campaign(), template=_template(), recipient=recipient)
    assert sent == []
    assert audit.reasons == [reason]


def test_an_unknown_recipient_id_in_the_payload_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=None,
        payload_recipient_id=uuid.uuid4(),
    )
    assert sent == []
    assert audit.reasons == ["not_a_designated_test_account"]


def test_the_emergency_stop_blocks_a_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient(),
        stop_engaged=True,
    )
    assert sent == []
    assert audit.reasons == ["global_emergency_stop"]


def test_an_unallowlisted_designated_mailbox_is_refused_under_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient(),
        settings=_settings(
            approval_policy="enforce",
            dev_stack=False,
            allowed_recipient_domains="",
            training_domains="corp.example,localhost,127.0.0.1",
        ),
    )
    assert sent == []
    assert audit.reasons == ["domain_not_allowed"]


def test_a_designated_mailbox_outside_the_allowlist_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient("proof@elsewhere.example"),
    )
    assert sent == []
    assert audit.reasons == ["domain_not_allowed"]


def test_a_bound_roe_still_binds_the_proof(monkeypatch: pytest.MonkeyPatch) -> None:
    roe_id = uuid.uuid4()
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(roe_id=roe_id),
        template=_template(),
        recipient=_recipient(),
        roe=SimpleNamespace(roe_id=roe_id, target_domains=["other.example"]),
    )
    assert sent == []
    assert audit.reasons == ["target_domain_not_roe_covered"]


def test_exclusions_and_suppressions_are_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    recipient = _recipient()
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=recipient,
        excluded={recipient.recipient_id},
    )
    assert sent == []
    assert audit.reasons == ["recipient_excluded"]

    recipient = _recipient()
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=recipient,
        suppressed=True,
    )
    assert sent == []
    assert audit.reasons == ["recipient_suppressed"]


def test_a_mailbox_this_campaign_already_contacts_is_never_proofed(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient(),
        assignment_id=uuid.uuid4(),
    )
    assert sent == []
    assert audit.reasons == ["recipient_already_assigned"]


@pytest.mark.parametrize(
    "state",
    [dm.CampaignState.APPROVED, dm.CampaignState.SCHEDULED, dm.CampaignState.ACTIVE, dm.CampaignState.COMPLETED],
)
def test_a_campaign_past_review_can_no_longer_be_proofed(
    monkeypatch: pytest.MonkeyPatch, state: dm.CampaignState
) -> None:
    audit, sent = _run(monkeypatch, campaign=_campaign(state), template=_template(), recipient=_recipient())
    assert sent == []
    assert audit.reasons == ["campaign_state_not_proofable"]


def test_a_stale_manifest_between_enqueue_and_dispatch_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient(),
        template_hash="z" * 64,
    )
    assert sent == []
    assert audit.reasons == ["stale_campaign_manifest"]


def test_a_provider_failure_is_audited_and_never_retried_as_a_delivery(monkeypatch: pytest.MonkeyPatch) -> None:
    audit, sent = _run(
        monkeypatch,
        campaign=_campaign(),
        template=_template(),
        recipient=_recipient(),
        send_error=RuntimeError("relay refused"),
    )
    assert sent == []
    assert audit.actions == ["campaign.proof-send.failed"]
    assert "relay refused" not in str(audit.records[0]["detail"])
