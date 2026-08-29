"""Opt-in loopback canary for delivery, tracking, training, and reporting.

The test sends only to one explicitly seeded ``example.com`` test account and
uses the loopback Mailpit relay. It never calls DNS, Azure, Graph, ACS, or an
external mail provider. Database/application records and the exact Mailpit
message are removed after the assertions; append-only audit evidence remains.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from kp_authorization import Principal, Role
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.audit_store import AuditStore
from kp_database.campaign_service import (
    AudienceDefinition,
    bind_campaign_launch_review,
    bind_campaign_training_resource,
    configure_campaign_audience,
    freeze_campaign_audience,
    prepare_campaign,
    preview_campaign_audience,
)
from kp_database.models import (
    Campaign,
    CampaignAudience,
    CampaignAudienceManifest,
    CampaignLaunchGate,
    CampaignPattern,
    CipherText,
    Recipient,
    RecipientAssignment,
    RulesOfEngagement,
    SystemSafetyState,
    TemplateVersion,
    TrackingEvent,
    TrainingAssignment,
    TrainingResource,
)
from kp_database.reporting import SINGLE_TENANT_DATABASE_SCOPE, campaign_funnel
from kp_database.session import create_db_engine, make_session_factory
from kp_domain_models import models as dm
from kp_operator_api.routers import TemplateDecision, decide_template
from kp_tracking_api.config import TrackingApiSettings
from kp_tracking_api.main import create_app
from kp_workers.config import WorkerSettings
from kp_workers.jobs import WorkerContext, process_delivery
from sqlalchemy import delete, select
from sqlalchemy.engine import make_url

pytestmark = pytest.mark.e2e

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_CLICK_URL = re.compile(r"http://127\.0\.0\.1:8001/v1/track/click/[A-Za-z0-9_-]{40,128}")
_OPEN_URL = re.compile(r"http://127\.0\.0\.1:8001/v1/track/open/[A-Za-z0-9_-]{40,128}")
_COMPLETION_ACTION = re.compile(r'action="(/v1/training/([A-Za-z0-9_-]{40,128})/complete)"')


def _require_loopback_url(label: str, value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in _LOOPBACK_HOSTS:
        pytest.fail(f"{label} must be an explicit loopback HTTP(S) URL")
    return value.rstrip("/")


def _require_loopback_database(label: str, value: str) -> str:
    if make_url(value).host not in _LOOPBACK_HOSTS:
        pytest.fail(f"{label} must be an explicit loopback database URL")
    return value


def _mailpit_messages(client: httpx.Client) -> list[dict[str, object]]:
    response = client.get("/api/v1/messages", params={"start": 0, "limit": 50})
    response.raise_for_status()
    payload = response.json()
    messages = payload.get("messages") if isinstance(payload, dict) else None
    if not isinstance(messages, list) or any(not isinstance(item, dict) for item in messages):
        pytest.fail("Mailpit returned a malformed message summary")
    return messages


def _mailpit_message_id(summary: dict[str, object]) -> str:
    message_id = summary.get("ID")
    if not isinstance(message_id, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", message_id) is None:
        pytest.fail("Mailpit returned a malformed message ID")
    return message_id


def _wait_for_subject(client: httpx.Client, subject: str, baseline_ids: set[str]) -> tuple[str, dict[str, object]]:
    for _ in range(50):
        matching = [
            item
            for item in _mailpit_messages(client)
            if _mailpit_message_id(item) not in baseline_ids and item.get("Subject") == subject
        ]
        if len(matching) == 1:
            message_id = _mailpit_message_id(matching[0])
            detail_response = client.get(f"/api/v1/message/{message_id}")
            detail_response.raise_for_status()
            if len(detail_response.content) > 1_000_000:
                pytest.fail("Mailpit canary message exceeded the one-megabyte evidence bound")
            detail = detail_response.json()
            if not isinstance(detail, dict):
                pytest.fail("Mailpit returned malformed message detail")
            return message_id, detail
        if len(matching) > 1:
            pytest.fail("the canary subject was delivered more than once")
        time.sleep(0.1)
    pytest.fail("Mailpit did not receive the canary message")


def _cleanup_canary(
    session_factory: object,
    campaign_id: uuid.UUID,
    template_id: uuid.UUID,
) -> None:
    with session_factory() as session:  # type: ignore[operator]
        session.execute(delete(TrackingEvent).where(TrackingEvent.campaign_id == campaign_id))
        audience = session.get(CampaignAudience, campaign_id, with_for_update=True)
        if audience is not None:
            # The database intentionally blocks manifest changes while frozen.
            audience.frozen_at = None
            session.flush()
            session.execute(delete(CampaignAudienceManifest).where(CampaignAudienceManifest.campaign_id == campaign_id))
            session.flush()
        campaign = session.get(Campaign, campaign_id)
        if campaign is not None:
            session.delete(campaign)
        template = session.get(TemplateVersion, template_id)
        if template is not None:
            session.delete(template)
        session.commit()


def test_mailpit_delivery_training_and_reporting_canary(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.getenv("KP_E2E_LIFECYCLE") != "1":
        pytest.skip("set KP_E2E_LIFECYCLE=1 to authorize the local Mailpit lifecycle canary")

    settings = WorkerSettings(
        worker_name="delivery",
        runtime_mode="development",
        email_provider="smtp",
        smtp_address="127.0.0.1:1025",
        smtp_sender="awareness@example.com",
        smtp_starttls=False,
        smtp_ssl=False,
        sending_domains="example.com",
        allowed_recipient_domains="example.com",
        tracking_base_url="http://127.0.0.1:8001",
        training_base_url="http://127.0.0.1:8001/v1/training/awareness",
        training_domains="example.com,127.0.0.1",
        reported_mailbox_provider="mailpit",
        reported_mailbox_url="http://127.0.0.1:8025",
        mailpit_api_url="http://127.0.0.1:8025",
    )
    database_url = _require_loopback_database("business database", settings.database_url)
    audit_database_url = _require_loopback_database("audit database", settings.audit_database_url)
    mailpit_url = _require_loopback_url("Mailpit", settings.mailpit_api_url)
    if not settings.roe_signing_key:
        pytest.fail("the local RoE signing key is required for the delivery canary")

    local_tracking_settings = TrackingApiSettings()
    tracking_key_hex = local_tracking_settings.tracking_token_hmac_key
    training_key_hex = local_tracking_settings.training_token_hmac_key
    if re.fullmatch(r"[0-9a-fA-F]{64}", tracking_key_hex) is None:
        pytest.fail("the local tracking token HMAC key is required for the delivery canary")
    if re.fullmatch(r"[0-9a-fA-F]{64}", training_key_hex) is None:
        pytest.fail("the local training token HMAC key is required for the delivery canary")
    tracking_key = bytes.fromhex(tracking_key_hex)

    ciphertext_key_id, ciphertext_key, ciphertext_prior_keys = settings.require_cipher_keyring()
    CipherText.configure_keyring(ciphertext_key_id, ciphertext_key, ciphertext_prior_keys)
    engine = create_db_engine(database_url)
    audit_engine = create_db_engine(audit_database_url)
    session_factory = make_session_factory(engine)
    audit_store = AuditStore(
        audit_engine,
        settings.require_hmac() if settings.audit_hmac_key else None,
        intent_engine=engine,
    )
    canary_id = uuid.uuid4()
    template_id = uuid.uuid4()
    subject = f"KP local delivery canary {canary_id}"
    message_id: str | None = None

    # The local canary is forbidden from making even a DNS preflight request.
    monkeypatch.setattr(
        "kp_workers.jobs.check_spf_for_mailbox",
        lambda _mailbox: SimpleNamespace(has_spf=True, domain="example.com"),
    )

    try:
        with httpx.Client(base_url=mailpit_url, timeout=5.0, trust_env=False) as mailpit:
            baseline_ids = {_mailpit_message_id(item) for item in _mailpit_messages(mailpit)}

            with session_factory() as session:
                pattern = session.scalar(
                    select(CampaignPattern)
                    .where(CampaignPattern.approval_state == dm.PatternApprovalState.APPROVED)
                    .order_by(CampaignPattern.campaign_pattern_id)
                    .limit(1)
                )
                recipient = next(
                    (
                        item
                        for item in session.scalars(
                            select(Recipient)
                            .where(
                                Recipient.is_test_account.is_(True),
                                Recipient.status == dm.RecipientStatus.ACTIVE,
                                Recipient.deleted_at.is_(None),
                            )
                            .order_by(Recipient.recipient_id)
                            .limit(100)
                        )
                        if item.mailbox.endswith("@example.com")
                    ),
                    None,
                )
                now = datetime.now(UTC)
                roe = session.scalar(
                    select(RulesOfEngagement)
                    .where(
                        RulesOfEngagement.revoked_at.is_(None),
                        RulesOfEngagement.window_start <= now,
                        RulesOfEngagement.window_end >= now + timedelta(hours=1),
                    )
                    .order_by(RulesOfEngagement.roe_id)
                    .limit(1)
                )
                resource = session.scalar(
                    select(TrainingResource)
                    .where(
                        TrainingResource.approval_state == dm.TemplateApprovalState.APPROVED,
                        TrainingResource.requires_completion.is_(True),
                    )
                    .order_by(TrainingResource.training_resource_id)
                    .limit(1)
                )
                safety = session.get(SystemSafetyState, 1)
                assert pattern is not None
                assert recipient is not None and recipient.is_test_account
                assert roe is not None and "example.com" in (roe.target_domains or [])
                assert resource is not None
                assert safety is not None and not safety.emergency_stop_engaged

                template = TemplateVersion(
                    template_version_id=template_id,
                    campaign_id=canary_id,
                    version=1,
                    idempotency_key=f"e2e-mailpit-template:{canary_id}",
                    generator_version="local-canary",
                    prompt_template_version="local-canary",
                    model_id="local-canary",
                    input_hash=hashlib.sha256(canary_id.bytes).hexdigest(),
                    raw_proposal={"requested_by": str(uuid.uuid4())},
                    subject=subject,
                    plain_text=f"Review this approved simulation: {TRAINING_URL_PLACEHOLDER}",
                    safe_html=f'<p>Approved local simulation</p><a href="{TRAINING_URL_PLACEHOLDER}">Review</a>',
                    approval_state=dm.TemplateApprovalState.DRAFT,
                )
                session.add(template)
                session.commit()
                decide_template(
                    template_id,
                    TemplateDecision(decision=dm.ApprovalDecision.APPROVED, rationale="Local canary review"),
                    session=session,
                    audit=audit_store,
                    principal=Principal(str(uuid.uuid4()), {Role.SECURITY_APPROVER}),
                )

                schedule_start = now - timedelta(minutes=5)
                schedule_end = now + timedelta(hours=1)
                campaign = Campaign(
                    campaign_id=canary_id,
                    pattern_id=pattern.campaign_pattern_id,
                    current_template_id=template_id,
                    title=subject,
                    state=dm.CampaignState.DRAFT,
                    sender_mailbox="awareness@example.com",
                    sender_display_name="Security Awareness",
                    training_domain="example.com",
                    schedule_start=schedule_start,
                    schedule_end=schedule_end,
                    timezone="UTC",
                    max_recipients=1,
                    manifest_hash=None,
                    manifest_signed_at=now,
                    expires_at=schedule_end,
                )
                bind_campaign_training_resource(campaign, resource)
                session.add(campaign)
                session.flush()
                configure_campaign_audience(
                    session,
                    campaign,
                    AudienceDefinition(include_recipient_ids=(recipient.recipient_id,)),
                )
                preview = preview_campaign_audience(
                    session,
                    campaign,
                    allowed_domains=frozenset({"example.com"}),
                    roe_options=((roe.roe_id, frozenset({"example.com"})),),
                )
                assert len(preview.included) == 1 and preview.included[0].recipient_id == recipient.recipient_id
                freeze_campaign_audience(
                    session,
                    campaign,
                    preview,
                    expected_preview_hash=preview.preview_hash,
                )
                launch_gate = bind_campaign_launch_review(session, campaign, template)
                prepared = prepare_campaign(
                    session,
                    campaign,
                    tracking_base_url=settings.tracking_base_url,
                    include_test_accounts=True,
                    test_only=True,
                    token_hmac_key=tracking_key,
                )
                assert len(prepared) == 1
                campaign.state = dm.CampaignState.SCHEDULED
                launch_gate.state = "canary_queued"
                launch_gate.canary_queued_at = now
                launch_gate.canary_expires_at = schedule_end
                launch_gate.updated_at = now
                session.commit()
                prepared_recipient = prepared[0]
                manifest_hash = campaign.manifest_hash

            context = WorkerContext(
                audit_store=audit_store,
                settings=settings,
                session_factory=session_factory,
                queue=SimpleNamespace(),  # type: ignore[arg-type]
            )
            delivery_message = {
                "idempotency_key": f"deliver:test:{canary_id}:0:1",
                "payload": {
                    "campaign_id": str(canary_id),
                    "recipient_assignment_ids": [prepared_recipient.assignment_id],
                    "template_hash": manifest_hash,
                    "test_send": True,
                    "delivery_phase": "canary",
                    "launch_manifest_hash": launch_gate.review_manifest_hash,
                    "tracking_bearers": {
                        prepared_recipient.assignment_id: {
                            "bearer": prepared_recipient.bearer_token,
                            "verifier": prepared_recipient.token_verifier,
                            "checksum": prepared_recipient.bearer_checksum,
                        }
                    },
                },
            }
            process_delivery(context, delivery_message)
            process_delivery(context, delivery_message)

            message_id, detail = _wait_for_subject(mailpit, subject, baseline_ids)
            new_messages = [
                item for item in _mailpit_messages(mailpit) if _mailpit_message_id(item) not in baseline_ids
            ]
            assert len([item for item in new_messages if item.get("Subject") == subject]) == 1
            rendered = "\n".join(str(detail.get(key) or "") for key in ("Text", "HTML"))
            click_urls = set(_CLICK_URL.findall(rendered))
            open_urls = set(_OPEN_URL.findall(rendered))
            assert click_urls == {prepared_recipient.click_url}
            assert open_urls == {prepared_recipient.open_url}
            assert settings.training_base_url not in rendered
            assert TRAINING_URL_PLACEHOLDER not in rendered

            tracking_app = create_app(
                TrackingApiSettings(
                    database_url=database_url,
                    tracking_token_hmac_key=tracking_key_hex,
                    training_token_hmac_key=training_key_hex,
                    rate_limit_token_per_min=20,
                    rate_limit_ip_per_min=100,
                    rate_limit_global_per_min=1000,
                )
            )
            with TestClient(tracking_app) as tracking:
                assert tracking.get(prepared_recipient.open_url).status_code == 200
                assert tracking.get(prepared_recipient.open_url).status_code == 200
                first_click = tracking.get(prepared_recipient.click_url, follow_redirects=False)
                second_click = tracking.get(prepared_recipient.click_url, follow_redirects=False)
                assert first_click.status_code == second_click.status_code == 302
                assert first_click.headers["location"] == second_click.headers["location"]
                training_path = first_click.headers["location"]
                opened = tracking.get(training_path)
                assert opened.status_code == 200 and "Knowledge check" in opened.text
                completion = _COMPLETION_ACTION.search(opened.text)
                assert completion is not None
                completion_path, completion_bearer = completion.groups()
                assert completion_bearer != training_path.rsplit("/", 1)[-1]
                incorrect = tracking.post(completion_path, data={"answer": "act_immediately"})
                assert incorrect.status_code == 422 and "Not quite" in incorrect.text
                completed = tracking.post(completion_path, data={"answer": "verify_independently"})
                assert completed.status_code == 200 and "Training complete" in completed.text
                replay = tracking.post(completion_path)
                assert replay.status_code == 200 and "Training complete" in replay.text

            with session_factory() as session:
                assignment = session.get(RecipientAssignment, uuid.UUID(prepared_recipient.assignment_id))
                launch_evidence = session.get(CampaignLaunchGate, canary_id)
                training_assignment = session.scalar(
                    select(TrainingAssignment).where(TrainingAssignment.campaign_id == canary_id)
                )
                assert assignment is not None
                assert assignment.send_state == dm.SendState.ACCEPTED
                assert assignment.delivery_attempt_count == 1
                assert assignment.provider_accepted_at is not None
                assert launch_evidence is not None
                assert launch_evidence.state == "canary_succeeded"
                assert launch_evidence.canary_evidence_hash is not None
                assert launch_evidence.provider == "smtp"
                assert training_assignment is not None
                assert training_assignment.status == dm.TrainingAssignmentStatus.COMPLETED
                completed_at = training_assignment.completed_at
                assert completed_at is not None

                report = campaign_funnel(session, canary_id, scope=SINGLE_TENANT_DATABASE_SCOPE)
                assert (report.targeted, report.sent, report.accepted) == (1, 1, 1)
                assert (report.opened, report.clicked, report.training_assigned, report.training_completed) == (
                    1,
                    1,
                    1,
                    1,
                )

            delivery_audit = [
                event
                for event in audit_store.list_events(limit=100)
                if event["object_id"] == str(canary_id) and event["action"] == "campaign.deliver"
            ]
            assert len(delivery_audit) == 1
            assert int(delivery_audit[0]["detail"]["sent"]) == 1
            duplicate_blocks = [
                event
                for event in audit_store.list_events(limit=100)
                if event["object_id"] == str(canary_id)
                and event["action"] == "campaign.deliver.blocked"
                and event["detail"].get("reason") == "canary_not_queued"
            ]
            assert len(duplicate_blocks) == 1

            # Mailpit v1.20 accepts exact-message deletion at this route. A
            # cleanup failure must not broaden into a mailbox-wide delete.
            cleanup_response = mailpit.request("DELETE", "/api/v1/messages", json={"IDs": [message_id]})
            assert cleanup_response.status_code == 200
            message_id = None
    finally:
        _cleanup_canary(session_factory, canary_id, template_id)
        if message_id is not None:
            with suppress(Exception), httpx.Client(base_url=mailpit_url, timeout=5.0, trust_env=False) as mailpit:
                mailpit.request("DELETE", "/api/v1/messages", json={"IDs": [message_id]})
        engine.dispose()
        audit_engine.dispose()
