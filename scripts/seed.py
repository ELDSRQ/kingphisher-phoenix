"""Local development seed.

Creates a reproducible demo dataset against the dev database: a source with a
couple of advisories, a derived campaign pattern (approved), an approved
template, active recipients (including two test accounts), and an approved
campaign ready to schedule. Writes a hash-chained audit trail for each step.

Run via `make seed` (or `uv run python scripts/seed.py`) against the local dev
stack. Reads the real audit HMAC key and CipherText KEK from `OPERATOR_API_*`
env vars (populated by scripts/bootstrap_env.sh) and fails fast if they are
missing or not 256-bit — no known defaults (WS-11 / HIGH-06).
"""

from __future__ import annotations

import hashlib
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

from kp_campaign_patterns.builder import build_pattern_candidate  # noqa: E402
from kp_database.audit_store import AuditStore  # noqa: E402
from kp_database.models import (  # noqa: E402
    Campaign,
    CampaignApproval,
    CampaignPattern,
    CipherText,
    PrivacyNotice,
    Recipient,
    RetentionPolicy,
    SourceItem,
    TemplateVersion,
)
from kp_database.models import (  # noqa: E402
    Source as SourceRow,
)
from kp_database.privacy import hash_mailbox  # noqa: E402
from kp_database.session import create_db_engine, make_session_factory  # noqa: E402
from kp_domain_models import models as dm  # noqa: E402
from kp_test_fixtures.builders import make_source_item  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

SOURCE_KEY = "seed-src-kaspersky"
SOURCE_OWNER = "seed"


def _require_hex_bytes(value: str, name: str) -> bytes:
    if not value:
        raise SystemExit(f"{name} is required — run scripts/bootstrap_env.sh or set it explicitly")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a hex string") from exc
    if len(raw) != 32:
        raise SystemExit(f"{name} must be a 256-bit hex key (64 hex chars)")
    return raw


DEV_HMAC_KEY = _require_hex_bytes(
    os.environ.get("OPERATOR_API_AUDIT_HMAC_KEY", ""),
    "OPERATOR_API_AUDIT_HMAC_KEY",
)
DEV_KEK = _require_hex_bytes(
    os.environ.get("OPERATOR_API_CIPHERTEXT_KEK", ""),
    "OPERATOR_API_CIPHERTEXT_KEK",
)
RECIPIENT_HASH_SALT = _require_hex_bytes(
    os.environ.get("OPERATOR_API_RECIPIENT_HASH_SALT", ""),
    "OPERATOR_API_RECIPIENT_HASH_SALT",
)

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql+psycopg://kingphisher:kingphisher@localhost:5432/kingphisher")
AUDIT_DATABASE_URL = os.environ.get(
    "AUDIT_DATABASE_URL", "postgresql+psycopg://audit_writer:audit_writer@localhost:5432/kingphisher"
)


def main() -> None:
    engine = create_db_engine(DATABASE_URL)
    session = make_session_factory(engine)()
    audit = AuditStore(
        create_db_engine(AUDIT_DATABASE_URL),
        hmac_key=DEV_HMAC_KEY,
    )
    CipherText.configure_key(DEV_KEK)

    try:
        policy = _seed_retention_and_notice(session)
        source_id = _seed_source(session)
        pattern = _seed_pattern(session, source_id)
        template = _seed_template(session)
        campaign = _seed_campaign(session, pattern.campaign_pattern_id, template.template_version_id, policy)
        _seed_recipients(session)
        _seed_approvals(session, campaign.campaign_id, template.template_version_id)
        pending = _seed_pending_campaign(session, pattern.campaign_pattern_id, template.template_version_id, policy)

        audit.record(
            actor=SOURCE_OWNER,
            action="seed.complete",
            object_type="campaign",
            object_id=str(campaign.campaign_id),
            detail={
                "source": str(source_id),
                "pattern": str(pattern.campaign_pattern_id),
                "template": str(template.template_version_id),
            },
        )
        session.commit()

        assignment_ids, token_hashes = _prepare_campaign(session)
    finally:
        session.close()
        engine.dispose()

    print(
        "seed complete:"
        f" source={source_id} pattern={pattern.campaign_pattern_id}"
        f" template={template.template_version_id} campaign={campaign.campaign_id}"
    )
    _ = assignment_ids
    print(f"prepared campaign with {len(token_hashes)} tracking tokens")
    print(f"awaiting approval: {pending.title} ({pending.campaign_id})")
    print(
        "  Open Campaigns in the console to walk the approval flow. Under the "
        "enforce policy the security and privacy approvals must come from two "
        "different people, so a second signed-in approver is required there."
    )


def _seed_source(session: Session) -> UUID:
    existing = session.scalar(select(SourceRow).where(SourceRow.source_key == SOURCE_KEY))
    if existing is not None:
        return existing.source_id  # type: ignore[no-any-return]
    source = SourceRow(
        source_id=uuid4(),
        source_key=SOURCE_KEY,
        name="Kaspersky Threat Research Feed",
        source_type=dm.SourceType.RSS,
        base_domain="kaspersky.com",
        enabled=True,
    )
    session.add(source)
    session.commit()
    return source.source_id  # type: ignore[no-any-return]


def _seed_pattern(session: Session, source_id: UUID) -> CampaignPattern:
    existing = session.scalar(select(CampaignPattern).where(CampaignPattern.created_by == UUID(int=0)))
    if existing is not None:
        return existing
    item = make_source_item(1, source_id=source_id)
    item.source_item_id = uuid5(NAMESPACE_URL, "seed-source-item-1")
    item.title = "Credential-harvesting invoice lure reported"
    item.sanitized_text = (
        "Observed credential phishing campaign referencing a fraudulent invoice; "
        "attackers urge immediate payment through a phishing link."
    )
    item.content_hash = hashlib.sha256(item.sanitized_text.encode("utf-8")).hexdigest()
    session.add(
        SourceItem(
            source_item_id=item.source_item_id,
            source_id=source_id,
            publisher="kaspersky.com",
            title=item.title,
            published_at=item.published_at,
            retrieved_at=item.retrieved_at,
            sanitized_text=item.sanitized_text,
            content_hash=item.content_hash,
            source_reference=item.source_reference,
            confidence=dm.Confidence.HIGH,
            claimed_actor="FinanciallyMotivated",
            claimed_target_sector="finance",
            extracted_indicators={},
            quarantine_state=dm.QuarantineState.ACTIVE,
        )
    )
    session.flush()

    candidate = build_pattern_candidate(item)
    pattern = CampaignPattern(
        campaign_pattern_id=uuid5(NAMESPACE_URL, "seed-pattern-invoice"),
        pattern_version=candidate.pattern_version,
        lure_category=candidate.lure_category,
        impersonation_category="IT Department",
        target_role_category=candidate.target_role_category,
        emotional_triggers=candidate.emotional_triggers,
        requested_action=candidate.requested_action,
        delivery_method="email",
        warning_cues=candidate.warning_cues,
        actor_type=candidate.actor_type,
        sector_targeting="finance",
        attack_mapping=candidate.attack_mapping,
        confidence=dm.Confidence.HIGH,
        supporting_evidence=candidate.supporting_evidence,
        prohibited_content_indicators=[],
        approval_state=dm.PatternApprovalState.APPROVED,
        approved_by=uuid5(NAMESPACE_URL, "seed-approver"),
        approved_at=datetime.now(UTC),
        created_by=UUID(int=0),
    )
    session.add(pattern)
    session.commit()
    return pattern


def _seed_template(session: Session) -> TemplateVersion:
    existing = session.scalar(select(TemplateVersion).where(TemplateVersion.idempotency_key == "seed-template"))
    if existing is not None:
        # Earlier local seeds hard-coded training.local and bypassed click attribution.
        existing.safe_html = (
            "<p>Dear {{ recipient.first_name }}, our records show an outstanding invoice "
            "that requires review.</p>"
            "<p>This is a training simulation. "
            '<a href="{{ tracking.click_url }}">Complete the awareness module</a>.</p>'
        )
        existing.plain_text = (
            "Dear {{ recipient.first_name }}, our records show an outstanding invoice "
            "that requires review. This is a training simulation — "
            "learn more at {{ tracking.click_url }}."
        )
        session.commit()
        return existing
    template = TemplateVersion(
        template_version_id=uuid5(NAMESPACE_URL, "seed-template"),
        version=1,
        idempotency_key="seed-template",
        generator_version="0.1.0",
        prompt_template_version="0.1.0",
        model_id="mock-ai",
        input_hash=hashlib.sha256(b"seed-pattern-invoice").hexdigest(),
        raw_proposal={
            "subject": "Invoice requires immediate review",
            "plain_text": (
                "Dear {{ recipient.first_name }}, our records show an outstanding invoice "
                "that requires review. This is a training simulation — "
                "learn more at {{ tracking.training_url }}."
            ),
            "safe_html": (
                "<p>Dear {{ recipient.first_name }}, our records show an outstanding invoice "
                "that requires review.</p>"
                "<p>This is a training simulation. "
                '<a href="{{ tracking.training_url }}">Complete the awareness module</a>.</p>'
            ),
        },
        safe_html=(
            "<p>Dear {{ recipient.first_name }}, our records show an outstanding invoice "
            "that requires review.</p>"
            "<p>This is a training simulation. "
            '<a href="{{ tracking.click_url }}">Complete the awareness module</a>.</p>'
        ),
        plain_text=(
            "Dear {{ recipient.first_name }}, our records show an outstanding invoice "
            "that requires review. This is a training simulation — "
            "learn more at {{ tracking.click_url }}."
        ),
        subject="Invoice requires immediate review",
        synthetic_sender_display="Accounts Payable",
        learning_objectives=["identify urgent-invoice lures", "report suspicious invoices"],
        warning_cues=["urgent-language", "unexpected-sender"],
        training_explanation="Fraudulent invoices are a top lure; verify with the sender out-of-band.",
        approval_hash=hashlib.sha256(b"seed-template").hexdigest(),
        approval_state=dm.TemplateApprovalState.APPROVED,
        unicode_validation={},
    )
    session.add(template)
    session.commit()
    return template


def _seed_retention_and_notice(session: Session) -> RetentionPolicy:
    policy = session.scalar(select(RetentionPolicy).where(RetentionPolicy.is_default.is_(True)).limit(1))
    if policy is None:
        policy = RetentionPolicy(
            retention_policy_id=uuid4(),
            name="Default",
            data_category="recipient_assignments",
            retention_days=365,
            is_default=True,
            description="Delivered assignments, tracking tokens, and interaction events are purged "
            "365 days after delivery.",
        )
        session.add(policy)
    notice = session.scalar(select(PrivacyNotice).where(PrivacyNotice.is_current.is_(True)).limit(1))
    if notice is None:
        session.add(
            PrivacyNotice(
                notice_id=uuid4(),
                version=1,
                notice_text=(
                    "Security-awareness simulations collect limited personal data (work mailbox, "
                    "department, and interaction events) to deliver and measure the exercises. Simulated "
                    "lures are clearly presented as training and participation is disclosed to your "
                    "administrator. Data is retained no longer than 365 days and can be exported or "
                    "deleted on request within 45 days; contact your administrator to exercise any "
                    "data-subject right."
                ),
                effective_at=datetime.now(UTC),
                is_current=True,
            )
        )
    session.commit()
    return policy


def _seed_campaign(session: Session, pattern_id: UUID, template_id: UUID, policy: RetentionPolicy) -> Campaign:
    existing = session.scalar(select(Campaign).where(Campaign.title == "Q3 Invoice Lure Drill"))
    if existing is not None:
        return existing
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid5(NAMESPACE_URL, "seed-campaign-invoice"),
        pattern_id=pattern_id,
        current_template_id=template_id,
        title="Q3 Invoice Lure Drill",
        state=dm.CampaignState.APPROVED,
        sender_mailbox="security-drills@example.com",
        training_domain="training.local",
        schedule_start=now - timedelta(days=1),
        schedule_end=now + timedelta(days=13),
        timezone="UTC",
        max_recipients=100_000,
        retention_policy_id=policy.retention_policy_id,
        manifest_hash=hashlib.sha256(b"seed-campaign-invoice").hexdigest(),
        created_by=UUID(int=0),
        expires_at=now + timedelta(days=14),
    )
    session.add(campaign)
    session.commit()
    return campaign


#: A second seeded author, distinct from the console operator
#: (CONSOLE_OPERATOR_UUID in console.py). The demo campaign below must not be
#: authored by whoever signs in, or the self-approval rule blocks the very flow
#: it exists to demonstrate.
SEED_SECOND_ADMIN = uuid5(NAMESPACE_URL, "seed-admin-campaign-author")


def _seed_pending_campaign(session: Session, pattern_id: UUID, template_id: UUID, policy: RetentionPolicy) -> Campaign:
    """A campaign awaiting approval, so the two-person flow is demonstrable.

    The other seeded campaign arrives pre-approved, which means a fresh install
    has nothing to approve and the approval screens can never be exercised.
    """
    title = "Q3 Credential Harvest Drill (awaiting approval)"
    existing = session.scalar(select(Campaign).where(Campaign.title == title))
    if existing is not None:
        return existing
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid5(NAMESPACE_URL, "seed-campaign-pending"),
        pattern_id=pattern_id,
        current_template_id=template_id,
        title=title,
        state=dm.CampaignState.PENDING_APPROVAL,
        sender_mailbox="security-drills@example.com",
        training_domain="training.local",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=15),
        timezone="UTC",
        max_recipients=100_000,
        retention_policy_id=policy.retention_policy_id,
        manifest_hash=hashlib.sha256(b"seed-campaign-pending").hexdigest(),
        created_by=SEED_SECOND_ADMIN,
        expires_at=now + timedelta(days=16),
    )
    session.add(campaign)
    session.commit()
    return campaign


def _seed_recipients(session: Session) -> list[Recipient]:
    created: list[Recipient] = []
    roster = [
        ("user0001@example.com", "Alex Rivera", "Engineering", False),
        ("user0002@example.com", "Jordan Lee", "Finance", False),
        ("user0003@example.com", "Sam Chen", "Marketing", False),
        ("test+batch1@example.com", "Batch Test 1", "QA", True),
        ("test+batch2@example.com", "Batch Test 2", "QA", True),
    ]
    for idx, (mailbox, name, department, is_test) in enumerate(roster):
        key = hash_mailbox(mailbox, RECIPIENT_HASH_SALT)
        existing = session.scalar(select(Recipient).where(Recipient.mailbox_sha256 == key))
        if existing is not None:
            created.append(existing)
            continue
        recipient = Recipient(
            recipient_id=uuid5(NAMESPACE_URL, f"seed-recipient-{idx}"),
            employee_key=mailbox.lower(),
            mailbox=mailbox,
            mailbox_sha256=key,
            display_name=name,
            department=department,
            is_test_account=is_test,
            status=dm.RecipientStatus.ACTIVE,
        )
        session.add(recipient)
        created.append(recipient)
    session.commit()
    return created


def _seed_approvals(session: Session, campaign_id: UUID, template_id: UUID) -> None:
    existing = session.scalar(
        select(CampaignApproval).where(
            CampaignApproval.campaign_id == campaign_id,
            CampaignApproval.approval_type == dm.ApprovalType.SECURITY,
        )
    )
    if existing is not None:
        return
    now = datetime.now(UTC)
    for approval_type in (dm.ApprovalType.SECURITY, dm.ApprovalType.PRIVACY, dm.ApprovalType.HR):
        session.add(
            CampaignApproval(
                campaign_approval_id=uuid4(),
                campaign_id=campaign_id,
                approval_type=approval_type,
                approver_id=uuid5(NAMESPACE_URL, f"seed-approver-{approval_type.value}"),
                decision=dm.ApprovalDecision.APPROVED,
                rationale="seed demo dataset",
                decided_at=now,
                template_version_id=template_id,
            )
        )
    session.commit()


def _prepare_campaign(session: Session) -> tuple[list[str], list[str]]:
    from kp_database.campaign_service import prepare_campaign

    campaign = session.scalar(select(Campaign).where(Campaign.title == "Q3 Invoice Lure Drill"))
    if campaign is None:
        return [], []
    prepared = prepare_campaign(
        session, campaign, tracking_base_url="http://localhost:8001", include_test_accounts=True
    )
    return [p.assignment_id for p in prepared], [p.token_hash for p in prepared]


if __name__ == "__main__":
    main()
