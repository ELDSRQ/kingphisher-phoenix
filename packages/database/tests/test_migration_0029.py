from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from types import ModuleType
from uuid import uuid4

from alembic.migration import MigrationContext
from alembic.operations import Operations
from kp_database.campaign_service import (
    campaign_canary_manifest_hash,
    campaign_launch_gate_error,
    campaign_launch_review_manifest_hash,
    template_content_approval_hash,
)
from kp_database.models import Campaign, CampaignAudience, CampaignLaunchGate, TemplateVersion
from kp_domain_models import models as dm

MIGRATION = Path(__file__).resolve().parents[1] / "alembic" / "versions" / "0029_campaign_canary_launch_gate.py"


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migration_0029", MIGRATION)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _review_objects() -> tuple[Campaign, CampaignAudience, TemplateVersion]:
    now = datetime.now(UTC)
    campaign = Campaign(
        campaign_id=uuid4(),
        pattern_id=uuid4(),
        current_template_id=uuid4(),
        title="Durable canary",
        state=dm.CampaignState.APPROVED,
        sender_mailbox="awareness@example.com",
        sender_display_name="Security team",
        roe_id=uuid4(),
        training_domain="training.example.com",
        schedule_start=now + timedelta(days=1),
        schedule_end=now + timedelta(days=2),
        timezone="UTC",
        max_recipients=25,
        manifest_hash="a" * 64,
        expires_at=now + timedelta(days=2),
    )
    audience = CampaignAudience(
        campaign_id=campaign.campaign_id,
        version=3,
        configuration_hash="b" * 64,
        manifest_hash="c" * 64,
        frozen_at=now,
        legacy_requires_configuration=False,
    )
    template = TemplateVersion(
        template_version_id=campaign.current_template_id,
        version=2,
        generator_version="test",
        prompt_template_version="test",
        model_id="test",
        input_hash="d" * 64,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    template.approval_hash = template_content_approval_hash(template)
    return campaign, audience, template


def test_canary_and_launch_hashes_bind_order_and_campaign_configuration() -> None:
    campaign, audience, template = _review_objects()
    recipient_a, recipient_b = uuid4(), uuid4()
    canary_hash = campaign_canary_manifest_hash([(recipient_a, "1" * 64), (recipient_b, "2" * 64)])
    reversed_hash = campaign_canary_manifest_hash([(recipient_b, "2" * 64), (recipient_a, "1" * 64)])
    assert canary_hash != reversed_hash

    launch_hash = campaign_launch_review_manifest_hash(
        campaign,
        audience,
        template_approval_hash=template.approval_hash or "",
        canary_manifest_hash=canary_hash,
    )
    campaign.sender_display_name = "Different sender"
    changed = campaign_launch_review_manifest_hash(
        campaign,
        audience,
        template_approval_hash=template.approval_hash or "",
        canary_manifest_hash=canary_hash,
    )
    assert launch_hash != changed


def test_legacy_or_drifted_launch_review_fails_closed() -> None:
    campaign, audience, template = _review_objects()
    assert campaign_launch_gate_error(campaign, audience, template, None) == (
        "campaign has no durable launch review; review it again"
    )
    canary_hash = campaign_canary_manifest_hash([(uuid4(), "1" * 64)])
    review_hash = campaign_launch_review_manifest_hash(
        campaign,
        audience,
        template_approval_hash=template.approval_hash or "",
        canary_manifest_hash=canary_hash,
    )
    gate = CampaignLaunchGate(
        campaign_id=campaign.campaign_id,
        review_manifest_hash=review_hash,
        content_manifest_hash=campaign.manifest_hash,
        template_approval_hash=template.approval_hash,
        audience_manifest_hash=audience.manifest_hash,
        canary_manifest_hash=canary_hash,
        roe_id=campaign.roe_id,
        state="reviewed",
    )
    assert campaign_launch_gate_error(campaign, audience, template, gate) is None
    audience.manifest_hash = "f" * 64
    assert campaign_launch_gate_error(campaign, audience, template, gate) == (
        "campaign audience changed after review; review it again"
    )


def test_migration_is_linear_additive_and_keeps_legacy_state_untrusted() -> None:
    migration = _load_migration()
    assert migration.revision == "0029_campaign_canary_gate"
    assert migration.down_revision == "0028_campaign_training_binding"
    source = MIGRATION.read_text(encoding="utf-8")
    assert "UPDATE campaign_approvals" not in source
    assert "UPDATE campaigns" not in source
    assert "DELETE FROM" not in source

    output = StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": output},
    )
    migration.op = Operations(context)
    migration.upgrade()
    sql = output.getvalue()
    assert "campaign_launch_gates" in sql
    assert "campaign_canary_recipients" in sql
    assert "launch_manifest_hash" in sql
    assert "campaign_canary_recipient_no_update" in sql


def test_model_retains_nullable_legacy_approval_binding() -> None:
    from kp_database.models import CampaignApproval

    assert CampaignApproval.__table__.c.launch_manifest_hash.nullable
    assert not CampaignLaunchGate.__table__.c.review_manifest_hash.nullable
