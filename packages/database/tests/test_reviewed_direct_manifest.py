from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

from kp_database.campaign_service import campaign_launch_review_manifest_hash


def test_delivery_mode_is_bound_without_changing_existing_canary_review_hashes() -> None:
    campaign = SimpleNamespace(
        campaign_id=uuid4(),
        title="Reviewed email",
        sender_mailbox="awareness@example.com",
        sender_display_name="Awareness",
        training_domain="training.example.com",
        schedule_start=datetime.now(UTC),
        schedule_end=datetime.now(UTC),
        timezone="UTC",
        max_recipients=2,
        roe_id=uuid4(),
        manifest_hash="c" * 64,
    )
    audience = SimpleNamespace(version=1, configuration_hash="d" * 64, manifest_hash="e" * 64)
    kwargs = {"template_approval_hash": "a" * 64, "canary_manifest_hash": "b" * 64}
    legacy = campaign_launch_review_manifest_hash(campaign, audience, **kwargs)
    campaign.delivery_mode = "canary"
    assert campaign_launch_review_manifest_hash(campaign, audience, **kwargs) == legacy
    campaign.delivery_mode = "reviewed_direct"
    direct = campaign_launch_review_manifest_hash(campaign, audience, **kwargs)
    assert direct != legacy
    campaign.sender_mailbox = "changed@example.com"
    assert campaign_launch_review_manifest_hash(campaign, audience, **kwargs) != direct
