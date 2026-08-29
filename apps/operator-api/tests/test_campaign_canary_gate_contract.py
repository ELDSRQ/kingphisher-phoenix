from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ROUTERS = (ROOT / "apps/operator-api/src/kp_operator_api/routers.py").read_text(encoding="utf-8")
UI = (ROOT / "apps/operator-ui/src/console/app.js").read_text(encoding="utf-8")
SCHEDULE = ROUTERS[ROUTERS.index("def schedule_campaign(") : ROUTERS.index("def publish_campaign(")]
PUBLISH = ROUTERS[ROUTERS.index("def publish_campaign(") : ROUTERS.index("def test_send_campaign(")]
TEST_SEND = ROUTERS[ROUTERS.index("def test_send_campaign(") : ROUTERS.index("def recall_campaign(")]


def test_first_launch_action_queues_only_locked_canary_recipients() -> None:
    assert "CampaignCanaryRecipient.recipient_id" in SCHEDULE
    assert "recipient_scope=canary_ids" in SCHEDULE
    assert 'delivery_phase="canary"' in SCHEDULE
    assert "test_send=True" in SCHEDULE
    assert 'gate.state = "canary_queued"' in SCHEDULE
    assert 'delivery_phase="full"' not in SCHEDULE


def test_full_publication_is_distinct_and_requires_current_server_evidence() -> None:
    assert '@router.post("/campaigns/{campaign_id}/publish"' in ROUTERS
    assert 'gate.state != "canary_succeeded"' in PUBLISH
    assert "gate.canary_evidence_hash is None" in PUBLISH
    assert "gate.provider_config_hash is None" in PUBLISH
    assert "gate.canary_expires_at <= now" in PUBLISH
    assert "omit_recipient_ids=canary_ids" in PUBLISH
    assert 'delivery_phase="full"' in PUBLISH
    assert 'gate.state = "full_published"' in PUBLISH


def test_ad_hoc_test_send_is_a_fail_closed_compatibility_route() -> None:
    assert "prepare_campaign(" not in TEST_SEND
    assert "_publish_delivery_batches(" not in TEST_SEND
    assert '"durable_canary_required"' in TEST_SEND


def test_gui_uses_server_flags_for_two_explicit_phases() -> None:
    assert '"can_schedule", "can_publish", "can_test_send"' in UI
    assert 'text: "Review & run canary"' in UI
    assert 'text: "Publish full audience"' in UI
    assert "c.can_schedule === true" in UI
    assert "c.can_publish === true" in UI
    assert "`/campaigns/${campaign.campaign_id}/publish`" in UI
    assert 'text: "Send to test accounts"' not in UI
