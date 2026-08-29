"""Keep development seed data on the production canary lifecycle."""

from pathlib import Path

SEED_SOURCE = (Path(__file__).resolve().parents[1] / "scripts" / "seed.py").read_text(encoding="utf-8")


def test_seed_binds_both_demo_campaigns_to_durable_launch_reviews() -> None:
    assert SEED_SOURCE.count("bind_campaign_launch_review(session,") >= 2
    assert "launch_gate.review_manifest_hash" in SEED_SOURCE
    assert "approval.launch_manifest_hash = launch_manifest_hash" in SEED_SOURCE


def test_seed_never_prepares_or_queues_full_audience_tracking_tokens() -> None:
    assert "def _prepare_campaign(" not in SEED_SOURCE
    assert "from kp_database.campaign_service import prepare_campaign" not in SEED_SOURCE
    assert "run its locked canary from Campaigns" in SEED_SOURCE


def test_seed_does_not_rewind_launched_campaigns() -> None:
    assert "Seeding must never rewind a scheduled/active/terminal campaign" in SEED_SOURCE
    assert "existing launched seed campaign has no durable launch review" in SEED_SOURCE
