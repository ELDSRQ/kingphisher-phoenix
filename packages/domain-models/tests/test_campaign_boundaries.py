from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import kp_domain_models
import pytest
from kp_domain_models.models import Campaign
from pydantic import ValidationError


def _campaign_fields(**overrides: object) -> dict[str, object]:
    start = datetime(2026, 8, 28, 12, tzinfo=UTC)
    fields: dict[str, object] = {
        "pattern_id": uuid4(),
        "title": "Authorized simulation",
        "sender_mailbox": "training@sender.example",
        "training_domain": "training.example",
        "schedule_start": start,
        "schedule_end": start + timedelta(hours=1),
        "max_recipients": 100,
        "expires_at": start + timedelta(hours=1),
    }
    fields.update(overrides)
    return fields


@pytest.mark.parametrize("max_recipients", [0, -1, 10_001])
def test_campaign_rejects_recipient_counts_outside_shared_boundary(max_recipients: int) -> None:
    with pytest.raises(ValidationError, match="max_recipients"):
        Campaign(**_campaign_fields(max_recipients=max_recipients))  # type: ignore[arg-type]


def test_campaign_accepts_maximum_recipient_boundary() -> None:
    campaign = Campaign(**_campaign_fields(max_recipients=10_000))  # type: ignore[arg-type]
    assert campaign.max_recipients == 10_000


def test_campaign_rejects_partial_reversed_or_naive_schedule() -> None:
    start = datetime(2026, 8, 28, 12, tzinfo=UTC)
    with pytest.raises(ValidationError, match="set together"):
        Campaign(**_campaign_fields(schedule_end=None))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="schedule_end"):
        Campaign(**_campaign_fields(schedule_end=start))  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timezone"):
        Campaign(**_campaign_fields(schedule_start=start.replace(tzinfo=None)))  # type: ignore[arg-type]


def test_campaign_rejects_expiry_before_delivery_end() -> None:
    start = datetime(2026, 8, 28, 12, tzinfo=UTC)
    with pytest.raises(ValidationError, match="expires_at"):
        Campaign(**_campaign_fields(expires_at=start + timedelta(minutes=30)))  # type: ignore[arg-type]


def test_domain_models_validate_security_boundaries_on_assignment() -> None:
    campaign = Campaign(**_campaign_fields())  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="max_recipients"):
        campaign.max_recipients = 0


def test_public_package_exports_active_models_and_state_deriver() -> None:
    assert kp_domain_models.AlertSubscription.__name__ == "AlertSubscription"
    assert kp_domain_models.training_state is not None
    assert "AlertSubscription" in kp_domain_models.__all__
    assert "training_state" in kp_domain_models.__all__
