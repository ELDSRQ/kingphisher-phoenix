"""Deterministic fixture builders.

Used by unit tests and the `make seed` script. No randomness: every fixture is
derived from an index so assertions are reproducible.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from kp_contracts.events import EventEnvelope, build_envelope
from kp_domain_models import models as dm


def make_recipient(index: int, *, department: str = "Engineering") -> dict[str, Any]:
    suffix = f"{index:04d}"
    return {
        "employee_key": f"EMP-{suffix}",
        "mailbox": f"user{suffix}@example.com",
        "display_name": f"User {suffix}",
        "department": department,
        "is_test_account": index % 20 == 0,
    }


def make_source_item(index: int, *, actor: str = "FinanciallyMotivated",
                     source_id: UUID | None = None) -> dm.SourceItem:
    body = (
        f"Advisory {index}: observed {actor} campaign using credential "
        f"harvesting lure referencing invoice for index {index}."
    )
    now = datetime.now(UTC)
    return dm.SourceItem(
        source_id=source_id or uuid5(NAMESPACE_URL, f"fixture-source-{index}"),
        publisher=f"fixture-feed-{index % 3}",
        title=f"Fixture advisory {index}",
        published_at=now - timedelta(hours=index),
        retrieved_at=now,
        sanitized_text=body,
        content_hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
        source_reference=f"https://fixtures.example/advisory/{index}",
        license_state_id=None,
        confidence=dm.Confidence.MEDIUM if index % 2 else dm.Confidence.LOW,
        claimed_actor=actor,
        claimed_target_sector="finance" if index % 2 else "technology",
        extracted_indicators={},
        quarantine_state=dm.QuarantineState.ACTIVE,
        quarantine_reason=None,
        duplicate_of=None,
    )


def make_send_batch_event(index: int) -> EventEnvelope:
    return build_envelope(
        schema="campaign.send_batch",
        payload={
            "campaign_id": f"c_{index:04d}",
            "batch_id": f"b_{index:04d}",
            "recipient_assignment_ids": [f"r_{index:04d}"],
            "template_hash": hashlib.sha256(f"template-{index}".encode()).hexdigest(),
        },
        idempotency_key=f"send-{index:04d}",
    )


def make_tracking_event(index: int) -> EventEnvelope:
    return build_envelope(
        schema="events.tracking",
        payload={
            "event_type": "opened",
            "token_hash": hashlib.sha256(f"token-{index}".encode()).hexdigest(),
            "occurred_at": datetime.now(UTC).isoformat(),
            "client_ip": "203.0.113.10",
            "user_agent": "kingphisher-test-agent/1.0",
        },
        idempotency_key=f"evt-{index:04d}",
    )
