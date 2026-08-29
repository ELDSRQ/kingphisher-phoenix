"""Strict, privacy-minimized Azure Communication Services receipt parsing.

Azure Event Grid authenticates to the HTTP ingress with its managed identity.
After validating that Entra token, the ingress signs a deterministic canonical
representation with a separate internal key before publishing it to the
private queue. This seam verifies that signature again before state mutation.
The Event Grid token and internal key therefore never enter Redis; the event ID
gives durable replay protection in the delivery-provider event store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

ACS_DELIVERY_EVENT_TYPE = "Microsoft.Communication.EmailDeliveryReportReceived"
_EVENT_ID = re.compile(r"[A-Za-z0-9._:/+-]{1,256}\Z")
_PROVIDER_ID = re.compile(r"[^\x00-\x1f\x7f]{1,512}\Z")
_STATUS_MAP = {
    "Delivered": "delivered",
    "Bounced": "bounced",
    "Suppressed": "suppressed",
    "Quarantined": "quarantined",
    "FilteredSpam": "filtered_spam",
    "Expanded": "expanded",
    "Failed": "failed",
}
_EVENT_KEYS = frozenset({"id", "eventType", "dataVersion", "metadataVersion", "eventTime", "data"})
_DATA_KEYS = frozenset({"messageId", "status", "deliveryStatusDetailsHash"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-fA-F]{64}\Z")
_MAX_EVENT_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class AcsDeliveryEvent:
    external_event_id_hash: str
    provider_message_id: str
    status: str
    status_detail_hash: str | None
    occurred_at: datetime


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("ACS delivery event time is missing or malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (OverflowError, ValueError) as exc:
        raise ValueError("ACS delivery event time is missing or malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError("ACS delivery event time must include a timezone")
    try:
        return parsed.astimezone(UTC)
    except (OverflowError, ValueError) as exc:
        raise ValueError("ACS delivery event time is missing or malformed") from exc


def parse_acs_delivery_event(
    event: object,
    *,
    supplied_signature: object,
    signing_key: bytes,
    now: datetime | None = None,
) -> AcsDeliveryEvent:
    """Authenticate and parse one Event Grid ACS delivery report.

    Recipient and sender addresses are intentionally ignored.  Free-form
    delivery details are represented only by a SHA-256 digest.
    """

    if len(signing_key) != 32:
        raise RuntimeError("ACS receipt signing key must be 256 bits")
    if not isinstance(event, dict):
        raise ValueError("ACS delivery event must be an object")
    try:
        canonical = json.dumps(
            event,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError):
        raise ValueError("ACS delivery event is malformed") from None
    if len(canonical) > _MAX_EVENT_BYTES:
        raise ValueError("ACS delivery event exceeds the configured size limit")
    expected_signature = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
    if (
        not isinstance(supplied_signature, str)
        or _SIGNATURE.fullmatch(supplied_signature) is None
        or not secrets.compare_digest(supplied_signature.lower(), expected_signature)
    ):
        raise PermissionError("ACS delivery event authentication failed")
    if set(event) != _EVENT_KEYS:
        raise ValueError("ACS delivery event contains missing or unexpected fields")
    if event.get("eventType") != ACS_DELIVERY_EVENT_TYPE:
        raise ValueError("unsupported ACS Event Grid event type")
    if event.get("dataVersion") != "1.0":
        raise ValueError("unsupported ACS Event Grid data version")
    if event.get("metadataVersion") != "1":
        raise ValueError("unsupported ACS Event Grid metadata version")
    event_id = event.get("id")
    if not isinstance(event_id, str) or _EVENT_ID.fullmatch(event_id) is None:
        raise ValueError("ACS delivery event ID is missing or malformed")
    occurred_at = _timestamp(event.get("eventTime"))
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if occurred_at > current + timedelta(minutes=5):
        raise ValueError("ACS delivery event is future-dated")
    data = event.get("data")
    if not isinstance(data, dict):
        raise ValueError("ACS delivery event data must be an object")
    if set(data) != _DATA_KEYS:
        raise ValueError("ACS delivery event data contains missing or unexpected fields")
    provider_message_id = data.get("messageId")
    if not isinstance(provider_message_id, str) or _PROVIDER_ID.fullmatch(provider_message_id) is None:
        raise ValueError("ACS delivery event provider message ID is missing or malformed")
    raw_status = data.get("status")
    if not isinstance(raw_status, str) or raw_status not in _STATUS_MAP:
        raise ValueError("ACS delivery event status is unsupported")
    detail_hash = data.get("deliveryStatusDetailsHash")
    if detail_hash is not None and (not isinstance(detail_hash, str) or _SHA256.fullmatch(detail_hash) is None):
        raise ValueError("ACS delivery status detail hash is malformed")
    return AcsDeliveryEvent(
        external_event_id_hash=hashlib.sha256(event_id.encode("utf-8")).hexdigest(),
        provider_message_id=provider_message_id,
        status=_STATUS_MAP[raw_status],
        status_detail_hash=detail_hash,
        occurred_at=occurred_at,
    )
