from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta

import pytest
from kp_workers.providers.acs_events import parse_acs_delivery_event

KEY = bytes.fromhex("12" * 32)
NOW = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)


def _event(**data_overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "messageId": "acs-operation-123",
        "status": "Delivered",
        "deliveryStatusDetailsHash": hashlib.sha256(
            b'{"statusMessage":"Mailbox accepted the message for delivery"}'
        ).hexdigest(),
    }
    data.update(data_overrides)
    return {
        "id": "event-grid-event-123",
        "eventType": "Microsoft.Communication.EmailDeliveryReportReceived",
        "eventTime": NOW.isoformat(),
        "dataVersion": "1.0",
        "metadataVersion": "1",
        "data": data,
    }


def _signature(event: object, key: bytes = KEY) -> str:
    canonical = json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def test_authenticated_receipt_retains_only_minimized_evidence() -> None:
    event = _event()

    receipt = parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)

    assert receipt.provider_message_id == "acs-operation-123"
    assert receipt.status == "delivered"
    assert receipt.external_event_id_hash == hashlib.sha256(b"event-grid-event-123").hexdigest()
    assert (
        receipt.status_detail_hash
        == hashlib.sha256(b'{"statusMessage":"Mailbox accepted the message for delivery"}').hexdigest()
    )
    assert "Mailbox accepted" not in repr(receipt)


def test_receipt_signature_binds_the_exact_event_body() -> None:
    event = _event()
    signature = _signature(event)
    event["data"] = {**event["data"], "status": "Bounced"}  # type: ignore[arg-type]

    with pytest.raises(PermissionError, match="authentication failed"):
        parse_acs_delivery_event(event, supplied_signature=signature, signing_key=KEY, now=NOW)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"eventType": "Microsoft.Storage.BlobCreated"}, "unsupported"),
        ({"dataVersion": "2.0"}, "data version"),
        ({"metadataVersion": "2"}, "metadata version"),
        ({"id": "bad event id"}, "event ID"),
        ({"eventTime": (NOW + timedelta(minutes=6)).isoformat()}, "future-dated"),
        (
            {
                "data": {
                    "messageId": "acs-operation-123",
                    "status": "Unknown",
                    "deliveryStatusDetailsHash": None,
                }
            },
            "status",
        ),
    ],
)
def test_receipt_parser_rejects_unsupported_or_unbounded_input(override: dict[str, object], message: str) -> None:
    event = {**_event(), **override}

    with pytest.raises(ValueError, match=message):
        parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)


@pytest.mark.parametrize(
    "private_field",
    ["sender", "recipient", "internetMessageId", "deliveryStatusDetails", "unknown"],
)
def test_receipt_parser_rejects_non_minimized_queue_data(private_field: str) -> None:
    event = _event()
    event["data"] = {**event["data"], private_field: "must-not-enter-redis"}  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="unexpected fields"):
        parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)


@pytest.mark.parametrize("private_field", ["topic", "subject", "unknown"])
def test_receipt_parser_rejects_non_minimized_top_level_fields(private_field: str) -> None:
    event = {**_event(), private_field: "must-not-enter-redis"}

    with pytest.raises(ValueError, match="unexpected fields"):
        parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)


def test_authenticated_delayed_backlog_receipt_remains_processable() -> None:
    event = {**_event(), "eventTime": (NOW - timedelta(days=120)).isoformat()}

    receipt = parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)

    assert receipt.occurred_at == NOW - timedelta(days=120)


def test_receipt_parser_bounds_canonical_event_before_hmac_processing() -> None:
    event = _event(messageId="x" * (64 * 1024))

    with pytest.raises(ValueError, match="size limit"):
        parse_acs_delivery_event(event, supplied_signature=_signature(event), signing_key=KEY, now=NOW)


def test_receipt_parser_rejects_non_json_values_and_malformed_signatures() -> None:
    non_json = _event(messageId={"not", "json"})
    with pytest.raises(ValueError, match="event is malformed"):
        parse_acs_delivery_event(non_json, supplied_signature="0" * 64, signing_key=KEY, now=NOW)

    event = _event()
    with pytest.raises(PermissionError, match="authentication failed"):
        parse_acs_delivery_event(event, supplied_signature="z" * 200, signing_key=KEY, now=NOW)
