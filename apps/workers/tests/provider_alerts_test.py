from __future__ import annotations

import hashlib
import hmac
import json

import httpx
import pytest
from kp_sanitization.fetcher import DomainNotAllowedError
from kp_workers.providers.alerts import SignedWebhookSender


def test_signed_webhook_uses_pinned_ip_and_verifiable_signature() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["host"] = request.headers["host"]
        captured["timestamp"] = request.headers["x-kp-timestamp"]
        captured["signature"] = request.headers["x-kp-signature-256"]
        captured["body"] = request.content
        return httpx.Response(204)

    sender = SignedWebhookSender(
        {"hooks.example.com"},
        transport=httpx.MockTransport(handler),
        resolver=lambda url, allowlist: ("hooks.example.com", 443, ["203.0.113.10"]),
    )
    sender.send("https://hooks.example.com/kp", "secret", {"event_type": "campaign.scheduled"})

    assert captured["url"] == "https://203.0.113.10/kp"
    assert captured["host"] == "hooks.example.com"
    expected = hmac.new(
        b"secret", str(captured["timestamp"]).encode() + b"." + bytes(captured["body"]), hashlib.sha256
    ).hexdigest()
    assert captured["signature"] == f"sha256={expected}"


def test_signed_webhook_fails_closed_without_allowlisted_domain() -> None:
    sender = SignedWebhookSender(set())
    with pytest.raises(DomainNotAllowedError):
        sender.send("https://hooks.example.com/kp", "secret", {"event_type": "campaign.scheduled"})


def test_ntfy_delivery_translates_event_to_publish_schema() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = request.headers
        captured["body"] = request.content
        return httpx.Response(200)

    sender = SignedWebhookSender(
        {"ntfy.sh"},
        transport=httpx.MockTransport(handler),
        resolver=lambda url, allowlist: ("ntfy.sh", 443, ["203.0.113.20"]),
    )
    sender.send_ntfy(
        "https://ntfy.sh/kp-test-topic",
        "secret",
        {"event_type": "campaign.scheduled", "campaign_id": "campaign-123"},
    )

    assert captured["url"] == "https://203.0.113.20/"
    body = json.loads(bytes(captured["body"]))
    assert body == {
        "message": "campaign.scheduled for campaign campaign-123",
        "tags": ["warning", "shield"],
        "title": "Kingphisher operational alert",
        "topic": "kp-test-topic",
    }
    headers = captured["headers"]
    assert headers["host"] == "ntfy.sh"
    assert "authorization" not in headers
    expected = hmac.new(
        b"secret", headers["x-kp-timestamp"].encode() + b"." + bytes(captured["body"]), hashlib.sha256
    ).hexdigest()
    assert headers["x-kp-signature-256"] == f"sha256={expected}"


@pytest.mark.parametrize(
    "destination",
    ["https://ntfy.sh", "https://ntfy.sh/one/two", "https://ntfy.sh/topic?token=secret"],
)
def test_ntfy_delivery_rejects_invalid_topic_urls(destination: str) -> None:
    sender = SignedWebhookSender({"ntfy.sh"})
    with pytest.raises(ValueError, match="ntfy destination"):
        sender.send_ntfy(destination, "secret", {"event_type": "campaign.scheduled"})
