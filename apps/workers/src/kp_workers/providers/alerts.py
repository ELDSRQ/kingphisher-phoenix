"""SSRF-resistant, HMAC-signed outbound alert delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import httpx
from kp_sanitization.fetcher import _pinned_url, _resolve_pinned

Resolver = Callable[[str, set[str]], tuple[str, int, list[str]]]


class SignedWebhookSender:
    def __init__(
        self,
        allowed_domains: set[str],
        *,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver = _resolve_pinned,
    ) -> None:
        self._allowed_domains = {domain.lower() for domain in allowed_domains}
        self._timeout = timeout
        self._transport = transport
        self._resolver = resolver

    def send(self, destination: str, signing_secret: str, payload: dict[str, Any]) -> None:
        self._send_json(destination, signing_secret, payload)

    def send_ntfy(
        self,
        destination: str,
        signing_secret: str,
        payload: dict[str, Any],
    ) -> None:
        parsed = urlparse(destination)
        topic = parsed.path.strip("/")
        if not topic or "/" in topic or parsed.query or parsed.fragment:
            raise ValueError("ntfy destination must be an HTTPS topic URL with one path segment")
        publish_url = parsed._replace(path="/", params="", query="", fragment="").geturl()
        event_type = str(payload.get("event_type", "campaign.event"))
        campaign_id = str(payload.get("campaign_id", "unknown"))
        ntfy_payload = {
            "topic": topic,
            "title": "Kingphisher operational alert",
            "message": f"{event_type} for campaign {campaign_id}",
            "tags": ["warning", "shield"],
        }
        self._send_json(publish_url, signing_secret, ntfy_payload)

    def _send_json(
        self,
        destination: str,
        signing_secret: str,
        payload: dict[str, Any],
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        parsed = urlparse(destination)
        host, port, ips = self._resolver(destination, self._allowed_domains)
        timestamp = str(int(time.time()))
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        signature = hmac.new(signing_secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        with httpx.Client(timeout=self._timeout, follow_redirects=False, transport=self._transport) as client:
            response = client.post(
                _pinned_url(destination, host, port, ips[0]),
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Host": parsed.hostname or host,
                    "X-KP-Timestamp": timestamp,
                    "X-KP-Signature-256": f"sha256={signature}",
                    **(extra_headers or {}),
                },
                extensions={"sni_hostname": host},
            )
            response.raise_for_status()
