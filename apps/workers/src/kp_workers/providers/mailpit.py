"""Mailpit-compatible reported-message polling client.

Messages are considered reports only when they carry ``X-KP-Reported: true``
and a valid ``X-KP-Token-Hash`` header. Message bodies and mailbox addresses
are deliberately not returned to the worker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

_TOKEN_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")


@dataclass(frozen=True)
class ReportedMessage:
    external_id: str
    token_hash: str
    reported_at: datetime


class ReportedMailboxProvider:
    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 10.0,
        limit: int = 50,
        transport: httpx.BaseTransport | None = None,
        bearer_token: str | None = None,
        basic_username: str | None = None,
        basic_password: str | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._limit = limit
        self._transport = transport
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._auth = (basic_username, basic_password or "") if basic_username else None

    def poll(self) -> list[ReportedMessage]:
        with httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            transport=self._transport,
            headers=self._headers,
            auth=self._auth,
        ) as client:
            response = client.get("/api/v1/messages", params={"limit": self._limit})
            response.raise_for_status()
            summaries = response.json().get("messages", [])
            if not isinstance(summaries, list):
                raise ValueError("Mailpit messages response is malformed")
            reports: list[ReportedMessage] = []
            for summary in summaries[: self._limit]:
                if not isinstance(summary, dict) or not isinstance(summary.get("ID"), str):
                    continue
                detail_response = client.get(f"/api/v1/message/{summary['ID']}")
                detail_response.raise_for_status()
                report = self._parse_detail(summary["ID"], detail_response.json())
                if report is not None:
                    reports.append(report)
            return reports

    @staticmethod
    def _parse_detail(external_id: str, detail: Any) -> ReportedMessage | None:
        if not isinstance(detail, dict):
            return None
        headers = detail.get("Headers", {})
        if not isinstance(headers, dict):
            return None

        def first(name: str) -> str:
            value = headers.get(name, "")
            if isinstance(value, list):
                value = value[0] if value else ""
            return str(value).strip()

        if first("X-KP-Reported").lower() != "true":
            return None
        token_hash = first("X-KP-Token-Hash")
        if _TOKEN_HASH.fullmatch(token_hash) is None:
            return None
        created = detail.get("Created") or detail.get("Date")
        try:
            reported_at = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            reported_at = datetime.now(UTC)
        if reported_at.tzinfo is None:
            reported_at = reported_at.replace(tzinfo=UTC)
        return ReportedMessage(external_id=external_id, token_hash=token_hash.lower(), reported_at=reported_at)


# Backward-compatible public name for existing integrations.
MailpitReportedMessageProvider = ReportedMailboxProvider
