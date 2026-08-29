"""Mailpit-compatible reported-message polling client.

Messages are considered reports only when they carry ``X-KP-Reported: true``
and a valid ``X-KP-Token-Hash`` header. Message bodies and mailbox addresses
are deliberately not returned to the worker.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

_TOKEN_HASH = re.compile(r"[0-9a-fA-F]{64}\Z")
_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")

_DEFAULT_MAX_PAGES = 100
_DEFAULT_MAX_SUMMARY_BYTES = 1_000_000
_DEFAULT_MAX_MESSAGE_BYTES = 1_000_000
_DEFAULT_SEEN_CAPACITY = 10_000


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
        max_pages: int = _DEFAULT_MAX_PAGES,
        max_summary_bytes: int = _DEFAULT_MAX_SUMMARY_BYTES,
        max_message_bytes: int = _DEFAULT_MAX_MESSAGE_BYTES,
        seen_capacity: int = _DEFAULT_SEEN_CAPACITY,
        cursor: str | None = None,
    ) -> None:
        if limit < 1 or max_pages < 1:
            raise ValueError("Mailpit page limit and max_pages must be positive")
        if max_summary_bytes < 1 or max_message_bytes < 1 or seen_capacity < 1:
            raise ValueError("Mailpit response limits and seen_capacity must be positive")
        if cursor is not None and _MESSAGE_ID.fullmatch(cursor) is None:
            raise ValueError("Mailpit cursor is malformed")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._limit = limit
        self._max_pages = max_pages
        self._max_summary_bytes = max_summary_bytes
        self._max_message_bytes = max_message_bytes
        self._seen_capacity = seen_capacity
        self._transport = transport
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._auth = (basic_username, basic_password or "") if basic_username else None
        self._watermark = cursor
        # Newest to oldest. This is intentionally instance-local: database
        # idempotency remains the durable replay boundary for worker restarts.
        self._seen_ids: OrderedDict[str, None] = OrderedDict()

    @property
    def cursor(self) -> str | None:
        """Newest ID from the last successful poll, suitable for persistence."""
        return self._watermark

    def poll(self) -> list[ReportedMessage]:
        """Return new reports, advancing the in-memory watermark on success.

        Mailpit orders summaries newest-first. Each poll walks offset pages
        until the prior high-water message is reached, or the current mailbox
        snapshot is exhausted. State is committed only after every required
        summary and detail response has been validated.
        """
        with httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            transport=self._transport,
            headers=self._headers,
            auth=self._auth,
        ) as client:
            reports: list[ReportedMessage] = []
            pending_seen: OrderedDict[str, None] = OrderedDict()
            poll_ids: set[str] = set()
            candidate_watermark: str | None = None
            start = 0

            for page_number in range(1, self._max_pages + 1):
                page = self._get_json(
                    client,
                    "/api/v1/messages",
                    params={"start": start, "limit": self._limit},
                    max_bytes=self._max_summary_bytes,
                    label="messages summary",
                )
                summaries, has_more = self._parse_page(page, requested_start=start)
                page_added_ids = 0
                reached_watermark = False

                for summary in summaries:
                    message_id = self._summary_id(summary)
                    if candidate_watermark is None:
                        candidate_watermark = message_id
                    if message_id in poll_ids:
                        continue
                    poll_ids.add(message_id)
                    page_added_ids += 1
                    if self._watermark is not None and message_id == self._watermark:
                        reached_watermark = True
                        break
                    if message_id in self._seen_ids:
                        continue

                    pending_seen[message_id] = None
                    detail = self._get_json(
                        client,
                        f"/api/v1/message/{message_id}",
                        max_bytes=self._max_message_bytes,
                        label="message detail",
                    )
                    report = self._parse_detail(message_id, detail)
                    if report is not None:
                        reports.append(report)

                if reached_watermark or not has_more:
                    break
                if not summaries or page_added_ids == 0:
                    raise ValueError("Mailpit pagination did not advance; later messages cannot be polled safely")
                if page_number == self._max_pages:
                    raise ValueError("Mailpit pagination exceeded max_pages; poll state was not advanced")
                start += len(summaries)
            else:  # pragma: no cover - defensive; the loop's explicit cap handles this
                raise ValueError("Mailpit pagination did not complete")

        self._commit_poll(candidate_watermark, pending_seen)
        return reports

    def _parse_page(self, page: Any, *, requested_start: int) -> tuple[list[Any], bool]:
        if not isinstance(page, dict):
            raise ValueError("Mailpit messages response is malformed")
        summaries = page.get("messages")
        if not isinstance(summaries, list):
            raise ValueError("Mailpit messages response is malformed")
        if len(summaries) > self._limit:
            raise ValueError("Mailpit messages response exceeded the requested page limit")

        response_start = page.get("start")
        if response_start is not None and (isinstance(response_start, bool) or not isinstance(response_start, int)):
            raise ValueError("Mailpit pagination start is malformed")
        if response_start is not None and response_start != requested_start:
            raise ValueError("Mailpit pagination returned the wrong offset")
        if requested_start > 0 and response_start is None:
            raise ValueError("Mailpit pagination is unsupported or returned the wrong offset")

        messages_count = page.get("messages_count")
        if messages_count is None:
            # A short first page is compatible with older/generic adapters and
            # needs no pagination. A full page is ambiguous, so request the
            # next offset and require it to be acknowledged there.
            return summaries, len(summaries) == self._limit
        if isinstance(messages_count, bool) or not isinstance(messages_count, int) or messages_count < 0:
            raise ValueError("Mailpit messages_count is malformed")
        page_end = requested_start + len(summaries)
        if page_end > messages_count:
            raise ValueError("Mailpit pagination metadata is inconsistent")
        return summaries, page_end < messages_count

    @staticmethod
    def _summary_id(summary: Any) -> str:
        if not isinstance(summary, dict):
            raise ValueError("Mailpit message summary is malformed")
        message_id = summary.get("ID")
        if not isinstance(message_id, str) or _MESSAGE_ID.fullmatch(message_id) is None:
            raise ValueError("Mailpit message summary has an invalid ID")
        return message_id

    def _commit_poll(self, watermark: str | None, pending_seen: OrderedDict[str, None]) -> None:
        combined = [*pending_seen, *(message_id for message_id in self._seen_ids if message_id not in pending_seen)]
        self._seen_ids = OrderedDict.fromkeys(combined[: self._seen_capacity])
        if watermark is not None:
            self._watermark = watermark

    @staticmethod
    def _get_json(
        client: httpx.Client,
        path: str,
        *,
        max_bytes: int,
        label: str,
        params: dict[str, int] | None = None,
    ) -> Any:
        with client.stream("GET", path, params=params) as response:
            response.raise_for_status()
            content_length = response.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_bytes = int(content_length)
                except ValueError as exc:
                    raise ValueError(f"Mailpit {label} Content-Length is malformed") from exc
                if declared_bytes < 0 or declared_bytes > max_bytes:
                    raise ValueError(f"Mailpit {label} exceeds the configured response limit")
            body = bytearray()
            for chunk in response.iter_bytes():
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise ValueError(f"Mailpit {label} exceeds the configured response limit")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Mailpit {label} response is not valid JSON") from exc

    @staticmethod
    def _parse_detail(external_id: str, detail: Any) -> ReportedMessage | None:
        if not isinstance(detail, dict):
            raise ValueError("Mailpit message detail is malformed")
        headers = detail.get("Headers", {})
        if not isinstance(headers, dict):
            raise ValueError("Mailpit message headers are malformed")

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
        except (TypeError, ValueError) as exc:
            raise ValueError("Mailpit reported message timestamp is malformed") from exc
        if reported_at.tzinfo is None:
            reported_at = reported_at.replace(tzinfo=UTC)
        return ReportedMessage(external_id=external_id, token_hash=token_hash.lower(), reported_at=reported_at)


# Backward-compatible public name for existing integrations.
MailpitReportedMessageProvider = ReportedMailboxProvider
