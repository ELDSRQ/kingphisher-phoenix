"""Bounded, data-minimizing reply-mailbox polling clients.

A recipient reply is correlated to a sent simulated-phishing message purely by
header references: the inbound reply's ``In-Reply-To`` and ``References``
headers carry the RFC822 Message-ID(s) of the message it answers. These clients
return only those referenced Message-IDs together with the provider's opaque
message id and the received time. The reply body and the sender address are
deliberately never read or returned — nothing identifying the replier leaves
the mailbox.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlparse

import httpx
from azure.core.credentials import TokenCredential
from azure.identity import ManagedIdentityCredential

_GRAPH_HOST = "graph.microsoft.com"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "mock-graph"})
_JSON_MEDIA_TYPE = re.compile(r"application/(?:[A-Za-z0-9!#$&^_.+-]+\+)?json\Z", re.IGNORECASE)
_MESSAGE_SELECT = "id,receivedDateTime,internetMessageId,internetMessageHeaders"
#: RFC822 msg-id token: angle-bracketed, no spaces or nested brackets. We keep
#: the brackets because DeliveryReportCorrelation.message_id is stored in the
#: same ``<local@domain>`` form.
_MESSAGE_ID_TOKEN = re.compile(r"<[^<>\s]{1,996}>")
_MAILPIT_MESSAGE_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_REFERENCE_HEADERS = frozenset({"in-reply-to", "references"})
_MAX_REFERENCES = 64
_MAX_CURSOR_CHARS = 512


@dataclass(frozen=True)
class ReplyCandidate:
    """One inbound reply reduced to correlation-only evidence."""

    external_id: str
    received_at: datetime
    #: Referenced sent Message-IDs, angle-bracketed, de-duplicated, bounded.
    referenced_message_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReplyMailboxPollResult:
    status: Literal["complete", "truncated", "error"]
    messages: tuple[ReplyCandidate, ...]
    cursor: str | None
    cursor_kind: Literal["watermark"] | None
    pages: int
    rejected_count: int
    error_code: str | None = None


def _extract_references(values: list[str]) -> tuple[str, ...]:
    """Collect bounded, de-duplicated angle-bracketed Message-IDs from headers."""

    seen: OrderedDict[str, None] = OrderedDict()
    for value in values:
        if not isinstance(value, str):
            continue
        for match in _MESSAGE_ID_TOKEN.findall(value):
            if match not in seen:
                seen[match] = None
            if len(seen) >= _MAX_REFERENCES:
                return tuple(seen)
    return tuple(seen)


def _parse_received(raw: Any) -> datetime | None:
    if not isinstance(raw, str) or len(raw) > 64:
        return None
    try:
        received_at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (OverflowError, ValueError):
        return None
    if received_at.tzinfo is None:
        return None
    try:
        return received_at.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


class Microsoft365ReplyMailboxError(RuntimeError):
    def __init__(self, code: str, *, http_status: int | None = None) -> None:
        super().__init__(f"Microsoft Graph reply mailbox request failed ({code})")
        self.code = code
        self.http_status = http_status


class Microsoft365ReplyMailboxProvider:
    """Read inbound replies header-only, newest-first, bounded by a watermark.

    The durable replay boundary is :class:`kp_database.models.ReplyMailReceipt`;
    the watermark cursor is an efficiency hint (the newest opaque message id
    already seen), so a lost or stale cursor cannot double-record a reply.
    """

    def __init__(
        self,
        base_url: str,
        *,
        mailbox_id: str,
        folder_id: str = "inbox",
        bearer_token: str | None = None,
        timeout: float = 10.0,
        page_size: int = 50,
        max_pages: int = 20,
        max_messages: int = 1000,
        max_response_bytes: int = 2 * 1024 * 1024,
        max_retries: int = 3,
        max_retry_after_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        credential: TokenCredential | None = None,
        managed_identity_client_id: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed = urlparse(base_url)
        hostname = parsed.hostname.lower() if parsed.hostname else None
        local = hostname in _LOCAL_HOSTS or bool(hostname and hostname.endswith(".localhost"))
        if (
            parsed.scheme not in {"http", "https"}
            or hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or (parsed.scheme != "https" and not local)
        ):
            raise ValueError("Microsoft Graph base URL must use HTTPS")
        if not mailbox_id or len(mailbox_id) > 320 or any(ord(character) < 32 for character in mailbox_id):
            raise ValueError("reply mailbox identifier is malformed")
        if not folder_id or len(folder_id) > 256 or any(ord(character) < 32 for character in folder_id):
            raise ValueError("reply mailbox folder identifier is malformed")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Microsoft Graph timeout must be positive")
        if page_size < 1 or page_size > 999 or max_pages < 1 or max_messages < 1:
            raise ValueError("Microsoft Graph reply mailbox page and message limits are invalid")
        if max_response_bytes < 1:
            raise ValueError("Microsoft Graph reply mailbox byte limit must be positive")
        if max_retries < 0 or not math.isfinite(max_retry_after_seconds) or max_retry_after_seconds < 0:
            raise ValueError("Microsoft Graph reply mailbox retry limits are invalid")

        self._base_url = base_url.rstrip("/") + "/"
        mailbox = quote(mailbox_id, safe="")
        folder = quote(folder_id, safe="")
        self._messages_url = urljoin(self._base_url, f"users/{mailbox}/mailFolders/{folder}/messages")
        self._timeout = timeout
        self._page_size = page_size
        self._max_pages = max_pages
        self._max_messages = max_messages
        self._max_response_bytes = max_response_bytes
        self._max_retries = max_retries
        self._max_retry_after_seconds = max_retry_after_seconds
        self._transport = transport
        self._sleep = sleep

        explicit_auth = bool(bearer_token)
        microsoft_graph = parsed.scheme == "https" and hostname == _GRAPH_HOST and parsed.port in (None, 443)
        if not local and not microsoft_graph and not explicit_auth:
            raise ValueError("non-Microsoft Graph endpoints require an explicit bearer token")
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._credential: TokenCredential | None = None
        if microsoft_graph and not explicit_auth:
            client_id = (managed_identity_client_id or os.getenv("KP_WORKER_REPLY_MAILBOX_CLIENT_ID", "") or "").strip()
            if credential is None and not client_id:
                raise ValueError("Microsoft Graph reply mailbox requires the mailbox managed identity client ID")
            # Keep the mailbox permission on its dedicated user-assigned identity
            # rather than letting DefaultAzureCredential fall back elsewhere.
            self._credential = credential or ManagedIdentityCredential(client_id=client_id)

    def _request_headers(self) -> dict[str, str]:
        if self._credential is None:
            return dict(self._headers)
        try:
            token = self._credential.get_token(_GRAPH_SCOPE)
        except Exception:
            raise Microsoft365ReplyMailboxError("authentication") from None
        if not token.token:
            raise Microsoft365ReplyMailboxError("authentication")
        return {"Authorization": f"Bearer {token.token}"}

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        raw = response.headers.get("retry-after")
        if raw is None:
            delay = min(float(2**attempt), self._max_retry_after_seconds)
        else:
            try:
                delay = float(raw)
            except ValueError:
                raise Microsoft365ReplyMailboxError("retry_after") from None
        if not math.isfinite(delay) or delay < 0 or delay > self._max_retry_after_seconds:
            raise Microsoft365ReplyMailboxError("retry_after")
        return delay

    def _request_json(self, client: httpx.Client, url: str, *, params: dict[str, str] | None) -> dict[str, Any]:
        for attempt in range(self._max_retries + 1):
            try:
                with client.stream("GET", url, params=params, headers=self._request_headers()) as response:
                    if response.status_code == 429:
                        if attempt >= self._max_retries:
                            raise Microsoft365ReplyMailboxError("retry_limit", http_status=429)
                        delay = self._retry_delay(response, attempt)
                    elif response.is_error:
                        raise Microsoft365ReplyMailboxError("http", http_status=response.status_code)
                    else:
                        declared_type = response.headers.get("content-type")
                        if declared_type:
                            media_type = declared_type.split(";", 1)[0].strip().lower()
                            if _JSON_MEDIA_TYPE.fullmatch(media_type) is None:
                                raise Microsoft365ReplyMailboxError("content_type")
                        declared = response.headers.get("content-length")
                        if declared is not None:
                            try:
                                declared_bytes = int(declared)
                            except ValueError:
                                raise Microsoft365ReplyMailboxError("malformed_response") from None
                            if declared_bytes < 0 or declared_bytes > self._max_response_bytes:
                                raise Microsoft365ReplyMailboxError("response_too_large")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if len(body) + len(chunk) > self._max_response_bytes:
                                raise Microsoft365ReplyMailboxError("response_too_large")
                            body.extend(chunk)
                        try:
                            payload = json.loads(body)
                        except (MemoryError, RecursionError, UnicodeDecodeError, json.JSONDecodeError):
                            raise Microsoft365ReplyMailboxError("malformed_response") from None
                        if not isinstance(payload, dict):
                            raise Microsoft365ReplyMailboxError("malformed_response")
                        return payload
            except Microsoft365ReplyMailboxError:
                raise
            except httpx.HTTPError:
                raise Microsoft365ReplyMailboxError("transport") from None
            self._sleep(delay)
        raise Microsoft365ReplyMailboxError("retry_limit")

    def poll(self, cursor: str | None = None) -> ReplyMailboxPollResult:
        try:
            return self._poll(cursor)
        except Microsoft365ReplyMailboxError as exc:
            return ReplyMailboxPollResult(
                status="error",
                messages=(),
                cursor=None,
                cursor_kind=None,
                pages=0,
                rejected_count=0,
                error_code=exc.code,
            )

    def _poll(self, cursor: str | None) -> ReplyMailboxPollResult:
        watermark = cursor if cursor and len(cursor) <= _MAX_CURSOR_CHARS else None
        candidates: list[ReplyCandidate] = []
        seen_ids: set[str] = set()
        newest_id: str | None = None
        rejected = 0
        pages = 0
        start = 0
        reached_watermark = False
        truncated = False

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            while pages < self._max_pages:
                params = {
                    "$select": _MESSAGE_SELECT,
                    "$top": str(self._page_size),
                    "$skip": str(start),
                    "$orderby": "receivedDateTime desc",
                }
                payload = self._request_json(client, self._messages_url, params=params)
                pages += 1
                raw_items = payload.get("value")
                if not isinstance(raw_items, list):
                    raise Microsoft365ReplyMailboxError("malformed_response")
                if len(raw_items) > self._page_size:
                    raise Microsoft365ReplyMailboxError("page_limit")
                for raw in raw_items:
                    candidate, external_id = self._parse(raw)
                    if external_id is None:
                        rejected += 1
                        continue
                    if newest_id is None:
                        newest_id = external_id
                    if watermark is not None and external_id == watermark:
                        reached_watermark = True
                        break
                    if external_id in seen_ids:
                        continue
                    seen_ids.add(external_id)
                    if candidate is None:
                        # A well-formed message with no reference header is not a
                        # correlatable reply; count it, do not surface it.
                        rejected += 1
                        continue
                    if len(candidates) >= self._max_messages:
                        truncated = True
                        break
                    candidates.append(candidate)
                if reached_watermark or truncated:
                    break
                has_more = len(raw_items) == self._page_size and bool(payload.get("@odata.nextLink"))
                if not has_more:
                    break
                start += len(raw_items)
            else:
                truncated = True

        next_cursor = newest_id if not truncated else watermark
        return ReplyMailboxPollResult(
            status="truncated" if truncated else "complete",
            messages=tuple(candidates),
            cursor=next_cursor,
            cursor_kind="watermark" if next_cursor else None,
            pages=pages,
            rejected_count=rejected,
        )

    @staticmethod
    def _parse(raw: Any) -> tuple[ReplyCandidate | None, str | None]:
        if not isinstance(raw, dict):
            return None, None
        external_id = raw.get("id")
        if (
            not isinstance(external_id, str)
            or not external_id
            or len(external_id) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in external_id)
        ):
            return None, None
        received_at = _parse_received(raw.get("receivedDateTime"))
        if received_at is None:
            return None, external_id
        headers = raw.get("internetMessageHeaders")
        values: list[str] = []
        if isinstance(headers, list):
            for header in headers:
                if not isinstance(header, dict):
                    continue
                name = header.get("name")
                value = header.get("value")
                if isinstance(name, str) and name.strip().lower() in _REFERENCE_HEADERS and isinstance(value, str):
                    values.append(value)
        references = _extract_references(values)
        if not references:
            return None, external_id
        return ReplyCandidate(external_id=external_id, received_at=received_at, referenced_message_ids=references), (
            external_id
        )


class MailpitReplyMailboxProvider:
    """Mailpit-compatible reply poller for local/dev reply ingestion.

    Walks the mailbox newest-first, reading each message's headers only, until
    the prior high-water id is reached or the snapshot is exhausted. Message
    bodies and sender addresses are never returned.
    """

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
        max_pages: int = 100,
        max_summary_bytes: int = 1_000_000,
        max_message_bytes: int = 1_000_000,
        cursor: str | None = None,
    ) -> None:
        if limit < 1 or max_pages < 1:
            raise ValueError("Mailpit reply page limit and max_pages must be positive")
        if max_summary_bytes < 1 or max_message_bytes < 1:
            raise ValueError("Mailpit reply response limits must be positive")
        if cursor is not None and _MAILPIT_MESSAGE_ID.fullmatch(cursor) is None:
            raise ValueError("Mailpit reply cursor is malformed")
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._limit = limit
        self._max_pages = max_pages
        self._max_summary_bytes = max_summary_bytes
        self._max_message_bytes = max_message_bytes
        self._transport = transport
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._auth = (basic_username, basic_password or "") if basic_username else None
        self._watermark = cursor

    @property
    def cursor(self) -> str | None:
        return self._watermark

    def poll(self) -> list[ReplyCandidate]:
        with httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            transport=self._transport,
            headers=self._headers,
            auth=self._auth,
        ) as client:
            candidates: list[ReplyCandidate] = []
            poll_ids: set[str] = set()
            candidate_watermark: str | None = None
            start = 0

            for _page in range(self._max_pages):
                page = self._get_json(
                    client,
                    "/api/v1/messages",
                    params={"start": start, "limit": self._limit},
                    max_bytes=self._max_summary_bytes,
                    label="messages summary",
                )
                summaries, has_more = self._parse_page(page, requested_start=start)
                page_added = 0
                reached_watermark = False
                for summary in summaries:
                    message_id = self._summary_id(summary)
                    if candidate_watermark is None:
                        candidate_watermark = message_id
                    if message_id in poll_ids:
                        continue
                    poll_ids.add(message_id)
                    page_added += 1
                    if self._watermark is not None and message_id == self._watermark:
                        reached_watermark = True
                        break
                    detail = self._get_json(
                        client,
                        f"/api/v1/message/{message_id}",
                        max_bytes=self._max_message_bytes,
                        label="message detail",
                    )
                    candidate = self._parse_detail(message_id, detail)
                    if candidate is not None:
                        candidates.append(candidate)
                if reached_watermark or not has_more:
                    break
                if not summaries or page_added == 0:
                    raise ValueError("Mailpit reply pagination did not advance")
                start += len(summaries)
            else:  # pragma: no cover - defensive; explicit cap handles this
                raise ValueError("Mailpit reply pagination did not complete")

        if candidate_watermark is not None:
            self._watermark = candidate_watermark
        return candidates

    def _parse_page(self, page: Any, *, requested_start: int) -> tuple[list[Any], bool]:
        if not isinstance(page, dict):
            raise ValueError("Mailpit reply messages response is malformed")
        summaries = page.get("messages")
        if not isinstance(summaries, list) or len(summaries) > self._limit:
            raise ValueError("Mailpit reply messages response is malformed")
        response_start = page.get("start")
        if response_start is not None and (isinstance(response_start, bool) or not isinstance(response_start, int)):
            raise ValueError("Mailpit reply pagination start is malformed")
        if response_start is not None and response_start != requested_start:
            raise ValueError("Mailpit reply pagination returned the wrong offset")
        messages_count = page.get("messages_count")
        if messages_count is None:
            return summaries, len(summaries) == self._limit
        if isinstance(messages_count, bool) or not isinstance(messages_count, int) or messages_count < 0:
            raise ValueError("Mailpit reply messages_count is malformed")
        page_end = requested_start + len(summaries)
        if page_end > messages_count:
            raise ValueError("Mailpit reply pagination metadata is inconsistent")
        return summaries, page_end < messages_count

    @staticmethod
    def _summary_id(summary: Any) -> str:
        if not isinstance(summary, dict):
            raise ValueError("Mailpit reply message summary is malformed")
        message_id = summary.get("ID")
        if not isinstance(message_id, str) or _MAILPIT_MESSAGE_ID.fullmatch(message_id) is None:
            raise ValueError("Mailpit reply message summary has an invalid ID")
        return message_id

    def _get_json(
        self,
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
    def _parse_detail(external_id: str, detail: Any) -> ReplyCandidate | None:
        if not isinstance(detail, dict):
            raise ValueError("Mailpit reply message detail is malformed")
        headers = detail.get("Headers", {})
        if not isinstance(headers, dict):
            raise ValueError("Mailpit reply message headers are malformed")
        values: list[str] = []
        for name, value in headers.items():
            if not isinstance(name, str) or name.strip().lower() not in _REFERENCE_HEADERS:
                continue
            if isinstance(value, list):
                values.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str):
                values.append(value)
        references = _extract_references(values)
        if not references:
            return None
        created = detail.get("Created") or detail.get("Date")
        received_at = _parse_received(str(created) if created is not None else None)
        if received_at is None:
            raise ValueError("Mailpit reply message timestamp is malformed")
        return ReplyCandidate(external_id=external_id, received_at=received_at, referenced_message_ids=references)
