"""Bounded Microsoft Graph provider for a reported-phishing mailbox."""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlparse

import httpx
from azure.core.credentials import TokenCredential
from azure.identity import ManagedIdentityCredential

from kp_workers.providers.reported_mime import ReportedMimeError, ReportedMimeParser, ReportedMimeResult

_GRAPH_HOST = "graph.microsoft.com"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "mock-graph"})
_MESSAGE_SELECT = "id,receivedDateTime,internetMessageId,hasAttachments"
_JSON_MEDIA_TYPE = re.compile(r"application/(?:[A-Za-z0-9!#$&^_.+-]+\+)?json\Z", re.IGNORECASE)
_MIME_MEDIA_TYPES = frozenset({"application/octet-stream", "message/rfc822"})
_MAX_CURSOR_URL_CHARS = 16 * 1024


@dataclass(frozen=True)
class ReportedMailboxMessage:
    external_id: str
    received_at: datetime
    internet_message_id: str | None
    mime: ReportedMimeResult


@dataclass(frozen=True)
class ReportedMailboxPollResult:
    status: Literal["complete", "truncated", "error"]
    messages: tuple[ReportedMailboxMessage, ...]
    cursor: str | None
    cursor_kind: Literal["next", "delta"] | None
    pages: int
    rejected_count: int
    duplicate_count: int
    removed_count: int
    error_code: str | None = None

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    @property
    def truncated(self) -> bool:
        return self.status == "truncated"


class Microsoft365MailboxError(RuntimeError):
    def __init__(self, code: str, *, http_status: int | None = None) -> None:
        super().__init__(f"Microsoft Graph mailbox request failed ({code})")
        self.code = code
        self.http_status = http_status


class Microsoft365ReportedMailboxProvider:
    """Read report messages without assigning trust to extracted evidence.

    The caller must persist a returned delta cursor only after committing a
    complete result. A truncated result with a next cursor is a fully fetched
    page segment; a truncated result without a cursor must be retried with a
    larger bound. Error results never expose partially fetched messages.
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
        max_mime_bytes: int = 5 * 1024 * 1024,
        max_retries: int = 3,
        max_retry_after_seconds: float = 5.0,
        transport: httpx.BaseTransport | None = None,
        credential: TokenCredential | None = None,
        managed_identity_client_id: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
        mime_parser: ReportedMimeParser | None = None,
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
            raise ValueError("reported mailbox identifier is malformed")
        if not folder_id or len(folder_id) > 256 or any(ord(character) < 32 for character in folder_id):
            raise ValueError("reported mailbox folder identifier is malformed")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Microsoft Graph timeout must be positive")
        if page_size < 1 or page_size > 999 or max_pages < 1 or max_messages < 1:
            raise ValueError("Microsoft Graph mailbox page and message limits are invalid")
        if max_response_bytes < 1 or max_mime_bytes < 1:
            raise ValueError("Microsoft Graph mailbox byte limits must be positive")
        if max_retries < 0 or not math.isfinite(max_retry_after_seconds) or max_retry_after_seconds < 0:
            raise ValueError("Microsoft Graph mailbox retry limits are invalid")

        self._base_url = base_url.rstrip("/") + "/"
        self._origin = self._url_origin(parsed)
        mailbox = quote(mailbox_id, safe="")
        folder = quote(folder_id, safe="")
        self._delta_path = urlparse(
            urljoin(self._base_url, f"users/{mailbox}/mailFolders/{folder}/messages/delta")
        ).path
        self._start_url = urljoin(self._base_url, f"users/{mailbox}/mailFolders/{folder}/messages/delta")
        self._message_base_url = urljoin(self._base_url, f"users/{mailbox}/messages/")
        self._timeout = timeout
        self._page_size = page_size
        self._max_pages = max_pages
        self._max_messages = max_messages
        self._max_response_bytes = max_response_bytes
        self._max_mime_bytes = max_mime_bytes
        self._max_retries = max_retries
        self._max_retry_after_seconds = max_retry_after_seconds
        self._transport = transport
        self._sleep = sleep
        self._mime_parser = mime_parser or ReportedMimeParser(max_total_bytes=max_mime_bytes)

        explicit_auth = bool(bearer_token)
        microsoft_graph = parsed.scheme == "https" and hostname == _GRAPH_HOST and parsed.port in (None, 443)
        if not local and not microsoft_graph and not explicit_auth:
            raise ValueError("non-Microsoft Graph endpoints require an explicit bearer token")
        self._headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        self._credential: TokenCredential | None = None
        if microsoft_graph and not explicit_auth:
            client_id = (
                managed_identity_client_id or os.getenv("KP_WORKER_REPORTED_MAILBOX_CLIENT_ID", "") or ""
            ).strip()
            if credential is None and not client_id:
                raise ValueError("Microsoft Graph mailbox requires the mailbox managed identity client ID")
            # Keep high-impact mailbox permissions on the dedicated
            # user-assigned identity. DefaultAzureCredential may otherwise
            # fall back to environment or developer credentials.
            self._credential = credential or ManagedIdentityCredential(client_id=client_id)

    @staticmethod
    def _url_origin(parsed: Any) -> tuple[str, str | None, int | None]:
        default_port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
        return parsed.scheme, parsed.hostname, parsed.port or default_port

    def _validated_cursor(self, value: str) -> str:
        if not value or len(value) > _MAX_CURSOR_URL_CHARS:
            raise Microsoft365MailboxError("unsafe_cursor")
        try:
            url = urljoin(self._base_url, value)
            parsed = urlparse(url)
            unsafe = (
                self._url_origin(parsed) != self._origin
                or parsed.username is not None
                or parsed.password is not None
                or bool(parsed.fragment)
                or parsed.path != self._delta_path
            )
        except ValueError:
            raise Microsoft365MailboxError("unsafe_cursor") from None
        if unsafe:
            raise Microsoft365MailboxError("unsafe_cursor")
        return url

    def _request_headers(self) -> dict[str, str]:
        if self._credential is None:
            return dict(self._headers)
        try:
            token = self._credential.get_token(_GRAPH_SCOPE)
        except Exception:
            raise Microsoft365MailboxError("authentication") from None
        if not token.token:
            raise Microsoft365MailboxError("authentication")
        return {"Authorization": f"Bearer {token.token}"}

    def _retry_delay(self, response: httpx.Response, attempt: int) -> float:
        raw = response.headers.get("retry-after")
        if raw is None:
            delay = min(float(2**attempt), self._max_retry_after_seconds)
        else:
            try:
                delay = float(raw)
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(raw)
                    if retry_at.tzinfo is None:
                        raise ValueError
                    delay = max(0.0, retry_at.timestamp() - time.time())
                except (TypeError, ValueError, OverflowError):
                    raise Microsoft365MailboxError("retry_after") from None
        if not math.isfinite(delay) or delay < 0 or delay > self._max_retry_after_seconds:
            raise Microsoft365MailboxError("retry_after")
        return delay

    def _request_bytes(
        self,
        client: httpx.Client,
        url: str,
        *,
        max_bytes: int,
        params: dict[str, str] | None = None,
        expected_content: Literal["json", "mime"] | None = None,
    ) -> bytes:
        for attempt in range(self._max_retries + 1):
            try:
                with client.stream("GET", url, params=params, headers=self._request_headers()) as response:
                    if response.status_code == 429:
                        if attempt >= self._max_retries:
                            raise Microsoft365MailboxError("retry_limit", http_status=429)
                        delay = self._retry_delay(response, attempt)
                    elif response.is_error:
                        raise Microsoft365MailboxError("http", http_status=response.status_code)
                    else:
                        declared_type = response.headers.get("content-type")
                        if declared_type:
                            media_type = declared_type.split(";", 1)[0].strip().lower()
                            valid_type = (
                                _JSON_MEDIA_TYPE.fullmatch(media_type) is not None
                                if expected_content == "json"
                                else media_type in _MIME_MEDIA_TYPES
                                if expected_content == "mime"
                                else True
                            )
                            if not valid_type:
                                raise Microsoft365MailboxError("content_type")
                        declared = response.headers.get("content-length")
                        if declared is not None:
                            try:
                                declared_bytes = int(declared)
                            except ValueError:
                                raise Microsoft365MailboxError("malformed_response") from None
                            if declared_bytes < 0 or declared_bytes > max_bytes:
                                raise Microsoft365MailboxError("response_too_large")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            if len(body) + len(chunk) > max_bytes:
                                raise Microsoft365MailboxError("response_too_large")
                            body.extend(chunk)
                        return bytes(body)
            except Microsoft365MailboxError:
                raise
            except httpx.HTTPError:
                raise Microsoft365MailboxError("transport") from None
            self._sleep(delay)
        raise Microsoft365MailboxError("retry_limit")

    def _request_json(
        self,
        client: httpx.Client,
        url: str,
        *,
        params: dict[str, str] | None,
    ) -> dict[str, Any]:
        body = self._request_bytes(
            client,
            url,
            max_bytes=self._max_response_bytes,
            params=params,
            expected_content="json",
        )
        try:
            payload = json.loads(body)
        except (MemoryError, RecursionError, UnicodeDecodeError, json.JSONDecodeError):
            raise Microsoft365MailboxError("malformed_response") from None
        if not isinstance(payload, dict):
            raise Microsoft365MailboxError("malformed_response")
        return payload

    def poll(self, cursor: str | None = None) -> ReportedMailboxPollResult:
        try:
            return self._poll(cursor)
        except Microsoft365MailboxError as exc:
            return ReportedMailboxPollResult(
                status="error",
                messages=(),
                cursor=None,
                cursor_kind=None,
                pages=0,
                rejected_count=0,
                duplicate_count=0,
                removed_count=0,
                error_code=exc.code,
            )

    def _poll(self, cursor: str | None) -> ReportedMailboxPollResult:
        next_url = self._validated_cursor(cursor) if cursor is not None else self._start_url
        params = None if cursor is not None else {"$select": _MESSAGE_SELECT, "$top": str(self._page_size)}
        messages: list[ReportedMailboxMessage] = []
        seen_ids: set[str] = set()
        pages = 0
        rejected = 0
        duplicates = 0
        removed = 0
        visited_urls: set[str] = set()

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            while next_url is not None:
                if next_url in visited_urls:
                    raise Microsoft365MailboxError("cursor_loop")
                visited_urls.add(next_url)
                if pages >= self._max_pages:
                    return self._result("truncated", messages, next_url, "next", pages, rejected, duplicates, removed)
                payload = self._request_json(client, next_url, params=params)
                pages += 1
                params = None
                raw_items = payload.get("value")
                if not isinstance(raw_items, list):
                    raise Microsoft365MailboxError("malformed_response")
                if len(raw_items) > self._page_size:
                    raise Microsoft365MailboxError("page_limit")
                overflow = False
                for raw in raw_items:
                    if not isinstance(raw, dict):
                        rejected += 1
                        continue
                    external_id = self._external_id(raw.get("id"))
                    if external_id is None:
                        rejected += 1
                        continue
                    if "@removed" in raw:
                        if not isinstance(raw["@removed"], dict):
                            rejected += 1
                            continue
                        removed += 1
                        continue
                    if external_id in seen_ids:
                        duplicates += 1
                        continue
                    parsed_summary = self._summary(raw)
                    if parsed_summary is None:
                        rejected += 1
                        continue
                    if len(seen_ids) >= self._max_messages:
                        overflow = True
                        continue
                    seen_ids.add(external_id)
                    received_at, internet_message_id = parsed_summary
                    mime_url = urljoin(self._message_base_url, f"{quote(external_id, safe='')}/$value")
                    try:
                        raw_mime = self._request_bytes(
                            client,
                            mime_url,
                            max_bytes=self._max_mime_bytes,
                            expected_content="mime",
                        )
                    except Microsoft365MailboxError as exc:
                        if exc.code == "response_too_large" or exc.http_status == 404:
                            rejected += 1
                            continue
                        raise
                    try:
                        parsed_mime = self._mime_parser.parse(raw_mime)
                    except ReportedMimeError:
                        rejected += 1
                        continue
                    messages.append(
                        ReportedMailboxMessage(
                            external_id=external_id,
                            received_at=received_at,
                            internet_message_id=internet_message_id,
                            mime=parsed_mime,
                        )
                    )

                raw_next, raw_delta = self._links(payload)
                if overflow:
                    return self._result("truncated", messages, None, None, pages, rejected, duplicates, removed)
                if raw_next is not None:
                    next_url = self._validated_cursor(raw_next)
                    if next_url in visited_urls:
                        raise Microsoft365MailboxError("cursor_loop")
                    if len(seen_ids) >= self._max_messages:
                        return self._result(
                            "truncated", messages, next_url, "next", pages, rejected, duplicates, removed
                        )
                    continue
                if raw_delta is None:
                    raise Microsoft365MailboxError("missing_delta_cursor")
                delta_cursor = self._validated_cursor(raw_delta)
                return self._result("complete", messages, delta_cursor, "delta", pages, rejected, duplicates, removed)

        raise Microsoft365MailboxError("malformed_response")

    @staticmethod
    def _external_id(raw: Any) -> str | None:
        if not isinstance(raw, str) or not raw or len(raw) > 512:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in raw):
            return None
        return raw

    @staticmethod
    def _summary(raw: dict[str, Any]) -> tuple[datetime, str | None] | None:
        received = raw.get("receivedDateTime")
        if not isinstance(received, str) or len(received) > 64:
            return None
        try:
            received_at = datetime.fromisoformat(received.replace("Z", "+00:00"))
        except (OverflowError, ValueError):
            return None
        if received_at.tzinfo is None:
            return None
        try:
            received_at = received_at.astimezone(UTC)
        except (OverflowError, ValueError):
            return None
        message_id = raw.get("internetMessageId")
        if message_id is None:
            internet_message_id = None
        elif (
            isinstance(message_id, str)
            and 0 < len(message_id) <= 998
            and not any(ord(character) < 32 or ord(character) == 127 for character in message_id)
        ):
            internet_message_id = message_id
        else:
            internet_message_id = None
        return received_at, internet_message_id

    @staticmethod
    def _links(payload: dict[str, Any]) -> tuple[str | None, str | None]:
        raw_next = payload.get("@odata.nextLink")
        raw_delta = payload.get("@odata.deltaLink")
        if raw_next is not None and (not isinstance(raw_next, str) or not raw_next):
            raise Microsoft365MailboxError("malformed_cursor")
        if raw_delta is not None and (not isinstance(raw_delta, str) or not raw_delta):
            raise Microsoft365MailboxError("malformed_cursor")
        if raw_next is not None and raw_delta is not None:
            raise Microsoft365MailboxError("ambiguous_cursor")
        return raw_next, raw_delta

    @staticmethod
    def _result(
        status: Literal["complete", "truncated"],
        messages: list[ReportedMailboxMessage],
        cursor: str | None,
        cursor_kind: Literal["next", "delta"] | None,
        pages: int,
        rejected: int,
        duplicates: int,
        removed: int,
    ) -> ReportedMailboxPollResult:
        return ReportedMailboxPollResult(
            status=status,
            messages=tuple(messages),
            cursor=cursor,
            cursor_kind=cursor_kind,
            pages=pages,
            rejected_count=rejected,
            duplicate_count=duplicates,
            removed_count=removed,
        )
