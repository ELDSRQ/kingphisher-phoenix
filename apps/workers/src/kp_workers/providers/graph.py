"""Bounded, data-minimizing Microsoft Graph-style directory client."""

from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any, Literal
from urllib.parse import quote, urljoin, urlparse

import httpx
from azure.core.credentials import TokenCredential
from azure.identity import ManagedIdentityCredential
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator

_MAILBOX = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "mock-graph"})
_MICROSOFT_GRAPH_HOST = "graph.microsoft.com"
_MICROSOFT_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_DEFAULT_MAX_RETRY_AFTER_SECONDS = 5.0
_DEFAULT_MAX_RETRIES = 3
_DIRECTORY_SELECT = "id,mail,userPrincipalName,displayName,department,accountEnabled,userType"
_GROUP_ID = re.compile(r"[A-Za-z0-9._~-]{1,256}\Z")
_JSON_MEDIA_TYPE = re.compile(r"application/(?:[A-Za-z0-9!#$&^_.+-]+\+)?json\Z", re.IGNORECASE)
_MAX_CURSOR_URL_CHARS = 16 * 1024


@dataclass(frozen=True)
class DirectoryUser:
    employee_key: str
    mailbox: str
    display_name: str | None
    department: str | None
    account_enabled: bool | None = None
    user_type: str | None = None
    mail: str | None = None
    user_principal_name: str | None = None

    @property
    def entra_id(self) -> str:
        """Stable Entra object identifier, retained as employee_key for compatibility."""

        return self.employee_key


@dataclass(frozen=True)
class DirectoryRemoval:
    entra_id: str
    reason: str | None = None


@dataclass(frozen=True)
class DirectorySyncResult:
    """A bounded snapshot/change result that must not be applied unless complete."""

    users: tuple[DirectoryUser, ...]
    removals: tuple[DirectoryRemoval, ...]
    cursor: str | None
    cursor_kind: Literal["next", "delta"] | None
    complete: bool
    truncated: bool
    rejected_count: int
    pages: int


class GraphDirectoryError(RuntimeError):
    """A redacted provider failure safe to expose to worker diagnostics."""


class GraphRequestError(GraphDirectoryError):
    pass


class GraphRetryLimitError(GraphDirectoryError):
    pass


class _GraphUser(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=256)
    mail: str = Field(min_length=3, max_length=320)
    displayName: str | None = Field(default=None, max_length=256)
    department: str | None = Field(default=None, max_length=256)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _GROUP_ID.fullmatch(value) is None:
            raise ValueError("invalid directory identifier")
        return value

    @field_validator("mail")
    @classmethod
    def validate_mailbox(cls, value: str) -> str:
        normalized = value.strip().lower()
        if _MAILBOX.fullmatch(normalized) is None:
            raise ValueError("invalid mailbox")
        return normalized


class _GraphChangeUser(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=256)
    mail: str | None = Field(default=None, max_length=320)
    userPrincipalName: str | None = Field(default=None, max_length=320)
    displayName: str | None = Field(default=None, max_length=256)
    department: str | None = Field(default=None, max_length=256)
    accountEnabled: StrictBool | None = None
    userType: str | None = Field(default=None, max_length=64)

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if _GROUP_ID.fullmatch(value) is None:
            raise ValueError("invalid directory identifier")
        return value

    @field_validator("mail", "userPrincipalName")
    @classmethod
    def validate_optional_mailbox(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if _MAILBOX.fullmatch(normalized) is None:
            raise ValueError("invalid mailbox")
        return normalized


class GraphDirectoryProvider:
    def __init__(
        self,
        base_url: str,
        *,
        bearer_token: str | None = None,
        api_key: str | None = None,
        timeout: float = 10.0,
        max_users: int = 1000,
        max_pages: int = 20,
        max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        max_retry_after_seconds: float = _DEFAULT_MAX_RETRY_AFTER_SECONDS,
        transport: httpx.BaseTransport | None = None,
        credential: TokenCredential | None = None,
        managed_identity_client_id: str | None = None,
        group_ids: Sequence[str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        parsed_base = urlparse(base_url)
        hostname = parsed_base.hostname.lower() if parsed_base.hostname else None
        local = hostname in _LOCAL_HOSTS or bool(hostname and hostname.endswith(".localhost"))
        if (
            parsed_base.scheme not in {"http", "https"}
            or hostname is None
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.query
            or parsed_base.fragment
            or (parsed_base.scheme != "https" and not local)
        ):
            raise ValueError("Graph base URL must be HTTPS (HTTP is allowed only for local development)")
        explicit_auth = bool(bearer_token or api_key)
        if bearer_token and api_key:
            raise ValueError("Graph bearer token and API key authentication are mutually exclusive")
        microsoft_graph = parsed_base.scheme == "https" and hostname == _MICROSOFT_GRAPH_HOST
        if not local and not microsoft_graph and not explicit_auth:
            raise ValueError("non-Microsoft Graph endpoints require an explicit bearer token or API key")
        if microsoft_graph and not explicit_auth and parsed_base.port not in (None, 443):
            raise ValueError("Microsoft Graph managed-identity authentication requires the standard HTTPS port")
        if not math.isfinite(timeout) or timeout <= 0 or max_users < 1 or max_pages < 1 or max_response_bytes < 1:
            raise ValueError("Graph timeout and response limits must be positive")
        if max_retries < 0 or not math.isfinite(max_retry_after_seconds) or max_retry_after_seconds < 0:
            raise ValueError("Graph retry limits must not be negative")
        self._base_url = base_url.rstrip("/") + "/"
        self._origin = self._url_origin(parsed_base)
        self._headers: dict[str, str] = {}
        if bearer_token:
            self._headers["Authorization"] = f"Bearer {bearer_token}"
        if api_key:
            self._headers["X-API-Key"] = api_key
        self._credential: TokenCredential | None = None
        if microsoft_graph and not explicit_auth:
            client_id = (managed_identity_client_id or os.getenv("KP_WORKER_GRAPH_CLIENT_ID", "") or "").strip()
            if credential is None and not client_id:
                raise ValueError("Microsoft Graph requires the directory managed identity client ID")
            # Do not use DefaultAzureCredential here: its environment and CLI
            # fallbacks can silently select a broader, shared worker identity.
            # These Graph permissions belong only to the dedicated directory
            # user-assigned managed identity.
            self._credential = credential or ManagedIdentityCredential(client_id=client_id)
        configured_groups = group_ids
        if configured_groups is None:
            configured_groups = tuple(
                item.strip() for item in os.getenv("KP_WORKER_GRAPH_GROUP_IDS", "").split(",") if item.strip()
            )
        self._group_ids = tuple(dict.fromkeys(configured_groups))
        self._timeout = timeout
        self._max_users = max_users
        self._max_pages = max_pages
        self._max_response_bytes = max_response_bytes
        self._max_retries = max_retries
        self._max_retry_after_seconds = max_retry_after_seconds
        self._transport = transport
        self._sleep = sleep

    @staticmethod
    def _url_origin(parsed: Any) -> tuple[str, str | None, int | None]:
        default_port = 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
        return parsed.scheme, parsed.hostname, parsed.port or default_port

    def _validated_url(self, value: str, *, expected_path: str | None = None) -> str:
        if not value or len(value) > _MAX_CURSOR_URL_CHARS:
            raise ValueError("Graph cursor URL changed origin or is malformed")
        url = urljoin(self._base_url, value)
        parsed = urlparse(url)
        if (
            self._url_origin(parsed) != self._origin
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.fragment)
            or (expected_path is not None and parsed.path != expected_path)
        ):
            raise ValueError("Graph cursor URL changed origin or is malformed")
        return url

    @staticmethod
    def _required_cursor_path(value: str) -> str:
        """Return a non-empty cursor path or fail without weakening path binding."""

        path = urlparse(value).path
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("Graph cursor URL changed origin or is malformed")
        return path

    def _request_headers(self) -> dict[str, str]:
        if self._credential is None:
            return dict(self._headers)
        try:
            access_token = self._credential.get_token(_MICROSOFT_GRAPH_SCOPE)
        except Exception:
            raise GraphRequestError("Microsoft Graph authentication failed") from None
        if not access_token.token:
            raise GraphRequestError("Microsoft Graph authentication returned an empty token")
        # Acquire on every request. Azure Identity performs synchronized token
        # caching internally and refreshes before expiry; the provider neither
        # logs nor persists bearer values.
        return {"Authorization": f"Bearer {access_token.token}"}

    def _bounded_json(self, response: httpx.Response) -> Any:
        declared_length = response.headers.get("content-length", "")
        if declared_length:
            if not declared_length.isdigit():
                raise ValueError("Graph users response is malformed")
            if int(declared_length) > self._max_response_bytes:
                raise ValueError("Graph response exceeds maximum size")
        declared_type = response.headers.get("content-type")
        if declared_type:
            media_type = declared_type.split(";", 1)[0].strip()
            if _JSON_MEDIA_TYPE.fullmatch(media_type) is None:
                raise ValueError("Graph users response is malformed")
        content = bytearray()
        for chunk in response.iter_bytes():
            if len(content) + len(chunk) > self._max_response_bytes:
                raise ValueError("Graph response exceeds maximum size")
            content.extend(chunk)
        try:
            return json.loads(content)
        except (MemoryError, RecursionError, UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("Graph users response is malformed") from None

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
                    raise GraphRetryLimitError("Microsoft Graph returned an invalid Retry-After value") from None
        if not math.isfinite(delay) or delay < 0 or delay > self._max_retry_after_seconds:
            raise GraphRetryLimitError("Microsoft Graph Retry-After exceeds the configured maximum")
        return delay

    def _request_json(
        self,
        client: httpx.Client,
        url: str,
        *,
        params: dict[str, str] | None = None,
    ) -> Any:
        for attempt in range(self._max_retries + 1):
            try:
                with client.stream(
                    "GET",
                    url,
                    params=params,
                    headers=self._request_headers(),
                ) as response:
                    if response.status_code == 429:
                        if attempt >= self._max_retries:
                            raise GraphRetryLimitError("Microsoft Graph retry limit reached")
                        delay = self._retry_delay(response, attempt)
                    elif response.is_error:
                        raise GraphRequestError(f"Microsoft Graph request failed with HTTP {response.status_code}")
                    else:
                        return self._bounded_json(response)
            except GraphDirectoryError:
                raise
            except httpx.HTTPError:
                # Do not retain a URL containing an opaque Graph cursor in the
                # exception chain or error message.
                raise GraphRequestError("Microsoft Graph request failed") from None
            self._sleep(delay)
        raise GraphRetryLimitError("Microsoft Graph retry limit reached")

    @staticmethod
    def _page_links(payload: dict[str, Any]) -> tuple[str | None, str | None]:
        raw_next = payload.get("@odata.nextLink")
        raw_delta = payload.get("@odata.deltaLink")
        if raw_next is not None and (not isinstance(raw_next, str) or not raw_next):
            raise ValueError("Graph next cursor is malformed")
        if raw_delta is not None and (not isinstance(raw_delta, str) or not raw_delta):
            raise ValueError("Graph delta cursor is malformed")
        if raw_next is not None and raw_delta is not None:
            raise ValueError("Graph response contains ambiguous cursors")
        return raw_next, raw_delta

    @staticmethod
    def _parse_change(raw: Any) -> tuple[DirectoryUser | None, DirectoryRemoval | None]:
        if not isinstance(raw, dict):
            return None, None
        removed = raw.get("@removed")
        if removed is not None:
            entra_id = raw.get("id")
            if not isinstance(entra_id, str) or _GROUP_ID.fullmatch(entra_id) is None or not isinstance(removed, dict):
                return None, None
            reason = removed.get("reason")
            return None, DirectoryRemoval(
                entra_id=entra_id,
                reason=reason[:64] if isinstance(reason, str) else None,
            )
        try:
            user = _GraphChangeUser.model_validate(raw)
        except ValidationError:
            return None, None
        mailbox = user.mail or user.userPrincipalName
        if mailbox is None:
            return None, None
        return (
            DirectoryUser(
                employee_key=user.id,
                mailbox=mailbox,
                display_name=user.displayName,
                department=user.department,
                account_enabled=user.accountEnabled,
                user_type=user.userType,
                mail=user.mail,
                user_principal_name=user.userPrincipalName,
            ),
            None,
        )

    def _collect(
        self,
        starts: Sequence[tuple[str, dict[str, str] | None]],
        *,
        allow_removals: bool,
        require_delta_cursor: bool = False,
    ) -> DirectorySyncResult:
        users: dict[str, DirectoryUser] = {}
        removals: dict[str, DirectoryRemoval] = {}
        rejected = 0
        pages = 0
        cursor: str | None = None
        cursor_kind: Literal["next", "delta"] | None = None
        truncated = False

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            for start_url, initial_params in starts:
                validated_start = self._validated_url(start_url)
                next_url: str | None = validated_start
                expected_path = self._required_cursor_path(validated_start)
                params = initial_params
                visited_urls: set[str] = set()
                while next_url is not None:
                    if next_url in visited_urls:
                        raise ValueError("Graph cursor loop detected")
                    visited_urls.add(next_url)
                    if pages >= self._max_pages:
                        truncated = True
                        cursor = next_url
                        cursor_kind = "next"
                        break
                    payload = self._request_json(client, next_url, params=params)
                    pages += 1
                    params = None
                    if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                        raise ValueError("Graph users response is malformed")
                    for raw in payload["value"]:
                        user, removal = self._parse_change(raw)
                        if user is None and removal is None:
                            rejected += 1
                            continue
                        if removal is not None:
                            if not allow_removals:
                                rejected += 1
                                continue
                            users.pop(removal.entra_id, None)
                            removals[removal.entra_id] = removal
                            continue
                        if user is None:
                            raise ValueError("Graph users response is malformed")
                        removals.pop(user.entra_id, None)
                        if user.entra_id not in users and len(users) >= self._max_users:
                            truncated = True
                            continue
                        users[user.entra_id] = user
                    raw_next, raw_delta = self._page_links(payload)
                    if raw_next is not None:
                        next_url = self._validated_url(raw_next, expected_path=expected_path)
                        if truncated or len(users) >= self._max_users:
                            truncated = True
                            cursor = None
                            cursor_kind = None
                            break
                        cursor = next_url
                        cursor_kind = "next"
                        continue
                    next_url = None
                    if raw_delta is not None and not truncated:
                        cursor = self._validated_url(raw_delta, expected_path=expected_path)
                        cursor_kind = "delta"
                    else:
                        cursor = None
                        cursor_kind = None
                if truncated:
                    break

        if require_delta_cursor and not truncated and cursor_kind != "delta":
            raise ValueError("Graph delta response omitted its terminal cursor")
        return DirectorySyncResult(
            users=tuple(users.values()),
            removals=tuple(removals.values()),
            cursor=cursor,
            cursor_kind=cursor_kind,
            complete=not truncated,
            truncated=truncated,
            rejected_count=rejected,
            pages=pages,
        )

    def fetch_changes(self, cursor: str | None = None) -> DirectorySyncResult:
        """Fetch a complete initial or incremental user delta.

        Callers must persist a returned delta cursor only after applying the
        complete result transactionally. A truncated result is diagnostic and
        must never be interpreted as a complete directory snapshot.
        """

        if cursor is None:
            start = urljoin(self._base_url, "users/delta")
            params = {"$select": _DIRECTORY_SELECT}
        else:
            expected_path = self._required_cursor_path(urljoin(self._base_url, "users/delta"))
            start = self._validated_url(cursor, expected_path=expected_path)
            params = None
        return self._collect(((start, params),), allow_removals=True, require_delta_cursor=True)

    def fetch_group_members(self, group_ids: Sequence[str]) -> DirectorySyncResult:
        """Fetch de-duplicated transitive user membership for selected groups."""

        if not group_ids:
            raise ValueError("at least one group id is required")
        unique_group_ids = tuple(dict.fromkeys(group_ids))
        if any(_GROUP_ID.fullmatch(group_id) is None for group_id in unique_group_ids):
            raise ValueError("Graph group id is malformed")
        starts = tuple(
            (
                urljoin(
                    self._base_url,
                    f"groups/{quote(group_id, safe='')}/transitiveMembers/microsoft.graph.user",
                ),
                {"$select": _DIRECTORY_SELECT},
            )
            for group_id in unique_group_ids
        )
        return self._collect(starts, allow_removals=False)

    def users(self) -> list[DirectoryUser]:
        if self._group_ids:
            selected = self.fetch_group_members(self._group_ids)
            if not selected.complete:
                raise GraphRetryLimitError("selected-group directory response exceeded configured bounds")
            return list(selected.users)
        output: list[DirectoryUser] = []
        start_url = urljoin(self._base_url, "users")
        next_url: str | None = start_url
        expected_path = self._required_cursor_path(start_url)
        first_page = True
        visited_urls: set[str] = set()
        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            for _ in range(self._max_pages):
                if next_url is None or len(output) >= self._max_users:
                    break
                next_url = self._validated_url(next_url, expected_path=expected_path)
                if next_url in visited_urls:
                    raise GraphRetryLimitError("Graph users pagination loop detected")
                visited_urls.add(next_url)
                # Graph next links already carry their complete opaque query,
                # including skip tokens. Reapplying first-page params would
                # discard or corrupt that cursor.
                payload = self._request_json(
                    client,
                    next_url,
                    params={"$select": "id,mail,displayName,department"} if first_page else None,
                )
                if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                    raise ValueError("Graph users response is malformed")
                for index, raw in enumerate(payload["value"]):
                    try:
                        user = _GraphUser.model_validate(raw)
                    except ValidationError:
                        continue
                    output.append(
                        DirectoryUser(
                            employee_key=user.id,
                            mailbox=str(user.mail).lower(),
                            display_name=user.displayName,
                            department=user.department,
                        )
                    )
                    if len(output) >= self._max_users:
                        if index < len(payload["value"]) - 1 or payload.get("@odata.nextLink") is not None:
                            raise GraphRetryLimitError("Graph users response exceeded configured bounds")
                        break
                link, delta = self._page_links(payload)
                if delta is not None:
                    raise ValueError("Graph users response contains an unexpected delta cursor")
                next_url = self._validated_url(link, expected_path=expected_path) if link is not None else None
                if next_url is not None and next_url in visited_urls:
                    raise GraphRetryLimitError("Graph users pagination loop detected")
                first_page = False
        if next_url is not None:
            raise GraphRetryLimitError("Graph users response exceeded configured bounds")
        return output

    def fetch_users(self) -> list[DirectoryUser]:
        """Compatibility adapter for callers expecting the legacy list API."""

        return self.users()
