"""Bounded, data-minimizing Microsoft Graph-style directory client."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_MAILBOX = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+\Z")


@dataclass(frozen=True)
class DirectoryUser:
    employee_key: str
    mailbox: str
    display_name: str | None
    department: str | None


class _GraphUser(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=256)
    mail: str = Field(min_length=3, max_length=320)
    displayName: str | None = Field(default=None, max_length=256)
    department: str | None = Field(default=None, max_length=256)

    @field_validator("mail")
    @classmethod
    def validate_mailbox(cls, value: str) -> str:
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
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parsed_base = urlparse(base_url)
        local_hosts = {"localhost", "127.0.0.1", "::1", "mock-graph"}
        if (
            parsed_base.scheme not in {"http", "https"}
            or not parsed_base.hostname
            or parsed_base.username is not None
            or parsed_base.password is not None
            or parsed_base.fragment
            or (parsed_base.scheme != "https" and parsed_base.hostname.lower() not in local_hosts)
        ):
            raise ValueError("Graph base URL must be HTTPS (HTTP is allowed only for local development)")
        self._base_url = base_url.rstrip("/") + "/"
        self._headers: dict[str, str] = {}
        if bearer_token:
            self._headers["Authorization"] = f"Bearer {bearer_token}"
        if api_key:
            self._headers["X-API-Key"] = api_key
        self._timeout = timeout
        self._max_users = max_users
        self._max_pages = max_pages
        self._transport = transport

    def users(self) -> list[DirectoryUser]:
        output: list[DirectoryUser] = []
        next_url: str | None = urljoin(self._base_url, "users")
        base = urlparse(self._base_url)
        origin = (base.scheme, base.hostname, base.port)
        with httpx.Client(timeout=self._timeout, headers=self._headers, transport=self._transport) as client:
            for _ in range(self._max_pages):
                if next_url is None or len(output) >= self._max_users:
                    break
                parsed_next = urlparse(next_url)
                if (parsed_next.scheme, parsed_next.hostname, parsed_next.port) != origin:
                    raise ValueError("Graph pagination URL changed origin")
                response = client.get(next_url, params={"$select": "id,mail,displayName,department"})
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                    raise ValueError("Graph users response is malformed")
                for raw in payload["value"]:
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
                        break
                link = payload.get("@odata.nextLink")
                next_url = urljoin(self._base_url, link) if isinstance(link, str) and link else None
        return output
