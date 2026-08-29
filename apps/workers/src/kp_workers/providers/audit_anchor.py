"""Create-only Azure Blob publication for verified audit-chain heads."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime
from typing import Literal
from urllib.parse import quote, urlparse

import httpx
from azure.core.credentials import TokenCredential
from azure.identity import ManagedIdentityCredential

_AZURE_STORAGE_SCOPE = "https://storage.azure.com/.default"
_AZURE_STORAGE_API_VERSION = "2023-11-03"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ANCHOR_BYTES = 4096


class AuditAnchorError(RuntimeError):
    """A redacted storage-boundary failure safe for worker diagnostics."""


class AuditAnchorMismatchError(AuditAnchorError):
    """The immutable key already exists with different content."""


@dataclass(frozen=True)
class AuditAnchor:
    sequence: int
    event_hash: str
    signed_at: datetime

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("audit anchor sequence must not be negative")
        if _HASH.fullmatch(self.event_hash) is None:
            raise ValueError("audit anchor event hash must be lowercase SHA-256")
        if self.signed_at.tzinfo is None:
            raise ValueError("audit anchor signed time must include a timezone")

    @property
    def blob_name(self) -> str:
        return f"v1/{self.sequence:020d}-{self.event_hash}.json"

    def canonical_bytes(self) -> bytes:
        signed_at = self.signed_at.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        document = {
            "event_hash": self.event_hash,
            "schema_version": 1,
            "sequence": self.sequence,
            "signed_at": signed_at,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


class AzureBlobAuditAnchorProvider:
    """Publish a canonical anchor once and compare on create collisions."""

    def __init__(
        self,
        container_url: str,
        *,
        managed_identity_client_id: str | None = None,
        timeout: float = 10.0,
        credential: TokenCredential | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        parsed = urlparse(container_url)
        path_parts = [part for part in parsed.path.split("/") if part]
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or not parsed.hostname.lower().endswith(".blob.core.windows.net")
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or len(path_parts) != 1
        ):
            raise ValueError("audit anchor URL must identify one Azure Blob container over HTTPS")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("audit anchor timeout must be positive")
        if credential is None and not managed_identity_client_id:
            raise ValueError("audit anchor managed identity client ID is required")

        self._container_url = container_url.rstrip("/")
        self._credential = credential or ManagedIdentityCredential(client_id=managed_identity_client_id)
        self._owns_credential = credential is None
        self._client = client or httpx.Client(timeout=httpx.Timeout(timeout), follow_redirects=False)
        self._owns_client = client is None

    def _headers(self) -> dict[str, str]:
        try:
            access_token = self._credential.get_token(_AZURE_STORAGE_SCOPE)
        except Exception:
            raise AuditAnchorError("Azure Blob authentication failed") from None
        if not access_token.token:
            raise AuditAnchorError("Azure Blob authentication returned an empty token")
        return {
            "Authorization": f"Bearer {access_token.token}",
            "x-ms-date": format_datetime(datetime.now(UTC), usegmt=True),
            "x-ms-version": _AZURE_STORAGE_API_VERSION,
        }

    @staticmethod
    def _bounded_content(response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > _MAX_ANCHOR_BYTES:
            raise AuditAnchorError("existing audit anchor exceeds maximum size")
        content = bytearray()
        for chunk in response.iter_bytes():
            if len(content) + len(chunk) > _MAX_ANCHOR_BYTES:
                raise AuditAnchorError("existing audit anchor exceeds maximum size")
            content.extend(chunk)
        return bytes(content)

    def publish(self, anchor: AuditAnchor) -> Literal["created", "exists"]:
        content = anchor.canonical_bytes()
        if len(content) > _MAX_ANCHOR_BYTES:
            raise AuditAnchorError("audit anchor exceeds maximum size")
        url = f"{self._container_url}/{quote(anchor.blob_name, safe='/')}"
        headers = {
            **self._headers(),
            "Content-Type": "application/json",
            "If-None-Match": "*",
            "x-ms-blob-type": "BlockBlob",
        }
        try:
            with self._client.stream("PUT", url, headers=headers, content=content) as response:
                status = response.status_code
            if status == 201:
                return "created"
            if status != 412:
                raise AuditAnchorError(f"Azure Blob create failed with status {status}")

            with self._client.stream("GET", url, headers=self._headers()) as response:
                if response.status_code != 200:
                    raise AuditAnchorError(f"Azure Blob collision check failed with status {response.status_code}")
                existing = self._bounded_content(response)
        except AuditAnchorError:
            raise
        except httpx.HTTPError:
            raise AuditAnchorError("Azure Blob request failed") from None
        if existing != content:
            raise AuditAnchorMismatchError("immutable audit anchor key contains different content")
        return "exists"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
        if self._owns_credential:
            close = getattr(self._credential, "close", None)
            if close is not None:
                close()

    def __enter__(self) -> AzureBlobAuditAnchorProvider:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
