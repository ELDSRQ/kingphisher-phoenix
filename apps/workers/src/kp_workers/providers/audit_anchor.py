"""Create-only publication (Azure Blob or local WORM) for verified audit heads."""

from __future__ import annotations

import json
import math
import os
import re
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import format_datetime
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlparse
from xml.etree import ElementTree

import httpx
from azure.core.credentials import TokenCredential
from azure.identity import ManagedIdentityCredential

_AZURE_STORAGE_SCOPE = "https://storage.azure.com/.default"
_AZURE_STORAGE_API_VERSION = "2023-11-03"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ANCHOR_BYTES = 4096

#: Statuses meaning "an anchor already exists at this immutable key". A create
#: guarded by ``If-None-Match: *`` is answered with 201 when it created the blob.
#: When the key is already taken Azure answers either 412 (Precondition Failed)
#: or 409 (BlobAlreadyExists) depending on the service version and request path.
#: Both mean the same thing here — the anchor was published before — so both must
#: fall through to the collision check. Treating 409 as a hard failure made every
#: re-publish of an existing anchor raise, which dead-lettered the job and left
#: the audit-anchor role permanently "configured_unproven" in managed deployments.
_EXISTING_ANCHOR_STATUSES = frozenset({409, 412})
#: Storage-layout version: the on-disk/blob path prefix anchors are written under.
#:
#: This must move whenever the anchor document gains or changes a field, because
#: the blob key is derived only from ``<sequence>-<event_hash>``. Two documents
#: for the same event that differ in any other field (chaining, schema version)
#: therefore collide on one key — and since anchors are immutable, that collision
#: is unresolvable: the stored bytes can never be rewritten to match.
#:
#: AUD-003 raised ``_ANCHOR_SCHEMA_VERSION`` to 2 (adding ``previous_anchor_hash``
#: chaining) while this prefix stayed at "v1", so re-publishing any event already
#: anchored before the change hit HTTP 409 and then failed the collision check as
#: "immutable audit anchor key contains different content" — a non-retryable
#: integrity failure that dead-lettered every anchor job and left the audit-anchor
#: role permanently unproven. Keep this in step with the document schema.
_ANCHOR_LAYOUT_PREFIX = "v2"
#: Current anchor document schema. v2 chains anchors via ``previous_anchor_hash``;
#: v1 (no chaining) is still parseable so a mixed history reads back cleanly.
_ANCHOR_SCHEMA_VERSION = 2
#: Bounds on a single List Blobs enumeration used only for read-back.
_LIST_PAGE_SIZE = 512
_MAX_LIST_PAGES = 64
_MAX_LIST_BYTES = 1_048_576


class AuditAnchorError(RuntimeError):
    """A redacted storage-boundary failure safe for worker diagnostics."""

    #: Transient by default: the queue may retry. Integrity failures below flip
    #: this to False so the worker supervisor dead-letters rather than retrying.
    retryable = True


class AuditAnchorMismatchError(AuditAnchorError):
    """The immutable key already exists with different content.

    This is tamper-relevant, not transient: the WORM key can never be rewritten,
    so a retry can only ever fail the same way. Fail closed and dead-letter.
    """

    retryable = False


@dataclass(frozen=True)
class AuditAnchor:
    sequence: int
    event_hash: str
    signed_at: datetime
    #: SHA-256 (hex) of the immediately-preceding anchor's canonical bytes, so
    #: published anchors form their own tamper-evident chain. ``None`` only for
    #: the very first anchor (or a legacy v1 anchor that predates chaining).
    previous_anchor_hash: str | None = None

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("audit anchor sequence must not be negative")
        if _HASH.fullmatch(self.event_hash) is None:
            raise ValueError("audit anchor event hash must be lowercase SHA-256")
        if self.signed_at.tzinfo is None:
            raise ValueError("audit anchor signed time must include a timezone")
        if self.previous_anchor_hash is not None and _HASH.fullmatch(self.previous_anchor_hash) is None:
            raise ValueError("previous anchor hash must be lowercase SHA-256")

    @property
    def leaf_name(self) -> str:
        """Storage-layout-independent file name: ``<seq>-<hash>.json``.

        Zero-padded so lexicographic order equals numeric sequence order, which
        read-back relies on to select the newest anchors without a side index.
        """

        return f"{self.sequence:020d}-{self.event_hash}.json"

    @property
    def blob_name(self) -> str:
        return f"{_ANCHOR_LAYOUT_PREFIX}/{self.leaf_name}"

    def canonical_bytes(self) -> bytes:
        signed_at = self.signed_at.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        document = {
            "event_hash": self.event_hash,
            "previous_anchor_hash": self.previous_anchor_hash,
            "schema_version": _ANCHOR_SCHEMA_VERSION,
            "sequence": self.sequence,
            "signed_at": signed_at,
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"

    @classmethod
    def from_bytes(cls, content: bytes) -> AuditAnchor:
        """Parse a stored anchor document, tolerating both v1 and v2 schemas.

        Fails closed on anything malformed: read-back must not silently treat an
        unparseable or oversized anchor as absent.
        """

        if len(content) > _MAX_ANCHOR_BYTES:
            raise AuditAnchorError("stored audit anchor exceeds maximum size")
        try:
            document = json.loads(content)
        except (ValueError, UnicodeDecodeError):
            raise AuditAnchorError("stored audit anchor is not valid JSON") from None
        if not isinstance(document, dict):
            raise AuditAnchorError("stored audit anchor is not a JSON object")
        schema_version = document.get("schema_version")
        if schema_version not in (1, 2):
            raise AuditAnchorError("stored audit anchor has an unsupported schema version")
        event_hash = document.get("event_hash")
        sequence = document.get("sequence")
        signed_at_raw = document.get("signed_at")
        previous = document.get("previous_anchor_hash")
        if not isinstance(event_hash, str) or not isinstance(sequence, int) or isinstance(sequence, bool):
            raise AuditAnchorError("stored audit anchor is missing required fields")
        if not isinstance(signed_at_raw, str):
            raise AuditAnchorError("stored audit anchor has a malformed signed time")
        if previous is not None and not isinstance(previous, str):
            raise AuditAnchorError("stored audit anchor has a malformed previous anchor hash")
        try:
            signed_at = datetime.fromisoformat(signed_at_raw.replace("Z", "+00:00"))
        except ValueError:
            raise AuditAnchorError("stored audit anchor has a malformed signed time") from None
        try:
            return cls(sequence=sequence, event_hash=event_hash, signed_at=signed_at, previous_anchor_hash=previous)
        except ValueError as exc:
            raise AuditAnchorError("stored audit anchor failed validation") from exc


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
            if status not in _EXISTING_ANCHOR_STATUSES:
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

    def read_recent(self, limit: int) -> list[AuditAnchor]:
        """Return the newest ``limit`` published anchors, newest first.

        Used for read-back verification: the caller re-checks that each still
        matches the live chain before publishing a new anchor. Enumeration is
        bounded; if the history is larger than the bound can traverse we fail
        closed rather than read back against a stale/partial view.
        """

        if limit <= 0:
            return []
        names = self._recent_blob_leaf_names(limit)
        return [self._fetch_anchor(name) for name in names]

    def _recent_blob_leaf_names(self, limit: int) -> list[str]:
        newest: deque[str] = deque(maxlen=limit)
        marker = ""
        for _ in range(_MAX_LIST_PAGES):
            page, marker = self._list_page(marker)
            newest.extend(page)
            if not marker:
                # Names arrive lexicographically ascending across pages, so the
                # last ``limit`` appended are the newest by sequence. Return them
                # newest-first to match the local provider's contract.
                return list(reversed(newest))
        raise AuditAnchorError("audit anchor history exceeds the read-back enumeration bound")

    def _list_page(self, marker: str) -> tuple[list[str], str]:
        url = (
            f"{self._container_url}?restype=container&comp=list"
            f"&prefix={quote(_ANCHOR_LAYOUT_PREFIX + '/', safe='')}&maxresults={_LIST_PAGE_SIZE}"
        )
        if marker:
            url = f"{url}&marker={quote(marker, safe='')}"
        try:
            with self._client.stream("GET", url, headers=self._headers()) as response:
                if response.status_code != 200:
                    raise AuditAnchorError(f"Azure Blob list failed with status {response.status_code}")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > _MAX_LIST_BYTES:
                        raise AuditAnchorError("Azure Blob list response exceeds maximum size")
                    body.extend(chunk)
        except AuditAnchorError:
            raise
        except httpx.HTTPError:
            raise AuditAnchorError("Azure Blob list request failed") from None
        return _parse_blob_list(bytes(body))

    def _fetch_anchor(self, leaf_name: str) -> AuditAnchor:
        url = f"{self._container_url}/{quote(f'{_ANCHOR_LAYOUT_PREFIX}/{leaf_name}', safe='/')}"
        try:
            with self._client.stream("GET", url, headers=self._headers()) as response:
                if response.status_code != 200:
                    raise AuditAnchorError(f"Azure Blob read-back fetch failed with status {response.status_code}")
                content = self._bounded_content(response)
        except AuditAnchorError:
            raise
        except httpx.HTTPError:
            raise AuditAnchorError("Azure Blob read-back request failed") from None
        return AuditAnchor.from_bytes(content)

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


def _parse_blob_list(body: bytes) -> tuple[list[str], str]:
    """Extract anchor leaf names and the continuation marker from list XML.

    Only ``<Name>`` values under the anchor layout prefix are returned, stripped
    to their leaf ``<seq>-<hash>.json`` form. Anything outside the prefix (a
    stray object in the container) is ignored rather than trusted.
    """

    try:
        root = ElementTree.fromstring(body)  # noqa: S314 - Azure control-plane XML, size-bounded above  # nosec B314
    except ElementTree.ParseError:
        raise AuditAnchorError("Azure Blob list response is not valid XML") from None
    prefix = f"{_ANCHOR_LAYOUT_PREFIX}/"
    leaves: list[str] = []
    for name_element in root.iterfind("./Blobs/Blob/Name"):
        name = (name_element.text or "").strip()
        if name.startswith(prefix) and "/" not in name[len(prefix) :]:
            leaves.append(name[len(prefix) :])
    marker_element = root.find("./NextMarker")
    marker = (marker_element.text or "").strip() if marker_element is not None else ""
    return leaves, marker


class LocalWormAuditAnchorProvider:
    """Create-only anchor publication onto a local, ideally-immutable volume.

    WORM CAVEAT (DRAFT — must be reviewed): a plain file under a directory this
    process can write is materially *weaker* than a legal-hold / immutable Azure
    Blob container. ``O_EXCL`` prevents *this* code from overwriting an existing
    anchor, but it does not stop a local root user, a compromised worker, or a
    backup/restore from deleting or rewriting the file. This provider is only
    equivalent to locked Blob when the directory lives on a genuinely separate,
    append-only / immutable volume (e.g. a WORM-mounted filesystem or a
    dedicated volume with restrictive ownership the worker cannot escalate).
    Otherwise treat it as a development / air-gapped-demo convenience, not a
    tamper-proof witness.
    """

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self._directory = Path(root) / _ANCHOR_LAYOUT_PREFIX

    @staticmethod
    def _read_bounded(path: Path) -> bytes:
        with path.open("rb") as handle:
            content = handle.read(_MAX_ANCHOR_BYTES + 1)
        if len(content) > _MAX_ANCHOR_BYTES:
            raise AuditAnchorError("existing audit anchor exceeds maximum size")
        return content

    def publish(self, anchor: AuditAnchor) -> Literal["created", "exists"]:
        content = anchor.canonical_bytes()
        if len(content) > _MAX_ANCHOR_BYTES:
            raise AuditAnchorError("audit anchor exceeds maximum size")
        self._directory.mkdir(parents=True, exist_ok=True)
        path = self._directory / anchor.leaf_name
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            existing = self._read_bounded(path)
            if existing != content:
                raise AuditAnchorMismatchError("immutable audit anchor key contains different content") from None
            return "exists"
        except OSError:
            raise AuditAnchorError("local audit anchor create failed") from None
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError:
            raise AuditAnchorError("local audit anchor write failed") from None
        return "created"

    def read_recent(self, limit: int) -> list[AuditAnchor]:
        if limit <= 0 or not self._directory.exists():
            return []
        try:
            candidates = [
                entry.name for entry in os.scandir(self._directory) if entry.is_file() and entry.name.endswith(".json")
            ]
            names = sorted(candidates, reverse=True)[:limit]
        except OSError:
            raise AuditAnchorError("local audit anchor enumeration failed") from None
        return [AuditAnchor.from_bytes(self._read_bounded(self._directory / name)) for name in names]

    def close(self) -> None:  # symmetry with AzureBlobAuditAnchorProvider
        return None

    def __enter__(self) -> LocalWormAuditAnchorProvider:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
