"""Source adapters.

Each adapter turns one allowlisted source (CERT advisory feed, vendor bulletin,
or curated threat-intel feed) into a sanitized SourceItem. All network access
goes through SecureFetcher; content is sanitized before it is stored.
"""

from __future__ import annotations

import hashlib
import re
import time
from datetime import UTC, datetime
from typing import Any, Protocol, TypedDict

import feedparser  # type: ignore[import-untyped]  # feedparser 6.x ships no py.typed marker
from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher

from kp_source_adapters.common import (
    AdapterError,
    clean_reference,
    clean_text,
    parse_datetime,
    source_url,
    validate_limit,
)

_RSS_CONTENT_TYPES = {"application/atom+xml", "application/rss+xml", "application/xml", "text/xml"}
_XML_DECLARATION_RE = re.compile(rb"<!\s*(?:doctype|entity)\b", re.I)


class SourceAdapter(Protocol):
    source_type: dm.SourceType

    def fetch(self) -> list[dm.SourceItem]: ...


class RssAdapter:
    """Adapter for RSS/Atom advisory feeds (CERT-CC, NVD, vendor feeds)."""

    source_type = dm.SourceType.RSS

    def __init__(self, source: dm.Source, fetcher: SecureFetcher, *, limit: int = 50) -> None:
        self._source = source
        self._fetcher = fetcher
        self._limit = validate_limit(limit, maximum=50)

    def fetch(self) -> list[dm.SourceItem]:
        result = self._fetcher.fetch(source_url(self._source))
        if result.content_type.lower() not in _RSS_CONTENT_TYPES:
            raise AdapterError("RSS source returned an unsupported content type")
        entries = _extract_items(result.content, limit=self._limit)
        now = datetime.now(UTC)
        items: list[dm.SourceItem] = []
        for entry in entries:
            title = clean_text(entry["title"], limit=255) or "Untitled source item"
            body = clean_text(entry["body"]) or title
            items.append(
                dm.SourceItem(
                    source_id=self._source.source_id,
                    publisher=clean_text(self._source.name, limit=255) or self._source.name,
                    title=title,
                    published_at=entry["published_at"],
                    retrieved_at=now,
                    sanitized_text=body,
                    content_hash=hashlib.sha256(body.encode("utf-8")).hexdigest(),
                    source_reference=clean_reference(entry["link"]),
                    license_state_id=self._source.license_state_id,
                    confidence=dm.Confidence.LOW,
                    claimed_actor=None,
                    claimed_target_sector=None,
                    extracted_indicators={},
                    quarantine_state=dm.QuarantineState.ACTIVE,
                    quarantine_reason=None,
                    duplicate_of=None,
                )
            )
        return items


class _ExtractedItem(TypedDict):
    title: str
    body: str
    link: str
    published_at: datetime


def _extract_items(data: str | bytes, *, limit: int) -> list[_ExtractedItem]:
    """Parse RSS/Atom entries with feedparser, preserving links and timestamps.

    Raw feed bytes go straight to feedparser (it honors XML encoding
    declarations); each entry's text is sanitized later by the caller through
    the standard sanitization pipeline. Feeds that yield no entries and are
    either malformed (bozo) or not recognized as RSS/Atom at all (e.g. an HTML
    error page) fail closed with AdapterError.
    """
    limit = validate_limit(limit, maximum=50)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    # Feed parsing never needs a DTD. Reject both ordinary ASCII declarations
    # and their NUL-interleaved UTF-16 representation before the XML parser.
    if _XML_DECLARATION_RE.search(raw.replace(b"\x00", b"")):
        raise AdapterError("RSS/Atom feed contains a prohibited XML declaration")
    parsed = feedparser.parse(data)
    if not parsed.entries and (parsed.bozo or not parsed.get("version")):
        raise AdapterError("malformed RSS/Atom feed")
    items: list[_ExtractedItem] = []
    for entry in parsed.entries:
        if len(items) >= limit:
            break
        title = str(entry.get("title") or "").strip()
        body = entry.get("summary") or entry.get("description") or title
        items.append(
            {
                "title": title,
                "body": str(body or ""),
                "link": str(entry.get("link") or ""),
                "published_at": _entry_datetime(entry, default=datetime.now(UTC)),
            }
        )
    return items


def _entry_datetime(entry: Any, *, default: datetime) -> datetime:
    """Normalize feedparser's published/updated fields to an aware UTC datetime."""
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if isinstance(parsed, time.struct_time):
            try:
                return datetime(*parsed[:6], tzinfo=UTC)
            except ValueError as exc:
                raise AdapterError(f"feed entry has an invalid timestamp: {parsed}") from exc
    for key in ("published", "updated"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return parse_datetime(value, default=default)
    return default
