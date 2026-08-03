"""Source adapters.

Each adapter turns one allowlisted source (CERT advisory feed, vendor bulletin,
or curated threat-intel feed) into a sanitized SourceItem. All network access
goes through SecureFetcher; content is sanitized before it is stored.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol, TypedDict

from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher
from kp_sanitization.html_to_text import sanitize_html


class AdapterError(Exception):
    pass


class SourceAdapter(Protocol):
    source_type: dm.SourceType

    def fetch(self) -> list[dm.SourceItem]: ...


class RssAdapter:
    """Adapter for RSS/Atom advisory feeds (CERT-CC, NVD, vendor feeds)."""

    source_type = dm.SourceType.RSS

    def __init__(self, source: dm.Source, fetcher: SecureFetcher, *, limit: int = 50) -> None:
        self._source = source
        self._fetcher = fetcher
        self._limit = limit

    def fetch(self) -> list[dm.SourceItem]:
        result = self._fetcher.fetch(f"https://{self._source.base_domain}")
        text = result.content.decode("utf-8", errors="replace")
        plain = sanitize_html(text)
        # Minimal XML-item extraction; the curation step later maps to patterns.
        items = _extract_items(plain, limit=self._limit)
        now = datetime.now(UTC)
        return [
            dm.SourceItem(
                source_id=self._source.source_id,
                publisher=item["title"],
                title=item["title"],
                published_at=item["published_at"],
                retrieved_at=now,
                sanitized_text=item["body"],
                content_hash=hashlib.sha256(item["body"].encode("utf-8")).hexdigest(),
                source_reference=item["link"],
                license_state_id=None,
                confidence=dm.Confidence.LOW,
                claimed_actor=None,
                claimed_target_sector=None,
                extracted_indicators={},
                quarantine_state=dm.QuarantineState.ACTIVE,
                quarantine_reason=None,
                duplicate_of=None,
            )
            for item in items
        ]


class _ExtractedItem(TypedDict):
    title: str
    body: str
    link: str
    published_at: datetime


def _extract_items(plain: str, *, limit: int) -> list[_ExtractedItem]:
    """Very small RSS item splitter: sections separated by <item> markers are
    replaced by plain-text blocks during sanitization; split on double-newline
    blocks. Production uses a proper feed parser per adapter."""
    blocks = [b.strip() for b in plain.split("\n\n") if b.strip()]
    items: list[_ExtractedItem] = []
    for block in blocks[:limit]:
        lines = [ln.strip() for ln in block.splitlines() if ln.strip()]
        if not lines:
            continue
        items.append(
            {
                "title": lines[0][:255],
                "body": block,
                "link": "",
                "published_at": datetime.now(UTC),
            }
        )
    return items
