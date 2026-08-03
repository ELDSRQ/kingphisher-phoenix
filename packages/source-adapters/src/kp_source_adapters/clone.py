"""Sanitized reference-page clone.

Ports the intent of the original King Phisher `WebPageCloner` (client/web_cloner.py)
into Phoenix's safe model. Instead of producing a live credential-harvesting
replica, this produces a **sanitized static reference snapshot** of a real page
used to author awareness-training material: scripts, forms, event handlers,
external resources, and tracking parameters are removed by the sanitizer, so
the output can never function as a credential entry form.

Unlike the WebKit2-based original, the clone is a single fetch through
SecureFetcher (allowlisted domain, no redirects off-site, size-capped) with
relative asset URLs stripped.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher
from kp_sanitization.html_to_text import sanitize_html


@dataclass
class ClonedReference:
    url: str
    final_url: str
    sanitized_text: str
    content_hash: str
    fetched_at: datetime


class ReferenceCloneService:
    def __init__(self, fetcher: SecureFetcher) -> None:
        self._fetcher = fetcher

    def clone(self, url: str) -> ClonedReference:
        result = self._fetcher.fetch(url)
        decoded = result.content.decode("utf-8", errors="replace")
        sanitized_text = sanitize_html(decoded)
        return ClonedReference(
            url=url,
            final_url=result.final_url,
            sanitized_text=sanitized_text,
            content_hash=hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest(),
            fetched_at=datetime.now(UTC),
        )

    def to_source_item(self, url: str, *, publisher: str, source_id: UUID) -> dm.SourceItem:
        ref = self.clone(url)
        return dm.SourceItem(
            source_id=source_id,
            publisher=publisher,
            title=f"Reference clone: {url}",
            published_at=ref.fetched_at,
            retrieved_at=ref.fetched_at,
            sanitized_text=ref.sanitized_text,
            content_hash=ref.content_hash,
            source_reference=ref.final_url,
            license_state_id=None,
            confidence=dm.Confidence.LOW,
            claimed_actor=None,
            claimed_target_sector=None,
            extracted_indicators={"clone_url": ref.final_url},
            quarantine_state=dm.QuarantineState.ACTIVE,
            quarantine_reason=None,
            duplicate_of=None,
        )
