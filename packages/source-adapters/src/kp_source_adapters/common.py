"""Shared normalization helpers for structured source adapters."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from kp_domain_models import models as dm
from kp_sanitization.html_to_text import sanitize_html


def source_url(source: dm.Source) -> str:
    path = source.fetch_path or "/"
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("source fetch path must be an absolute path, not a URL")
    return f"https://{source.base_domain}{path}"


def parse_datetime(value: Any, *, default: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        return default
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return default
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def clean_text(value: Any, *, limit: int = 100_000) -> str:
    return sanitize_html(str(value or ""))[:limit].strip()


def build_item(
    source: dm.Source,
    *,
    title: Any,
    body: Any,
    published_at: Any,
    source_reference: Any = "",
    publisher: Any = "",
    indicators: dict[str, Any] | None = None,
    retrieved_at: datetime | None = None,
) -> dm.SourceItem:
    now = retrieved_at or datetime.now(UTC)
    sanitized = clean_text(body)
    safe_title = clean_text(title, limit=255) or "Untitled source item"
    return dm.SourceItem(
        source_id=source.source_id,
        publisher=clean_text(publisher, limit=255) or source.name,
        title=safe_title,
        published_at=parse_datetime(published_at, default=now),
        retrieved_at=now,
        sanitized_text=sanitized,
        content_hash=hashlib.sha256(sanitized.encode("utf-8")).hexdigest(),
        source_reference=clean_text(source_reference, limit=2048),
        license_state_id=source.license_state_id,
        confidence=dm.Confidence.LOW,
        claimed_actor=None,
        claimed_target_sector=None,
        extracted_indicators=indicators or {},
        quarantine_state=dm.QuarantineState.ACTIVE,
        quarantine_reason=None,
        duplicate_of=None,
    )
