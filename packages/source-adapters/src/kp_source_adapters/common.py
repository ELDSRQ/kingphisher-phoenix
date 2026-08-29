"""Shared normalization helpers for structured source adapters."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from kp_domain_models import models as dm
from kp_sanitization.html_to_text import SanitizationError, sanitize_html, strip_tracking

_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)


class AdapterError(Exception):
    """Stable, content-free source ingestion failure."""


def validate_limit(limit: int, *, maximum: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= maximum:
        raise ValueError(f"adapter limit must be between 1 and {maximum}")
    return limit


def _source_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if not domain or len(domain) > 253 or "." not in domain or any(ord(character) < 33 for character in domain):
        raise AdapterError("source base domain is malformed")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise AdapterError("source base domain is malformed") from None
    if not all(_DOMAIN_LABEL_RE.fullmatch(label) for label in domain.split(".")):
        raise AdapterError("source base domain is malformed")
    return domain


def source_url(source: dm.Source) -> str:
    path = source.fetch_path or "/"
    if len(path) > 2048 or any(ord(character) < 32 for character in path) or "\\" in path:
        raise AdapterError("source fetch path is malformed")
    parsed = urlsplit(path)
    if (
        not parsed.path.startswith("/")
        or parsed.path.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
    ):
        raise AdapterError("source fetch path must be an absolute path, not a URL")
    return urlunsplit(("https", _source_domain(source.base_domain), parsed.path, parsed.query, ""))


def parse_datetime(value: Any, *, default: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        return default
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return default
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def clean_text(value: Any, *, limit: int = 100_000) -> str:
    try:
        return sanitize_html(str(value or ""))[:limit].strip()
    except SanitizationError:
        raise AdapterError("source field exceeds the sanitization boundary") from None


def clean_reference(value: Any) -> str:
    """Sanitize provenance and discard common recipient tracking fields."""
    return strip_tracking(clean_text(value, limit=2048))


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
        source_reference=clean_reference(source_reference),
        license_state_id=source.license_state_id,
        confidence=dm.Confidence.LOW,
        claimed_actor=None,
        claimed_target_sector=None,
        extracted_indicators=indicators or {},
        quarantine_state=dm.QuarantineState.ACTIVE,
        quarantine_reason=None,
        duplicate_of=None,
    )
