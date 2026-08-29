"""STIX 2.x bundle adapter with sanitized, bounded object extraction."""

from __future__ import annotations

import json
from typing import Any

from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher

from kp_source_adapters.common import AdapterError, build_item, clean_text, source_url, validate_limit

_SUPPORTED_TYPES = {"attack-pattern", "campaign", "indicator", "malware", "threat-actor", "tool", "vulnerability"}


class StixAdapter:
    source_type = dm.SourceType.STIX

    def __init__(self, source: dm.Source, fetcher: SecureFetcher, *, limit: int = 500) -> None:
        self._source = source
        self._fetcher = fetcher
        self._limit = validate_limit(limit, maximum=500)

    def fetch(self) -> list[dm.SourceItem]:
        result = self._fetcher.fetch(source_url(self._source))
        if result.content_type.lower() not in {"application/json", "application/stix+json"}:
            raise AdapterError("STIX source returned an unsupported content type")
        try:
            document = json.loads(result.content)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise AdapterError("source did not return valid JSON") from None
        if not isinstance(document, dict) or document.get("type") != "bundle":
            raise AdapterError("STIX payload must be a bundle")
        objects = document.get("objects")
        if not isinstance(objects, list):
            raise AdapterError("STIX bundle objects must be a list")
        items: list[dm.SourceItem] = []
        for obj in objects:
            if len(items) >= self._limit:
                break
            if not isinstance(obj, dict) or obj.get("type") not in _SUPPORTED_TYPES or obj.get("revoked") is True:
                continue
            stix_id = clean_text(obj.get("id", ""), limit=255)
            name = obj.get("name") or obj.get("pattern") or stix_id
            body = obj.get("description") or obj.get("pattern") or name
            indicators: dict[str, Any] = {"stix_id": stix_id, "stix_type": obj.get("type")}
            if isinstance(obj.get("pattern"), str):
                indicators["pattern"] = clean_text(obj["pattern"], limit=4096)
            items.append(
                build_item(
                    self._source,
                    title=name,
                    body=body,
                    published_at=obj.get("published") or obj.get("created") or obj.get("modified"),
                    source_reference=stix_id,
                    publisher=self._source.name,
                    indicators=indicators,
                )
            )
        return items
