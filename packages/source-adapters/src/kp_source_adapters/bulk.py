"""Bounded JSON and CSV bulk-download source adapter."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher

from kp_source_adapters.common import build_item, source_url
from kp_source_adapters.rss import AdapterError


class BulkDownloadAdapter:
    source_type = dm.SourceType.BULK_DOWNLOAD

    def __init__(self, source: dm.Source, fetcher: SecureFetcher, *, limit: int = 1000) -> None:
        self._source = source
        self._fetcher = fetcher
        self._limit = limit

    def fetch(self) -> list[dm.SourceItem]:
        result = self._fetcher.fetch(source_url(self._source))
        text = result.content.decode("utf-8-sig", errors="strict")
        content_type = result.content_type.lower()
        is_json = "json" in content_type or text.lstrip().startswith(("[", "{"))
        records = self._json_records(text) if is_json else self._csv_records(text)
        return [self._to_item(record) for record in records[: self._limit]]

    @staticmethod
    def _json_records(text: str) -> list[dict[str, Any]]:
        try:
            value = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AdapterError("bulk source did not return valid JSON") from exc
        if isinstance(value, dict):
            value = value.get("items")
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise AdapterError("bulk JSON must be an array or an object containing an items array")
        return value

    @staticmethod
    def _csv_records(text: str) -> list[dict[str, Any]]:
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise AdapterError("bulk CSV requires a header row")
        return [dict(row) for row in reader]

    def _to_item(self, record: dict[str, Any]) -> dm.SourceItem:
        title = record.get("title") or record.get("name") or record.get("subject")
        body = record.get("description") or record.get("body") or record.get("text") or title
        if not title or not body:
            raise AdapterError("bulk record requires title/name and description/body/text")
        reserved = {
            "title",
            "name",
            "subject",
            "description",
            "body",
            "text",
            "published_at",
            "published",
            "reference",
            "url",
            "publisher",
        }
        indicators = {
            str(key)[:128]: str(value)[:4096]
            for key, value in record.items()
            if key not in reserved and value not in (None, "")
        }
        return build_item(
            self._source,
            title=title,
            body=body,
            published_at=record.get("published_at") or record.get("published"),
            source_reference=record.get("reference") or record.get("url"),
            publisher=record.get("publisher"),
            indicators=indicators,
        )
