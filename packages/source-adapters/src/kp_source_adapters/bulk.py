"""Bounded JSON and CSV bulk-download source adapter."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from kp_domain_models import models as dm
from kp_sanitization.fetcher import SecureFetcher

from kp_source_adapters.common import AdapterError, build_item, clean_text, source_url, validate_limit

_JSON_CONTENT_TYPES = {"application/json", "application/stix+json"}
_CSV_CONTENT_TYPES = {"text/csv"}


class BulkDownloadAdapter:
    source_type = dm.SourceType.BULK_DOWNLOAD

    def __init__(self, source: dm.Source, fetcher: SecureFetcher, *, limit: int = 1000) -> None:
        self._source = source
        self._fetcher = fetcher
        self._limit = validate_limit(limit, maximum=1000)

    def fetch(self) -> list[dm.SourceItem]:
        result = self._fetcher.fetch(source_url(self._source))
        try:
            text = result.content.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError:
            raise AdapterError("bulk source is not valid UTF-8") from None
        if "\x00" in text:
            raise AdapterError("bulk source contains prohibited NUL bytes")
        content_type = result.content_type.lower()
        if content_type in _JSON_CONTENT_TYPES:
            records = self._json_records(text)
        elif content_type in _CSV_CONTENT_TYPES:
            if text.lstrip().startswith(("[", "{")):
                raise AdapterError("bulk CSV content does not match its declared type")
            records = self._csv_records(text)
        elif content_type == "text/plain":
            records = self._json_records(text) if text.lstrip().startswith(("[", "{")) else self._csv_records(text)
        else:
            raise AdapterError("bulk source returned an unsupported content type")
        return [self._to_item(record) for record in records[: self._limit]]

    @staticmethod
    def _json_records(text: str) -> list[dict[str, Any]]:
        try:
            value = json.loads(text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            raise AdapterError("bulk source did not return valid JSON") from None
        if isinstance(value, dict):
            value = value.get("items")
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise AdapterError("bulk JSON must be an array or an object containing an items array")
        return value

    @staticmethod
    def _csv_records(text: str) -> list[dict[str, Any]]:
        try:
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames:
                raise AdapterError("bulk CSV requires a header row")
            return [dict(row) for row in reader]
        except csv.Error:
            raise AdapterError("bulk source did not return valid CSV") from None

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
            clean_text(key, limit=128): clean_text(value, limit=4096)
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
