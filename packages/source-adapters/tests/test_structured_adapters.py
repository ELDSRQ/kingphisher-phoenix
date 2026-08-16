from __future__ import annotations

import json
import uuid

import pytest
from kp_domain_models import models as dm
from kp_sanitization.fetcher import FetchResult
from kp_source_adapters import AdapterError, BulkDownloadAdapter, StixAdapter


class _Fetcher:
    def __init__(self, content: bytes, content_type: str) -> None:
        self.result = FetchResult(
            url="https://feed.example",
            final_url="https://feed.example",
            content=content,
            content_type=content_type,
            status_code=200,
        )
        self.urls: list[str] = []

    def fetch(self, url: str) -> FetchResult:
        self.urls.append(url)
        return self.result


def _source(source_type: dm.SourceType) -> dm.Source:
    return dm.Source(
        source_id=uuid.uuid4(),
        source_key="test",
        name="Test Publisher",
        source_type=source_type,
        base_domain="feed.example",
        fetch_path="/feeds/current",
        enabled=True,
    )


def test_stix_bundle_extracts_supported_objects_and_sanitizes() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--123",
                "name": "Credential lure",
                "description": "<script>bad()</script><b>Invoice link</b>",
                "pattern": "[url:value = 'https://example.test']",
                "created": "2026-01-02T03:04:05Z",
            },
            {"type": "identity", "id": "identity--ignored", "name": "ignored"},
        ],
    }
    fetcher = _Fetcher(json.dumps(bundle).encode(), "application/json")
    items = StixAdapter(_source(dm.SourceType.STIX), fetcher).fetch()  # type: ignore[arg-type]
    assert fetcher.urls == ["https://feed.example/feeds/current"]
    assert len(items) == 1
    assert items[0].title == "Credential lure"
    assert "script" not in items[0].sanitized_text
    assert items[0].extracted_indicators["stix_id"] == "indicator--123"


def test_stix_rejects_non_bundle() -> None:
    fetcher = _Fetcher(b'{"type":"indicator"}', "application/json")
    with pytest.raises(AdapterError, match="bundle"):
        StixAdapter(_source(dm.SourceType.STIX), fetcher).fetch()  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("content", "content_type", "expected_title"),
    [
        (b'[{"title":"JSON alert","description":"A body","severity":"high"}]', "application/json", "JSON alert"),
        (b"title,description,severity\nCSV alert,A body,medium\n", "text/csv", "CSV alert"),
    ],
)
def test_bulk_json_and_csv(content: bytes, content_type: str, expected_title: str) -> None:
    fetcher = _Fetcher(content, content_type)
    items = BulkDownloadAdapter(_source(dm.SourceType.BULK_DOWNLOAD), fetcher).fetch()  # type: ignore[arg-type]
    assert items[0].title == expected_title
    assert items[0].extracted_indicators["severity"] in {"high", "medium"}


def test_bulk_enforces_record_limit() -> None:
    content = json.dumps([{"title": f"item-{i}", "body": "body"} for i in range(20)]).encode()
    items = BulkDownloadAdapter(
        _source(dm.SourceType.BULK_DOWNLOAD),
        _Fetcher(content, "application/json"),
        limit=3,  # type: ignore[arg-type]
    ).fetch()
    assert len(items) == 3
