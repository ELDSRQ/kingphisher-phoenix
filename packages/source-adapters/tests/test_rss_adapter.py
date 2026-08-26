"""RssAdapter tests: real RSS/Atom parsing through feedparser + sanitization."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import pytest
from kp_domain_models import models as dm
from kp_sanitization.fetcher import FetchResult
from kp_source_adapters import AdapterError, RssAdapter

_ESCAPED_HTML_DESCRIPTION = (
    "&lt;p&gt;Attackers send &lt;b&gt;invoice lures&lt;/b&gt;&lt;/p&gt;&lt;script&gt;steal()&lt;/script&gt;"
)

RSS_FEED = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Example Advisories</title>
    <link>https://feed.example/</link>
    <description>Advisory feed</description>
    <item>
      <title>Payroll phishing campaign</title>
      <link>https://feed.example/advisories/101</link>
      <description>{_ESCAPED_HTML_DESCRIPTION}</description>
      <pubDate>Tue, 24 Feb 2026 10:30:00 GMT</pubDate>
    </item>
    <item>
      <title>Credential harvesting kit</title>
      <link>https://feed.example/advisories/102</link>
      <guid>urn:uuid:102</guid>
      <description><![CDATA[<p>Malicious <b>OAuth consent</b> page.</p>]]></description>
    </item>
  </channel>
</rss>
"""

ATOM_FEED = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example Atom Advisories</title>
  <entry>
    <title type="html">Atom advisory title</title>
    <link rel="alternate" href="https://feed.example/atom/201" />
    <id>urn:uuid:201</id>
    <published>2026-02-24T09:00:00Z</published>
    <updated>2026-02-24T18:00:00Z</updated>
    <summary type="html">&lt;p&gt;Atom &lt;b&gt;summary&lt;/b&gt; body&lt;/p&gt;</summary>
  </entry>
</feed>
"""


class _Fetcher:
    def __init__(self, content: bytes) -> None:
        self.result = FetchResult(
            url="https://feed.example/feeds/current",
            final_url="https://feed.example/feeds/current",
            content=content,
            content_type="application/rss+xml",
            status_code=200,
        )

    def fetch(self, url: str) -> FetchResult:
        return self.result


def _source() -> dm.Source:
    return dm.Source(
        source_id=uuid.uuid4(),
        source_key="test",
        name="Example Advisories",
        source_type=dm.SourceType.RSS,
        base_domain="feed.example",
        fetch_path="/feeds/current",
        enabled=True,
    )


def _fetch_items(content: bytes, *, limit: int = 50) -> list[dm.SourceItem]:
    return RssAdapter(_source(), _Fetcher(content), limit=limit).fetch()  # type: ignore[arg-type]


def test_rss_feed_extracts_title_link_and_timestamp() -> None:
    items = _fetch_items(RSS_FEED.encode())
    assert len(items) == 2
    first = items[0]
    assert first.title == "Payroll phishing campaign"
    assert first.source_reference == "https://feed.example/advisories/101"
    assert first.published_at == datetime(2026, 2, 24, 10, 30, tzinfo=UTC)
    assert first.source_id is not None
    assert first.publisher == "Example Advisories"
    assert first.quarantine_state == dm.QuarantineState.ACTIVE


def test_rss_entry_without_pubdate_defaults_to_retrieval_time() -> None:
    items = _fetch_items(RSS_FEED.encode())
    second = items[1]
    assert second.source_reference == "https://feed.example/advisories/102"
    assert abs((second.retrieved_at - second.published_at).total_seconds()) < 1


def test_sanitization_pipeline_strips_markup_and_scripts() -> None:
    items = _fetch_items(RSS_FEED.encode())
    body = items[0].sanitized_text
    assert body == "Attackers send invoice lures"
    assert "script" not in body.lower()
    assert "<" not in body
    assert items[0].content_hash == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_atom_feed_extracts_entries() -> None:
    items = _fetch_items(ATOM_FEED.encode())
    assert len(items) == 1
    entry = items[0]
    assert entry.title == "Atom advisory title"
    assert entry.source_reference == "https://feed.example/atom/201"
    assert entry.published_at == datetime(2026, 2, 24, 9, 0, tzinfo=UTC)
    assert entry.sanitized_text == "Atom summary body"


@pytest.mark.parametrize(
    "content",
    [
        b"this is not a feed at all",
        b"<rss version='2.0'><channel><title>Broken</title>",
        b"<html><body><p>an HTML error page, not a feed</p></body></html>",
    ],
)
def test_malformed_feed_fails_closed(content: bytes) -> None:
    with pytest.raises(AdapterError, match="malformed RSS/Atom feed"):
        _fetch_items(content)


def test_valid_feed_with_zero_items_returns_empty_list() -> None:
    empty = b'<?xml version="1.0"?><rss version="2.0"><channel><title>Empty</title></channel></rss>'
    assert _fetch_items(empty) == []


def test_entry_without_title_or_body_gets_placeholder() -> None:
    feed = (
        b'<?xml version="1.0"?><rss version="2.0"><channel>'
        b"<item><link>https://feed.example/x</link></item></channel></rss>"
    )
    items = _fetch_items(feed)
    assert len(items) == 1
    assert items[0].title == "Untitled source item"


def test_limit_bounds_item_count() -> None:
    entries = "".join(f"<item><title>item-{i}</title><description>body {i}</description></item>" for i in range(5))
    feed = f'<?xml version="1.0"?><rss version="2.0"><channel>{entries}</channel></rss>'.encode()
    assert len(_fetch_items(feed, limit=3)) == 3
