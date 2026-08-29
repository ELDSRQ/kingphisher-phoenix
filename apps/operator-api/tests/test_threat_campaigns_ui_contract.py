from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console-js" / "app.js").read_text(
    encoding="utf-8"
)
SOURCES = APP[APP.index("/* ---------- sources ---------- */") : APP.index("/* ---------- patterns ---------- */")]


def test_sources_area_is_extended_into_one_threat_campaigns_workbench() -> None:
    assert 'el("h2", { text: "Threat Campaigns" })' in SOURCES
    assert 'el("h3", { text: "Threat Campaigns workbench" })' in SOURCES
    assert 'el("h3", { text: "Configured sources" })' in SOURCES
    assert 'el("h3", { text: "New source" })' in SOURCES
    assert "supported RSS, STIX, and bulk-download source adapters" in SOURCES
    assert '["sources", "Sources"]' in APP


def test_threat_queue_uses_only_bounded_server_pagination_and_filters() -> None:
    assert "const THREAT_PAGE_LIMIT = 25;" in SOURCES
    assert "const THREAT_MAX_OFFSET = 10000;" in SOURCES
    assert "limit: String(THREAT_PAGE_LIMIT), offset: String(threatPageOffset)" in SOURCES
    assert "payload.items.length <= THREAT_PAGE_LIMIT" in SOURCES
    assert "Previous threat page" in SOURCES
    assert "Next threat page" in SOURCES
    assert "Math.min(THREAT_MAX_OFFSET" in SOURCES
    assert 'boundedCollection("/threats' not in SOURCES
    for field in ("review_state", "confidence", "freshness", "source_id"):
        assert f"threatFilterState.{field}" in SOURCES


def test_threat_rows_show_required_bounded_evidence_and_health() -> None:
    for field in (
        "item.title",
        "item.publisher",
        "item.citation",
        "item.published_at",
        "item.retrieved_at",
        "item.freshness.bucket",
        "item.claimed_actor",
        "item.claimed_target_sector",
        "item.ttp_indicator_summary",
        "item.confidence",
        "item.review_state",
        "item.source_health",
    ):
        assert field in SOURCES
    assert "Daily ingestion last attempt" in SOURCES
    assert "Last success" in SOURCES
    assert "health.consecutive_failures" in SOURCES
    assert "Server snapshot ${timeLabel(page.as_of)}" in SOURCES


def test_excerpt_and_citation_remain_untrusted_non_executing_text() -> None:
    assert "item.excerpt_is_untrusted === true" in SOURCES
    assert 'el("summary", { text: "View minimized untrusted excerpt" })' in SOURCES
    assert "remote HTML is never executed" in SOURCES
    assert "text: boundedMetadata(item.excerpt, 500)" in SOURCES
    assert "text: `Citation text: ${boundedMetadata(item.citation, 2048)}`" in SOURCES
    assert "href: item.citation" not in SOURCES
    assert "window.open" not in SOURCES
    assert ".innerHTML" not in SOURCES


def test_curation_actions_use_capability_guarded_server_routes() -> None:
    assert "const canManageSources = hasCapability(CAPABILITY.MANAGE_SOURCES);" in SOURCES
    assert 'api(`/threats/${encodeURIComponent(item.source_item_id)}/activate`, { method: "POST" })' in SOURCES
    assert "api(`/threats/${encodeURIComponent(item.source_item_id)}/reject`, {" in SOURCES
    assert "api(`/threats/${encodeURIComponent(item.source_item_id)}/merge-duplicate`, {" in SOURCES
    assert "disabled: !canManageSources" in SOURCES
    assert "maxLength: 256" in SOURCES
    assert "Non-identifying rationale" in SOURCES
    assert "page.items.filter((candidate) => candidate.source_item_id !== item.source_item_id)" in SOURCES
    assert "The server prevents self-links, missing targets, and duplicate cycles." in SOURCES


def test_loading_and_malformed_responses_fail_closed() -> None:
    assert "const validThreatPage = (payload) => Boolean(" in SOURCES
    assert "if (!validThreatPage(page))" in SOURCES
    assert "Actions remain unavailable." in SOURCES
    assert 'threatContent.setAttribute("aria-busy", "true")' in SOURCES
    assert '"aria-live": "polite"' in SOURCES
    assert '"aria-label": "Bounded threat campaign curation queue"' in SOURCES


def test_pattern_review_is_explicit_and_never_automatic() -> None:
    assert "creates or retains one deterministic draft pattern-basis candidate" in SOURCES
    assert "never approve a pattern, select recipients, or launch a campaign" in SOURCES
    assert 'text: "Open pattern review"' in SOURCES
    assert 'onclick: () => navigateTo("patterns")' in SOURCES
    assert "Pattern review is the explicit next step." in SOURCES
    action_success = SOURCES[SOURCES.index('toast("Threat evidence activated.') : SOURCES.index('text: "Reject"')]
    assert 'navigateTo("patterns")' not in action_success
