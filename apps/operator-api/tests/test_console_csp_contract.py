"""Console CSP delivery and source-compatibility contract.

The operator console is a static SPA mounted at ``/console`` inside the same
FastAPI app that serves the operator API.  The API's security middleware
stamps ``Content-Security-Policy: _CONSOLE_CSP`` on every response whose path
starts with ``/console``, and middleware wraps the router including the
StaticFiles mount — so the SPA must be compatible with that strict policy:

- event handlers are attached with ``addEventListener`` (never inline
  ``onclick="..."`` HTML attributes), which ``script-src 'self'`` permits; and
- dynamic presentation comes from stylesheet classes (never inline
  ``style="..."`` attributes), which ``style-src 'self'`` without
  ``'unsafe-inline'`` permits.

This test is the deterministic precursor to the live browser/WCAG
qualification lane.  It cannot replace a real browser, but it fails fast on
either half of the contract: the header not reaching the static mount, or the
source regressing to an inline handler/style that the policy would block.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from kp_operator_api.config import OperatorApiSettings
from kp_operator_api.main import _CONSOLE_CSP, create_app

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CONSOLE_DIR = _REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console"
INDEX_HTML = (_CONSOLE_DIR / "index.html").read_text(encoding="utf-8")
APP_JS = (_CONSOLE_DIR / "app.js").read_text(encoding="utf-8")

# Same fixed values as test_console.py so pydantic-settings cannot leak a
# developer's local .env into the app under test.
CONSOLE_JWT = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
CONSOLE_PASSWORD = "test-console-password"


def _settings() -> OperatorApiSettings:
    return OperatorApiSettings(
        audit_hmac_key="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ciphertext_kek="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        console_jwt_secret=CONSOLE_JWT,
        env_file="/dev/null",
        oidc_issuer="http://localhost:8443/realms/kingphisher",
        oidc_audience="kp-operator-api",
        console_static_dir=str(_CONSOLE_DIR),
    )


def _client() -> TestClient:
    return TestClient(create_app(_settings()))


def test_console_static_responses_carry_the_strict_csp() -> None:
    for path in ("/console/", "/console/app.js", "/console/styles.css"):
        with _client() as client:
            response = client.get(path)
        assert response.status_code == 200, path
        # The header must be the exact strict policy, not a weaker default.
        assert response.headers.get("content-security-policy") == _CONSOLE_CSP, path


def test_console_csp_forbids_unsafe_inline_and_unsafe_eval() -> None:
    assert "'unsafe-inline'" not in _CONSOLE_CSP
    assert "'unsafe-eval'" not in _CONSOLE_CSP
    assert "script-src 'self'" in _CONSOLE_CSP
    assert "style-src 'self'" in _CONSOLE_CSP


def test_console_index_has_no_inline_script_or_handler_attributes() -> None:
    # The SPA must load only self-hosted assets; any inline script block or
    # inline event-handler/style attribute would violate the strict CSP.
    assert "<script" in INDEX_HTML  # the single self-hosted app.js tag
    assert "onclick=" not in INDEX_HTML
    assert "onerror=" not in INDEX_HTML
    assert "style=" not in INDEX_HTML
    # Only the one script tag, referencing a self URL.
    assert INDEX_HTML.count("<script") == 1
    assert 'src="/console/app.js"' in INDEX_HTML


def test_console_el_attaches_handlers_via_add_event_listener() -> None:
    # el() must keep routing on* keys to addEventListener; a regression to
    # setAttribute would produce inline handler attributes that the console's
    # own script-src 'self' policy would block.
    assert "node.addEventListener(k.slice(2), v)" in APP_JS


def test_console_uses_no_inline_style_attributes() -> None:
    # Dynamic presentation must come from stylesheet classes.  A style: key
    # passed to el() falls through to setAttribute("style", ...), which the
    # console's own style-src 'self' policy would silently block.
    assert "style:" not in APP_JS
    assert 'setAttribute("style"' not in APP_JS


def test_ledger_trend_chart_is_csp_safe_and_namespace_correct() -> None:
    # The SVG chart must use createElementNS (SVG namespace), never el() with
    # inline style, and only presentation attributes (fill/x/y/width) that the
    # console's style-src 'self' policy permits.
    assert "SVG_NS" in APP_JS
    assert "document.createElementNS(SVG_NS, tag" in APP_JS
    assert "function svg(" in APP_JS
    assert "function ledgerTrendChart(" in APP_JS
    chart = APP_JS.split("function ledgerTrendChart(", 1)[1].split("\n  // Accessible", 1)[0]
    # No inline style attribute anywhere in the chart body.
    assert "style:" not in chart
    assert 'setAttribute("style"' not in chart
    # Series are drawn as bars with per-bar accessible titles.
    assert 'fill: s.color, role: "img"' in chart
    assert 'svg("title"' in chart
    # The SVG carries an accessible label and is a visual summary, not the data.
    assert '"aria-label"' in chart
    assert "report-chart-svg" in chart


def test_ledger_trend_chart_is_rendered_before_the_data_table() -> None:
    # The chart is a visual summary; the exact table must remain present as
    # the authoritative data surface (chronicled accessibility fallback).
    table_fn = APP_JS.split("function ledgerTable(", 1)[1]
    chart_index = table_fn.find("ledgerTrendChart(report)")
    table_index = table_fn.find('class: "report-table", "aria-label": "Five-year')
    assert chart_index != -1 and table_index != -1
    assert chart_index < table_index


def test_preview_height_and_frame_classes_exist_in_stylesheet() -> None:
    css = (_CONSOLE_DIR / "styles.css").read_text(encoding="utf-8")
    for selector in (".template-body.tall", ".template-body.medium", ".preview-frame.desktop", ".preview-frame.mobile"):
        assert selector in css, selector


def test_console_static_dir_resolves_inside_the_repository() -> None:
    # Guard against the mount silently degrading to API-only (missing dir) in
    # this test environment, which would make the delivery assertions vacuous.
    assert _CONSOLE_DIR.is_dir()
    assert (_CONSOLE_DIR / "app.js").is_file()
    assert (_CONSOLE_DIR / "index.html").is_file()
