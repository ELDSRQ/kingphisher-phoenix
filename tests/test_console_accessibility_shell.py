from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

CONSOLE_ROOT = Path(__file__).resolve().parents[1] / "apps" / "operator-ui" / "src" / "console"
CONSOLE_SRC = Path(__file__).resolve().parents[1] / "apps" / "operator-ui" / "src" / "console-js"
HTML = (CONSOLE_ROOT / "index.html").read_text(encoding="utf-8")
CSS = (CONSOLE_ROOT / "styles.css").read_text(encoding="utf-8")
APP = (CONSOLE_SRC / "app.js").read_text(encoding="utf-8")


class _ConsoleShellParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []
        self.title_parts: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))
        self._in_title = tag == "title"

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def _parsed_shell() -> _ConsoleShellParser:
    parser = _ConsoleShellParser()
    parser.feed(HTML)
    return parser


def test_console_document_has_language_viewport_and_specific_title() -> None:
    parser = _parsed_shell()
    html_elements = [attrs for tag, attrs in parser.tags if tag == "html"]
    viewports = [attrs for tag, attrs in parser.tags if tag == "meta" and attrs.get("name") == "viewport"]

    assert html_elements == [{"lang": "en"}]
    assert viewports == [{"name": "viewport", "content": "width=device-width, initial-scale=1"}]
    assert "".join(parser.title_parts).strip() == "Kingphisher-Phoenix Operator Console"


def test_console_skip_link_precedes_and_targets_the_main_app_mount() -> None:
    parser = _parsed_shell()
    skip_links = [
        (position, attrs)
        for position, (tag, attrs) in enumerate(parser.tags)
        if tag == "a" and "skip-link" in (attrs.get("class") or "").split()
    ]
    app_mounts = [
        (position, tag, attrs) for position, (tag, attrs) in enumerate(parser.tags) if attrs.get("id") == "app"
    ]

    assert len(skip_links) == 1
    assert len(app_mounts) == 1
    skip_position, skip_attributes = skip_links[0]
    app_position, app_tag, app_attributes = app_mounts[0]
    assert skip_attributes.get("href") == "#app"
    assert "Skip to main content" in HTML
    assert app_tag == "main"
    assert app_attributes.get("tabindex") == "-1"
    assert skip_position < app_position


def test_console_css_keeps_keyboard_focus_and_user_display_preferences_visible() -> None:
    assert ":focus," in CSS
    assert ":focus-visible" in CSS
    assert "outline: 3px solid var(--focus)" in CSS
    assert "outline: 0" not in CSS
    assert "outline: none" not in CSS
    assert ".skip-link:focus" in CSS
    assert "transform: translateY(0)" in CSS
    assert "@media (prefers-reduced-motion: reduce)" in CSS
    assert "@media (prefers-contrast: more)" in CSS
    assert "@media (forced-colors: active)" in CSS
    assert "--focus: Highlight" in CSS


def test_dynamic_navigation_and_views_have_keyboard_focus_contracts() -> None:
    assert 'el("nav", { "aria-label": "Operator sections" })' in APP
    assert '"aria-current": id === active ? "page" : null' in APP
    assert 'id: "console-view", class: "content", role: "region", tabindex: "-1"' in APP
    assert 'const heading = content.querySelector("h1, h2")' in APP
    assert "if (!viewChanged || !content.isConnected) return" in APP
    assert "document.title = `${activeLabel} — Kingphisher-Phoenix Operator Console`" in APP
    assert 'class: "brand-logo", width: "36", height: "36"' in APP


def test_dialogs_are_named_restore_focus_and_support_native_form_submission() -> None:
    assert '"aria-labelledby": titleId' in APP
    assert '"aria-describedby": description ? descriptionId : null' in APP
    assert "const returnFocus = document.activeElement" in APP
    assert "returnFocus.isConnected) returnFocus.focus()" in APP
    assert 'form.addEventListener("submit"' in APP
    assert 'class: "btn primary", type: "submit", text: submitLabel' in APP


def test_errors_remain_dismissible_and_are_not_timed_away() -> None:
    assert 'notice.setAttribute("aria-atomic", "true")' in APP
    assert '"aria-label": "Dismiss notification"' in APP
    assert 'if (type !== "error") setTimeout(() => notice.remove(), 5000)' in APP
    assert ".toast-dismiss" in CSS


def test_primary_control_fill_has_a_separate_text_contrast_token() -> None:
    match = re.search(r"--accent-fill:\s*(#[0-9a-fA-F]{6})", CSS)
    assert match is not None
    fill = match.group(1)

    def luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [channel / 12.92 if channel <= 0.03928 else ((channel + 0.055) / 1.055) ** 2.4 for channel in channels]
        return (0.2126 * linear[0]) + (0.7152 * linear[1]) + (0.0722 * linear[2])

    contrast = (luminance("#ffffff") + 0.05) / (luminance(fill) + 0.05)
    assert contrast >= 4.5
    assert ".btn.primary { background: var(--accent-fill)" in CSS
    assert ".sidebar nav button.active { background: var(--accent-fill)" in CSS
    assert ".sidebar .brand-logo { grid-row: 1 / 3; width: 36px; height: 36px" in CSS
