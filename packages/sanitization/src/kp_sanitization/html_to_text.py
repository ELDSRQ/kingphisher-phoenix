"""HTML-to-plain-text sanitizer.

Implements SAN-002: remove scripts, styles, forms, comments, hidden elements,
embedded objects, event handlers, remote resources, and tracking parameters,
then render to plain text.
"""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qsl, urlencode, urlparse

from bs4 import BeautifulSoup, Comment

REMOVE_TAGS = {
    "script",
    "style",
    "form",
    "iframe",
    "object",
    "embed",
    "svg",
    "math",
    "noscript",
    "template",
    "head",
}
REMOVE_ATTRS = {
    "onerror",
    "onload",
    "onclick",
    "onmouseover",
    "onmouseout",
    "onfocus",
    "onblur",
    "onchange",
    "onsubmit",
    "onkeydown",
    "onkeyup",
    "onkeypress",
    "oninput",
    "srcdoc",
    "formaction",
}
REMOVED_EVENT_PREFIX = "on"
TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "ref",
    "spm",
    "mtm_source",
    "mc_cid",
    "mc_eid",
}
_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_HIDDEN_STYLE_RE = re.compile(r"(?:^|;)(?:display:none|visibility:hidden|content-visibility:hidden)(?:;|$)")


class SanitizationError(Exception):
    """Raised when sanitization cannot produce safe output (fail closed)."""


def sanitize_html(html: str, max_length: int = 200_000) -> str:
    if len(html) > max_length:
        raise SanitizationError(f"input too large: {len(html)} > {max_length}")
    # Feed the parser only markup. Source adapters legitimately pass plain
    # titles and URLs through this boundary; parsing those adds no safety and
    # makes Beautiful Soup treat them as probable filenames/locators.
    if "<" not in html:
        return " ".join(unescape(html).split())
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(REMOVE_TAGS):
        tag.decompose()

    # Hidden feed/page content is a prompt-injection carrier: a human reviewer
    # cannot see it, but an HTML-to-text extractor otherwise would. Match the
    # ordinary declarative hiding mechanisms without trying to implement a CSS
    # engine or fetch stylesheets.
    for tag in list(soup.find_all(True)):
        style = _CSS_COMMENT_RE.sub("", str(tag.attrs.get("style", ""))).lower()
        compact_style = re.sub(r"\s+", "", style)
        if (
            tag.has_attr("hidden")
            or str(tag.attrs.get("aria-hidden", "")).strip().lower() == "true"
            or _HIDDEN_STYLE_RE.search(compact_style)
        ):
            tag.decompose()

    for tag in soup.find_all(True):
        if tag.name.startswith(REMOVED_EVENT_PREFIX):
            raise SanitizationError(f"unexpected tag name {tag.name!r}")
        for attr in list(tag.attrs):
            if attr.lower().startswith(REMOVED_EVENT_PREFIX) or attr.lower() in REMOVE_ATTRS:
                del tag.attrs[attr]
        blocked_tags = {"img", "link", "video", "audio", "source", "script"}
        if tag.name in blocked_tags and ("src" in tag.attrs or "href" in tag.attrs):
            # Remote resource references removed; src rewritten to about:blank if present.
            for attr in ("src", "href"):
                tag.attrs.pop(attr, None)
            tag.attrs["data-blocked-resource"] = "true"

    for element in soup.find_all(string=lambda text: isinstance(text, Comment)):
        element.extract()

    text = soup.get_text(separator=" ", strip=True)
    text = unescape(text)
    # Collapse whitespace.
    text = " ".join(text.split())
    return text


def strip_tracking(url: str) -> str:
    """Remove common tracking parameters from a URL for storage provenance."""
    parsed = urlparse(url)
    kept = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key.casefold() not in TRACKING_PARAMS
    ]
    return parsed._replace(query=urlencode(kept, doseq=True)).geturl()
