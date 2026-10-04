"""Allow-list sanitizer for *generated* awareness-email HTML (P2).

Distinct from ``html_to_text.sanitize_html`` (which flattens inbound threat-feed
HTML to plain text). This one keeps a safe HTML *structure* for an outbound
simulation body: it rebuilds the markup from a small allow-list, drops active
elements (scripts, forms, iframes, media, objects), keeps an email-safe
*presentational* layer (sanitized inline ``style``, table/layout attributes, and
branded ``<img>`` graphics whose source is either a self-contained
``data:image`` or an https host on the operator's image allow-list), strips every
unsafe attribute (all ``on*`` handlers, ``url()``/``expression()``/``@import``
inside styles), and neutralizes any link by removing its ``href`` unless it is
exactly the training placeholder (the anchor text stays).

A realistic simulation needs to *look* like the brand it impersonates, so branded
layout and logos are deliberately preserved. The payload surface is not: there is
still no JavaScript, no form, no iframe, and no navigable link other than the one
recipient-bound tracking placeholder.

It is a **salvage** step, not the security authority: the platform's
``SafetyValidator`` still runs on the sanitized output and remains the
fail-closed gate (see ``apps/workers/.../jobs.py``). So the worst case of an
imperfect clean is that validation still rejects — never that unsafe content
passes. Running it first means a draft with one stray element (a ``<form>``, an
off-allowlist link, a tracking pixel) is cleaned and kept rather than the whole
generation being discarded.

Inline ``<svg>`` is intentionally NOT permitted: BeautifulSoup over
``html.parser`` lowercases case-sensitive SVG attributes (``viewBox`` etc.) and
SVG can itself carry script, so vector logos are not worth the surface — raster
logos via ``<img>`` (data URI or allow-listed https host) cover the same need.

No network, no new dependency: pure Beautiful Soup over the stdlib
``html.parser`` — safe on a fully disconnected on-prem deployment.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from html import unescape as _html_unescape
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment

from kp_sanitization.html_to_text import SanitizationError

#: Structural tags permitted in a simulation body. Everything here is inert —
#: no scripts, no forms, no resource loaders except the vetted ``<img>``.
_ALLOWED_TAGS = frozenset(
    {
        "p",
        "br",
        "hr",
        "a",
        "img",
        "span",
        "div",
        "center",
        "font",
        "strong",
        "b",
        "em",
        "i",
        "u",
        "s",
        "small",
        "sub",
        "sup",
        "mark",
        "ul",
        "ol",
        "li",
        "dl",
        "dt",
        "dd",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "blockquote",
        "pre",
        "code",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
        "td",
        "th",
        "caption",
        "colgroup",
        "col",
    }
)

#: Tags removed together with their contents: active content, forms, media, and
#: anything that can load a remote resource other than the vetted ``<img>``.
_DROP_WITH_CONTENT = frozenset(
    {
        "script",
        "style",
        "noscript",
        "template",
        "head",
        "title",
        "base",
        "link",
        "meta",
        "form",
        "input",
        "button",
        "textarea",
        "select",
        "option",
        "label",
        "fieldset",
        "legend",
        "iframe",
        "frame",
        "frameset",
        "object",
        "embed",
        "applet",
        "param",
        "picture",
        "source",
        "video",
        "audio",
        "track",
        "canvas",
        "map",
        "area",
        "svg",
        "math",
    }
)

#: Presentational attributes kept on any allow-listed tag. These are layout and
#: colour only — none can load a resource or run code. ``style`` is kept too but
#: its *value* is sanitized (see ``_sanitize_style``); ``href``/``src`` are
#: handled per-tag below.
_PRESENTATIONAL_ATTRS = frozenset(
    {
        "style",
        "align",
        "valign",
        "dir",
        "title",
        "width",
        "height",
        "bgcolor",
        "color",
        "colspan",
        "rowspan",
        "cellpadding",
        "cellspacing",
        "cellborder",
        "border",
        "face",
        "size",
        "span",
        "nowrap",
    }
)

#: Substrings that, if present in a CSS declaration (whitespace-stripped,
#: lower-cased), make the whole declaration unsafe. ``url()`` and ``@import``
#: fetch remote resources; the rest are script/behaviour vectors.
_STYLE_BLOCKLIST = (
    "url(",
    "@import",
    "expression",
    "javascript:",
    "vbscript:",
    "-moz-binding",
    "behavior",
)

#: Self-contained raster image data URIs. SVG data URIs are excluded on purpose
#: (they can carry script); vector logos are not supported here.
_DATA_IMAGE_RE = re.compile(
    r"^data:image/(?:png|jpe?g|gif|webp)(?:;[a-z0-9.+=-]+)*;base64,[a-z0-9+/=\s]+$",
    re.I,
)


#: CSS comment and escape handling, so an obfuscated ``url(...)`` cannot hide
#: from the blocklist below. ``ur/**/l(`` (comment), ``\75 rl(`` (hex escape),
#: and ``url\28 ...\29`` (escaped parens) must all normalize to ``url(``.
_CSS_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_CSS_ESCAPE_RE = re.compile(r"\\(?:([0-9a-fA-F]{1,6})\s?|(.))", re.S)


def _decode_css_escapes(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        hex_digits, literal = match.group(1), match.group(2)
        if hex_digits:
            try:
                return chr(int(hex_digits, 16))
            except (ValueError, OverflowError):
                return ""
        return literal or ""

    return _CSS_ESCAPE_RE.sub(_replace, value)


def _sanitize_style(value: str) -> str:
    """Drop any CSS declaration that could fetch a resource or run code.

    Keeps colour/font/spacing/border/layout declarations; removes ``url(...)``,
    ``@import``, ``expression(...)``, ``javascript:``/``vbscript:`` values,
    ``-moz-binding``/``behavior`` and off-flow ``position: fixed|absolute``. The
    dangerous-token test runs against a normalized probe (comments stripped,
    HTML entities and CSS escapes decoded) so obfuscated forms cannot slip past;
    this makes the sanitizer self-sufficient rather than relying on the
    delivery-time validator to catch the same thing.
    """

    # Strip CSS comments up front so they cannot hide a token or break the split.
    value = _CSS_COMMENT_RE.sub("", value)
    safe: list[str] = []
    for declaration in value.split(";"):
        decl = declaration.strip()
        if not decl or ":" not in decl:
            continue
        prop, _, val = decl.partition(":")
        prop_l = prop.strip().lower()
        val_l = val.strip().lower()
        probe = re.sub(r"\s+", "", _decode_css_escapes(_html_unescape(f"{prop_l}:{val_l}")))
        if any(token in probe for token in _STYLE_BLOCKLIST):
            continue
        if prop_l == "position" and val_l in {"fixed", "absolute"}:
            continue
        # Drop declarations that hide content from the reviewer's preview: a
        # realistic lure must show the reviewer exactly what the recipient sees.
        if (
            (prop_l == "display" and val_l == "none")
            or (prop_l == "visibility" and val_l in {"hidden", "collapse"})
            or (prop_l == "opacity" and val_l in {"0", "0.0", "0%"})
        ):
            continue
        safe.append(f"{prop.strip()}:{val.strip()}")
    return "; ".join(safe)


def _host_allowed(host: str, allowed_image_hosts: frozenset[str]) -> bool:
    if "*" in allowed_image_hosts:
        return True
    host = host.lower().rstrip(".")
    return any(host == allowed or host.endswith("." + allowed) for allowed in allowed_image_hosts)


def _valid_img_src(src: str, allowed_image_hosts: frozenset[str]) -> str | None:
    """Return a cleaned ``src`` if the image is self-contained or allow-listed.

    Permits a raster ``data:image`` URI, or an ``https://`` URL whose host is on
    the operator's image allow-list. Everything else (``http://``, other schemes,
    off-allowlist hosts, SVG data URIs) returns ``None`` so the image is dropped.
    """

    value = _html_unescape(src).strip()
    if _DATA_IMAGE_RE.match(value):
        return value
    if value.lower().startswith("https://"):
        host = (urlparse(value).hostname or "").lower()
        if host and _host_allowed(host, allowed_image_hosts):
            return value
    return None


@dataclass(frozen=True)
class SanitizedHtml:
    """The cleaned HTML plus a structured record of what was removed, for audit."""

    html: str
    removed_tags: dict[str, int] = field(default_factory=dict)
    neutralized_links: int = 0
    stripped_attributes: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.removed_tags) or self.neutralized_links > 0 or self.stripped_attributes > 0

    def as_provenance(self) -> dict[str, object]:
        """A compact, JSON-safe summary for the template's audit trail."""

        return {
            "removed_tags": dict(self.removed_tags),
            "neutralized_links": self.neutralized_links,
            "stripped_attributes": self.stripped_attributes,
            "changed": self.changed,
        }


def sanitize_safe_html(
    html: str,
    *,
    training_placeholder: str,
    max_length: int = 200_000,
    allowed_image_hosts: Iterable[str] = (),
) -> SanitizedHtml:
    """Return ``html`` reduced to the inert, email-safe allow-list.

    Keeps an email-safe presentational layer (sanitized inline ``style``, layout
    attributes, branded ``<img>`` graphics) so the simulation can look like the
    brand it impersonates. The only ``href`` kept is the training placeholder on
    ``<a>`` (bound to the recipient at delivery); every other link is neutralized
    to plain text. An ``<img>`` is kept only when its source is a self-contained
    ``data:image`` or an https host on ``allowed_image_hosts`` (``"*"`` allows any
    https host); otherwise the image is dropped. Every disallowed tag, attribute,
    and ``on*`` handler is removed.
    """

    if len(html) > max_length:
        raise SanitizationError(f"input too large: {len(html)} > {max_length}")

    image_hosts = frozenset(h.strip().lower().rstrip(".") for h in allowed_image_hosts if h.strip())

    removed: dict[str, int] = {}
    neutralized = 0
    stripped = 0
    soup = BeautifulSoup(html, "html.parser")

    # Comments can hide injected directives; a reviewer cannot see them.
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    # Drop active/resource-bearing elements with their contents first.
    for tag in soup.find_all(lambda t: t.name in _DROP_WITH_CONTENT):
        removed[tag.name] = removed.get(tag.name, 0) + 1
        tag.decompose()

    # Then scrub what remains against the allow-list. Document order means an
    # outer disallowed wrapper is unwrapped before its (kept) children.
    for tag in list(soup.find_all(True)):
        name = tag.name
        if name not in _ALLOWED_TAGS:
            # Not active content (already decomposed) and not allow-listed: keep
            # the text, drop the tag.
            removed[name] = removed.get(name, 0) + 1
            tag.unwrap()
            continue

        # An <img> is kept only with a vetted source; otherwise drop it entirely.
        # Handle it in its own block so the kept source is a definite ``str``.
        if name == "img":
            cleaned_src = _valid_img_src(str(tag.get("src", "")), image_hosts)
            if cleaned_src is None:
                removed["img"] = removed.get("img", 0) + 1
                tag.decompose()
                continue
            for attr in list(tag.attrs):
                low_attr = attr.lower()
                if low_attr == "src":
                    tag.attrs[attr] = cleaned_src
                    continue
                if low_attr == "alt":
                    continue
                if low_attr == "style":
                    cleaned_style = _sanitize_style(str(tag.attrs.get("style", "")))
                    if cleaned_style:
                        tag.attrs[attr] = cleaned_style
                    else:
                        del tag.attrs[attr]
                        stripped += 1
                    continue
                if low_attr in _PRESENTATIONAL_ATTRS and not low_attr.startswith("on"):
                    continue
                del tag.attrs[attr]
                stripped += 1
            continue

        for attr in list(tag.attrs):
            low_attr = attr.lower()
            if low_attr.startswith("on"):
                del tag.attrs[attr]
                stripped += 1
                continue
            if name == "a" and low_attr == "href":
                if str(tag.attrs.get("href", "")).strip() == training_placeholder:
                    continue  # the one legitimate, recipient-bound link
                del tag.attrs[attr]
                neutralized += 1
                continue
            if low_attr == "style":
                cleaned_style = _sanitize_style(str(tag.attrs.get("style", "")))
                if cleaned_style:
                    tag.attrs[attr] = cleaned_style
                else:
                    del tag.attrs[attr]
                    stripped += 1
                continue
            if low_attr in _PRESENTATIONAL_ATTRS:
                continue
            del tag.attrs[attr]
            stripped += 1

    return SanitizedHtml(
        html=str(soup),
        removed_tags=removed,
        neutralized_links=neutralized,
        stripped_attributes=stripped,
    )
