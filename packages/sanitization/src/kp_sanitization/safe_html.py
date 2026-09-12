"""Allow-list sanitizer for *generated* awareness-email HTML (P2).

Distinct from ``html_to_text.sanitize_html`` (which flattens inbound threat-feed
HTML to plain text). This one keeps a safe HTML *structure* for an outbound
simulation body: it rebuilds the markup from a small allow-list, drops active
and resource-bearing elements (scripts, forms, iframes, images/tracking pixels,
media, objects), strips every attribute except a training-placeholder ``href``,
and neutralizes any other link by removing its ``href`` (the anchor text stays).

It is a **salvage** step, not the security authority: the platform's
``SafetyValidator`` still runs on the sanitized output and remains the
fail-closed gate (see ``apps/workers/.../jobs.py``). So the worst case of an
imperfect clean is that validation still rejects — never that unsafe content
passes. Running it first means a draft with one stray element (a ``<form>``, an
off-allowlist link, a tracking pixel) is cleaned and kept rather than the whole
generation being discarded.

No network, no new dependency: pure Beautiful Soup over the stdlib
``html.parser`` — safe on a fully disconnected on-prem deployment.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Comment

from kp_sanitization.html_to_text import SanitizationError

#: Structural tags permitted in a simulation body. Everything here is inert —
#: no scripts, no forms, no resource loaders.
_ALLOWED_TAGS = frozenset(
    {
        "p",
        "br",
        "hr",
        "a",
        "span",
        "div",
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
    }
)

#: Tags removed together with their contents: active content, forms, media, and
#: anything that can load a remote resource (a tracking pixel is an ``<img>``).
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
        "img",
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


def sanitize_safe_html(html: str, *, training_placeholder: str, max_length: int = 200_000) -> SanitizedHtml:
    """Return ``html`` reduced to the inert allow-list, plus what was removed.

    The only attribute kept is ``href`` on ``<a>``, and only when it is exactly
    the training placeholder (the one link a simulation legitimately carries,
    bound to the recipient at delivery). Every other link is neutralized to
    plain text, and every other attribute and tag is dropped.
    """

    if len(html) > max_length:
        raise SanitizationError(f"input too large: {len(html)} > {max_length}")

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
        if name in _ALLOWED_TAGS:
            for attr in list(tag.attrs):
                if name == "a" and attr == "href" and str(tag.attrs.get("href", "")).strip() == training_placeholder:
                    continue  # the one legitimate, recipient-bound link
                del tag.attrs[attr]
                if name == "a" and attr == "href":
                    neutralized += 1
                else:
                    stripped += 1
            continue
        # Not active content (already decomposed) and not allow-listed: keep the
        # text, drop the tag.
        removed[name] = removed.get(name, 0) + 1
        tag.unwrap()

    return SanitizedHtml(
        html=str(soup),
        removed_tags=removed,
        neutralized_links=neutralized,
        stripped_attributes=stripped,
    )
