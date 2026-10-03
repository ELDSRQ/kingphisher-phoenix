"""Clone a real phishing message into a neutralized training template.

The operator pastes a genuine phishing email they have observed (e.g. one their
tenant received). To be useful training, the simulation must *look* like the
real campaign — including its deceptive language. To be safe, the *payload* is
removed: every link is pointed at the training placeholder, and the allow-list
sanitizer drops scripts, forms, iframes, media, trackers and every other
attribute. The result is a believable lure that can capture nothing and lead
nowhere real; the recognition happens when the recipient clicks and lands on the
training page.

This path deliberately does NOT run the text-based ``SafetyValidator`` (which
rejects words like "password" or "verification code") — reproducing the real
message's wording is the entire point. The harm is removed by neutralizing the
*mechanics*, not by forbidding the *copy*. Every clone is persisted as a DRAFT
and requires human review + approval before it can be attached to a campaign,
which itself only sends to a domain named in a signed Rules-of-Engagement.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_sanitization.safe_html import sanitize_safe_html

#: Conservative caps; TemplateVersion columns are Text, but keep clones bounded.
_MAX_SUBJECT = 998
_MAX_BODY = 200_000
#: A bare-URL matcher for neutralizing links in the plain-text body.
_URL_RE = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
#: Fallback CTA when the source message carried no link at all.
_FALLBACK_HTML_CTA = f'<p><a href="{TRAINING_URL_PLACEHOLDER}">Open the secure portal</a></p>'
_FALLBACK_TEXT_CTA = f"Open the secure portal: {TRAINING_URL_PLACEHOLDER}"


class CloneError(ValueError):
    """The supplied message could not be turned into a safe clone."""


@dataclass(slots=True)
class ClonedTemplate:
    """The neutralized content ready to persist as a DRAFT template."""

    subject: str
    plain_text: str
    safe_html: str
    provenance: dict[str, Any]


def _rewrite_anchor_hrefs(html: str) -> tuple[str, int]:
    """Point every ``<a href>`` at the training placeholder.

    The sanitizer keeps an href only when it already equals the placeholder, so
    rewriting first preserves the deceptive link *text* ("Verify your account")
    while guaranteeing the destination is the inert training link.
    """
    soup = BeautifulSoup(html, "html.parser")
    rewritten = 0
    for anchor in soup.find_all("a"):
        anchor["href"] = TRAINING_URL_PLACEHOLDER
        rewritten += 1
    return str(soup), rewritten


def _foreign_hrefs(html: str) -> list[str]:
    """Any href that is not the training placeholder (defensive payload gate)."""
    soup = BeautifulSoup(html, "html.parser")
    return [
        str(anchor.get("href"))
        for anchor in soup.find_all("a")
        if str(anchor.get("href", "")).strip() != TRAINING_URL_PLACEHOLDER
    ]


def clone_real_message(
    *,
    subject: str,
    raw_html: str,
    plain_text: str | None = None,
    allowed_image_hosts: Iterable[str] = (),
) -> ClonedTemplate:
    """Neutralize a real phishing message into a safe DRAFT-ready template.

    ``allowed_image_hosts`` is forwarded to the sanitizer so the clone can keep
    branded logos (self-contained ``data:image`` logos are always kept; https
    images are kept only from an allow-listed host). Raises :class:`CloneError`
    on empty input or if any navigable link somehow survives neutralization.
    """
    subject = subject.strip()
    if not subject:
        raise CloneError("a subject is required")
    if not raw_html.strip() and not (plain_text or "").strip():
        raise CloneError("the message body is empty")

    # 1. Neutralize the payload: real link destinations -> training placeholder,
    #    then allow-list sanitize (drops scripts/forms/iframes/media/trackers and
    #    every attribute except the placeholder href). The deceptive copy stays.
    rewritten_html, rewritten_links = _rewrite_anchor_hrefs(raw_html or "")
    sanitized = sanitize_safe_html(
        rewritten_html,
        training_placeholder=TRAINING_URL_PLACEHOLDER,
        max_length=_MAX_BODY,
        allowed_image_hosts=allowed_image_hosts,
    )
    safe_html = sanitized.html

    # 2. Guarantee the one legitimate link exists (append a CTA if the source had
    #    none), so the clone can still become a recipient-bound training link.
    if TRAINING_URL_PLACEHOLDER not in safe_html:
        safe_html = f"{safe_html}{_FALLBACK_HTML_CTA}"

    # 3. plain_text: prefer the supplied text, else derive from the clean HTML;
    #    neutralize any bare URL and guarantee the placeholder is present.
    text = (plain_text or BeautifulSoup(safe_html, "html.parser").get_text("\n")).strip()
    text = _URL_RE.sub(TRAINING_URL_PLACEHOLDER, text)
    if TRAINING_URL_PLACEHOLDER not in text:
        text = f"{text}\n\n{_FALLBACK_TEXT_CTA}".strip()

    # 4. Payload gate (the safety guarantee, in place of the text validator): the
    #    sanitizer's allow-list already removes scripts/forms/iframes and keeps
    #    only the placeholder href; assert no navigable link escaped.
    foreign = _foreign_hrefs(safe_html)
    if foreign:
        raise CloneError(f"a non-training link survived neutralization: {foreign[:3]}")

    provenance = {
        "source": "operator_clone",
        "rewritten_links": rewritten_links,
        "sanitizer": sanitized.as_provenance(),
    }
    return ClonedTemplate(
        subject=subject[:_MAX_SUBJECT],
        plain_text=text[:_MAX_BODY],
        safe_html=safe_html[:_MAX_BODY],
        provenance=provenance,
    )
