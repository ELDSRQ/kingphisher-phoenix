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

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from bs4 import BeautifulSoup
from kp_contracts.cue_ontology import (
    MAX_EVIDENCE_HASHES,
    build_cue_manifest,
    receipts_from_removed_tags,
    transformation_receipt,
)
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
    #: Deterministic cue + transformation manifest (see ``kp_contracts.cue_ontology``).
    cue_manifest: dict[str, Any]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _rewrite_anchor_hrefs(html: str) -> tuple[str, int, list[str]]:
    """Point every ``<a href>`` at the training placeholder.

    The sanitizer keeps an href only when it already equals the placeholder, so
    rewriting first preserves the deceptive link *text* ("Verify your account")
    while guaranteeing the destination is the inert training link. Returns the
    rewritten HTML, the count, and SHA-256 hashes of the *original* (replaced)
    destinations — bounded, and hashed so the manifest never carries the real
    malicious URL.
    """
    soup = BeautifulSoup(html, "html.parser")
    rewritten = 0
    original_hashes: list[str] = []
    for anchor in soup.find_all("a"):
        original = str(anchor.get("href", "")).strip()
        if original and original != TRAINING_URL_PLACEHOLDER and len(original_hashes) < MAX_EVIDENCE_HASHES:
            original_hashes.append(_sha256(original))
        anchor["href"] = TRAINING_URL_PLACEHOLDER
        rewritten += 1
    return str(soup), rewritten, original_hashes


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

    # Capture the originating (pre-neutralization) text now: cue extraction must
    # see the real lure, but only offsets + hashes of it are ever persisted.
    source_text = (plain_text or BeautifulSoup(raw_html or "", "html.parser").get_text("\n")).strip()

    # 1. Neutralize the payload: real link destinations -> training placeholder,
    #    then allow-list sanitize (drops scripts/forms/iframes/media/trackers and
    #    every attribute except the placeholder href). The deceptive copy stays.
    rewritten_html, rewritten_links, original_href_hashes = _rewrite_anchor_hrefs(raw_html or "")
    sanitized = sanitize_safe_html(
        rewritten_html,
        training_placeholder=TRAINING_URL_PLACEHOLDER,
        max_length=_MAX_BODY,
        allowed_image_hosts=allowed_image_hosts,
    )
    safe_html = sanitized.html

    # 2. Guarantee the one legitimate link exists (append a CTA if the source had
    #    none), so the clone can still become a recipient-bound training link.
    cta_injected = TRAINING_URL_PLACEHOLDER not in safe_html
    if cta_injected:
        safe_html = f"{safe_html}{_FALLBACK_HTML_CTA}"

    # 3. plain_text: prefer the supplied text, else derive from the clean HTML;
    #    neutralize any bare URL and guarantee the placeholder is present.
    text = (plain_text or BeautifulSoup(safe_html, "html.parser").get_text("\n")).strip()
    text, bare_urls_neutralized = _URL_RE.subn(TRAINING_URL_PLACEHOLDER, text)
    if TRAINING_URL_PLACEHOLDER not in text:
        text = f"{text}\n\n{_FALLBACK_TEXT_CTA}".strip()

    # 4. Payload gate (the safety guarantee, in place of the text validator): the
    #    sanitizer's allow-list already removes scripts/forms/iframes and keeps
    #    only the placeholder href; assert no navigable link escaped.
    foreign = _foreign_hrefs(safe_html)
    if foreign:
        raise CloneError(f"a non-training link survived neutralization: {foreign[:3]}")

    # 5. Transformation receipts: one per removed/replaced component class, each
    #    citing a fixed policy reason. The anchor-rewrite receipt carries hashed
    #    original destinations (never the raw URL); sanitiser-removed tags and
    #    stripped attributes fold into their own receipts.
    transformations: list[dict[str, Any]] = []
    if rewritten_links:
        transformations.append(
            transformation_receipt(
                "anchor_href",
                "replaced",
                "payload_link_removed",
                count=rewritten_links,
                evidence_hashes=tuple(original_href_hashes),
                detail={"replacement": "training_placeholder"},
            )
        )
    if bare_urls_neutralized:
        transformations.append(
            transformation_receipt(
                "bare_url", "replaced", "bare_url_neutralized", count=bare_urls_neutralized
            )
        )
    transformations.extend(receipts_from_removed_tags(dict(sanitized.removed_tags)))
    if sanitized.stripped_attributes:
        transformations.append(
            transformation_receipt(
                "attribute", "stripped", "disallowed_attribute_removed", count=sanitized.stripped_attributes
            )
        )
    if cta_injected:
        transformations.append(
            transformation_receipt("training_cta", "injected", "training_link_guaranteed")
        )

    cue_manifest = build_cue_manifest(
        subject=subject,
        body=source_text,
        transformations=transformations,
        source="reconstruction",
    )

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
        cue_manifest=cue_manifest,
    )
