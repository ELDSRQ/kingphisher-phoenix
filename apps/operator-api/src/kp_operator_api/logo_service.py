"""Attach (or remove) an operator-supplied logo on a DRAFT email template.

A generated or cloned lure is branded and styled but has no logo image — the
model only ever invents a placeholder image host, which the sanitizer correctly
drops. This lets the operator paste a real logo (an https URL to the brand's
asset, or a self-contained ``data:image``) which is injected as a centered
header at the top of the template's ``safe_html``; passing an empty logo removes
any previously-injected one, leaving the stylized branding as-is.

The logo lands in ``safe_html`` (not a side column), so it is covered by the
template's approval hash and by the same allow-list sanitizer + SafetyValidator
as all other content: an ``<img>`` survives only from a ``data:image`` or an
https host, and every other link/script/handler is still stripped. The operator
is the trusted party here, so the host they paste is allow-listed for this one
operation even if it is not in the global image-host policy — an image can
beacon but cannot harvest, and a human still approves the result.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from kp_sanitization.safe_html import sanitize_safe_html

#: Generous cap: a base64 ``data:image`` logo plus the body must still fit.
_MAX_BODY = 400_000


class LogoError(ValueError):
    """The supplied logo could not be applied."""


@dataclass(slots=True)
class LogoResult:
    safe_html: str
    logo_src: str | None


def _logo_host(logo: str) -> str | None:
    """Return the https host of ``logo``, or None for a data:image / invalid."""

    value = logo.strip()
    if value.lower().startswith("https://"):
        return (urlparse(value).hostname or "").lower() or None
    return None


def _is_supported_logo(logo: str) -> bool:
    value = logo.strip().lower()
    return value.startswith("https://") or value.startswith("data:image/")


def _strip_previous_logo(soup: BeautifulSoup, previous_logo_src: str | None) -> None:
    """Remove a logo this service injected earlier, so re-applying never stacks."""

    if not previous_logo_src:
        return
    for img in soup.find_all("img", src=previous_logo_src):
        parent = img.parent
        img.decompose()
        # Drop the now-empty centered <p> wrapper we added, so nothing accretes.
        if parent is not None and parent.name == "p" and not parent.get_text(strip=True) and not parent.find("img"):
            parent.decompose()


def apply_logo(
    current_safe_html: str,
    *,
    logo: str,
    previous_logo_src: str | None,
    training_placeholder: str,
    allowed_image_hosts: set[str],
) -> LogoResult:
    """Inject ``logo`` as a header (or remove the prior one when empty).

    Returns the re-sanitized ``safe_html`` and the logo src that now applies
    (``None`` when removed). Raises :class:`LogoError` for an unsupported logo
    scheme, or if applying it would drop the training placeholder or the image
    itself (e.g. an https host the sanitizer still refuses).
    """

    logo = (logo or "").strip()
    soup = BeautifulSoup(current_safe_html or "", "html.parser")
    _strip_previous_logo(soup, previous_logo_src)
    body_without_logo = str(soup)

    hosts = set(allowed_image_hosts)
    if logo:
        if not _is_supported_logo(logo):
            raise LogoError("a logo must be an https:// URL or a data:image value")
        host = _logo_host(logo)
        if host:
            hosts.add(host)
        # Prepend a centered logo header. Escape the src so an attribute-break
        # cannot smuggle markup; the sanitizer re-parses and re-validates anyway.
        safe_src = logo.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")
        logo_block = (
            '<p style="text-align:center; margin:0 0 16px 0">'
            f'<img src="{safe_src}" alt="Logo" style="max-height:48px; max-width:240px" />'
            "</p>"
        )
        combined = logo_block + body_without_logo
    else:
        combined = body_without_logo

    sanitized = sanitize_safe_html(
        combined,
        training_placeholder=training_placeholder,
        max_length=_MAX_BODY,
        allowed_image_hosts=hosts,
    )
    cleaned = sanitized.html

    if training_placeholder and training_placeholder not in cleaned:
        # Defensive: logo injection must never cost the recipient-bound link.
        raise LogoError("applying the logo removed the required training link")
    if logo and "<img" not in cleaned:
        # The sanitizer refused the image (unsupported scheme/host); say so
        # rather than silently persisting an unchanged, logo-less body.
        raise LogoError("the logo image could not be applied (unsupported source)")

    return LogoResult(safe_html=cleaned, logo_src=logo or None)
