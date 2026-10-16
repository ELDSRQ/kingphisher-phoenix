"""Apply reusable, approved image assets to a DRAFT template's HTML body.

An asset from the library (a FLUX-generated banner, a brand logo) is inlined into
``safe_html`` as a self-contained ``data:image`` URI — the same raster path the
sanitizer and SafetyValidator already permit, so delivery stays self-contained
and nothing new is reachable over the network. Placement is deterministic and
slot-based: a ``banner``/``decorative`` asset is a full-width header at the very
top, a ``logo`` is a centered header just below it. The header is rebuilt from
the recorded slots on every apply, so re-applying never stacks and the order
never depends on which asset was applied first.

Mirrors :mod:`kp_operator_api.logo_service`: the image lands in ``safe_html`` so
it is covered by the template approval hash and re-run through the same allow-list
sanitizer + SafetyValidator as all other content; a human still approves the
result.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass

from bs4 import BeautifulSoup
from kp_domain_models import models as dm
from kp_sanitization.safe_html import sanitize_safe_html

#: Generous cap: base64 data:image header(s) plus the body must still fit. Matches
#: logo_service so a banner+logo+body shares the same ceiling.
_MAX_BODY = 400_000

#: The slot an asset kind occupies in the rebuilt header.
_BANNER_SLOT = "banner"
_LOGO_SLOT = "logo"


class AssetApplyError(ValueError):
    """The asset could not be applied to the template body."""


@dataclass(slots=True)
class AssetApplyResult:
    safe_html: str
    #: The data:image URI now occupying each slot (absent slot == not present).
    slots: dict[str, str]


def asset_data_uri(media_type: str, content: bytes) -> str:
    """Build a self-contained ``data:image`` URI from stored asset bytes."""

    encoded = base64.b64encode(content).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


def slot_for_kind(kind: dm.AssetKind) -> str:
    """Map an asset kind to its header slot (decorative shares the banner slot)."""

    return _LOGO_SLOT if kind is dm.AssetKind.LOGO else _BANNER_SLOT


def _escape_src(src: str) -> str:
    return src.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")


def _banner_block(src: str) -> str:
    return (
        '<p style="margin:0 0 16px 0">'
        f'<img src="{_escape_src(src)}" alt="" '
        'style="display:block; width:100%; max-width:600px; height:auto; border:0" />'
        "</p>"
    )


def _logo_block(src: str) -> str:
    return (
        '<p style="text-align:center; margin:0 0 16px 0">'
        f'<img src="{_escape_src(src)}" alt="Logo" style="max-height:48px; max-width:240px" />'
        "</p>"
    )


def _strip_previous(soup: BeautifulSoup, previous_srcs: Iterable[str]) -> None:
    """Remove any header image this service injected before, so re-applying never stacks."""

    for prev in previous_srcs:
        if not prev:
            continue
        for img in soup.find_all("img", src=prev):
            parent = img.parent
            img.decompose()
            if parent is not None and parent.name == "p" and not parent.get_text(strip=True) and not parent.find("img"):
                parent.decompose()


def apply_assets(
    current_safe_html: str,
    *,
    slots: dict[str, str],
    previous_srcs: Iterable[str],
    training_placeholder: str,
) -> AssetApplyResult:
    """Rebuild the header from ``slots`` and re-sanitize.

    ``slots`` maps ``"banner"``/``"logo"`` to the data:image URI that should
    occupy it (omit or empty to leave a slot clear). ``previous_srcs`` are the
    data:image URIs previously injected, stripped first so nothing accretes.
    Raises :class:`AssetApplyError` if sanitizing drops the training placeholder
    or an applied image.
    """

    soup = BeautifulSoup(current_safe_html or "", "html.parser")
    _strip_previous(soup, previous_srcs)
    body_without_assets = str(soup)

    header = ""
    banner = (slots.get(_BANNER_SLOT) or "").strip()
    logo = (slots.get(_LOGO_SLOT) or "").strip()
    if banner:
        header += _banner_block(banner)
    if logo:
        header += _logo_block(logo)

    # data:image URIs carry their own payload and need no host allow-list.
    sanitized = sanitize_safe_html(
        header + body_without_assets,
        training_placeholder=training_placeholder,
        max_length=_MAX_BODY,
        allowed_image_hosts=set(),
    )
    cleaned = sanitized.html

    if training_placeholder and training_placeholder not in cleaned:
        raise AssetApplyError("applying the asset removed the required training link")
    applied_slots = {name: src for name, src in (("banner", banner), ("logo", logo)) if src}
    if applied_slots and "<img" not in cleaned:
        raise AssetApplyError("the asset image could not be applied (rejected by the sanitizer)")

    return AssetApplyResult(safe_html=cleaned, slots=applied_slots)
