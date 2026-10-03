"""Tests for operator logo attach/remove on a DRAFT template (logo_service)."""

from __future__ import annotations

import pytest
from bs4 import BeautifulSoup
from kp_operator_api.logo_service import LogoError, apply_logo

PLACEHOLDER = "{{ tracking.training_url }}"
BODY = f'<table><tr><td><p style="color:#005a9c">Hello</p><a href="{PLACEHOLDER}">Verify</a></td></tr></table>'
_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)


def _imgs(html: str) -> list[str]:
    return [str(i.get("src")) for i in BeautifulSoup(html, "html.parser").find_all("img")]


def test_https_logo_from_pasted_host_is_injected_and_link_preserved() -> None:
    # The operator's pasted host is trusted for this op even if not in the
    # global policy, so an empty allow-list still keeps the pasted logo.
    res = apply_logo(
        BODY,
        logo="https://cdn.acme.example/logo.png",
        previous_logo_src=None,
        training_placeholder=PLACEHOLDER,
        allowed_image_hosts=set(),
    )
    assert res.logo_src == "https://cdn.acme.example/logo.png"
    assert "cdn.acme.example/logo.png" in res.safe_html
    assert PLACEHOLDER in res.safe_html  # the training link survives
    assert "Hello" in res.safe_html


def test_data_image_logo_is_injected() -> None:
    res = apply_logo(
        BODY, logo=_PNG, previous_logo_src=None, training_placeholder=PLACEHOLDER, allowed_image_hosts=set()
    )
    assert res.logo_src == _PNG
    assert _imgs(res.safe_html) == [_PNG]


def test_empty_logo_removes_previous_leaving_branding() -> None:
    added = apply_logo(
        BODY, logo=_PNG, previous_logo_src=None, training_placeholder=PLACEHOLDER, allowed_image_hosts=set()
    )
    removed = apply_logo(
        added.safe_html, logo="", previous_logo_src=_PNG, training_placeholder=PLACEHOLDER, allowed_image_hosts=set()
    )
    assert removed.logo_src is None
    assert _imgs(removed.safe_html) == []
    assert "Hello" in removed.safe_html and PLACEHOLDER in removed.safe_html


def test_reapplying_replaces_and_does_not_stack() -> None:
    first = apply_logo(
        BODY,
        logo="https://cdn.acme.example/old.png",
        previous_logo_src=None,
        training_placeholder=PLACEHOLDER,
        allowed_image_hosts=set(),
    )
    second = apply_logo(
        first.safe_html,
        logo="https://cdn.acme.example/new.png",
        previous_logo_src="https://cdn.acme.example/old.png",
        training_placeholder=PLACEHOLDER,
        allowed_image_hosts=set(),
    )
    assert _imgs(second.safe_html) == ["https://cdn.acme.example/new.png"]


@pytest.mark.parametrize(
    "bad", ["http://cdn.acme.example/logo.png", "javascript:alert(1)", "ftp://h/x.png", "/logo.png"]
)
def test_unsupported_logo_scheme_is_rejected(bad: str) -> None:
    with pytest.raises(LogoError):
        apply_logo(BODY, logo=bad, previous_logo_src=None, training_placeholder=PLACEHOLDER, allowed_image_hosts=set())


def test_svg_data_image_logo_is_rejected() -> None:
    # Passes the scheme check but the sanitizer drops SVG data URIs -> surfaced.
    with pytest.raises(LogoError):
        apply_logo(
            BODY,
            logo="data:image/svg+xml;base64,PHN2Zy8+",
            previous_logo_src=None,
            training_placeholder=PLACEHOLDER,
            allowed_image_hosts=set(),
        )
