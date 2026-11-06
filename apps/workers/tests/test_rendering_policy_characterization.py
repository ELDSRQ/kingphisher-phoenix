"""Characterization tests for the worker rendering/URL-fence policy (W5-03).

These pin the CURRENT observable behavior of the static-destination URL fence
(``_url_identity`` / ``_contains_url``) and the approved-template content guard
(``_delivery_template_content``) so the policy extraction in KP-AUD-023 is
provably behavior-preserving. They import from the stable public location
(``kp_workers.jobs``) so the SAME tests pass before and after the extraction.

Pure, in-memory, no PostgreSQL or network dependency.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_telemetry.errors import SafetyRejectionError
from kp_workers.jobs import (
    _contains_url,
    _delivery_template_content,
    _url_identity,
)


class TestUrlIdentity:
    def test_https_default_port_and_path(self) -> None:
        assert _url_identity("https://example.com/awareness") == ("https", "example.com", 443, "/awareness")

    def test_http_default_port_root_path(self) -> None:
        assert _url_identity("http://example.com") == ("http", "example.com", 80, "/")

    def test_explicit_port_preserved(self) -> None:
        assert _url_identity("https://example.com:8443/x") == ("https", "example.com", 8443, "/x")

    def test_host_lowercased(self) -> None:
        assert _url_identity("https://EXAMPLE.COM/A") == ("https", "example.com", 443, "/A")

    def test_trailing_punctuation_stripped(self) -> None:
        assert _url_identity("https://example.com/page).,") == ("https", "example.com", 443, "/page")

    def test_trailing_slash_normalized(self) -> None:
        assert _url_identity("https://example.com/path/") == ("https", "example.com", 443, "/path")

    def test_non_http_scheme_rejected(self) -> None:
        assert _url_identity("ftp://example.com/x") is None

    def test_no_hostname_rejected(self) -> None:
        assert _url_identity("https:///just-a-path") is None

    def test_not_a_url_rejected(self) -> None:
        assert _url_identity("not a url") is None

    @pytest.mark.parametrize("port", ["invalid", "65536", "-1"])
    def test_invalid_or_out_of_range_port_rejected(self, port: str) -> None:
        assert _url_identity(f"https://example.com:{port}/x") is None

    def test_explicit_zero_port_uses_default(self) -> None:
        assert _url_identity("https://example.com:0/x") == ("https", "example.com", 443, "/x")

    def test_ipv6_hostname_preserved_without_brackets(self) -> None:
        assert _url_identity("http://[::1]:8080/x") == ("http", "::1", 8080, "/x")


class TestContainsUrl:
    def test_exact_match(self) -> None:
        assert _contains_url("visit https://example.com/awareness today", "https://example.com/awareness") is True

    def test_query_string_ignored(self) -> None:
        assert _contains_url("https://example.com/awareness?x=1", "https://example.com/awareness") is True

    def test_html_escaped_match(self) -> None:
        content = "click &lt;https://example.com/awareness&gt;"
        assert _contains_url(content, "https://example.com/awareness") is True

    def test_percent_encoded_path_decoded_before_matching(self) -> None:
        assert _contains_url("https://example.com/%61wareness", "https://example.com/awareness") is True

    @pytest.mark.parametrize("entity", ["&amp;", "&#38;", "&#x26;"])
    def test_html_entities_decoded_in_path(self, entity: str) -> None:
        assert _contains_url(f"https://example.com/safety{entity}privacy", "https://example.com/safety&privacy")

    def test_later_url_can_match_after_an_unrelated_url(self) -> None:
        assert _contains_url(
            "https://other.example/awareness and https://example.com/awareness", "https://example.com/awareness"
        )

    def test_different_path_rejected(self) -> None:
        assert _contains_url("https://example.com/v1/track/click/abc", "https://example.com/awareness") is False

    def test_origin_root_does_not_match_path(self) -> None:
        assert _contains_url("https://example.com/", "https://example.com/awareness") is False

    def test_invalid_configured_url_is_false(self) -> None:
        assert _contains_url("https://example.com/awareness", "not-a-url") is False

    def test_absent_url_is_false(self) -> None:
        assert _contains_url("no links here", "https://example.com/awareness") is False


def _template(*, subject: str, plain_text: str, safe_html: str) -> SimpleNamespace:
    return SimpleNamespace(subject=subject, plain_text=plain_text, safe_html=safe_html)


class TestDeliveryTemplateContent:
    def test_valid_text_only(self) -> None:
        tmpl = _template(
            subject="Subject",
            plain_text=f"Hello {TRAINING_URL_PLACEHOLDER}",
            safe_html="",
        )
        assert _delivery_template_content(tmpl) == ("Subject", f"Hello {TRAINING_URL_PLACEHOLDER}", "")

    def test_valid_with_html_alternative(self) -> None:
        tmpl = _template(
            subject="S",
            plain_text=f"p {TRAINING_URL_PLACEHOLDER}",
            safe_html=f"<p>{TRAINING_URL_PLACEHOLDER}</p>",
        )
        assert _delivery_template_content(tmpl) == (
            "S",
            f"p {TRAINING_URL_PLACEHOLDER}",
            f"<p>{TRAINING_URL_PLACEHOLDER}</p>",
        )

    def test_empty_subject_rejected(self) -> None:
        tmpl = _template(subject="  ", plain_text=f"p {TRAINING_URL_PLACEHOLDER}", safe_html="")
        with pytest.raises(SafetyRejectionError):
            _delivery_template_content(tmpl)

    def test_whitespace_only_plain_text_rejected(self) -> None:
        tmpl = _template(subject="S", plain_text=" \t\n", safe_html=f"<p>{TRAINING_URL_PLACEHOLDER}</p>")
        with pytest.raises(SafetyRejectionError):
            _delivery_template_content(tmpl)

    def test_whitespace_only_html_is_a_text_only_template(self) -> None:
        tmpl = _template(subject="S", plain_text=f"Hello {TRAINING_URL_PLACEHOLDER}", safe_html=" \t\n")
        assert _delivery_template_content(tmpl) == ("S", f"Hello {TRAINING_URL_PLACEHOLDER}", " \t\n")

    def test_missing_plain_placeholder_rejected(self) -> None:
        tmpl = _template(subject="S", plain_text="no placeholder", safe_html="")
        with pytest.raises(SafetyRejectionError):
            _delivery_template_content(tmpl)

    def test_html_present_but_missing_placeholder_rejected(self) -> None:
        tmpl = _template(
            subject="S",
            plain_text=f"p {TRAINING_URL_PLACEHOLDER}",
            safe_html="<p>no placeholder</p>",
        )
        with pytest.raises(SafetyRejectionError):
            _delivery_template_content(tmpl)

    def test_non_string_fields_coerced_then_rejected(self) -> None:
        tmpl = _template(subject=None, plain_text=None, safe_html=None)
        with pytest.raises(SafetyRejectionError):
            _delivery_template_content(tmpl)
