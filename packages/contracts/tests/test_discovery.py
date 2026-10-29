"""Tests for the P3 web-search discovery contracts and its two in-code gates."""

from __future__ import annotations

import pytest
from kp_contracts.discovery import (
    DEFAULT_ALLOWED_CITATION_DOMAINS,
    CampaignLead,
    DiscoveryQueryError,
    DiscoveryResult,
    assert_pii_free_query,
    citation_is_allowlisted,
)

ALLOW = DEFAULT_ALLOWED_CITATION_DOMAINS


def test_pii_free_query_accepts_public_threat_terms() -> None:
    assert (
        assert_pii_free_query("  DocuSign phishing campaign September 2026  ")
        == "DocuSign phishing campaign September 2026"
    )


@pytest.mark.parametrize("bad", ["find phishing targeting jane.doe@corp.com", "a@b.co lure", ""])
def test_pii_free_query_rejects_email_or_empty(bad: str) -> None:
    with pytest.raises(DiscoveryQueryError):
        assert_pii_free_query(bad)


def test_pii_free_query_rejects_overlong() -> None:
    with pytest.raises(DiscoveryQueryError):
        assert_pii_free_query("x" * 501)


def test_citation_allowlist_requires_https_and_approved_host() -> None:
    assert citation_is_allowlisted("https://www.proofpoint.com/us/blog/x", ALLOW) is True
    assert citation_is_allowlisted("https://blog.checkpoint.com/x", ALLOW) is True  # subdomain
    assert citation_is_allowlisted("https://phish.evil/x", ALLOW) is False  # off-allowlist
    assert citation_is_allowlisted("http://www.proofpoint.com/x", ALLOW) is False  # not https
    assert citation_is_allowlisted("https://notproofpoint.com/x", ALLOW) is False  # not a real subdomain


def _lead(urls: list[str], brand: str = "DocuSign") -> dict:
    return {
        "title": "t",
        "claimed_brand": brand,
        "lure_theme": "invoice",
        "target_sector": "finance",
        "summary": "s",
        "published_date": "2026-09",
        "source_urls": urls,
        "confidence": 1.5,  # clamped to 1.0
    }


def test_sourced_leads_drops_unsourced_and_keeps_only_allowlisted_urls() -> None:
    result = DiscoveryResult(
        leads=[
            CampaignLead.model_validate(_lead(["https://www.proofpoint.com/a", "https://phish.evil/b"])),
            CampaignLead.model_validate(_lead(["https://phish.evil/only"], brand="Unsourced")),
        ],
        model_id="gpt-5.6-luna",
    )
    kept = result.sourced_leads(ALLOW)
    assert len(kept) == 1
    assert kept[0].claimed_brand == "DocuSign"
    assert kept[0].source_urls == ["https://www.proofpoint.com/a"]  # off-allowlist url filtered out
    assert kept[0].confidence == 1.0  # clamped


def test_discovery_result_requires_model_id() -> None:
    with pytest.raises(ValueError):
        DiscoveryResult(leads=[], model_id="")


def test_pii_free_query_is_only_an_email_backstop_not_general_pii() -> None:
    # KP-AUD-012 honesty: the guard is an email/"@" backstop, NOT general PII
    # detection. A query carrying a human name + role (clear PII) passes
    # UNTOUCHED — this test documents that limitation so no caller relies on it
    # as if it screened PII. An email address is still rejected.
    name_and_role = "phishing targeting the CFO Jane Smith in finance 2026"
    assert assert_pii_free_query(name_and_role) == name_and_role
    with pytest.raises(DiscoveryQueryError):
        assert_pii_free_query("report about victim jane.smith@corp.com")


def test_pii_free_query_docstring_states_its_narrow_scope() -> None:
    # The source-of-truth copy must say what the guard does NOT do (KP-AUD-012).
    doc = (assert_pii_free_query.__doc__ or "").lower()
    assert "not general pii detection" in doc
