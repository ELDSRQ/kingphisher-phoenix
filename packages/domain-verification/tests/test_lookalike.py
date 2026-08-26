"""Lookalike candidate generator tests."""

from __future__ import annotations

import pytest
from kp_domain_verification.lookalike import _brand_token, candidate_sending_domains

_KEY = b"k" * 32


def test_brand_token_normalizes() -> None:
    assert _brand_token("Microsoft 365") == "microsoft"
    assert _brand_token("IT Service Desk") == "itservicedesk"
    assert _brand_token("sharepoint!!") == "sharepoint"


def test_candidates_are_subdomains_of_base() -> None:
    candidates = candidate_sending_domains("corp-training.example", "Microsoft", signing_key=_KEY, limit=4)
    assert len(candidates) == 4
    for candidate in candidates:
        assert candidate.domain.endswith(".corp-training.example")
        assert candidate.brand == "microsoft"
        assert len(candidate.records) == 4


def test_candidates_carry_ready_to_paste_records() -> None:
    candidates = candidate_sending_domains("corp-training.example", "Okta", signing_key=_KEY, relay="ses", limit=2)
    candidate = candidates[0]
    assert candidate.records[0].name == candidate.domain
    assert candidate.records[0].value.startswith("kp-phoenix-verification=")
    assert any("include:amazonses.com" in r.value for r in candidate.records)
    assert any(r.name == f"_dmarc.{candidate.domain}" for r in candidate.records)


def test_candidates_are_deterministic_and_deduplicated() -> None:
    first = candidate_sending_domains("example.com", "Google", signing_key=_KEY, limit=10)
    second = candidate_sending_domains("example.com", "Google", signing_key=_KEY, limit=10)
    assert [c.domain for c in first] == [c.domain for c in second]
    assert len({c.domain for c in first}) == len(first)


def test_limit_is_bounded() -> None:
    candidates = candidate_sending_domains("example.com", "Microsoft", signing_key=_KEY, limit=2)
    assert len(candidates) == 2


def test_invalid_base_domain_is_rejected() -> None:
    with pytest.raises(ValueError):
        candidate_sending_domains("not a domain", "Microsoft", signing_key=_KEY)
