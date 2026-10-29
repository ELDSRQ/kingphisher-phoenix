from __future__ import annotations

import pytest
from aieval.egress_policy import (
    DEFAULT_DISCOVERY_SOURCE,
    DISCOVERY_SOURCE_HOSTED_WEB_SEARCH,
    DISCOVERY_SOURCE_LOCAL_METADATA,
    decide_discovery_egress,
    decide_generation_egress,
    discovery_requires_acknowledgement,
    pii_backstop,
)


def test_default_discovery_source_is_local_metadata_with_no_egress() -> None:
    assert DEFAULT_DISCOVERY_SOURCE == DISCOVERY_SOURCE_LOCAL_METADATA
    decision = decide_discovery_egress()
    assert decision.allowed is True
    assert decision.requires_acknowledgement is False
    assert decision.egress_class == "on_network"
    assert "no egress" in decision.reason


def test_local_and_baseline_providers_need_no_acknowledgement() -> None:
    for provider in ("local", "model_free"):
        decision = decide_generation_egress(provider, None, acknowledged=False)
        assert decision.allowed is True
        assert decision.requires_acknowledgement is False
        assert decision.egress_class == "on_network"


def test_onprem_custom_base_url_stays_on_network() -> None:
    decision = decide_generation_egress("custom", "http://127.0.0.1:11434/v1", acknowledged=False)
    assert decision.allowed is True
    assert decision.egress_class == "on_network"


def test_offsite_provider_denied_without_acknowledgement_allowed_with() -> None:
    denied = decide_generation_egress("openai", "https://api.openai.com/v1", acknowledged=False)
    assert denied.allowed is False
    assert denied.requires_acknowledgement is True
    assert "leave the local network" in denied.reason
    # The reason describes egress honestly; it must NOT claim "no PII".
    assert "no pii" not in denied.reason.lower()

    allowed = decide_generation_egress("openai", "https://api.openai.com/v1", acknowledged=True)
    assert allowed.allowed is True
    assert allowed.egress_class == "offsite"


def test_unknown_host_fails_safe_to_requiring_acknowledgement() -> None:
    decision = decide_generation_egress("custom", "", acknowledged=False)
    assert decision.allowed is False
    assert decision.requires_acknowledgement is True
    assert decision.egress_class == "unknown"


def test_hosted_web_search_discovery_requires_acknowledgement() -> None:
    assert discovery_requires_acknowledgement(DISCOVERY_SOURCE_LOCAL_METADATA) is False
    assert discovery_requires_acknowledgement(DISCOVERY_SOURCE_HOSTED_WEB_SEARCH) is True

    denied = decide_discovery_egress(DISCOVERY_SOURCE_HOSTED_WEB_SEARCH, acknowledged=False)
    assert denied.allowed is False
    allowed = decide_discovery_egress(DISCOVERY_SOURCE_HOSTED_WEB_SEARCH, acknowledged=True)
    assert allowed.allowed is True
    assert "public web" in allowed.reason


def test_pii_backstop_is_the_single_at_guard() -> None:
    # Delegates to the W1-05 @-backstop; a clean public query passes through.
    assert pii_backstop("qr code phishing campaign 2026") == "qr code phishing campaign 2026"
    with pytest.raises(ValueError):
        pii_backstop("investigate alice@example.com phishing")
