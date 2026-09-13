"""Contracts for the P3 web-search threat-discovery stage.

The discovery stage is the one place the platform reaches the *public web* (via
the Foundry Responses API ``web_search`` tool / Grounding with Bing). Two rules
shape this module, both enforced in code, not just convention:

* **No PII ever leaves in a query.** A discovery query may contain only public
  threat-research terms — never a recipient name/email, internal result, or any
  other PII (Microsoft documents that web-search data can flow outside the Azure
  compliance/geographic boundary). ``assert_pii_free_query`` is the guard.
* **No source, no campaign.** Every lead must cite at least one URL on the
  approved threat-intelligence allow-list; leads that cannot be sourced are
  dropped. ``citation_is_allowlisted`` is the guard.

A lead is an operator-facing *research lead*, not an approved pattern: a human
still reviews and promotes it through the existing governance path.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_DISCOVERY_QUERY_CHARS = 500
MAX_DISCOVERY_LEADS = 10
MAX_LEAD_FIELD_CHARS = 500
MAX_LEAD_SUMMARY_CHARS = 2000
MAX_LEAD_SOURCES = 5

#: Default approved public threat-intelligence citation domains. A lead must cite
#: at least one of these (or a subdomain). Overridable by configuration so the
#: operator can widen/narrow it without a code change.
DEFAULT_ALLOWED_CITATION_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "proofpoint.com",
        "cofense.com",
        "paloaltonetworks.com",
        "unit42.paloaltonetworks.com",
        "mandiant.com",
        "cloud.google.com",
        "talosintelligence.com",
        "cisco.com",
        "fortinet.com",
        "fortiguard.com",
        "mimecast.com",
        "abnormalsecurity.com",
        "recordedfuture.com",
        "checkpoint.com",
        "trendmicro.com",
        "sophos.com",
        "crowdstrike.com",
        "cisa.gov",
        "ncsc.gov.uk",
        "sans.org",
        "krebsonsecurity.com",
    }
)

# A query that looks like it carries PII (an email address, or an explicit
# name+role/department targeting phrase) must never be sent to the public web.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


class DiscoveryQueryError(ValueError):
    """Raised when a discovery query is unsafe to send to the public web."""


def assert_pii_free_query(query: str) -> str:
    """Return ``query`` if it is safe for public web search, else raise.

    Conservative and fail-closed: rejects anything containing an ``@`` email, to
    keep recipient identifiers out of a boundary-crossing search. The caller is
    expected to build queries from public threat terms only; this is the
    backstop, enforced in code (spec §10).
    """

    stripped = query.strip()
    if not stripped:
        raise DiscoveryQueryError("discovery query must not be empty")
    if len(stripped) > MAX_DISCOVERY_QUERY_CHARS:
        raise DiscoveryQueryError("discovery query exceeds the maximum length")
    if "@" in stripped or _EMAIL_RE.search(stripped):
        raise DiscoveryQueryError("discovery query must not contain an email address or PII")
    return stripped


def citation_is_allowlisted(url: str, allowed_domains: frozenset[str]) -> bool:
    """True when ``url`` is https and its host is (a subdomain of) an allowed domain."""

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in allowed_domains)


class CampaignLead(BaseModel):
    """A single cited, evidence-grounded discovery lead. Strict and bounded; it
    carries only public threat-intel facts (no PII)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(max_length=MAX_LEAD_FIELD_CHARS)
    claimed_brand: str = Field(default="", max_length=MAX_LEAD_FIELD_CHARS)
    lure_theme: str = Field(default="", max_length=MAX_LEAD_FIELD_CHARS)
    target_sector: str = Field(default="", max_length=MAX_LEAD_FIELD_CHARS)
    summary: str = Field(default="", max_length=MAX_LEAD_SUMMARY_CHARS)
    published_date: str = Field(default="", max_length=64)
    source_urls: list[str] = Field(default_factory=list, max_length=MAX_LEAD_SOURCES)
    confidence: float = 0.0

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, value: float) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return 0.0
        if numeric != numeric:  # NaN
            return 0.0
        return max(0.0, min(1.0, numeric))

    def allowlisted_sources(self, allowed_domains: frozenset[str]) -> list[str]:
        return [u for u in self.source_urls if citation_is_allowlisted(u, allowed_domains)]


class DiscoveryResult(BaseModel):
    """The gateway's /discover response: cited leads plus the pinned model id."""

    model_config = ConfigDict(extra="forbid")

    leads: list[CampaignLead] = Field(default_factory=list, max_length=MAX_DISCOVERY_LEADS)
    model_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def bound_leads(self) -> DiscoveryResult:
        if len(self.leads) > MAX_DISCOVERY_LEADS:
            raise ValueError("too many discovery leads")
        return self

    def sourced_leads(self, allowed_domains: frozenset[str]) -> list[CampaignLead]:
        """Leads that cite at least one allow-listed URL (no source => no campaign)."""

        kept: list[CampaignLead] = []
        for lead in self.leads:
            allowed = lead.allowlisted_sources(allowed_domains)
            if allowed:
                kept.append(lead.model_copy(update={"source_urls": allowed}))
        return kept
