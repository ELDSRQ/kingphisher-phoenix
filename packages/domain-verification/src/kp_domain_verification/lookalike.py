"""Candidate sending domains (the lookalike generator).

Given a brand a lure imitates and a base domain the operator controls, this
proposes candidate sending hostnames and their ready-to-paste DNS records.
Every candidate is a subdomain of the operator's own registered domain, so
it is registerable and provable by the same DNS-TXT challenge — an operator
never has to guess which name is actually theirs.

Deliverability truth preserved: mail only delivers from a domain the
operator controls with valid SPF/DKIM/DMARC. Each candidate ships the exact
records to publish (ownership challenge, provider SPF, DMARC, DKIM
placeholder), and it only enters the sending pool after the challenge
verifies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from kp_domain_verification.verification import DnsRecord, RelayKind, normalize_domain, required_dns_records

#: The "adversary tradecraft" shapes: brand + a plausible service word, and the
#: service word prefixed by the brand. First word wins when a candidate would
#: otherwise collide or overflow a DNS label.
_SUFFIX_WORDS = [
    "alerts",
    "security",
    "support",
    "update",
    "portal",
    "notice",
    "verify",
    "account",
    "service",
    "access",
]

_LABEL_MAX = 63
_SAFE_TOKEN = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class LookalikeCandidate:
    """One candidate sending domain with everything needed to onboard it."""

    domain: str
    base_domain: str
    brand: str
    records: list[DnsRecord] = field(default_factory=list)


def _brand_token(brand: str) -> str:
    """Lowercase alphanumeric token for a brand ("Microsoft 365" -> m365).

    The token is truncated so the candidate label stays inside DNS limits
    after the suffix word is appended.
    """
    token = _SAFE_TOKEN.sub("", brand.lower())
    # Common words are dropped first so the distinctive brand part survives.
    for word in ("the", "365", "office", "security"):
        token = token.replace(word, "")
    return token[:20] or "brand"


def candidate_sending_domains(
    base_domain: str,
    brand: str,
    *,
    limit: int = 6,
    signing_key: bytes,
    relay: RelayKind = "smtp",
    relay_address: str | None = None,
    dmarc_address: str | None = None,
) -> list[LookalikeCandidate]:
    """Propose ``limit`` candidate sending hostnames under ``base_domain``.

    Each candidate is a valid DNS name on the operator's own domain and comes
    with the exact DNS records to publish. ``signing_key`` is the deployment
    key that mints the ownership-challenge token.
    """
    normalized_base = normalize_domain(base_domain)
    if normalized_base is None:
        raise ValueError(f"not a usable base domain: {base_domain!r}")
    token = _brand_token(brand)
    if not token:
        raise ValueError(f"brand produces no usable token: {brand!r}")

    candidates: list[LookalikeCandidate] = []
    seen: set[str] = set()
    patterns = [f"{token}-{word}" for word in _SUFFIX_WORDS] + [f"{word}-{token}" for word in _SUFFIX_WORDS[:5]]
    for label in patterns:
        if len(label) > _LABEL_MAX:
            continue
        domain = f"{label}.{normalized_base}"
        if domain in seen:
            continue
        seen.add(domain)
        records = required_dns_records(
            domain,
            signing_key=signing_key,
            relay=relay,
            relay_address=relay_address,
            dmarc_address=dmarc_address,
        )
        candidates.append(
            LookalikeCandidate(
                domain=domain,
                base_domain=normalized_base,
                brand=token,
                records=records,
            )
        )
        if len(candidates) >= max(1, limit):
            break
    return candidates
