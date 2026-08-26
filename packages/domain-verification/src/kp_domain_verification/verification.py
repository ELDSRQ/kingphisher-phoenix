"""DNS-challenge domain ownership verification.

A domain is treated as operator-verified only when a TXT record the operator
was told to publish is observable in public DNS. That observation is the proof
of control, and it anchors both authorization boundaries of the platform:

* **Target domains** (who may be mailed). Recipients may only sit in domains
  covered by a signed Rules-of-Engagement, and a domain only becomes a
  legitimate RoE target after passing this challenge.
* **Sending domains** (who mail is sent as). A lookalike domain only enters the
  sending pool after the same challenge plus the deliverability records from
  :func:`required_dns_records`.

A self-asserted config string is never proof of ownership — the verification
*is* the DNS observation. Every failure mode is fail-closed: no answer, a DNS
error, or a record mismatch all mean "not verified".

The DNS interaction mirrors ``kp_templating/spf.py`` (dnspython, bounded
``lifetime``, DNSExceptions converted to a result rather than raised).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Literal

import dns.exception
import dns.name
import dns.resolver

#: TXT record prefix the operator publishes as proof of control. The full
#: record value is ``{PREFIX}={challenge_token(domain)}``.
CHALLENGE_PREFIX = "kp-phoenix-verification"

#: When the DNS lookup itself fails we cannot distinguish "record absent" from
#: "verifier broken"; both are reported as verification errors, never success.
_VERIFY_FAIL_CLOSED_ERRORS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

_DOMAIN_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")

#: Relay provider -> the SPF mechanism that authorizes its sending IPs. The
#: wizard emits these so the lookalike path only claims what actually delivers.
_RELAY_SPF_INCLUDE = {
    "ses": "v=spf1 include:amazonses.com ~all",
    "mailgun": "v=spf1 include:mailgun.org ~all",
}

RelayKind = Literal["smtp", "ses", "mailgun", "postfix"]


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of one DNS-challenge verification attempt."""

    domain: str
    verified: bool
    token: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class DnsRecord:
    """One DNS record for the operator to publish, with the reasoning."""

    record_type: str
    name: str
    value: str
    ttl: int = 3600
    note: str = ""


def normalize_domain(domain: str) -> str | None:
    """Normalize a single domain for verification, or None if unusable.

    Mirrors the recipient-allowlist normalization (leading ``@``/``.``
    stripped, lowercased) but rejects anything that is not a plausible DNS
    name. Non-ASCII input is refused: punycode must be supplied explicitly.
    """
    candidate = domain.strip().lower().lstrip("@").lstrip(".").rstrip(".")
    if not candidate or len(candidate) > 253:
        return None
    if not _DOMAIN_PATTERN.fullmatch(candidate):
        return None
    return candidate


def challenge_token(domain: str, *, signing_key: bytes) -> str:
    """Deterministic per-domain challenge token (HMAC-SHA256, base64url).

    The token is a keyed function of the domain alone, so the wizard can hand
    it to the operator to publish and later re-derive it during verification
    without storing per-challenge state. Only the deployment key can mint or
    recognize a token; an attacker who can read the DNS zone must also know
    the key to fake the record.
    """
    normalized = normalize_domain(domain)
    if normalized is None:
        raise ValueError(f"not a usable domain: {domain!r}")
    digest = hmac.new(signing_key, f"kp-phoenix:verify:{normalized}".encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:16]).decode("ascii")


def challenge_record_value(domain: str, *, signing_key: bytes) -> str:
    """The exact TXT value to publish for ``domain``."""
    return f"{CHALLENGE_PREFIX}={challenge_token(domain, signing_key=signing_key)}"


def _resolve_txt(domain: str, *, resolver_timeout: float) -> tuple[list[str], str | None]:
    """All TXT strings for ``domain``, or ``(records, error)``.

    Fail-closed contract: a DNS error is reported as ``error`` and the caller
    must treat the domain as unverified.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=resolver_timeout)
    except _VERIFY_FAIL_CLOSED_ERRORS:
        return [], None
    except (dns.exception.DNSException, dns.name.EmptyLabel, dns.name.IDNAException) as exc:
        return [], str(exc)
    records = ["".join(part.decode("utf-8", "replace") for part in rr.strings).strip() for rr in answers]
    return records, None


def verify_domain(domain: str, *, signing_key: bytes, resolver_timeout: float = 5.0) -> VerificationResult:
    """Check that ``domain`` publishes the challenge TXT record.

    Verified means: the TXT set contains exactly the value derived from the
    deployment key. Anything else — no record, malformed name, resolver error,
    or a stale/wrong value — is ``verified=False``.
    """
    normalized = normalize_domain(domain)
    if normalized is None:
        return VerificationResult(domain=domain, verified=False, error=f"not a usable domain: {domain!r}")
    token = challenge_token(normalized, signing_key=signing_key)
    expected = f"{CHALLENGE_PREFIX}={token}"
    records, error = _resolve_txt(normalized, resolver_timeout=resolver_timeout)
    if error is not None:
        return VerificationResult(domain=normalized, verified=False, token=token, error=f"dns error: {error}")
    if expected not in records:
        return VerificationResult(
            domain=normalized, verified=False, token=token, error="challenge TXT record not found"
        )
    return VerificationResult(domain=normalized, verified=True, token=token)


def required_dns_records(
    domain: str,
    *,
    signing_key: bytes,
    relay: RelayKind = "smtp",
    relay_address: str | None = None,
    dmarc_address: str | None = None,
) -> list[DnsRecord]:
    """The exact DNS records the wizard asks the operator to publish.

    The challenge TXT is the ownership proof and is exact. SPF must authorize
    the configured relay or mail will not deliver; DKIM keys are minted by the
    relay provider, so the record carries a placeholder and the operator
    fills in the relay's published value.
    """
    normalized = normalize_domain(domain)
    if normalized is None:
        raise ValueError(f"not a usable domain: {domain!r}")
    records = [
        DnsRecord(
            record_type="TXT",
            name=normalized,
            value=challenge_record_value(normalized, signing_key=signing_key),
            note="ownership challenge: publish this exact TXT value, then run verification",
        )
    ]
    spf_value = _RELAY_SPF_INCLUDE.get(relay)
    if relay == "postfix" or (relay == "smtp" and relay_address):
        spf_value = f"v=spf1 ip4:{relay_address} ~all"
    records.append(
        DnsRecord(
            record_type="TXT",
            name=normalized,
            value=spf_value or "v=spf1 <mechanism-for-your-relay> ~all",
            note=(
                "SPF: authorizes the relay's sending IPs. Without it, receiving "
                "servers treat the mail as unauthenticated and it will not deliver."
                if not spf_value
                else "SPF: authorizes the configured relay's sending IPs"
            ),
        )
    )
    dmarc = "v=DMARC1; p=reject"
    if dmarc_address:
        dmarc = f"v=DMARC1; p=reject; rua=mailto:{dmarc_address}"
    records.append(
        DnsRecord(
            record_type="TXT",
            name=f"_dmarc.{normalized}",
            value=dmarc,
            note="DMARC: policy for how receivers treat unauthenticated mail",
        )
    )
    records.append(
        DnsRecord(
            record_type="TXT",
            name=f"<selector>._domainkey.{normalized}",
            value="<value published by your relay provider>",
            note="DKIM: the relay provider mints the key; publish the provider's exact value",
        )
    )
    return records
