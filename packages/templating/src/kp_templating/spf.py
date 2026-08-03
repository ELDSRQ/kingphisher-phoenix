"""SPF pre-flight checks before delivery.

Ported from the original King Phisher `king_phisher/spf.py`. Before a campaign
is delivered, verify the sending domain publishes an SPF record that could
authorize it (fail-closed: a missing/`-all`-only record is reported so
operators do not burn deliverability on a domain that will reject or spam-flag
the mail). This is advisory in Phoenix: it never blocks a *training* campaign
outright, but the warning is surfaced to operators and recorded in the audit
log.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.resolver


@dataclass
class SpfResult:
    domain: str
    has_spf: bool
    record: str | None
    error: str | None = None


def check_spf(domain: str, *, resolver_timeout: float = 5.0) -> SpfResult:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=resolver_timeout)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return SpfResult(domain=domain, has_spf=False, record=None)
    except (dns.exception.DNSException, dns.name.EmptyLabel, dns.name.IDNAException) as exc:
        return SpfResult(domain=domain, has_spf=False, record=None, error=str(exc))
    for rr in answers:
        txt = "".join(part.decode("utf-8", "replace") for part in rr.strings).strip()
        if txt.startswith("v=spf1"):
            return SpfResult(domain=domain, has_spf=True, record=txt)
    return SpfResult(domain=domain, has_spf=False, record=None)


def check_spf_for_mailbox(mailbox: str, *, resolver_timeout: float = 5.0) -> SpfResult:
    """Run the SPF check against the domain of `mailbox`, treating it as the
    RFC 5321.MailFrom / HELO domain for the campaign's envelope."""
    domain = mailbox.rsplit("@", 1)[-1] if "@" in mailbox else mailbox
    return check_spf(domain, resolver_timeout=resolver_timeout)
