"""Send-safety policy primitives shared by the operator API and the workers.

Two controls live here because both services must agree on them exactly:

* **Approval policy** — whether a campaign may be scheduled without a completed
  two-person (security + privacy) approval.
* **Recipient-domain allowlist** — which mail domains a simulation may target.

Both are enforced twice, at the operator boundary (import / schedule) and again
in the delivery worker, so a message that was queued before a policy tightened
cannot slip out under the old rules.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum

_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_DOMAIN_SEPARATOR = re.compile(r"[,\s]+")


class ApprovalPolicy(StrEnum):
    """How strictly campaign approvals are enforced before scheduling."""

    #: Scheduling requires completed security AND privacy approvals.
    ENFORCE = "enforce"
    #: Legacy/offline behaviour: a single admin may schedule unilaterally.
    #: Only permitted when the operator API runs in dev-auth mode.
    SINGLE_ADMIN = "single-admin"


def normalize_policy_domain(raw: str, *, allow_config_prefix: bool = False) -> str | None:
    """Return one unambiguous ASCII DNS name, or ``None``.

    Unicode domain input is deliberately refused. Operators can supply the
    explicit IDNA A-label (``xn--...``), which is also the exact value proven
    by DNS verification. This avoids platform-dependent IDNA mappings in a
    send-authorization boundary.

    ``allow_config_prefix`` accepts exactly one legacy config marker (``@`` or
    ``.``). Repeated markers are invalid instead of being stripped until an
    attacker-controlled value happens to look valid.
    """

    if not isinstance(raw, str):
        return None
    candidate = raw.strip()
    if allow_config_prefix and candidate.startswith(("@", ".")):
        candidate = candidate[1:]
        if candidate.startswith(("@", ".")):
            return None
    if candidate.endswith("."):
        candidate = candidate[:-1]
        if candidate.endswith("."):
            return None
    try:
        candidate = candidate.encode("ascii").decode("ascii").lower()
    except UnicodeError:
        return None
    if not candidate or len(candidate) > 253:
        return None
    labels = candidate.split(".")
    # A single label (for example ``com``) would authorize every mailbox below
    # that DNS suffix and is never a suitable campaign boundary.
    if len(labels) < 2 or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels):
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return None


def parse_domain_allowlist(raw: str | None) -> frozenset[str]:
    """Parse a comma/whitespace-separated domain list into a normalized set.

    Entries are lowercased and stripped of a leading ``@`` or ``.`` so that
    ``@example.com``, ``example.com`` and ``.example.com`` all mean the same
    thing. Empty input yields an empty set, which callers must interpret as
    "unconfigured" — never as "allow nothing" or "allow everything"; that
    decision belongs to the caller because it differs by auth mode.
    """
    if raw is None or raw == "":
        return frozenset()
    if not isinstance(raw, str):
        raise ValueError("domain allowlist must be text")
    normalized: set[str] = set()
    for piece in _DOMAIN_SEPARATOR.split(raw.strip()):
        if not piece:
            continue
        domain = normalize_policy_domain(piece, allow_config_prefix=True)
        if domain is None:
            raise ValueError("domain allowlist contains an invalid domain")
        normalized.add(domain)
    return frozenset(normalized)


def mailbox_domain(mailbox: str) -> str | None:
    """Return the lowercased domain of ``mailbox``, or None if unparseable.

    Deliberately strict: exactly one ``@``, and a non-empty local part and
    domain. Anything else is not a mailbox we are willing to send to.
    """
    if not isinstance(mailbox, str):
        return None
    candidate = mailbox.strip()
    local, sep, domain = candidate.rpartition("@")
    if (
        not sep
        or not local
        or not domain
        or candidate.count("@") != 1
        or len(local) > 64
        or len(candidate) > 254
        or any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in local)
    ):
        return None
    return normalize_policy_domain(domain)


def is_recipient_allowed(mailbox: str, allowlist: frozenset[str]) -> bool:
    """True when ``mailbox`` sits in an allowed domain or a subdomain of one.

    An empty ``allowlist`` returns False. Callers decide whether an
    unconfigured allowlist means fail-closed (OIDC/production) or
    allow-with-warning (dev-auth), so this function never guesses.
    """
    domain = mailbox_domain(mailbox)
    if domain is None or not allowlist:
        return False
    normalized_allowlist = frozenset(
        normalized for item in allowlist if (normalized := normalize_policy_domain(item)) is not None
    )
    if domain in normalized_allowlist:
        return True
    return any(domain.endswith(f".{allowed}") for allowed in normalized_allowlist)


def resolve_sender(
    requested_mailbox: str,
    *,
    sending_domains: frozenset[str],
    default_sender: str,
) -> tuple[str, bool]:
    """Choose the envelope From address for a campaign.

    Returns ``(address, honored)``. When the requested mailbox sits on one of
    the authenticated ``sending_domains`` it is used verbatim, so an operator
    gets ``payroll@corp-benefits.example`` if ``corp-benefits.example`` is in
    the pool. Otherwise it falls back to ``default_sender`` and ``honored`` is
    False, because sending as an unauthenticated domain does not deliver —
    honoring the request would trade a visible fallback for an invisible bounce.

    An empty pool means "no restriction configured": the request is honored as
    given, which is the SMTP/offline path where the operator owns the relay.
    """
    domain = mailbox_domain(requested_mailbox)
    if domain is None:
        return default_sender, False
    if not sending_domains:
        return requested_mailbox, True
    normalized_domains = frozenset(
        normalized for item in sending_domains if (normalized := normalize_policy_domain(item)) is not None
    )
    if domain in normalized_domains or any(domain.endswith(f".{allowed}") for allowed in normalized_domains):
        return requested_mailbox, True
    return default_sender, False
