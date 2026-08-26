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

from enum import StrEnum


class ApprovalPolicy(StrEnum):
    """How strictly campaign approvals are enforced before scheduling."""

    #: Scheduling requires completed security AND privacy approvals.
    ENFORCE = "enforce"
    #: Legacy/offline behaviour: a single admin may schedule unilaterally.
    #: Only permitted when the operator API runs in dev-auth mode.
    SINGLE_ADMIN = "single-admin"


def parse_domain_allowlist(raw: str | None) -> frozenset[str]:
    """Parse a comma/whitespace-separated domain list into a normalized set.

    Entries are lowercased and stripped of a leading ``@`` or ``.`` so that
    ``@example.com``, ``example.com`` and ``.example.com`` all mean the same
    thing. Empty input yields an empty set, which callers must interpret as
    "unconfigured" — never as "allow nothing" or "allow everything"; that
    decision belongs to the caller because it differs by auth mode.
    """
    if not raw:
        return frozenset()
    parts = (piece.strip().lower().lstrip("@").lstrip(".") for piece in raw.replace("\n", ",").split(","))
    return frozenset(part for part in parts if part)


def mailbox_domain(mailbox: str) -> str | None:
    """Return the lowercased domain of ``mailbox``, or None if unparseable.

    Deliberately strict: exactly one ``@``, and a non-empty local part and
    domain. Anything else is not a mailbox we are willing to send to.
    """
    candidate = mailbox.strip().lower()
    local, sep, domain = candidate.rpartition("@")
    if not sep or not local or not domain or candidate.count("@") != 1:
        return None
    return domain


def is_recipient_allowed(mailbox: str, allowlist: frozenset[str]) -> bool:
    """True when ``mailbox`` sits in an allowed domain or a subdomain of one.

    An empty ``allowlist`` returns False. Callers decide whether an
    unconfigured allowlist means fail-closed (OIDC/production) or
    allow-with-warning (dev-auth), so this function never guesses.
    """
    domain = mailbox_domain(mailbox)
    if domain is None or not allowlist:
        return False
    if domain in allowlist:
        return True
    return any(domain.endswith(f".{allowed}") for allowed in allowlist)
