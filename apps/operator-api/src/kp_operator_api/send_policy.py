"""Resolve the recipient-domain policy for a request.

Kept out of the routers so the fail-closed decision can be tested directly
rather than through an authenticated HTTP round trip.
"""

from __future__ import annotations

from kp_telemetry.errors import ValidationError_

from kp_operator_api.config import OperatorApiSettings

UNSET_ALLOWLIST_MESSAGE = (
    "no recipient domains are allowed yet; set KP_ALLOWED_RECIPIENT_DOMAINS before importing recipients"
)


def resolve_recipient_policy(settings: OperatorApiSettings) -> tuple[frozenset[str], bool]:
    """Return ``(allowlist, unrestricted)`` for recipient admission.

    An unconfigured allowlist means different things by posture:

    * **OIDC / production / any un-marked stack** — fail closed. Refusing the
      import costs an operator one configuration step; getting it wrong mails a
      simulation to an unintended domain.
    * **explicitly-marked dev stack** (dev-auth + ``KP_DEV_STACK=1``) — allow
      all, so the offline demo stack still works. The caller is expected to
      audit that it happened.

    PLT-002: allow-all now requires the explicit ``KP_DEV_STACK`` marker in
    addition to dev-auth, so an unset allowlist can never mean allow-all by
    default or via a single accidental env flip.

    Raises:
        ValidationError_: 422, when the allowlist is unset outside the marked
        dev stack.
    """
    allowlist = settings.recipient_domain_allowlist()
    if allowlist:
        return allowlist, False
    if not settings.dev_relaxations_allowed:
        raise ValidationError_(UNSET_ALLOWLIST_MESSAGE)
    return allowlist, True
