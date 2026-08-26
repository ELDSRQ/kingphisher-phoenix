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

    An unconfigured allowlist means different things by auth mode:

    * **OIDC / production** — fail closed. Refusing the import costs an
      operator one configuration step; getting it wrong mails a simulation to
      an unintended domain.
    * **dev-auth** — allow all, so the offline demo stack still works. The
      caller is expected to audit that it happened.

    Raises:
        ValidationError_: 422, when the allowlist is unset outside dev-auth.
    """
    allowlist = settings.recipient_domain_allowlist()
    if allowlist:
        return allowlist, False
    if not settings.dev_auth_mode:
        raise ValidationError_(UNSET_ALLOWLIST_MESSAGE)
    return allowlist, True
