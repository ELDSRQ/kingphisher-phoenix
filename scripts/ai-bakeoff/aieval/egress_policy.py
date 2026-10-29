"""Egress posture for AI evaluation: default local, acknowledge hosted.

KP-AUD-012 + Report-04 require that AI egress be used only when it adds
measurable value, and never by default. This module encodes the posture the
rest of the harness and the operator surface are held to:

* **Discovery defaults to local threat metadata.** The default discovery source
  is the on-network metadata already held by the platform; a hosted web-search
  discovery is a separate, explicitly acknowledged action.
* **A hosted (offsite) provider requires an explicit acknowledgement.** On- or
  unknown-network providers run without one; an offsite provider is denied
  unless the operator has acknowledged that content leaves the local network.
* **One PII backstop, not a second "no PII" claim.** The sole guard is the
  ``@``-backstop ``assert_pii_free_query`` in ``kp_contracts.discovery`` (W1-05
  corrected the over-broad "no PII" copy; this module does not re-assert it).
  ``pii_backstop`` delegates to that one function so there is a single source of
  truth, and the decision reasons describe egress honestly — "content leaves the
  local network" — never "no data leaves".

Egress classification is reused from the operator provider registry
(``kp_operator_api.ai_providers``); nothing here re-implements it.
"""

from __future__ import annotations

from dataclasses import dataclass

from kp_contracts.discovery import assert_pii_free_query
from kp_operator_api.ai_providers import (  # type: ignore[import-untyped]
    EGRESS_OFFSITE,
    EGRESS_ON_NETWORK,
    EGRESS_UNKNOWN,
    LOCAL,
    provider_egress,
)

#: The model-free deterministic baseline runs no model and reaches no network,
#: so it is on-network by construction (it is not a registry provider).
MODEL_FREE = "model_free"

#: Providers that are on-network by construction regardless of a base URL.
_ON_NETWORK_BY_CONSTRUCTION: frozenset[str] = frozenset({LOCAL, MODEL_FREE})

#: The default discovery source: on-network threat metadata, no egress.
DISCOVERY_SOURCE_LOCAL_METADATA = "local_metadata"
#: Hosted web-search discovery — the one path that reaches the public web.
DISCOVERY_SOURCE_HOSTED_WEB_SEARCH = "hosted_web_search"
DEFAULT_DISCOVERY_SOURCE = DISCOVERY_SOURCE_LOCAL_METADATA


@dataclass(frozen=True, slots=True)
class EgressDecision:
    """Whether an AI call may proceed, and why. Reasons describe egress honestly."""

    allowed: bool
    provider: str
    egress_class: str
    requires_acknowledgement: bool
    acknowledged: bool
    reason: str


def decide_generation_egress(provider: str, base_url: str | None, *, acknowledged: bool) -> EgressDecision:
    """Decide whether generation may run against ``provider``.

    Local and other on-network providers proceed without acknowledgement. An
    offsite provider — or one whose base URL cannot be proven on-network — is an
    egress decision the operator must make explicitly: it is allowed only when
    ``acknowledged`` is true, and denied otherwise.
    """

    egress = EGRESS_ON_NETWORK if provider in _ON_NETWORK_BY_CONSTRUCTION else provider_egress(provider, base_url)
    if egress == EGRESS_ON_NETWORK:
        return EgressDecision(
            allowed=True,
            provider=provider,
            egress_class=egress,
            requires_acknowledgement=False,
            acknowledged=acknowledged,
            reason="on-network provider; content stays on the local network",
        )
    # Offsite or unknown: fail safe to requiring an explicit acknowledgement.
    where = "offsite" if egress == EGRESS_OFFSITE else "a host that cannot be proven on-network"
    if acknowledged:
        return EgressDecision(
            allowed=True,
            provider=provider,
            egress_class=egress,
            requires_acknowledgement=True,
            acknowledged=True,
            reason=f"hosted provider acknowledged; content leaves the local network to {where}",
        )
    return EgressDecision(
        allowed=False,
        provider=provider,
        egress_class=egress,
        requires_acknowledgement=True,
        acknowledged=False,
        reason=f"hosted provider not acknowledged; content would leave the local network to {where}",
    )


def discovery_requires_acknowledgement(source: str) -> bool:
    """True when a discovery source reaches the public web and must be acknowledged."""

    return source != DISCOVERY_SOURCE_LOCAL_METADATA


def decide_discovery_egress(source: str = DEFAULT_DISCOVERY_SOURCE, *, acknowledged: bool = False) -> EgressDecision:
    """Decide whether a discovery run may proceed for the chosen source.

    The default source is on-network metadata and always proceeds. A hosted
    web-search source reaches the public web and is allowed only when explicitly
    acknowledged.
    """

    if source == DISCOVERY_SOURCE_LOCAL_METADATA:
        return EgressDecision(
            allowed=True,
            provider=LOCAL,
            egress_class=EGRESS_ON_NETWORK,
            requires_acknowledgement=False,
            acknowledged=acknowledged,
            reason="discovery uses local threat metadata; no egress",
        )
    egress = EGRESS_OFFSITE if source == DISCOVERY_SOURCE_HOSTED_WEB_SEARCH else EGRESS_UNKNOWN
    if acknowledged:
        return EgressDecision(
            allowed=True,
            provider=source,
            egress_class=egress,
            requires_acknowledgement=True,
            acknowledged=True,
            reason="hosted web-search discovery acknowledged; queries reach the public web",
        )
    return EgressDecision(
        allowed=False,
        provider=source,
        egress_class=egress,
        requires_acknowledgement=True,
        acknowledged=False,
        reason="hosted web-search discovery not acknowledged; queries would reach the public web",
    )


def pii_backstop(query: str) -> str:
    """The single PII backstop: delegate to the ``@``-backstop, add no new claim.

    W1-05 corrected the over-broad "no PII leaves" copy. This harness does not
    re-assert it; it reuses the one guard that fails closed on an ``@``/email in
    a boundary-crossing query, and nothing more.
    """

    return assert_pii_free_query(query)
