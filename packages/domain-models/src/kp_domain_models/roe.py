"""Signed Rules-of-Engagement (RoE): the authorization boundary for delivery.

An RoE is one signed artifact recording: who signed it (``signer``), on whose
authority (``authorizing_party``), for what period (``window_start`` /
``window_end``), against which operator-verified target domains
(``target_domains``), under what terms (``terms_text`` / ``terms_hash``).

The signature binds exactly ``terms_hash | signer | signed_at`` under the
deployment key. That is the minimum set that makes the artifact
non-repudiable: the terms text is itself hashed, so editing the terms —
including the embedded target-domain set and window — breaks verification.

Two coverage rules, both fail-closed:

* ``roe_covers_schedule`` — a campaign may only be scheduled when an
  unrevoked RoE's engagement window contains the campaign's whole delivery
  window.
* ``roe_active_at`` — delivery may only proceed while the RoE is unrevoked
  and the current time is inside its engagement window.

The target-domain boundary is enforced separately per recipient at delivery;
these functions only decide whether the RoE itself is valid for use.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime

from kp_domain_models.policy import is_recipient_allowed


def canonical_roe_bytes(terms_hash: str, signer: str, signed_at: datetime) -> bytes:
    """Canonical byte form of the signed RoE fields.

    ``signed_at`` is serialized to ISO-8601 with a fixed UTC offset so the
    signature does not depend on Python's chosen timezone representation.
    """
    if signed_at.tzinfo is None:
        signed_at = signed_at.replace(tzinfo=UTC)
    return f"{terms_hash}|{signer}|{signed_at.astimezone(UTC).isoformat()}".encode()


def roe_signature_hex(terms_hash: str, signer: str, signed_at: datetime, *, signing_key: bytes) -> str:
    """HMAC-SHA256 over ``canonical_roe_bytes``, hex-encoded."""
    return hmac.new(signing_key, canonical_roe_bytes(terms_hash, signer, signed_at), hashlib.sha256).hexdigest()


def verify_roe_signature(
    terms_hash: str,
    signer: str,
    signed_at: datetime,
    signature: str,
    *,
    signing_key: bytes,
) -> bool:
    """True only for a signature the deployment key could have produced."""
    if not signature:
        return False
    expected = roe_signature_hex(terms_hash, signer, signed_at, signing_key=signing_key)
    return hmac.compare_digest(expected, signature)


def roe_active_at(
    *,
    revoked_at: datetime | None,
    window_start: datetime,
    window_end: datetime,
    when: datetime,
) -> bool:
    """True when the RoE is unrevoked and ``when`` is inside its window."""
    return revoked_at is None and window_start <= when <= window_end


def roe_covers_schedule(
    *,
    revoked_at: datetime | None,
    window_start: datetime,
    window_end: datetime,
    schedule_start: datetime,
    schedule_end: datetime,
) -> bool:
    """True when an unrevoked RoE window contains the whole delivery window.

    A campaign that would outlive the engagement window is never covered.
    """
    if revoked_at is not None or schedule_end < schedule_start:
        return False
    return window_start <= schedule_start and schedule_end <= window_end


def recipient_domain_roe_covered(mailbox: str, target_domains: frozenset[str]) -> bool:
    """True when ``mailbox`` sits in an RoE target domain (or subdomain).

    The RoE's target set must have been verified via the DNS challenge before
    signing; this function enforces the boundary itself, matching the
    recipient-allowlist semantics so a lookalike registered domain can never
    match. An empty target set covers nobody.
    """
    return is_recipient_allowed(mailbox, target_domains)
