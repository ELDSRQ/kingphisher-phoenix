"""Signed Rules-of-Engagement (RoE): the authorization boundary for delivery.

An RoE is one signed artifact recording: who signed it (``signer``), on whose
authority (``authorizing_party``), for what period (``window_start`` /
``window_end``), against which operator-verified target domains
(``target_domains``), under what terms (``terms_text`` / ``terms_hash``).

Signature version 2 binds a canonical payload containing the terms hash,
authorizing party, normalized target-domain set, engagement window, signer,
signature time, and artifact version. Authorization never depends on fields
being repeated informally inside the terms text.

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
import json
import re
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime

from kp_domain_models.policy import is_recipient_allowed, normalize_policy_domain

ROE_SIGNATURE_VERSION = 2
ROE_ARTIFACT_TYPE = "kp-rules-of-engagement"
ROE_MAX_TARGET_DOMAINS = 100
_TERMS_DIGEST = re.compile(r"[A-Za-z0-9]{64}\Z")
_HMAC_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")


def normalize_roe_domains(target_domains: Iterable[str]) -> tuple[str, ...]:
    """Return a bounded, deterministic set of explicit ASCII DNS names.

    Unicode spellings are rejected rather than implicitly mapped. An IDN must
    be supplied as its DNS-verified ``xn--`` A-label, eliminating IDNA-version
    ambiguity between the GUI, signer, database, and delivery worker.
    """

    if isinstance(target_domains, (str, bytes)):
        raise ValueError("RoE target domains must be an iterable of domain names")
    normalized: set[str] = set()
    try:
        for index, raw in enumerate(target_domains):
            if index >= ROE_MAX_TARGET_DOMAINS:
                raise ValueError(f"an RoE supports at most {ROE_MAX_TARGET_DOMAINS} target domains")
            domain = normalize_policy_domain(raw)
            if domain is None:
                raise ValueError("RoE contains an invalid target domain")
            normalized.add(domain)
    except TypeError as exc:
        raise ValueError("RoE target domains must be an iterable of domain names") from exc
    if not normalized:
        raise ValueError("an RoE must contain at least one target domain")
    return tuple(sorted(normalized))


def _utc_datetime(value: datetime) -> datetime | None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    try:
        if value.utcoffset() is None:
            return None
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        return None


def _canonical_timestamp(value: datetime) -> str:
    normalized = _utc_datetime(value)
    if normalized is None:
        raise ValueError("RoE timestamps must include a timezone offset")
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"RoE {field_name} must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if (
        not normalized
        or len(normalized) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
    ):
        raise ValueError(f"RoE {field_name} is invalid")
    return normalized


def canonical_roe_bytes(
    terms_hash: str,
    signer: str,
    signed_at: datetime,
    *,
    authorizing_party: str,
    target_domains: Iterable[str],
    window_start: datetime,
    window_end: datetime,
    signature_version: int = ROE_SIGNATURE_VERSION,
) -> bytes:
    """Canonical JSON byte form of every authorization-bearing field.

    Sorted keys, compact separators, explicit ASCII DNS names, and fixed UTC
    timestamps make signing deterministic across API and worker processes.
    """
    if type(signature_version) is not int or signature_version != ROE_SIGNATURE_VERSION:
        raise ValueError(f"unsupported RoE signature version: {signature_version}")
    normalized_start = _utc_datetime(window_start)
    normalized_end = _utc_datetime(window_end)
    normalized_signed_at = _utc_datetime(signed_at)
    if normalized_start is None or normalized_end is None or normalized_signed_at is None:
        raise ValueError("RoE timestamps must include a timezone offset")
    if normalized_end <= normalized_start:
        raise ValueError("RoE window_end must be after window_start")
    if normalized_signed_at > normalized_end:
        raise ValueError("RoE signed_at cannot be after window_end")
    # Existing imported artifacts may use a non-hex digest encoding. The
    # signature binds all 64 characters, while the API continues to mint
    # lowercase SHA-256 hex. Reject variable-length/unprintable inputs without
    # invalidating that supported storage contract.
    if not isinstance(terms_hash, str) or _TERMS_DIGEST.fullmatch(terms_hash) is None:
        raise ValueError("RoE terms_hash must be a 64-character digest")
    payload = {
        "artifact_type": ROE_ARTIFACT_TYPE,
        "authorizing_party": _canonical_text(authorizing_party, field_name="authorizing_party"),
        "signature_version": signature_version,
        "signed_at": _canonical_timestamp(normalized_signed_at),
        "signer": _canonical_text(signer, field_name="signer"),
        "target_domains": list(normalize_roe_domains(target_domains)),
        "terms_hash": terms_hash.strip().lower(),
        "window_end": _canonical_timestamp(normalized_end),
        "window_start": _canonical_timestamp(normalized_start),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def roe_signature_hex(
    terms_hash: str,
    signer: str,
    signed_at: datetime,
    *,
    authorizing_party: str,
    target_domains: Iterable[str],
    window_start: datetime,
    window_end: datetime,
    signature_version: int = ROE_SIGNATURE_VERSION,
    signing_key: bytes,
) -> str:
    """HMAC-SHA256 over ``canonical_roe_bytes``, hex-encoded."""
    if not isinstance(signing_key, bytes) or len(signing_key) < hashlib.sha256().digest_size:
        raise ValueError("RoE signing key must contain at least 256 bits")
    canonical = canonical_roe_bytes(
        terms_hash,
        signer,
        signed_at,
        authorizing_party=authorizing_party,
        target_domains=target_domains,
        window_start=window_start,
        window_end=window_end,
        signature_version=signature_version,
    )
    return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()


def verify_roe_signature(
    terms_hash: str,
    signer: str,
    signed_at: datetime,
    signature: str,
    *,
    authorizing_party: str,
    target_domains: Iterable[str],
    window_start: datetime,
    window_end: datetime,
    signature_version: int,
    signing_key: bytes,
) -> bool:
    """True only for a signature the deployment key could have produced."""
    if not isinstance(signature, str) or _HMAC_SHA256_HEX.fullmatch(signature) is None:
        return False
    try:
        expected = roe_signature_hex(
            terms_hash,
            signer,
            signed_at,
            authorizing_party=authorizing_party,
            target_domains=target_domains,
            window_start=window_start,
            window_end=window_end,
            signature_version=signature_version,
            signing_key=signing_key,
        )
    except (TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(expected, signature)


def roe_active_at(
    *,
    revoked_at: datetime | None,
    window_start: datetime,
    window_end: datetime,
    when: datetime,
) -> bool:
    """True when the RoE is unrevoked and ``when`` is inside its window."""
    if revoked_at is not None:
        return False
    start = _utc_datetime(window_start)
    end = _utc_datetime(window_end)
    candidate = _utc_datetime(when)
    return start is not None and end is not None and candidate is not None and start < end and start <= candidate <= end


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
    if revoked_at is not None:
        return False
    start = _utc_datetime(window_start)
    end = _utc_datetime(window_end)
    delivery_start = _utc_datetime(schedule_start)
    delivery_end = _utc_datetime(schedule_end)
    return (
        start is not None
        and end is not None
        and delivery_start is not None
        and delivery_end is not None
        and start < end
        and delivery_start < delivery_end
        and start <= delivery_start
        and delivery_end <= end
    )


def recipient_domain_roe_covered(mailbox: str, target_domains: frozenset[str]) -> bool:
    """True when ``mailbox`` sits in an RoE target domain (or subdomain).

    The RoE's target set must have been verified via the DNS challenge before
    signing; this function enforces the boundary itself, matching the
    recipient-allowlist semantics so a lookalike registered domain can never
    match. An empty target set covers nobody.
    """
    return is_recipient_allowed(mailbox, target_domains)
