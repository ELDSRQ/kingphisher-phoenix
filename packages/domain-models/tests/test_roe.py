"""Signed Rules-of-Engagement primitives (authorization boundary).

These helpers are shared by the operator API (signing, scheduling coverage)
and the delivery worker (signature verification, per-recipient boundary), so
they are tested once here rather than twice at the call sites.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kp_domain_models.roe import (
    canonical_roe_bytes,
    recipient_domain_roe_covered,
    roe_active_at,
    roe_covers_schedule,
    roe_signature_hex,
    verify_roe_signature,
)

_KEY = bytes(range(32))
_NOW = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
_WINDOW_START = _NOW - timedelta(days=1)
_WINDOW_END = _NOW + timedelta(days=30)
_TERMS = "Engagement authorized for verified domains; recipients only in these domains."
_TERMS_HASH = "abc123"
_SIGNER = "operator@example.com"


def test_signature_is_deterministic_and_key_bound() -> None:
    sig = roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW, signing_key=_KEY)
    assert sig == roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW, signing_key=_KEY)
    assert sig != roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW, signing_key=bytes(31) + b"x")
    assert sig != roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW + timedelta(seconds=1), signing_key=_KEY)


def test_signature_binds_terms_signer_and_timestamp() -> None:
    sig = roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW, signing_key=_KEY)
    # Tampering with any signed field must fail verification.
    assert not verify_roe_signature("tampered", _SIGNER, _NOW, sig, signing_key=_KEY)
    assert not verify_roe_signature(_TERMS_HASH, "attacker@example.com", _NOW, sig, signing_key=_KEY)
    assert not verify_roe_signature(_TERMS_HASH, _SIGNER, _NOW + timedelta(days=1), sig, signing_key=_KEY)
    assert not verify_roe_signature(_TERMS_HASH, _SIGNER, _NOW, "0" * 64, signing_key=_KEY)


def test_verify_rejects_empty_signature() -> None:
    assert not verify_roe_signature(_TERMS_HASH, _SIGNER, _NOW, "", signing_key=_KEY)


def test_verify_accepts_only_deployment_key() -> None:
    sig = roe_signature_hex(_TERMS_HASH, _SIGNER, _NOW, signing_key=_KEY)
    assert verify_roe_signature(_TERMS_HASH, _SIGNER, _NOW, sig, signing_key=_KEY)
    assert not verify_roe_signature(_TERMS_HASH, _SIGNER, _NOW, sig, signing_key=b"z" * 32)


def test_canonical_bytes_are_utc_normalized() -> None:
    aware = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    naive = datetime(2026, 8, 26, 12, 0)
    assert canonical_roe_bytes(_TERMS_HASH, _SIGNER, aware) == canonical_roe_bytes(_TERMS_HASH, _SIGNER, naive)


def test_roe_active_at_window_and_revocation() -> None:
    assert roe_active_at(revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_NOW)
    assert not roe_active_at(
        revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_WINDOW_END + timedelta(seconds=1)
    )
    assert not roe_active_at(revoked_at=_NOW, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_NOW)


def test_roe_covers_schedule_requires_full_window() -> None:
    start = _NOW + timedelta(days=1)
    end = _NOW + timedelta(days=5)
    assert roe_covers_schedule(
        revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, schedule_start=start, schedule_end=end
    )
    # A campaign that outlives the engagement window is never covered.
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=start,
        schedule_end=_WINDOW_END + timedelta(days=1),
    )
    # A campaign starting before the window is not covered.
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=_WINDOW_START - timedelta(days=1),
        schedule_end=end,
    )
    # A revoked RoE covers nothing.
    assert not roe_covers_schedule(
        revoked_at=_NOW, window_start=_WINDOW_START, window_end=_WINDOW_END, schedule_start=start, schedule_end=end
    )


def test_recipient_domain_boundary() -> None:
    targets = frozenset({"example.com"})
    assert recipient_domain_roe_covered("user@example.com", targets)
    assert recipient_domain_roe_covered("user@mail.example.com", targets)
    # Lookalike registered domains and other domains are outside the boundary.
    assert not recipient_domain_roe_covered("user@notexample.com", targets)
    assert not recipient_domain_roe_covered("user@example.com.evil.test", targets)
    assert not recipient_domain_roe_covered("user@elsewhere.com", targets)
    # An empty target set covers nobody (fail-closed).
    assert not recipient_domain_roe_covered("user@example.com", frozenset())
