"""Signed Rules-of-Engagement primitives (authorization boundary)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from kp_domain_models.roe import (
    ROE_SIGNATURE_VERSION,
    canonical_roe_bytes,
    normalize_roe_domains,
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
_TERMS_HASH = "ab" * 32
_SIGNER = "operator@example.com"
_PARTY = "Example Corp"
_DOMAINS = ["example.com", "mail.example.com"]


def _fields(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "authorizing_party": _PARTY,
        "target_domains": _DOMAINS,
        "window_start": _WINDOW_START,
        "window_end": _WINDOW_END,
        "signature_version": ROE_SIGNATURE_VERSION,
    }
    values.update(overrides)
    return values


def _signature(**overrides: object) -> str:
    return roe_signature_hex(
        _TERMS_HASH,
        _SIGNER,
        _NOW,
        signing_key=_KEY,
        **_fields(**overrides),  # type: ignore[arg-type]
    )


def _verify(signature: str, **overrides: object) -> bool:
    terms_hash = str(overrides.pop("terms_hash", _TERMS_HASH))
    signer = str(overrides.pop("signer", _SIGNER))
    signed_at = overrides.pop("signed_at", _NOW)
    return verify_roe_signature(
        terms_hash,
        signer,
        signed_at,  # type: ignore[arg-type]
        signature,
        signing_key=_KEY,
        **_fields(**overrides),  # type: ignore[arg-type]
    )


def test_signature_is_deterministic_and_key_bound() -> None:
    sig = _signature()
    assert sig == _signature()
    assert sig != roe_signature_hex(
        _TERMS_HASH,
        _SIGNER,
        _NOW,
        signing_key=bytes(31) + b"x",
        **_fields(),  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("terms_hash", "cd" * 32),
        ("signer", "attacker@example.com"),
        ("signed_at", _NOW + timedelta(seconds=1)),
        ("authorizing_party", "Other Corp"),
        ("target_domains", ["evil.example"]),
        ("window_start", _WINDOW_START + timedelta(hours=1)),
        ("window_end", _WINDOW_END - timedelta(hours=1)),
        ("signature_version", 1),
    ],
)
def test_signature_binds_every_authorization_field(field: str, tampered: object) -> None:
    assert not _verify(_signature(), **{field: tampered})


def test_verify_rejects_empty_or_wrong_signature() -> None:
    assert not _verify("")
    assert not _verify("0" * 64)


def test_canonical_payload_is_normalized_and_versioned() -> None:
    offset = timezone(timedelta(hours=-4))
    canonical = canonical_roe_bytes(
        _TERMS_HASH.upper(),
        f" {_SIGNER} ",
        _NOW.astimezone(offset),
        authorizing_party=f" {_PARTY} ",
        target_domains=["EXAMPLE.COM.", "mail.example.com", "example.com"],
        window_start=_WINDOW_START.astimezone(offset),
        window_end=_WINDOW_END.astimezone(offset),
    )
    payload = json.loads(canonical)
    assert payload["signature_version"] == 2
    assert payload["artifact_type"] == "kp-rules-of-engagement"
    assert payload["target_domains"] == ["example.com", "mail.example.com"]
    assert payload["terms_hash"] == _TERMS_HASH
    assert payload["signed_at"].endswith("Z")


def test_domain_normalization_rejects_empty_or_malformed_values() -> None:
    assert normalize_roe_domains(["EXAMPLE.COM.", "example.com"]) == ("example.com",)
    assert normalize_roe_domains(["XN--BCHER-KVA.EXAMPLE"]) == ("xn--bcher-kva.example",)
    for invalid in (
        [],
        ["user@example.com"],
        ["com"],
        ["bad_label.example"],
        ["exämple.com"],
    ):
        with pytest.raises(ValueError):
            normalize_roe_domains(invalid)


def test_domain_normalization_is_bounded_and_rejects_scalar_text() -> None:
    with pytest.raises(ValueError, match="iterable"):
        normalize_roe_domains("example.com")
    with pytest.raises(ValueError, match="at most 100"):
        normalize_roe_domains(f"tenant-{index}.example" for index in range(101))


@pytest.mark.parametrize(
    "overrides",
    [
        {"terms_hash": "not-a-64-character-digest"},
        {"signer": "  "},
        {"signer": "operator\n@example.com"},
        {"authorizing_party": "  "},
        {"authorizing_party": "party\x00name"},
        {"signed_at": _NOW.replace(tzinfo=None)},
        {"window_start": _WINDOW_START.replace(tzinfo=None)},
        {"window_end": _WINDOW_END.replace(tzinfo=None)},
        {"signed_at": _WINDOW_END + timedelta(seconds=1)},
        {"signature_version": True},
        {"signature_version": 2.0},
    ],
)
def test_canonical_payload_rejects_malformed_authorization_fields(overrides: dict[str, object]) -> None:
    terms_hash = str(overrides.pop("terms_hash", _TERMS_HASH))
    signer = str(overrides.pop("signer", _SIGNER))
    signed_at = overrides.pop("signed_at", _NOW)
    with pytest.raises(ValueError):
        canonical_roe_bytes(
            terms_hash,
            signer,
            signed_at,  # type: ignore[arg-type]
            **_fields(**overrides),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("key", [b"", b"short", bytes(31), bytearray(32)])
def test_signing_rejects_weak_or_non_bytes_keys(key: object) -> None:
    with pytest.raises(ValueError, match="256 bits"):
        roe_signature_hex(
            _TERMS_HASH,
            _SIGNER,
            _NOW,
            signing_key=key,  # type: ignore[arg-type]
            **_fields(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("signature", [None, b"0" * 64, "A" * 64, "0" * 63, "0" * 65, "g" * 64])
def test_verification_rejects_noncanonical_signatures(signature: object) -> None:
    assert not _verify(signature)  # type: ignore[arg-type]


def test_roe_active_at_window_and_revocation() -> None:
    assert roe_active_at(revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_NOW)
    assert not roe_active_at(
        revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_WINDOW_END + timedelta(seconds=1)
    )
    assert not roe_active_at(revoked_at=_NOW, window_start=_WINDOW_START, window_end=_WINDOW_END, when=_NOW)


def test_roe_active_at_denies_invalid_or_ambiguous_time_values_without_raising() -> None:
    naive = _NOW.replace(tzinfo=None)
    assert not roe_active_at(revoked_at=None, window_start=naive, window_end=_WINDOW_END, when=_NOW)
    assert not roe_active_at(revoked_at=None, window_start=_WINDOW_START, window_end=naive, when=_NOW)
    assert not roe_active_at(revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, when=naive)
    assert not roe_active_at(
        revoked_at=None,
        window_start=_WINDOW_END,
        window_end=_WINDOW_START,
        when=_NOW,
    )


def test_roe_covers_schedule_requires_full_window() -> None:
    start = _NOW + timedelta(days=1)
    end = _NOW + timedelta(days=5)
    assert roe_covers_schedule(
        revoked_at=None, window_start=_WINDOW_START, window_end=_WINDOW_END, schedule_start=start, schedule_end=end
    )
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=start,
        schedule_end=_WINDOW_END + timedelta(days=1),
    )
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=_WINDOW_START - timedelta(days=1),
        schedule_end=end,
    )
    assert not roe_covers_schedule(
        revoked_at=_NOW, window_start=_WINDOW_START, window_end=_WINDOW_END, schedule_start=start, schedule_end=end
    )


def test_roe_covers_schedule_denies_zero_length_or_naive_windows_without_raising() -> None:
    naive = _NOW.replace(tzinfo=None)
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=_NOW,
        schedule_end=_NOW,
    )
    assert not roe_covers_schedule(
        revoked_at=None,
        window_start=_WINDOW_START,
        window_end=_WINDOW_END,
        schedule_start=naive,
        schedule_end=_NOW,
    )


def test_recipient_domain_boundary() -> None:
    targets = frozenset({"example.com"})
    assert recipient_domain_roe_covered("user@example.com", targets)
    assert recipient_domain_roe_covered("user@mail.example.com", targets)
    assert not recipient_domain_roe_covered("user@notexample.com", targets)
    assert not recipient_domain_roe_covered("user@example.com.evil.test", targets)
    assert not recipient_domain_roe_covered("user@elsewhere.com", targets)
    assert not recipient_domain_roe_covered("user@example.com", frozenset())
