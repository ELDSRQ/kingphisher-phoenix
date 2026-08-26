"""DNS-challenge domain verification tests.

The DNS path is mocked at ``_resolve_txt``; the fail-closed cases are the
important ones because an attacker who can read the zone must not be able to
force a "verified" outcome through DNS errors.
"""

from __future__ import annotations

import pytest
from kp_domain_verification.verification import (
    CHALLENGE_PREFIX,
    challenge_record_value,
    challenge_token,
    normalize_domain,
    required_dns_records,
    verify_domain,
)

_KEY = b"k" * 32


def _patch_resolve(monkeypatch: pytest.MonkeyPatch, records: list[str], error: str | None = None) -> None:
    def fake_resolve(domain: str, rtype: str, *, lifetime: float) -> None:  # type: ignore[no-untyped-def]
        raise AssertionError("_resolve_txt must be the seam that is patched")

    # Patch through the private seam so the resolver itself stays untested here.
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda domain, *, resolver_timeout: (records, error),
    )
    return None


def test_normalize_domain_accepts_and_rejects() -> None:
    assert normalize_domain("Example.COM") == "example.com"
    assert normalize_domain("@example.com") == "example.com"
    assert normalize_domain(".example.com.") == "example.com"
    assert normalize_domain("mail.corp-benefits.example") == "mail.corp-benefits.example"
    assert normalize_domain("") is None
    assert normalize_domain("not a domain") is None
    assert normalize_domain("example.com/path") is None
    assert normalize_domain("user@example.com") is None
    assert normalize_domain("bäde.example") is None


def test_challenge_token_is_deterministic_and_domain_bound() -> None:
    token_a = challenge_token("example.com", signing_key=_KEY)
    assert token_a == challenge_token("Example.com", signing_key=_KEY)
    assert challenge_token("example.com", signing_key=b"x" * 32) != token_a
    assert challenge_token("other.com", signing_key=_KEY) != token_a
    assert challenge_record_value("example.com", signing_key=_KEY) == f"{CHALLENGE_PREFIX}={token_a}"


def test_challenge_token_rejects_junk_domain() -> None:
    with pytest.raises(ValueError):
        challenge_token("", signing_key=_KEY)


def test_verify_domain_succeeds_on_exact_record(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [challenge_record_value("example.com", signing_key=_KEY)])
    result = verify_domain("example.com", signing_key=_KEY)
    assert result.verified is True
    assert result.error is None
    assert result.token is not None


def test_verify_domain_ignores_unrelated_txt_records(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(
        monkeypatch,
        ["v=spf1 -all", "some other record", challenge_record_value("example.com", signing_key=_KEY)],
    )
    assert verify_domain("example.com", signing_key=_KEY).verified is True


def test_verify_domain_fails_closed_on_missing_record(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, ["v=spf1 -all"])
    result = verify_domain("example.com", signing_key=_KEY)
    assert result.verified is False
    assert "not found" in (result.error or "")


def test_verify_domain_fails_closed_on_wrong_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # A record someone else published (e.g. for their own key) must not verify.
    _patch_resolve(monkeypatch, [challenge_record_value("example.com", signing_key=b"a" * 32)])
    assert verify_domain("example.com", signing_key=_KEY).verified is False


def test_verify_domain_fails_closed_on_dns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [], error="timed out")
    result = verify_domain("example.com", signing_key=_KEY)
    assert result.verified is False
    assert result.error is not None


def test_verify_domain_fails_closed_on_no_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [])
    assert verify_domain("example.com", signing_key=_KEY).verified is False


def test_verify_domain_rejects_malformed_input() -> None:
    assert verify_domain("", signing_key=_KEY).verified is False
    assert verify_domain("user@example.com", signing_key=_KEY).verified is False


def test_required_dns_records_emit_challenge_spf_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [])
    records = required_dns_records(
        "corp-benefits.example", signing_key=_KEY, relay="ses", dmarc_address="dmarc@example.com"
    )
    assert len(records) == 4
    assert any(r.value == challenge_record_value("corp-benefits.example", signing_key=_KEY) for r in records)
    assert any("v=spf1 include:amazonses.com" in r.value for r in records)
    assert any(r.name == "_dmarc.corp-benefits.example" and "p=reject" in r.value for r in records)
    assert any("<selector>._domainkey" in r.name for r in records)


def test_required_dns_records_postfix_uses_relay_address(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, [])
    records = required_dns_records("example.com", signing_key=_KEY, relay="postfix", relay_address="203.0.113.10")
    assert any(r.value == "v=spf1 ip4:203.0.113.10 ~all" for r in records)
