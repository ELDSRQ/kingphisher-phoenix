"""Per-record domain diagnosis.

`verify_domain` answers the authorization question and stays the gate. These
cover the operator's question instead: what is not finished, and is it my
mistake or just DNS being slow. The `absent` vs `mismatch` split is the point -
a pass/fail check renders those identically while they mean opposite things.
"""

from __future__ import annotations

import pytest
from kp_domain_verification.verification import (
    CHALLENGE_PREFIX,
    challenge_record_value,
    diagnose_domain,
)

_KEY = b"k" * 32
_DOMAIN = "corp-benefits.example"


def _patch(monkeypatch: pytest.MonkeyPatch, by_name: dict[str, list[str]], error: str | None = None) -> None:
    """Resolve TXT per name, so apex and _dmarc can differ as they do in reality."""
    monkeypatch.setattr(
        "kp_domain_verification.verification._resolve_txt",
        lambda domain, *, resolver_timeout: (by_name.get(domain, []), error),
    )


def _check(diagnosis, purpose: str):
    return next(c for c in diagnosis.checks if c.purpose == purpose)


def test_nothing_published_reads_as_propagation_not_operator_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {})

    d = diagnose_domain(_DOMAIN, signing_key=_KEY)

    assert d.verified is False
    assert _check(d, "ownership challenge").status == "absent"
    # The whole reason this exists: tell them to wait, not to go hunting.
    assert d.likely_propagating is True


def test_a_wrong_challenge_value_is_a_mismatch_not_an_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stale challenge from an earlier attempt is the common real case."""
    _patch(monkeypatch, {_DOMAIN: [f"{CHALLENGE_PREFIX}=stale-token-from-a-previous-attempt"]})

    d = diagnose_domain(_DOMAIN, signing_key=_KEY)

    challenge = _check(d, "ownership challenge")
    assert d.verified is False
    assert challenge.status == "mismatch"
    # The observed value is surfaced, so the operator can see it is their old one.
    assert challenge.observed == (f"{CHALLENGE_PREFIX}=stale-token-from-a-previous-attempt",)
    # Waiting will never fix this, so it must NOT read as propagation.
    assert d.likely_propagating is False


def test_correct_challenge_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = challenge_record_value(_DOMAIN, signing_key=_KEY)
    _patch(monkeypatch, {_DOMAIN: ["some-unrelated-txt", expected]})

    d = diagnose_domain(_DOMAIN, signing_key=_KEY)

    assert d.verified is True
    assert _check(d, "ownership challenge").status == "ok"
    assert d.blocking == ()


def test_spf_and_dmarc_are_reported_but_never_block_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = challenge_record_value(_DOMAIN, signing_key=_KEY)
    _patch(monkeypatch, {_DOMAIN: [expected]})

    d = diagnose_domain(_DOMAIN, signing_key=_KEY)

    assert d.verified is True
    assert _check(d, "SPF").status == "absent"
    assert _check(d, "DMARC").status == "absent"
    assert _check(d, "SPF").required is False
    assert d.blocking == ()


def test_an_operators_own_spf_is_accepted_and_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    """A domain that already sends mail has its own SPF. That is not a fault."""
    expected = challenge_record_value(_DOMAIN, signing_key=_KEY)
    _patch(monkeypatch, {_DOMAIN: [expected, "v=spf1 include:_spf.google.com ~all"]})

    spf = _check(diagnose_domain(_DOMAIN, signing_key=_KEY), "SPF")

    assert spf.status == "ok"
    assert spf.observed == ("v=spf1 include:_spf.google.com ~all",)
    assert "deliberate" in spf.detail


def test_dmarc_is_read_from_its_own_name(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = challenge_record_value(_DOMAIN, signing_key=_KEY)
    _patch(
        monkeypatch,
        {_DOMAIN: [expected], f"_dmarc.{_DOMAIN}": ["v=DMARC1; p=reject"]},
    )

    dmarc = _check(diagnose_domain(_DOMAIN, signing_key=_KEY), "DMARC")

    assert dmarc.status == "ok"


def test_dkim_says_it_cannot_be_checked_rather_than_passing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reporting an unknowable record as satisfied would be a lie."""
    _patch(monkeypatch, {_DOMAIN: [challenge_record_value(_DOMAIN, signing_key=_KEY)]})

    dkim = _check(diagnose_domain(_DOMAIN, signing_key=_KEY), "DKIM")

    assert dkim.status == "not_checkable"
    assert dkim.required is False
    assert "selector" in dkim.detail


def test_a_dns_error_fails_closed_and_is_not_mistaken_for_propagation(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, {}, error="SERVFAIL")

    d = diagnose_domain(_DOMAIN, signing_key=_KEY)

    assert d.verified is False
    assert _check(d, "ownership challenge").status == "dns_error"
    assert d.likely_propagating is False


def test_an_unusable_domain_is_refused_outright() -> None:
    with pytest.raises(ValueError):
        diagnose_domain("not a domain", signing_key=_KEY)
