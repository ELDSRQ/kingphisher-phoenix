from kp_templating.spf import check_spf, check_spf_for_mailbox


def test_check_spf_malformed_domain_returns_no_spf() -> None:
    result = check_spf("", resolver_timeout=0.5)
    assert result.has_spf is False


def test_check_spf_for_mailbox_extracts_domain() -> None:
    result = check_spf_for_mailbox("ops@nonexistent.invalid", resolver_timeout=0.5)
    assert result.domain == "nonexistent.invalid"
