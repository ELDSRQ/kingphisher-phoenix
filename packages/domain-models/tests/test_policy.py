"""Send-safety policy primitives (T-06).

These are the shared rules the operator API and the delivery worker both apply,
so they are tested once here rather than twice at the call sites.
"""

from __future__ import annotations

import pytest
from kp_domain_models.policy import (
    ApprovalPolicy,
    is_recipient_allowed,
    mailbox_domain,
    normalize_policy_domain,
    parse_domain_allowlist,
    resolve_sender,
)


def test_approval_policy_values_are_stable() -> None:
    # These strings are configuration surface; changing them breaks deployments.
    assert ApprovalPolicy.ENFORCE.value == "enforce"
    assert ApprovalPolicy.SINGLE_ADMIN.value == "single-admin"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", frozenset()),
        (None, frozenset()),
        ("example.com", frozenset({"example.com"})),
        ("  Example.COM  ", frozenset({"example.com"})),
        ("@example.com", frozenset({"example.com"})),
        (".example.com", frozenset({"example.com"})),
        ("a.com,b.com", frozenset({"a.com", "b.com"})),
        ("a.com\nb.com", frozenset({"a.com", "b.com"})),
        ("a.com b.com", frozenset({"a.com", "b.com"})),
        ("EXAMPLE.COM.", frozenset({"example.com"})),
        ("a.com,,  ,b.com", frozenset({"a.com", "b.com"})),
    ],
)
def test_parse_domain_allowlist_normalizes(raw: str | None, expected: frozenset[str]) -> None:
    assert parse_domain_allowlist(raw) == expected


@pytest.mark.parametrize(
    ("mailbox", "expected"),
    [
        ("user@example.com", "example.com"),
        ("USER@Example.COM", "example.com"),
        ("  user@example.com  ", "example.com"),
        ("no-at-sign", None),
        ("@example.com", None),
        ("user@", None),
        ("a@b@c.com", None),
        ("user @example.com", None),
        ("user@exämple.com", None),
        ("user@127.0.0.1", None),
        ("user@example.com.", "example.com"),
        ("", None),
    ],
)
def test_mailbox_domain_is_strict(mailbox: str, expected: str | None) -> None:
    assert mailbox_domain(mailbox) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "com",
        "127.0.0.1",
        "bad_label.example",
        "-bad.example",
        "bad-.example",
        "example..com",
        "example.com..",
        "@@example.com",
        "..example.com",
        "user@example.com",
        "exämple.com",
    ],
)
def test_allowlist_rejects_ambiguous_or_non_dns_boundaries(raw: str) -> None:
    with pytest.raises(ValueError, match="invalid domain"):
        parse_domain_allowlist(raw)


def test_explicit_ascii_idna_a_label_is_stable() -> None:
    assert normalize_policy_domain("XN--BCHER-KVA.EXAMPLE.") == "xn--bcher-kva.example"
    assert parse_domain_allowlist("XN--BCHER-KVA.EXAMPLE") == frozenset({"xn--bcher-kva.example"})


def test_allowlist_matches_domain_and_subdomains() -> None:
    allowlist = parse_domain_allowlist("example.com")
    assert is_recipient_allowed("user@example.com", allowlist)
    assert is_recipient_allowed("user@mail.example.com", allowlist)
    # Suffix matching must not leak to a lookalike registered domain.
    assert not is_recipient_allowed("user@notexample.com", allowlist)
    assert not is_recipient_allowed("user@example.com.attacker.test", allowlist)


def test_direct_allowlist_values_are_canonicalized_fail_closed() -> None:
    assert is_recipient_allowed("user@MAIL.EXAMPLE.COM", frozenset({"EXAMPLE.COM."}))
    assert not is_recipient_allowed("user@example.com", frozenset({"com", "bad_label.example"}))


def test_empty_allowlist_allows_nobody() -> None:
    # Fail-closed: interpreting "unset" as "allow everything" is the caller's
    # decision to make explicitly, never this function's default.
    assert not is_recipient_allowed("user@example.com", parse_domain_allowlist(""))


def test_unparseable_mailbox_is_never_allowed() -> None:
    allowlist = parse_domain_allowlist("example.com")
    for bad in ("not-an-email", "a@b@example.com", "", "@example.com"):
        assert not is_recipient_allowed(bad, allowlist)


def test_sender_resolution_rejects_malformed_pool_entries() -> None:
    assert resolve_sender(
        "sender@example.com",
        sending_domains=frozenset({"com", "bad_label.example"}),
        default_sender="safe@sender.example",
    ) == ("safe@sender.example", False)
