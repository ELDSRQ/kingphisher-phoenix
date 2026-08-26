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
    parse_domain_allowlist,
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
        ("", None),
    ],
)
def test_mailbox_domain_is_strict(mailbox: str, expected: str | None) -> None:
    assert mailbox_domain(mailbox) == expected


def test_allowlist_matches_domain_and_subdomains() -> None:
    allowlist = parse_domain_allowlist("example.com")
    assert is_recipient_allowed("user@example.com", allowlist)
    assert is_recipient_allowed("user@mail.example.com", allowlist)
    # Suffix matching must not leak to a lookalike registered domain.
    assert not is_recipient_allowed("user@notexample.com", allowlist)
    assert not is_recipient_allowed("user@example.com.attacker.test", allowlist)


def test_empty_allowlist_allows_nobody() -> None:
    # Fail-closed: interpreting "unset" as "allow everything" is the caller's
    # decision to make explicitly, never this function's default.
    assert not is_recipient_allowed("user@example.com", parse_domain_allowlist(""))


def test_unparseable_mailbox_is_never_allowed() -> None:
    allowlist = parse_domain_allowlist("example.com")
    for bad in ("not-an-email", "a@b@example.com", "", "@example.com"):
        assert not is_recipient_allowed(bad, allowlist)
