"""Import-time RoE coverage advisory.

Recipient import validates against the env allowlist but historically never
against the signed Rules-of-Engagement. Under single-operator an unset allowlist
admits everyone, so a recipient outside the RoE target domains imported cleanly
and then failed SILENTLY at send time with target_domain_not_roe_covered. This
advisory moves that signal to import time. It is advisory only: it never blocks
import (an RoE can be signed afterward), and delivery remains the real boundary.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kp_database.models import RulesOfEngagement
from kp_operator_api.recipient_import import ParsedRecipient
from kp_operator_api.recipient_import_planning import _roe_coverage_advisory


def _roe(target_domains, *, revoked=False, window=("past", "future")) -> RulesOfEngagement:
    now = datetime.now(UTC)
    starts = {"past": now - timedelta(days=1), "future": now + timedelta(days=1)}
    return RulesOfEngagement(
        target_domains=list(target_domains),
        window_start=starts[window[0]],
        window_end=starts[window[1]],
        revoked_at=now if revoked else None,
    )


def _rcpt(mailbox: str, row: int = 1) -> ParsedRecipient:
    return ParsedRecipient(row=row, mailbox=mailbox, mailbox_hash="h" * 64, display_name=None, department=None)


class _RoeSession:
    """Minimal session: scalars(select(RulesOfEngagement)) -> the given RoEs."""

    def __init__(self, roes):
        self._roes = list(roes)

    def scalars(self, _statement):
        return iter(self._roes)


def test_no_active_roe_reports_unchecked_not_all_uncovered() -> None:
    # A fresh deployment has no RoE yet. Flagging every recipient as uncovered
    # would be noise; the getting-started flow signs an RoE before a campaign.
    result = _roe_coverage_advisory(_RoeSession([]), (_rcpt("a@corp.example"),))
    assert result == {"checked": False, "active_roe_domains": [], "uncovered": 0, "uncovered_domains": []}


def test_all_recipients_inside_roe_domains_are_covered() -> None:
    session = _RoeSession([_roe(["corp.example"])])
    result = _roe_coverage_advisory(session, (_rcpt("a@corp.example"), _rcpt("b@corp.example")))
    assert result["checked"] is True
    assert result["uncovered"] == 0
    assert result["uncovered_domains"] == []
    assert result["active_roe_domains"] == ["corp.example"]


def test_recipients_outside_the_roe_are_flagged_by_domain() -> None:
    session = _RoeSession([_roe(["corp.example"])])
    recipients = (_rcpt("a@corp.example"), _rcpt("b@partner.example"), _rcpt("c@partner.example"))
    result = _roe_coverage_advisory(session, recipients)
    assert result["checked"] is True
    assert result["uncovered"] == 2
    # Distinct domains only, and the address local-parts never appear.
    assert result["uncovered_domains"] == ["partner.example"]


def test_subdomain_of_a_target_is_covered() -> None:
    # Matches recipient_domain_roe_covered: a target domain covers its subdomains.
    session = _RoeSession([_roe(["corp.example"])])
    result = _roe_coverage_advisory(session, (_rcpt("a@eng.corp.example"),))
    assert result["uncovered"] == 0


def test_revoked_roe_does_not_count_as_active() -> None:
    session = _RoeSession([_roe(["corp.example"], revoked=True)])
    result = _roe_coverage_advisory(session, (_rcpt("a@corp.example"),))
    assert result["checked"] is False


def test_out_of_window_roe_does_not_count_as_active() -> None:
    session = _RoeSession([_roe(["corp.example"], window=("future", "future"))])
    result = _roe_coverage_advisory(session, (_rcpt("a@corp.example"),))
    assert result["checked"] is False


def test_union_of_multiple_active_roes_is_used() -> None:
    session = _RoeSession([_roe(["corp.example"]), _roe(["partner.example"])])
    recipients = (_rcpt("a@corp.example"), _rcpt("b@partner.example"), _rcpt("c@other.example"))
    result = _roe_coverage_advisory(session, recipients)
    assert result["uncovered"] == 1
    assert result["uncovered_domains"] == ["other.example"]
    assert result["active_roe_domains"] == ["corp.example", "partner.example"]


def test_uncovered_domains_are_bounded_and_deduped() -> None:
    session = _RoeSession([_roe(["corp.example"])])
    # 30 distinct uncovered domains, plus a duplicate, from 31 recipients.
    recipients = tuple(_rcpt(f"u{i}@d{i}.example", row=i) for i in range(30))
    recipients += (_rcpt("dup@d0.example", row=99),)
    result = _roe_coverage_advisory(session, recipients)
    assert result["uncovered"] == 31  # every recipient counted
    assert len(result["uncovered_domains"]) == 20  # domain list capped
    assert result["uncovered_domains"] == sorted(result["uncovered_domains"])


def test_output_never_contains_a_full_mailbox() -> None:
    session = _RoeSession([_roe(["corp.example"])])
    result = _roe_coverage_advisory(session, (_rcpt("secret.person@partner.example"),))
    blob = repr(result)
    assert "secret.person" not in blob
    assert "partner.example" in blob
