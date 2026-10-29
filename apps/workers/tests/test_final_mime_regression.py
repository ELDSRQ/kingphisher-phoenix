"""RB-01 — final-MIME safety regression harness.

The W0-01 audit finding (KP-AUD-001) was a *mismatch* between a safety
component's view of content and the content that actually reaches a recipient:
a host trusted for inline images was also trusted when used as a navigable
link. A unit test of either component in isolation missed it, because the gap
only appears in the *reconstructed, final-delivery* message.

This harness closes that class of gap. It drives the real worker delivery
reconstruction path — render -> static-URL fence -> ``SafetyValidator`` ->
MIME build — and captures the FINAL ``EmailMessage`` that would be handed to
the provider, using the same MagicMock-transport capture the existing
``test_sender_persona`` delivery tests use (``_send_email(..., sender=mock)``).
No component is tested in isolation; every assertion is about the message that
would actually ship.

It asserts, end to end:

* (a) the DRAFT ``raw_proposal`` / original reconstructed content is never
  selected by the delivery path — only the approved, sanitized fields ship;
* (b) the approved-version binding cannot select a malicious "original"
  version (an unapproved row is refused);
* (c) every corpus case either reconstructs to the expected SAFE MIME or FAILS
  CLOSED (``SafetyRejectionError``) before the provider is ever called;
* (d) a wrong-version selection (manifest hash mismatch) fails closed.

INVARIANTS: inert synthetic payloads only (``*.invalid`` / ``example.com`` /
stub ``data:`` images); no network; embedded hosts are never contacted; no
production code is imported-and-patched, only exercised. The corpus includes
``KP-AUD-001`` canary cases that reconstruct an image-allow-listed host in a
NON-image origin (an ``<a href>`` and bare prose): with the W0-01 origin-scoping
fix present they FAIL CLOSED; reverting that fix makes them deliver, which
makes this harness fail (see ``test_w0_01_origin_scoping_canary_fails_closed``).

Every assertion here is HERMETIC: no PostgreSQL, Redis, or network is touched.
``_send_email`` renders/validates/builds in memory against a captured
transport, and the version-binding assertions drive ``_authorize_delivery``
against an in-memory fake session, stopping at the pre-provider refusal.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import Campaign, CampaignPattern, TemplateVersion
from kp_domain_models import models as dm
from kp_telemetry.errors import SafetyRejectionError
from kp_workers.config import WorkerSettings
from kp_workers.jobs import (
    WorkerContext,
    _authorize_delivery,
    _delivery_template_content,
    _send_email,
)

# The placeholder literal the generator contract guarantees and the renderer
# substitutes for the recipient-bound tracked click URL. Kept as the imported
# constant so a contract change can never silently desync the corpus.
assert TRAINING_URL_PLACEHOLDER == "{{ tracking.training_url }}"

_CORPUS_PATH = Path(__file__).parent / "fixtures" / "final_mime_corpus_v1.json"
_CORPUS = json.loads(_CORPUS_PATH.read_text(encoding="utf-8"))
_CORPUS_VERSION = "final-mime-corpus/v1"
_CASES: list[dict[str, Any]] = _CORPUS["cases"]

_BEARER = "A" * 43
_RECIPIENT_MAILBOX = "learner@example.com"


def _settings(**overrides: Any) -> WorkerSettings:
    values: dict[str, Any] = {
        "_env_file": None,
        # One synthetic image host for the whole corpus: it is allow-listed for
        # <img> graphics only. Default training link allowlist stays
        # example.com / 127.0.0.1, so any other host fails closed.
        "safe_html_image_hosts": "cdn.brand.invalid",
    }
    values.update(overrides)
    return WorkerSettings(**values)


def _context(settings: WorkerSettings | None = None) -> WorkerContext:
    def factory() -> Any:  # pragma: no cover - never entered by _send_email
        raise AssertionError("the render/validate/build path must not open a DB session")

    return WorkerContext(  # type: ignore[arg-type]
        settings or _settings(),
        factory,
        SimpleNamespace(record=lambda **_k: None),
        SimpleNamespace(),
    )


def _campaign() -> Campaign:
    now = datetime.now(UTC)
    return Campaign(
        campaign_id=uuid.uuid4(),
        pattern_id=uuid.uuid4(),
        current_template_id=uuid.uuid4(),
        title="Awareness drill",
        state=dm.CampaignState.SCHEDULED,
        sender_mailbox="itsecurity@example.com",
        sender_display_name="IT Security",
        training_domain="example.com",
        max_recipients=100,
        manifest_hash="m" * 64,
        roe_id=uuid.uuid4(),
        expires_at=now + timedelta(days=30),
    )


def _template(
    *,
    subject: str,
    plain_text: str,
    safe_html: str,
    template_id: uuid.UUID,
    approval_state: dm.TemplateApprovalState = dm.TemplateApprovalState.APPROVED,
    raw_proposal: dict[str, Any] | None = None,
) -> TemplateVersion:
    return TemplateVersion(
        template_version_id=template_id,
        generator_version="0.1.0",
        prompt_template_version="0.1.0",
        model_id="mock",
        input_hash="i" * 64,
        subject=subject,
        plain_text=plain_text,
        safe_html=safe_html,
        raw_proposal=raw_proposal,
        approval_state=approval_state,
    )


def _send_capture(
    campaign: Campaign,
    template: TemplateVersion,
    *,
    settings: WorkerSettings,
    lure_category: dm.LureCategory,
    captured: list[EmailMessage],
) -> None:
    """Render, validate and build the final MIME, capturing what would ship.

    Reuses the ``test_sender_persona`` capture shape: a MagicMock transport
    whose ``send`` records the ``EmailMessage``. If the message never reaches
    ``send`` the batch failed closed before the provider, which is exactly what
    the adversarial corpus asserts.
    """

    ctx = _context(settings)
    recipient = SimpleNamespace(
        recipient_id=uuid.uuid4(),
        mailbox=_RECIPIENT_MAILBOX,
        display_name="Learner",
        department="IT",
    )
    assignment = SimpleNamespace(recipient_id=recipient.recipient_id)
    token = SimpleNamespace(token_hash="ab" * 32)
    pattern = CampaignPattern(
        campaign_pattern_id=campaign.pattern_id,
        lure_category=lure_category,
        confidence=dm.Confidence.HIGH,
    )
    transport = MagicMock(send=lambda msg: captured.append(msg))
    _send_email(
        ctx,
        campaign,
        template,
        pattern,
        assignment,  # type: ignore[arg-type]
        recipient,  # type: ignore[arg-type]
        token,  # type: ignore[arg-type]
        tracking_bearer=_BEARER,
        sender=transport,
    )


def _text_haystack(message: EmailMessage) -> str:
    """Decoded text of the subject and every text part (transfer-decoded).

    Decoding per part avoids quoted-printable soft line breaks splitting a URL
    mid-string, so substring assertions see what the recipient's client sees.
    """

    parts: list[str] = [message["Subject"] or ""]
    for part in message.walk():
        if part.get_content_maintype() == "text":
            parts.append(part.get_content())
    return "\n".join(parts)


def _content_types(message: EmailMessage) -> set[str]:
    return {part.get_content_type() for part in message.walk() if part.get_content_maintype() != "multipart"}


def _lure(case: dict[str, Any]) -> dm.LureCategory:
    return {
        "other": dm.LureCategory.OTHER,
        "calendar_invite": dm.LureCategory.CALENDAR_INVITE,
    }[case["lure_category"]]


# --------------------------------------------------------------------------
# Corpus versioning and shape.
# --------------------------------------------------------------------------


def test_corpus_is_versioned_and_balanced() -> None:
    assert _CORPUS["version"] == _CORPUS_VERSION
    ids = [case["id"] for case in _CASES]
    assert len(ids) == len(set(ids)), "corpus case ids must be unique"
    assert any(case["kind"] == "benign" for case in _CASES)
    assert any(case["kind"] == "adversarial" for case in _CASES)
    # The W0-01 origin-scoping fix must stay exercised end to end.
    assert any(case.get("revert_canary") == "KP-AUD-001" for case in _CASES)


# --------------------------------------------------------------------------
# (c) Every corpus case: expected SAFE MIME, or FAIL CLOSED before the provider.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("case", [c for c in _CASES if c["expected"] == "safe"], ids=lambda c: c["id"])
def test_benign_case_reconstructs_to_expected_safe_mime(case: dict[str, Any]) -> None:
    campaign = _campaign()
    template = _template(
        subject=case["subject"],
        plain_text=case["plain_text"],
        safe_html=case["safe_html"],
        template_id=campaign.current_template_id,
    )
    captured: list[EmailMessage] = []
    _send_capture(
        campaign,
        template,
        settings=_settings(),
        lure_category=_lure(case),
        captured=captured,
    )

    assert len(captured) == 1, "a benign case must reconstruct and reach the provider exactly once"
    message = captured[0]
    haystack = _text_haystack(message)

    for needle in case.get("expect_substrings", []):
        assert needle in haystack, f"{case['id']}: expected {needle!r} in the final MIME"
    for needle in case.get("forbid_substrings", []):
        assert needle not in haystack, f"{case['id']}: {needle!r} must not survive into the final MIME"

    present = _content_types(message)
    for content_type in case.get("expect_content_types", []):
        assert content_type in present, f"{case['id']}: expected a {content_type} part"
    for content_type in case.get("forbid_content_types", []):
        assert content_type not in present, f"{case['id']}: unexpected {content_type} part"

    # The recipient-bound tracked URL — never a static destination — is the
    # only training link that may appear.
    assert _BEARER in haystack
    assert "127.0.0.1:8001/v1/training/awareness" not in haystack


@pytest.mark.parametrize("case", [c for c in _CASES if c["expected"] == "reject"], ids=lambda c: c["id"])
def test_adversarial_case_fails_closed_before_the_provider(case: dict[str, Any]) -> None:
    campaign = _campaign()
    template = _template(
        subject=case["subject"],
        plain_text=case["plain_text"],
        safe_html=case["safe_html"],
        template_id=campaign.current_template_id,
    )
    captured: list[EmailMessage] = []
    with pytest.raises(SafetyRejectionError) as caught:
        _send_capture(
            campaign,
            template,
            settings=_settings(),
            lure_category=_lure(case),
            captured=captured,
        )

    assert re.search(re.escape(case["reject_reason_contains"]), str(caught.value)), (
        f"{case['id']}: reject reason {str(caught.value)!r} did not mention {case['reject_reason_contains']!r}"
    )
    # Fail CLOSED: the rejection happened before any provider hand-off.
    assert captured == [], f"{case['id']}: content reached the provider instead of failing closed"


# --------------------------------------------------------------------------
# (a) The DRAFT raw_proposal / original reconstructed content is never shipped.
# --------------------------------------------------------------------------


def test_raw_proposal_is_never_selected_by_the_delivery_path() -> None:
    sentinel = "RAW-PROPOSAL-MUST-NEVER-SHIP"
    # A malicious pre-approval proposal: external credential-harvest host and a
    # sentinel in every field. The approved, sanitized content is benign.
    raw_proposal = {
        "subject": f"{sentinel} verify your account",
        "plain_text": f"Enter your password: https://login.evil.invalid/pw {sentinel}",
        "safe_html": f'<a href="https://login.evil.invalid/pw">{sentinel}</a>',
        "reviewer_note": sentinel,
    }
    campaign = _campaign()
    template = _template(
        subject="Security awareness check",
        plain_text=f"Please review the notice: {TRAINING_URL_PLACEHOLDER}",
        safe_html=(f'<html><body><a href="{TRAINING_URL_PLACEHOLDER}">review</a></body></html>'),
        template_id=campaign.current_template_id,
        raw_proposal=raw_proposal,
    )

    # The content selector reads only the approved fields.
    subject, plain_text, safe_html = _delivery_template_content(template)
    for field in (subject, plain_text, safe_html):
        assert sentinel not in field
        assert "login.evil.invalid" not in field

    # End to end: the sentinel and the malicious host never reach the MIME.
    captured: list[EmailMessage] = []
    _send_capture(
        campaign,
        template,
        settings=_settings(),
        lure_category=dm.LureCategory.OTHER,
        captured=captured,
    )
    message = captured[0]
    assert sentinel not in message.as_string()
    assert sentinel not in _text_haystack(message)
    assert "login.evil.invalid" not in message.as_string()


# --------------------------------------------------------------------------
# (b)/(d) Approved-version binding: a malicious or wrong version cannot ship.
# --------------------------------------------------------------------------


class _FakeSession:
    """Minimal in-memory stand-in: only ``get`` is reached before the refusal."""

    def __init__(self, objects: dict[tuple[Any, Any], Any]) -> None:
        self._objects = objects
        self.commits = 0

    def get(self, model: Any, identifier: Any, **_kwargs: Any) -> Any:
        return self._objects.get((model, identifier))

    def commit(self) -> None:  # pragma: no cover - refusal paths may commit audit rows
        self.commits += 1


def _authorize(campaign: Campaign, template: TemplateVersion, *, template_hash: object) -> None:
    session = _FakeSession({(TemplateVersion, campaign.current_template_id): template})
    _authorize_delivery(
        _context(),
        session,  # type: ignore[arg-type]
        campaign,
        {"launch_manifest_hash": "l" * 64},
        campaign_id=str(campaign.campaign_id),
        template_hash=template_hash,
    )


def test_an_unapproved_original_version_cannot_be_selected_for_delivery() -> None:
    # The approved-version binding points at a malicious DRAFT "original": even
    # with a matching manifest hash it must be refused because it is not the
    # approved version.
    campaign = _campaign()
    malicious = _template(
        subject="verify your account",
        plain_text=f"Go to https://login.evil.invalid/pw now {TRAINING_URL_PLACEHOLDER}",
        safe_html="",
        template_id=campaign.current_template_id,
        approval_state=dm.TemplateApprovalState.DRAFT,
    )
    with pytest.raises(SafetyRejectionError, match="delivery requires an approved template"):
        _authorize(campaign, malicious, template_hash=campaign.manifest_hash)


def test_a_wrong_version_selection_fails_closed_on_manifest_mismatch() -> None:
    # The named version is APPROVED, but the delivery manifest hash does not
    # match the reviewed campaign (a swapped/wrong version): refuse.
    campaign = _campaign()
    approved = _template(
        subject="Security awareness check",
        plain_text=f"Review: {TRAINING_URL_PLACEHOLDER}",
        safe_html="",
        template_id=campaign.current_template_id,
        approval_state=dm.TemplateApprovalState.APPROVED,
    )
    with pytest.raises(SafetyRejectionError, match="delivery manifest does not match the approved campaign"):
        _authorize(campaign, approved, template_hash="z" * 64)


# --------------------------------------------------------------------------
# W0-01 (KP-AUD-001) explicit canary: reverting the origin-scoping fix fails here.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "case",
    [c for c in _CASES if c.get("revert_canary") == "KP-AUD-001"],
    ids=lambda c: c["id"],
)
def test_w0_01_origin_scoping_canary_fails_closed(case: dict[str, Any]) -> None:
    """An image-allow-listed host in a NON-image origin must fail closed.

    This is the W0-01 fix exercised end to end. If KP-AUD-001 were reverted (so
    the image-host allowance were not scoped to genuine ``<img src>`` origins),
    ``cdn.brand.invalid`` used as an ``<a href>`` or bare prose URL would be
    allowed, the message would reach the provider, and this test would fail on
    the ``captured == []`` assertion below.
    """

    campaign = _campaign()
    template = _template(
        subject=case["subject"],
        plain_text=case["plain_text"],
        safe_html=case["safe_html"],
        template_id=campaign.current_template_id,
    )
    captured: list[EmailMessage] = []
    with pytest.raises(SafetyRejectionError, match="external link not on training allowlist"):
        _send_capture(
            campaign,
            template,
            settings=_settings(safe_html_image_hosts="cdn.brand.invalid"),
            lure_category=dm.LureCategory.OTHER,
            captured=captured,
        )
    assert captured == []
