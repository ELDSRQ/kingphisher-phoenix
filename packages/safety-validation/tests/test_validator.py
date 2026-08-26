"""Regression tests for the GEN-004 safety validator anti-evasion hardening.

Each test reproduces a bypass that the pre-hardening validator accepted and
asserts it is now rejected. The validator must never silently approve content
that a recipient's mail client would render as a live external link, a
credential request, or an executable download.
"""

from __future__ import annotations

import pytest
from kp_safety_validation.validator import SafetyValidator

TRAINING = {"example.com", "training.local"}


@pytest.fixture
def validator() -> SafetyValidator:
    return SafetyValidator(training_domains=TRAINING)


def _allowed(validator: SafetyValidator, text: str) -> bool:
    return validator.validate(None, text, None).allowed


def _reasons(validator: SafetyValidator, text: str) -> list[str]:
    return validator.validate(None, text, None).reasons


def test_allowlisted_training_link_is_accepted(validator: SafetyValidator) -> None:
    assert validator.validate(None, "Visit https://training.example.com/module-1", None).allowed


def test_external_link_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "See https://evil.example/phish")


def test_html_entity_colon_bypass_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, '<a href="https&#58;//evil.example/phish">click</a>')


def test_html_entity_password_bypass_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Please confirm your &#112;&#97;&#115;&#115;&#119;&#111;&#114;&#100;")


def test_cyrillic_homoglyph_password_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Enter your p\u0430ssword to continue")


def test_percent_encoded_scheme_bypass_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Open https%3A%2F%2Fevil.example%2Fphish now")


def test_scheme_less_www_link_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Visit www.evil.example to verify your account")


def test_bare_domain_in_prose_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Complete your review at evil-site.net/verify")


def test_bare_training_domain_in_prose_is_accepted(validator: SafetyValidator) -> None:
    assert _allowed(validator, "Complete your review at training.example.com/module-2")


def test_href_bare_domain_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, '<a href="evil.example/phish">login</a>')


def test_prohibited_schemes_are_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, '<img src="file:///etc/passwd">')
    assert not _allowed(validator, '<a href="data:text/html;base64,PHNjcmlwdA==">x</a>')
    assert not _allowed(validator, '<a href="vbscript:msgbox(1)">x</a>')


def test_shortener_with_trailing_dot_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Go to https://bit.ly./abc123")


def test_ip_link_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Verify at http://203.0.113.10/portal")


def test_obfuscated_command_bypass_is_rejected(validator: SafetyValidator) -> None:
    assert not _allowed(validator, "Run &quot;powershell&quot; -enc IABlAGMAbwBoAG8A")


def test_qr_code_is_rejected_unless_enabled() -> None:
    assert not SafetyValidator(training_domains=TRAINING).validate(None, "Scan the QR code", None).allowed
    assert (
        SafetyValidator(training_domains=TRAINING, allow_qr_codes=True).validate(None, "Scan the QR code", None).allowed
    )


def test_executable_attachment_is_rejected(validator: SafetyValidator) -> None:
    assert not validator.validate(None, "attached invoice", None, attachments=["invoice.exe"]).allowed


def test_normal_prose_stays_allowed(validator: SafetyValidator) -> None:
    text = (
        "A new phishing pattern uses invoice-themed lures. Please complete the "
        "security awareness module at training.example.com/lesson-4. Contact IT "
        "with questions. See fig. 1 for a summary."
    )
    verdict = validator.validate(None, text, None)
    assert verdict.allowed, verdict.reasons


def test_external_link_in_html_body_is_rejected(validator: SafetyValidator) -> None:
    html_body = '<p>Hello, <a href="https://evil.example/credential-check">verify now</a></p>'
    assert not validator.validate(None, "Hello", html_body).allowed


def test_zero_width_space_in_href_host_is_rejected(validator: SafetyValidator) -> None:
    reasons = _reasons(validator, '<a href="attacker\u200b.com/security">click</a>')
    assert any("external link" in r for r in reasons)
    assert any("obfuscation" in r for r in reasons)


def test_directional_isolate_in_prose_host_is_rejected(validator: SafetyValidator) -> None:
    reasons = _reasons(validator, "Reset your password at attacker\u2066.evil-site.net/verify")
    assert any("external link" in r for r in reasons)
    assert any("obfuscation" in r for r in reasons)


def test_word_joiner_in_prose_host_is_rejected(validator: SafetyValidator) -> None:
    reasons = _reasons(validator, "Confirm your account at secure\u2060-login.example.net/auth")
    assert any("external link" in r for r in reasons)
    assert any("obfuscation" in r for r in reasons)


def test_soft_hyphen_in_prose_host_is_rejected(validator: SafetyValidator) -> None:
    reasons = _reasons(validator, "Visit attacker\u00ad.com/security to keep your access")
    assert any("external link" in r for r in reasons)
    assert any("obfuscation" in r for r in reasons)


def test_hidden_chars_in_allowlisted_host_still_rejected(validator: SafetyValidator) -> None:
    verdict = validator.validate(None, "Visit training\u200b.example.com/lesson-1", None)
    assert not verdict.allowed
    assert any("obfuscation" in r for r in verdict.reasons)
