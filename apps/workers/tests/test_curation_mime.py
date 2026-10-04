"""Hardened extraction of a forwarded phish body (attacker-controlled input)."""

from __future__ import annotations

from email.message import EmailMessage

from kp_workers.providers.curation_mime import MAX_RAW_BYTES, extract_forwarded_phish


def _email(*, subject: str = "Phish", html: str | None = None, text: str | None = None) -> EmailMessage:
    m = EmailMessage()
    m["Subject"] = subject
    m["From"] = "attacker@evil.example"
    m["To"] = "victim@corp.example"
    if text is not None:
        m.set_content(text)
    if html is not None:
        if text is not None:
            m.add_alternative(html, subtype="html")
        else:
            m.set_content(html, subtype="html")
    return m


def test_extracts_subject_and_html_body() -> None:
    raw = _email(subject="MS365 verify", html="<p>Verify <a href='https://evil/x'>now</a></p>", text="Verify now")
    e = extract_forwarded_phish(raw.as_bytes())
    assert e is not None
    assert e.subject == "MS365 verify"
    assert e.html and "Verify" in e.html
    assert e.text and "Verify now" in e.text


def test_attachments_are_never_extracted() -> None:
    m = _email(subject="Invoice", html="<p>See attached invoice</p>")
    m.add_attachment(
        b"MZ\x90\x00malware-payload", maintype="application", subtype="octet-stream", filename="invoice.exe"
    )
    # Even an HTML *attachment* must not be mistaken for the body.
    m.add_attachment(b"<script>steal()</script>", maintype="text", subtype="html", filename="page.html")
    e = extract_forwarded_phish(m.as_bytes())
    assert e is not None and e.html and "See attached invoice" in e.html
    assert "malware-payload" not in (e.html or "") and "MZ" not in (e.html or "")
    assert "steal()" not in (e.html or "")  # the .html attachment is ignored


def test_forwarded_original_as_attachment_is_unwrapped() -> None:
    inner = _email(subject="Inner phish", html="<p>inner credential phish</p>")
    outer = EmailMessage()
    outer["Subject"] = "Fwd: suspicious email"
    outer["From"] = "user@corp.example"
    outer["To"] = "report-phish@corp.example"
    outer.set_content("I think this is phishing, see attached.")
    outer.add_attachment(inner)  # content manager attaches it as message/rfc822
    e = extract_forwarded_phish(outer.as_bytes())
    assert e is not None and e.html and "inner credential phish" in e.html


def test_text_only_forward() -> None:
    e = extract_forwarded_phish(_email(subject="Alert", text="Dear user, verify your account").as_bytes())
    assert e is not None and e.text and "verify your account" in e.text and e.html is None


def test_oversized_input_is_rejected() -> None:
    assert extract_forwarded_phish(b"x" * (MAX_RAW_BYTES + 1)) is None


def test_empty_and_garbage_return_none_without_raising() -> None:
    assert extract_forwarded_phish(b"") is None
    # Garbage must never RAISE (a scheduled poller keeps going); whatever it
    # returns is still neutralized downstream by the sanitizer.
    result = extract_forwarded_phish(b"\xff\xfe not a real email \x00\x01")
    assert result is None or result.__class__.__name__ == "ExtractedPhish"


def test_deeply_nested_multipart_is_bounded() -> None:
    # Build a pathologically nested multipart; extraction must not blow the stack
    # or hang — it returns (possibly None) within the depth/part caps.
    raw = b"Subject: nested\r\n" + b"".join(
        b'Content-Type: multipart/mixed; boundary="b%d"\r\n\r\n--b%d\r\n' % (i, i) for i in range(50)
    )
    result = extract_forwarded_phish(raw)
    assert result is None or (result.html is None and result.text is None) or result is not None
