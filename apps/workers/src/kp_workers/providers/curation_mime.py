"""Safely extract subject + body HTML/text from a forwarded phishing email.

This is deliberately SEPARATE from ``reported_mime.py`` (which never renders a
body — it only reads an opaque correlation header). Curation *does* need the
body in order to clone it, so this parser is hardened against hostile input:

* bounded raw size, nesting depth, and part count (no zip-bomb / billion-parts);
* pure stdlib parsing — it never *renders* or *executes* anything and never
  touches the network;
* **attachments are never read, decoded, saved, or forwarded** — the primary
  malware vector is ignored entirely; only ``text/html`` and ``text/plain`` body
  parts (and a forwarded original inside ``message/rfc822``) are extracted;
* output is length-capped.

The extracted HTML is still untrusted: it is handed to the allow-list sanitizer
(``clone_real_message`` → ``sanitize_safe_html``), which strips every script,
form, iframe, event handler, remote resource, and navigable link. This parser
only limits the blast radius of *parsing* hostile MIME; the sanitizer remains
the authority that guarantees the replica carries no live payload.
"""

from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

#: Hard caps. A forwarded phish body is small; anything larger is hostile.
MAX_RAW_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 6
MAX_PARTS = 200
MAX_BODY_CHARS = 400_000
MAX_SUBJECT_CHARS = 998


@dataclass(slots=True)
class ExtractedPhish:
    subject: str
    html: str | None
    text: str | None


@dataclass
class _Acc:
    html: str | None = None
    text: str | None = None
    parts_left: int = MAX_PARTS


def _is_attachment(part: EmailMessage) -> bool:
    disposition = (part.get_content_disposition() or "").lower()
    if disposition == "attachment":
        return True
    # A named inline part is treated as an attachment too (never a body).
    return bool(part.get_filename())


def _text_of(part: EmailMessage) -> str | None:
    try:
        content = part.get_content()
    except (LookupError, ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(content, str):
        return None
    return content[:MAX_BODY_CHARS]


def _walk(part: EmailMessage, depth: int, acc: _Acc) -> None:
    if depth > MAX_DEPTH or acc.parts_left <= 0:
        return
    acc.parts_left -= 1
    content_type = part.get_content_type()

    if part.is_multipart():
        payload = part.get_payload()
        if isinstance(payload, list):
            for child in payload:
                if acc.parts_left <= 0:
                    return
                if isinstance(child, EmailMessage):
                    _walk(child, depth + 1, acc)
        return

    if content_type == "message/rfc822":
        # A forwarded original email carried as an attached message. Recurse one
        # level to pull the real phish body out of it.
        payload = part.get_payload()
        inner = payload[0] if isinstance(payload, list) and payload else payload
        if isinstance(inner, EmailMessage):
            _walk(inner, depth + 1, acc)
        return

    # Only inline body parts are extracted; attachments are ignored entirely.
    if _is_attachment(part):
        return
    if content_type == "text/html" and acc.html is None:
        acc.html = _text_of(part)
    elif content_type == "text/plain" and acc.text is None:
        acc.text = _text_of(part)


def extract_forwarded_phish(raw: bytes) -> ExtractedPhish | None:
    """Return subject + body for one forwarded email, or ``None`` if unusable.

    Never raises on hostile input; returns ``None`` instead so a scheduled
    poller keeps processing the rest of the batch.
    """
    if not raw or len(raw) > MAX_RAW_BYTES:
        return None
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except (ValueError, TypeError, IndexError, UnicodeError, MemoryError):
        return None
    subject = ""
    try:
        subject = str(message.get("Subject", "") or "").strip()[:MAX_SUBJECT_CHARS]
    except (ValueError, TypeError):
        subject = ""

    acc = _Acc()
    try:
        _walk(message, 0, acc)
    except (ValueError, TypeError, IndexError, UnicodeError, MemoryError):
        return None

    if not subject and not acc.html and not acc.text:
        return None
    if not acc.html and not acc.text:
        return None
    return ExtractedPhish(subject=subject or "(no subject)", html=acc.html, text=acc.text)
