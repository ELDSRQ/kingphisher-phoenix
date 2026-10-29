"""Rendering/URL-fence policy for worker delivery (W5-03 / KP-AUD-023).

Behavior-preserving extraction of the small, pure policy helpers that decide the
static-destination URL fence and the approved-template content guard. The logic
is byte-for-byte identical to its former home in :mod:`kp_workers.jobs`; that
module re-exports these under their original private names so existing callers
and tests are unaffected.
"""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import unquote, urlparse

from kp_contracts.generation import TRAINING_URL_PLACEHOLDER
from kp_database.models import TemplateVersion
from kp_telemetry.errors import SafetyRejectionError

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def url_identity(value: str) -> tuple[str, str, int | None, str] | None:
    """Return the URL identity relevant to the static-destination fence."""

    try:
        parsed = urlparse(value.rstrip(".,);]}>"))
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"} or parsed.hostname is None:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    path = parsed.path.rstrip("/") or "/"
    return scheme, parsed.hostname.lower(), port, path


def contains_configured_url(content: str, configured_url: str) -> bool:
    """Detect an exact configured destination after common mail encodings.

    Query strings and fragments cannot turn the configured awareness page into
    a recipient-bound assignment, so identity deliberately uses origin + path.
    A configured origin root does not match the distinct tracking-click path.
    """

    target = url_identity(configured_url)
    if target is None:
        return False
    visible = unquote(unescape(content))
    return any(url_identity(match.group(0)) == target for match in _URL_RE.finditer(visible))


def delivery_template_content(template: TemplateVersion) -> tuple[str, str, str]:
    """Return canonical approved content or fail before recipient rendering."""

    subject = template.subject if isinstance(template.subject, str) else ""
    plain_text = template.plain_text if isinstance(template.plain_text, str) else ""
    safe_html = template.safe_html if isinstance(template.safe_html, str) else ""
    if not subject.strip() or not plain_text.strip():
        raise SafetyRejectionError("approved template content is incomplete or not recipient-bound")
    if TRAINING_URL_PLACEHOLDER not in plain_text:
        raise SafetyRejectionError("approved template content is incomplete or not recipient-bound")
    # Text-only templates are supported. When an HTML alternative exists, it
    # must carry the same recipient-bound assignment path as the plain body.
    if safe_html.strip() and TRAINING_URL_PLACEHOLDER not in safe_html:
        raise SafetyRejectionError("approved template content is incomplete or not recipient-bound")
    return subject, plain_text, safe_html
