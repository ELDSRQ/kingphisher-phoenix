"""Deterministic safety validator.

Implements GEN-004: reject external links, URL shorteners, credential requests,
MFA requests, executable attachments, macros, JavaScript, QR codes (initial
release), real financial-transfer instructions, sensitive employee scenarios,
software-installation requests, and command-execution requests.

The validator is fully deterministic — it never uses an AI model — and cannot
be bypassed by operator editing (the same validator runs on edited content at
save time and on the approved template hash before delivery).

Anti-evasion hardening:
- HTML entities are decoded before pattern matching (``https&#58;//``,
  ``&#112;&#97;&#115;&#115;`` render to the strings the victim's client sees).
- Unicode NFKC normalization plus a Cyrillic->Latin fold defeats homoglyphs.
- Percent-encoded schemes (``https%3A%2F%2F``), scheme-less ``www.`` links,
  href/src attribute values, and trailing-dot FQDNs are all checked.
- Zero-width/bidi characters and soft hyphens are stripped before matching
  (browsers ignore them when resolving hosts) and their presence is itself a
  blocking reason, so hidden characters cannot split a host past the regexes.
"""

from __future__ import annotations

import contextlib
import html
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

from kp_sanitization.neutralize import _CONTROL_CHARS

# External link detection: anything with a scheme-host that is not on the
# approved training-domain allowlist is rejected.
URL_SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "shorturl.at",
    "cutt.ly",
    "tiny.cc",
    "sniply.in",
    "x.co",
    "t.ly",
    "rebrand.ly",
    "tiny.one",
    "dub.sh",
    "bl.ink",
    "clicky.me",
    "go2l.ink",
    "j.mp",
    "lnkd.in",
    "po.st",
    "qr.ae",
    "short.cm",
    "smarturl.it",
    "snip.ly",
    "t2m.io",
    "u.nu",
    "v.gd",
    "vgd.me",
    "yep.it",
    "kutt.it",
    "soo.gd",
    "tr.im",
    "zurl.ws",
    "adf.ly",
    "shorte.st",
    "bc.vc",
    "bit.do",
}

# Visual-homoglyph fold for Cyrillic letters that render identically to Latin.
# Applied only for detection; the original text is never modified downstream.
_HOMOGLYPH_FOLD = {
    0x0410: "A",
    0x0412: "B",
    0x0415: "E",
    0x041A: "K",
    0x041C: "M",
    0x041D: "H",
    0x041E: "O",
    0x0420: "P",
    0x0421: "C",
    0x0422: "T",
    0x0425: "X",
    0x0423: "Y",
    0x0430: "a",
    0x0435: "e",
    0x043A: "k",
    0x043C: "m",
    0x043D: "h",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0442: "t",
    0x0443: "y",
    0x0445: "x",
    0x0456: "i",
    0x0458: "j",
    0x045C: "k",
    0x044D: "a",
    0x044F: "a",
    0x0451: "e",
    0x04AF: "u",
}

_COMMAND_PATTERNS = [
    re.compile(r"\b(powershell|cmd\.exe|bash\s+-c|sh\s+-c|python\s+-c|curl\b.*\|\s*(bash|sh))\b", re.I),
    re.compile(r"\b(wscript|mshta|rundll32|cscript)\b", re.I),
    re.compile(r"\b(iex|invoke-expression|invoke-webrequest|iwr|bitsadmin|certutil|regsvr32|wmic)\b", re.I),
]

_SOFTWARE_INSTALL_PATTERNS = [
    re.compile(r"\b(install|download)\s+(and\s+)?(run|execute|install)\b", re.I),
    re.compile(r"\bupdate\s+(your\s+)?(browser|reader|player)\b", re.I),
]

_FINANCIAL_PATTERNS = [
    re.compile(r"\b(wire|transfer)\s+\$?\d", re.I),
    re.compile(r"\bbank\s+account\s+(number|details)\b", re.I),
    re.compile(r"\brouting\s+number\b", re.I),
    re.compile(r"\bcredit\s+card\b", re.I),
]

_CREDENTIAL_PATTERNS = [
    re.compile(r"\b(password|passcode|pin)\b", re.I),
    re.compile(r"\b(one-time|mfa|otp|2fa|two-factor|verification)\s*code\b", re.I),
    re.compile(r"\bsign\s+in\b.*\b(password|credentials)\b", re.I),
    re.compile(r"\blogin\s+(id|username)\b", re.I),
]

_ATTACHMENT_PATTERNS = [
    re.compile(r"\.(exe|scr|bat|cmd|com|vbs|ps1|js|jar|msi|hta|lnk|reg|iso)$", re.I),
    re.compile(r"\battached\s+(file|document|invoice|details)\b", re.I),
]

_SENSITIVE_EMPLOYEE_PATTERNS = [
    re.compile(r"\b(salary|payroll\s+details|compensation)\b", re.I),
    re.compile(r"\b(health|medical)\s+(records?|details)\b", re.I),
    re.compile(r"\b(hr\s+file|personal\s+file|disciplinary)\b", re.I),
]

QR_CODE_PATTERN = re.compile(r"\b(qr\s*code|qrcode)\b", re.I)
JAVASCRIPT_PATTERN = re.compile(r"\bjavascript\s*:", re.I)
SCRIPT_URI_PATTERN = re.compile(r"\b(vbscript|data|file)\s*:", re.I)
MACRO_PATTERN = re.compile(r"\b(macro|vba|enable\s+content)\b", re.I)

# Explicit-scheme URLs (also data:/file:/vbscript:) plus the scheme-less link
# shapes that mail clients auto-linkify or that appear in href attributes.
_SCHEME_URL_RE = re.compile(r"(?:https?|ftp|data|file|vbscript):[^\s<>\"']+", re.I)
_PERCENT_SCHEME_RE = re.compile(r"https?%3A%2F%2F[^\s<>\"']+", re.I)
_WWW_HOST_RE = re.compile(r"\bwww\.[a-z0-9](?:[a-z0-9.-]{0,253})?[a-z0-9]", re.I)
_HREF_RE = re.compile(r"\b(?:href|src)\s*=\s*[\"']?([^\"'>\s][^\"'>\s]*)", re.I)
_BARE_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.I)

# Reuse the sanitizer's hidden-character set (zero-width + bidi classes) and
# add soft hyphen: browsers strip all of these when resolving hosts, so an
# embedded one only hides the host from the regexes above.
_HIDDEN_CHARS = _CONTROL_CHARS | {"\u00ad"}
_HIDDEN_CHAR_RE = re.compile("[" + re.escape("".join(sorted(_HIDDEN_CHARS))) + "]")


def _normalize(text: str) -> tuple[str, bool]:
    """Fold a message into the shape the recipient's client renders.

    HTML-entity decoding first (so ``&#112;&#97;&#115;&#115;`` becomes
    ``pass``), then NFKC normalization, then a Cyrillic homoglyph fold so
    ``pаssword`` matches ``password``. NFKC also collapses fullwidth and
    compatibility characters used to smuggle keywords past the regexes.
    Zero-width/bidi characters and soft hyphens are stripped so every
    detector sees the host the browser resolves; the second return value
    flags their presence so the caller blocks on the obfuscation itself.
    """
    decoded = html.unescape(text)
    normalized = unicodedata.normalize("NFKC", decoded).translate(_HOMOGLYPH_FOLD)
    stripped, hidden_count = _HIDDEN_CHAR_RE.subn("", normalized)
    return stripped, hidden_count > 0


def _clean_host(host: str) -> str:
    host = host.strip().strip(".").lower()
    if host.endswith("."):
        host = host[:-1]
    with contextlib.suppress(UnicodeError):
        host = host.encode("idna").decode("ascii")
    return host


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class SafetyValidatorError(Exception):
    """Raised when a safety-critical input cannot be checked (fail closed)."""


@dataclass
class SafetyVerdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class SafetyValidator:
    """Deterministic validator. Configured with the approved training domain."""

    training_domains: set[str]
    allow_qr_codes: bool = False

    def _allowed_host(self, host: str) -> bool:
        host = _clean_host(host)
        if not host or host.startswith((".", "-")):
            return False
        return any(host == d or host.endswith("." + d) for d in self.training_domains)

    def _extract_hosts(self, haystack: str) -> list[tuple[str, str]]:
        """Return (host, origin) pairs for every link-shaped string found."""
        found: list[tuple[str, str]] = []
        seen: set[str] = set()

        def _add(host: str, origin: str) -> None:
            host = _clean_host(host)
            if not host or host in seen:
                return
            seen.add(host)
            found.append((host, origin))

        for url in _SCHEME_URL_RE.findall(haystack):
            if url.lower().startswith(("data:", "file:", "vbscript:")):
                _add(url.split(":", 1)[0], "prohibited-scheme")
                continue
            _add(urlparse(url).hostname or "", "explicit-url")

        for url in _PERCENT_SCHEME_RE.findall(haystack):
            _add(urlparse(url.replace("%3A", ":", 1).replace("%2F", "/", 2)).hostname or "", "percent-encoded-url")

        for host in _WWW_HOST_RE.findall(haystack):
            _add(host, "scheme-less-www")

        for match in _HREF_RE.finditer(haystack):
            value = html.unescape(match.group(1))
            if not value or value.startswith("#"):
                continue
            if value.lower().startswith(("data:", "file:", "vbscript:", "javascript:")):
                _add(value.split(":", 1)[0], "prohibited-scheme")
            elif value.lower().startswith(("http://", "https://")):
                _add(urlparse(value).hostname or "", "href-url")
            elif re.match(r"^[a-z0-9][a-z0-9.-]+$", value, re.I):
                # bare domain in an href/src (mail clients will open it directly)
                _add(value, "href-bare-domain")

        # Bare multi-label hosts in prose (e.g. "training.example.com"); only
        # when they carry a real TLD and more than one label, to avoid flagging
        # abbreviations like "e.g." or sentence fragments.
        for host in _BARE_HOST_RE.findall(haystack):
            labels = host.split(".")
            if len(labels) >= 2 and len(labels[0]) >= 2:
                _add(host, "bare-domain")

        return found

    def validate(
        self, subject: str | None, plain_text: str, html_body: str | None = None, attachments: list[str] | None = None
    ) -> SafetyVerdict:
        reasons: list[str] = []
        raw = "\n".join(x for x in (subject, plain_text, html_body) if x)
        haystack, has_hidden_chars = _normalize(raw)
        if has_hidden_chars:
            reasons.append("obfuscation: hidden zero-width/bidi/control characters present")

        for host, origin in self._extract_hosts(haystack):
            if host in URL_SHORTENER_HOSTS:
                reasons.append(f"URL shortener: {host} ({origin})")
            elif _looks_like_ip(host) and not self._allowed_host(host):
                reasons.append(f"external IP link not on training allowlist: {host} ({origin})")
            elif not self._allowed_host(host):
                reasons.append(f"external link not on training allowlist: {host} ({origin})")

        for pattern in _CREDENTIAL_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"credential/MFA request pattern: {pattern.pattern}")

        for pattern in _ATTACHMENT_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"attachment/executable pattern: {pattern.pattern}")

        for pattern in _COMMAND_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"command-execution pattern: {pattern.pattern}")

        for pattern in _SOFTWARE_INSTALL_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"software-installation request: {pattern.pattern}")

        for pattern in _FINANCIAL_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"financial-transfer instruction: {pattern.pattern}")

        for pattern in _SENSITIVE_EMPLOYEE_PATTERNS:
            if pattern.search(haystack):
                reasons.append(f"sensitive employee scenario: {pattern.pattern}")

        if JAVASCRIPT_PATTERN.search(haystack):
            reasons.append("javascript: URI present")

        if SCRIPT_URI_PATTERN.search(haystack):
            reasons.append("data:/file:/vbscript: URI present")

        if MACRO_PATTERN.search(haystack):
            reasons.append("macro content present")

        if QR_CODE_PATTERN.search(haystack) and not self.allow_qr_codes:
            reasons.append("QR code content not permitted in initial release")

        if attachments:
            for name in attachments:
                is_executable = re.search(r"\.(exe|scr|bat|vbs|ps1|js|msi|jar)$", name, re.I)
                if _ATTACHMENT_PATTERNS[0].search(name) or is_executable:
                    reasons.append(f"disallowed attachment: {name}")

        return SafetyVerdict(allowed=not reasons, reasons=reasons)
