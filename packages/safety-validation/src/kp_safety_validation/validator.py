"""Deterministic safety validator.

Implements GEN-004: reject external links, URL shorteners, credential requests,
MFA requests, executable attachments, macros, JavaScript, QR codes (initial
release), real financial-transfer instructions, sensitive employee scenarios,
software-installation requests, and command-execution requests.

The validator is fully deterministic — it never uses an AI model — and cannot
be bypassed by operator editing (the same validator runs on edited content at
save time and on the approved template hash before delivery).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# External link detection: anything with a scheme-host that is not on the
# approved training-domain allowlist is rejected.
URL_SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rb.gy", "shorturl.at", "cutt.ly", "tiny.cc", "sniply.in", "x.co",
}

_COMMAND_PATTERNS = [
    re.compile(r"\b(powershell|cmd\.exe|bash\s+-c|sh\s+-c|python\s+-c|curl\b.*\|\s*(bash|sh))\b", re.I),
    re.compile(r"\b(wscript|mshta|rundll32|cscript)\b", re.I),
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
    re.compile(r"\b(one-time|mfa|otp|2fa|two-factor|verification)\s*(code|code)\b", re.I),
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
MACRO_PATTERN = re.compile(r"\b(macro|vba|enable\s+content)\b", re.I)


@dataclass
class SafetyVerdict:
    allowed: bool
    reasons: list[str] = field(default_factory=list)


@dataclass
class SafetyValidator:
    """Deterministic validator. Configured with the approved training domain."""

    training_domains: set[str]
    allow_qr_codes: bool = False

    def validate(self, subject: str | None, plain_text: str, html: str | None = None,
                 attachments: list[str] | None = None) -> SafetyVerdict:
        reasons: list[str] = []
        haystack = "\n".join(x for x in (subject, plain_text, html) if x)

        urls = re.findall(r"https?://[^\s<>\"']+", haystack)
        for url in urls:
            host = (urlparse(url).hostname or "").lower()
            if host in URL_SHORTENER_HOSTS:
                reasons.append(f"URL shortener: {host}")
            elif host and not any(host == d or host.endswith("." + d) for d in self.training_domains):
                reasons.append(f"external link not on training allowlist: {host}")

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
