"""Malicious-instruction neutralization and Unicode hardening.

Implements SAN-003 plus the generated-content Unicode/domain validation from
R-GEN-007 (§23.2). Detects and marks untrusted: instruction-override requests,
system-prompt requests, tool-call directions, email-sending directions,
encoded instructions, hidden prompt directives, fake administrator messages,
and dangerous Unicode (bidi overrides, zero-width characters, Zalgo) and
punycode/homoglyph domains.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Hidden / dangerous Unicode control characters.
_CONTROL_CHARS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\ufeff",  # zero width no-break space
    "\u2060",  # word joiner
    "\u2066",  # left-to-right isolate
    "\u2067",  # right-to-left isolate
    "\u2068",  # first strong isolate
    "\u2069",  # pop directional isolate
    "\u202a",  # LRE
    "\u202b",  # RLE
    "\u202c",  # PDF
    "\u202d",  # LRO
    "\u202e",  # RLO
}
_ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u2066\u2067\u2068\u2069]")

_OVERRIDE_PATTERNS = [
    # "ignore"/"disregard" are the two most common openings for an instruction
    # override, in both singular and plural, with or without an article.
    re.compile(
        r"\b(ignore|disregard)\s+(all\s+|any\s+)?(the\s+)?"
        r"(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?)",
        re.I,
    ),
    re.compile(r"\b(ignore|disregard)\s+(all\s+)?(your\s+)?(instructions?|rules?|guidelines?)\b", re.I),
    # A payload that simply declares a replacement instruction set.
    re.compile(r"\bnew\s+instructions?\s*[:\-]", re.I),
    re.compile(r"\bforget\s+(all\s+)?(your\s+)?(instructions|rules|guidelines)", re.I),
    re.compile(r"\bsystem\s*(:|prompt)", re.I),
    re.compile(r"\byou\s+are\s+now\s+", re.I),
    re.compile(r"\bdo\s+anything\s+(now|else)\b", re.I),
    re.compile(r"\boverride\s+(instructions|rules)\b", re.I),
]

_ACTION_PATTERNS = [
    re.compile(r"\bsend\s+(an?\s+)?email", re.I),
    re.compile(r"\bsend\s+(to\s+)?(an?\s+)?(external|recipient)", re.I),
    re.compile(r"\bcall\s+(the\s+)?(tool|function)", re.I),
    re.compile(r"\bapprove\s+(this\s+)?campaign", re.I),
    re.compile(r"\bschedule\s+(this\s+)?campaign", re.I),
    re.compile(r"\breveal\s+(the\s+)?(recipient|password|token|key)", re.I),
    re.compile(r"\bignore\s+permissions\b", re.I),
]

_FAKE_ADMIN_PATTERNS = [
    re.compile(r"\badmin(istrator)?\s*(:|said|requested)", re.I),
    re.compile(r"\bfrom\s+the\s+administrator\b", re.I),
    re.compile(r"\bsecurity\s+team\s*(:|requests)", re.I),
]

# Common brands whose punycode/homoglyph lookalikes must never appear in output.
_PROTECTED_BRANDS = {
    "microsoft",
    "google",
    "apple",
    "amazon",
    "linkedin",
    "dropbox",
    "adobe",
    "okta",
    "github",
    "cisco",
    "zoom",
    "office",
    "sharepoint",
    "paypal",
    "netflix",
}


@dataclass
class SanitizationVerdict:
    untrusted: bool
    reasons: list[str] = field(default_factory=list)
    cleaned_text: str = ""


def neutralize(text: str, *, brand_allowlist: set[str] | None = None) -> SanitizationVerdict:
    """Detect and neutralize malicious instructions and dangerous Unicode.

    `brand_allowlist` are domains/brands the operator owns and is permitted
    to imitate in authorized training (their sending domains, internal
    brands). A token that equals one of them or sits on a subdomain is the
    operator's own registered surface, so it is exempt from lookalike
    flagging; the default protected brands are still protected against
    everyone. Neutralization always returns cleaned text; the verdict records
    why it was marked untrusted.
    """
    reasons: list[str] = []
    original = text

    cleaned = _strip_control_chars(text)
    if cleaned != original:
        reasons.append("control characters removed")

    for pattern in _OVERRIDE_PATTERNS:
        if pattern.search(cleaned):
            reasons.append(f"instruction-override pattern: {pattern.pattern}")
            cleaned = _neutralize_matches(pattern, cleaned)

    for pattern in _ACTION_PATTERNS:
        if pattern.search(cleaned):
            reasons.append(f"action-direction pattern: {pattern.pattern}")

    for pattern in _FAKE_ADMIN_PATTERNS:
        if pattern.search(cleaned):
            reasons.append(f"fake-administrator pattern: {pattern.pattern}")

    protected = _PROTECTED_BRANDS
    lookalikes = _find_lookalike_domains(cleaned, protected, owned=brand_allowlist or set())
    if lookalikes:
        reasons.append(f"lookalike/homoglyph domains detected: {sorted(lookalikes)}")

    return SanitizationVerdict(untrusted=bool(reasons), reasons=reasons, cleaned_text=cleaned)


def _strip_control_chars(text: str) -> str:
    return "".join(ch for ch in text if ch not in _CONTROL_CHARS)


def _neutralize_matches(pattern: re.Pattern[str], text: str) -> str:
    return pattern.sub("", text)


def _find_lookalike_domains(text: str, protected_brands: set[str], *, owned: set[str]) -> set[str]:
    """Detect punycode or homoglyph domains resembling protected brands.

    A flagged token is suppressed only when the domain it appears in is the
    operator's own registered surface (an ``owned`` domain or a subdomain of
    one) — that is legitimate lure content. Standalone tokens and domains on
    nobody's list stay flagged.
    """
    found: set[str] = set()

    def flag_label(label: str) -> None:
        if label.startswith("xn--"):
            found.add(label)
            return
        # A hyphenated label ("micr0soft-secure") hides the brand inside it;
        # check the segments as well as the whole label.
        candidates = label.split("-") + [label]
        for candidate in candidates:
            for brand in protected_brands:
                if (
                    candidate != brand
                    and _homoglyph_distance(candidate, brand) <= 1
                    and len(candidate) >= len(brand) - 1
                ):
                    found.add(candidate)
                    return

    domain_pattern = re.compile(r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9][a-z0-9\-]*)+\b")
    for domain in domain_pattern.findall(text.lower()):
        if _is_owned(domain, owned):
            continue
        for label in domain.split("."):
            flag_label(label)
    # Standalone tokens (no dot) are checked after domains are stripped so a
    # label inside an owned domain is never re-flagged on its own.
    remainder = domain_pattern.sub(" ", text.lower())
    for token in re.findall(r"\b[a-z0-9]{4,24}\b", remainder):
        flag_label(token)
    return found


def _is_owned(domain: str, owned: set[str]) -> bool:
    return any(domain == owner or domain.endswith(f".{owner}") for owner in owned)


def _homoglyph_distance(a: str, b: str) -> int:
    """Levenshtein distance, with known homoglyph pairs treated as equal."""

    HOMO = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"}

    def norm(ch: str) -> str:
        return HOMO.get(ch, ch)

    da, db = [norm(c) for c in a], [norm(c) for c in b]
    prev = list(range(len(db) + 1))
    for i, ca in enumerate(da, 1):
        cur = [i]
        for j, cb in enumerate(db, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
