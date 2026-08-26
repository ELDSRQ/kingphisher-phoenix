"""Deterministic campaign-pattern candidate builder.

Turns a sanitized SourceItem into a CampaignPattern candidate. Deterministic
keyword heuristics only — no AI. Human security review approves the pattern
before it can be used to generate campaigns (approval gate is enforced by the
operator API, not here).

Fail-closed by design: an item that matches no known lure theme maps to the
neutral OTHER category with no fabricated urgency. Enrichment (ATT&CK
techniques, difficulty heuristic, freshness decay) is emitted inside
`attack_mapping` — an existing JSONB dict field — alongside the provenance
hash, so no schema change is required.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from kp_domain_models import models as dm

_LURE_KEYWORDS = {
    "impersonation": [
        "microsoft",
        "google",
        "apple",
        "linkedin",
        "amazon",
        "okta",
        "zoom",
        "adobe",
        "slack",
        "github",
        "facebook",
        "netflix",
        "paypal",
    ],
    "credential-phish": ["password", "credential", "log in", "sign in", "verify your account", "mfa", "2fa", "otp"],
    "malware": ["malware", "ransomware", "trojan", "dropper", "loader"],
    "invoice": ["invoice", "payment", "remittance", "purchase order", "billing"],
    "password-reset": ["reset your password", "password reset", "account locked"],
    "urgent": ["urgent", "immediate action", "final notice", "account suspended", "within 24 hours"],
    "link": ["link", "click", "url", "href"],
    "attachment": ["attachment", "document", "pdf", "download"],
    "exploit": ["exploit", "cve-", "vulnerability", "zero-day"],
    "ceo-fraud": ["ceo", "wire transfer", "gift card", "direct deposit"],
    "qr-code": ["qr code", "qrcode"],
    "mfa-fatigue": ["mfa", "multi-factor", "approve the request", "push notification"],
}

_SECTOR_KEYWORDS = {
    "technology": ["technology", "software", "cloud", "saas", "it"],
    "finance": ["bank", "financial", "finance", "payment"],
    "healthcare": ["healthcare", "hospital", "health"],
    "government": ["government", "public sector", "agency"],
    "retail": ["retail", "ecommerce"],
    "education": ["education", "university", "school"],
}

# Sector keywords match on word boundaries so short tokens like "it" cannot
# fire inside unrelated words ("with", "position", "hospital").
_SECTOR_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    sector: [re.compile(rf"\b{re.escape(keyword)}\b") for keyword in keywords]
    for sector, keywords in _SECTOR_KEYWORDS.items()
}

_ACTOR_KEYWORDS = {
    "financially-motivated": ["financial", "ransom", "money", "payment", "extortion"],
    "nation-state": ["apt", "state-sponsored", "nation-state", "government-sponsored"],
    "opportunistic": ["opportunistic", "commodity", "spam"],
}

# Lure theme -> MITRE ATT&CK initial-access phishing technique. Maps what the
# LURE mimics (the platform itself never sends attachments or malware). Themes
# without a listed technique stay unmapped — fail-closed, no fabrication.
_ATTACK_TECHNIQUE_NAMES = {
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1656": "Impersonation",
}
_TRIGGER_ATTACK_TECHNIQUES = {
    "link": "T1566.002",
    "attachment": "T1566.001",
    "credential-phish": "T1566.002",
    "password-reset": "T1566.002",
    "mfa-fatigue": "T1621",
    "impersonation": "T1656",
    "ceo-fraud": "T1566.003",
}

# Lure theme -> party such lures typically impersonate, most specific first.
# An actor type is NOT an impersonation target; it stays in `actor_type`.
_IMPERSONATION_TARGETS: list[tuple[str, str]] = [
    ("ceo-fraud", "executive-leadership"),
    ("credential-phish", "it-helpdesk"),
    ("password-reset", "it-helpdesk"),
    ("mfa-fatigue", "it-helpdesk"),
    ("invoice", "bank"),
    ("attachment", "delivery-courier"),
]

# Deterministic 1-5 difficulty heuristic: category base complexity + urgency
# cue + actor sophistication + credential/data-entry theme, clamped to [1, 5].
_CATEGORY_BASE_DIFFICULTY: dict[dm.LureCategory, int] = {
    dm.LureCategory.OTHER: 1,
    dm.LureCategory.URGENT_RESPONSE: 2,
    dm.LureCategory.INVOICE_REFERENCE: 2,
    dm.LureCategory.CREDENTIAL_REFERENCE: 3,
    dm.LureCategory.MALWARE_REFERENCE: 3,
}
_CREDENTIAL_THEME_TRIGGERS = ("credential-phish", "password-reset", "mfa-fatigue")
_SOPHISTICATED_ACTOR_TYPES = frozenset({"nation-state"})

# Freshness decay: full marks at or below 7 days of age, linear decay to 0.0
# at 90 days, 0.0 beyond. No wall clock is consulted — the caller pins `as_of`.
_FULL_FRESHNESS_DAYS = 7.0
_STALE_DAYS = 90.0


def _attack_techniques(triggers: list[str]) -> list[dict[str, str]]:
    """Map fired lure themes to ATT&CK techniques, deduped in trigger order."""
    technique_ids: list[str] = []
    for trigger in triggers:
        technique_id = _TRIGGER_ATTACK_TECHNIQUES.get(trigger)
        if technique_id is not None and technique_id not in technique_ids:
            technique_ids.append(technique_id)
    return [
        {"technique_id": technique_id, "technique_name": _ATTACK_TECHNIQUE_NAMES[technique_id]}
        for technique_id in technique_ids
    ]


def _impersonation_target(triggers: list[str], text: str) -> str | None:
    """Typical impersonated party for the fired lure theme; None when not derivable."""
    for trigger, target in _IMPERSONATION_TARGETS:
        if trigger in triggers:
            return target
    if "impersonation" in triggers:
        # Brand-impersonation theme with no more specific party: the matched
        # brand itself is the impersonated party.
        return next((brand for brand in _LURE_KEYWORDS["impersonation"] if brand in text), None)
    return None


def _difficulty(lure_category: dm.LureCategory, triggers: list[str], actor_type: str | None) -> dict[str, Any]:
    """Deterministic 1-5 difficulty with transparent components."""
    category_base = _CATEGORY_BASE_DIFFICULTY.get(lure_category, 1)
    urgency_pressure = 1 if "urgent" in triggers else 0
    actor_sophistication = 1 if actor_type in _SOPHISTICATED_ACTOR_TYPES else 0
    credential_theme = 1 if any(trigger in triggers for trigger in _CREDENTIAL_THEME_TRIGGERS) else 0
    score = category_base + urgency_pressure + actor_sophistication + credential_theme
    return {
        "score": max(1, min(5, score)),
        "components": {
            "category_base": category_base,
            "urgency_pressure": urgency_pressure,
            "actor_sophistication": actor_sophistication,
            "credential_theme": credential_theme,
        },
    }


def _freshness(published_at: datetime | None, as_of: datetime | None) -> dict[str, Any]:
    """Recency component: 1.0 for age <= 7d, linear decay to 0.0 at 90d.

    Unknown inputs (missing published_at, or no caller-supplied as_of) yield a
    recency_score of None — the score never consults a wall clock.
    """
    recency_score: float | None = None
    if (
        published_at is not None
        and as_of is not None
        # Mixed naive/aware datetimes cannot be compared deterministically.
        and (published_at.tzinfo is None) == (as_of.tzinfo is None)
    ):
        age_days = (as_of - published_at).total_seconds() / 86400.0
        if age_days <= _FULL_FRESHNESS_DAYS:
            recency_score = 1.0
        elif age_days >= _STALE_DAYS:
            recency_score = 0.0
        else:
            recency_score = 1.0 - (age_days - _FULL_FRESHNESS_DAYS) / (_STALE_DAYS - _FULL_FRESHNESS_DAYS)
    return {
        "published_at": published_at.isoformat() if published_at is not None else None,
        "as_of": as_of.isoformat() if as_of is not None else None,
        "recency_score": recency_score,
    }


def build_pattern_candidate(item: dm.SourceItem, *, as_of: datetime | None = None) -> dm.CampaignPattern:
    text = f"{item.title}\n{item.sanitized_text}".lower()
    triggers: list[str] = []
    for category, keywords in _LURE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            triggers.append(category)

    if not triggers:
        # Fail-closed: no recognized lure theme -> neutral category, no
        # fabricated urgency triggers or cues.
        lure_category = dm.LureCategory.OTHER
    elif "credential-phish" in triggers:
        lure_category = dm.LureCategory.CREDENTIAL_REFERENCE
    elif "malware" in triggers or "exploit" in triggers:
        lure_category = dm.LureCategory.MALWARE_REFERENCE
    elif "invoice" in triggers:
        lure_category = dm.LureCategory.INVOICE_REFERENCE
    else:
        lure_category = dm.LureCategory.URGENT_RESPONSE

    sectors = [s for s, patterns in _SECTOR_PATTERNS.items() if any(p.search(text) for p in patterns)]
    actors = [a for a, kws in _ACTOR_KEYWORDS.items() if any(k in text for k in kws)]

    claimed_actor = actors[0] if actors else None
    claimed_target_sector = sectors[0] if sectors else None

    return dm.CampaignPattern(
        pattern_version=1,
        lure_category=lure_category,
        impersonation_category=_impersonation_target(triggers, text),
        target_role_category=None,
        emotional_triggers=triggers,
        requested_action="click_link" if "link" in triggers else "none",
        delivery_method="email",
        warning_cues=["urgent-language", "unexpected-sender"] if "urgent" in triggers else ["none"],
        actor_type=claimed_actor,
        sector_targeting=claimed_target_sector,
        attack_mapping={
            "source_hash": item.content_hash,
            "source_item_id": str(item.source_item_id) if item.source_item_id else None,
            "attack_techniques": _attack_techniques(triggers),
            "difficulty": _difficulty(lure_category, triggers, claimed_actor),
            "freshness": _freshness(item.published_at, as_of),
        },
        confidence=item.confidence,
        supporting_evidence=[
            {
                "source_item_id": str(item.source_item_id),
                "title": item.title,
            }
        ],
        prohibited_content_indicators=[],
        approval_state=dm.PatternApprovalState.DRAFT,
        approved_by=None,
        approved_at=None,
        created_by=None,
    )
