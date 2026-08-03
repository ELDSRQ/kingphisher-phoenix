"""Deterministic campaign-pattern candidate builder.

Turns a sanitized SourceItem into a CampaignPattern candidate. Deterministic
keyword heuristics only — no AI. Human security review approves the pattern
before it can be used to generate campaigns (approval gate is enforced by the
operator API, not here).
"""

from __future__ import annotations

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

_ACTOR_KEYWORDS = {
    "financially-motivated": ["financial", "ransom", "money", "payment", "extortion"],
    "nation-state": ["apt", "state-sponsored", "nation-state", "government-sponsored"],
    "opportunistic": ["opportunistic", "commodity", "spam"],
}


def build_pattern_candidate(item: dm.SourceItem) -> dm.CampaignPattern:
    text = f"{item.title}\n{item.sanitized_text}".lower()
    triggers: list[str] = []
    for category, keywords in _LURE_KEYWORDS.items():
        if any(kw in text for kw in keywords):
            triggers.append(category)
    if not triggers:
        triggers = ["urgent"]

    sectors = [s for s, kws in _SECTOR_KEYWORDS.items() if any(k in text for k in kws)]
    actors = [a for a, kws in _ACTOR_KEYWORDS.items() if any(k in text for k in kws)]

    lure_category = dm.LureCategory.URGENT_RESPONSE
    if "credential-phish" in triggers:
        lure_category = dm.LureCategory.CREDENTIAL_REFERENCE
    elif "malware" in triggers or "exploit" in triggers:
        lure_category = dm.LureCategory.MALWARE_REFERENCE
    elif "invoice" in triggers:
        lure_category = dm.LureCategory.INVOICE_REFERENCE

    claimed_actor = actors[0] if actors else None
    claimed_target_sector = sectors[0] if sectors else None

    return dm.CampaignPattern(
        pattern_version=1,
        lure_category=lure_category,
        impersonation_category=claimed_actor,
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
