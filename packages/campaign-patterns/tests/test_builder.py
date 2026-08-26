"""Tests for the deterministic campaign-pattern builder.

These pin `build_pattern_candidate`: keyword-based lure, sector, and actor
classification; the fail-closed neutral default when nothing matches (T-07);
word-boundary sector matching (T-07); impersonation-target semantics (T-07);
ATT&CK technique mapping, difficulty heuristic, and freshness decay emitted in
`attack_mapping` alongside the provenance hash; and the DRAFT/no-owner output
contract. Regression tests keep the old fail-open/substring/mixed-semantics
bugs from coming back.
"""

from __future__ import annotations

import datetime
from uuid import uuid4

import pytest
from kp_campaign_patterns import build_pattern_candidate
from kp_campaign_patterns.builder import _freshness
from kp_domain_models import models as dm

_PUBLISHED = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
_RETRIEVED = datetime.datetime(2026, 1, 2, tzinfo=datetime.UTC)
_AS_OF = datetime.datetime(2026, 1, 8, tzinfo=datetime.UTC)


def _item(
    title: str = "Advisory summary",
    text: str = "",
    content_hash: str = "hash-1",
    confidence: dm.Confidence = dm.Confidence.UNVERIFIED,
) -> dm.SourceItem:
    return dm.SourceItem(
        source_id=uuid4(),
        publisher="test-publisher",
        title=title,
        published_at=_PUBLISHED,
        retrieved_at=_RETRIEVED,
        sanitized_text=text,
        content_hash=content_hash,
        source_reference="ref-1",
        confidence=confidence,
    )


# --- Lure-category keyword classification (one representative keyword per category) ---


@pytest.mark.parametrize(
    ("keyword", "expected_trigger"),
    [
        ("microsoft", "impersonation"),
        ("log in", "credential-phish"),
        ("trojan", "malware"),
        ("remittance", "invoice"),
        ("account locked", "password-reset"),
        ("final notice", "urgent"),
        ("click", "link"),
        ("pdf", "attachment"),
        ("cve-", "exploit"),
        ("gift card", "ceo-fraud"),
        ("qrcode", "qr-code"),
        ("multi-factor", "mfa-fatigue"),
    ],
)
def test_lure_keyword_classifies_to_its_category(keyword: str, expected_trigger: str) -> None:
    pattern = build_pattern_candidate(_item(text=keyword))
    assert expected_trigger in pattern.emotional_triggers


def test_single_keyword_produces_exactly_one_trigger() -> None:
    pattern = build_pattern_candidate(_item(text="click"))
    assert pattern.emotional_triggers == ["link"]


@pytest.mark.parametrize(
    ("text", "expected_lure"),
    [
        ("log in", dm.LureCategory.CREDENTIAL_REFERENCE),
        ("trojan", dm.LureCategory.MALWARE_REFERENCE),
        ("cve-", dm.LureCategory.MALWARE_REFERENCE),
        ("remittance", dm.LureCategory.INVOICE_REFERENCE),
        ("microsoft", dm.LureCategory.URGENT_RESPONSE),
        ("account locked", dm.LureCategory.URGENT_RESPONSE),
        ("multi-factor", dm.LureCategory.URGENT_RESPONSE),
    ],
)
def test_lure_category_selection(text: str, expected_lure: dm.LureCategory) -> None:
    pattern = build_pattern_candidate(_item(text=text))
    assert pattern.lure_category == expected_lure


def test_lure_category_precedence_credential_over_malware() -> None:
    pattern = build_pattern_candidate(_item(text="password malware"))
    assert pattern.lure_category == dm.LureCategory.CREDENTIAL_REFERENCE


def test_lure_category_precedence_malware_over_invoice() -> None:
    pattern = build_pattern_candidate(_item(text="trojan invoice"))
    assert pattern.lure_category == dm.LureCategory.MALWARE_REFERENCE


def test_password_reset_trigger_does_not_change_lure_category() -> None:
    """The password-reset trigger stays on URGENT_RESPONSE as its lure
    category (T-07 decision: no new category); the credential theme is
    captured by the impersonation target, difficulty, and ATT&CK mapping.
    """
    pattern = build_pattern_candidate(_item(text="account locked"))
    assert pattern.emotional_triggers == ["password-reset"]
    assert pattern.lure_category == dm.LureCategory.URGENT_RESPONSE


# --- Keyword overlaps (shared keywords across dictionaries) ---


def test_mfa_keyword_triggers_both_credential_phish_and_mfa_fatigue() -> None:
    """Characterization: "mfa" appears in both the credential-phish and
    mfa-fatigue dictionaries, so one token sets two triggers (in dictionary
    order) and the lure becomes CREDENTIAL_REFERENCE.
    """
    pattern = build_pattern_candidate(_item(text="mfa"))
    assert pattern.emotional_triggers == ["credential-phish", "mfa-fatigue"]
    assert pattern.lure_category == dm.LureCategory.CREDENTIAL_REFERENCE


def test_password_reset_phrase_also_matches_credential_phish() -> None:
    pattern = build_pattern_candidate(_item(text="reset your password"))
    assert pattern.emotional_triggers == ["credential-phish", "password-reset"]


def test_payment_keyword_spans_lure_sector_and_actor() -> None:
    pattern = build_pattern_candidate(_item(text="payment"))
    assert pattern.emotional_triggers == ["invoice"]
    assert pattern.sector_targeting == "finance"
    assert pattern.actor_type == "financially-motivated"


# --- No keyword matches: fail-closed default (T-07 defect 1) ---


def test_no_keyword_match_fails_closed_to_neutral_other() -> None:
    """Regression (T-07): the old builder fail-OPENED to the "urgent" trigger,
    URGENT_RESPONSE category, and urgent warning cues when nothing matched.
    Fail-closed: neutral OTHER category, no triggers, no urgency cues.
    """
    pattern = build_pattern_candidate(_item(title="calm sunset", text="calm sunset over the meadow"))
    assert pattern.emotional_triggers == []
    assert pattern.lure_category == dm.LureCategory.OTHER
    assert pattern.warning_cues == ["none"]
    assert pattern.requested_action == "none"
    assert pattern.sector_targeting is None
    assert pattern.actor_type is None
    assert pattern.impersonation_category is None


def test_no_keyword_match_still_carries_provenance_and_enrichment() -> None:
    item = _item(title="calm sunset", content_hash="sha256:none")
    mapping = build_pattern_candidate(item).attack_mapping
    assert mapping["source_hash"] == "sha256:none"
    assert mapping["source_item_id"] == str(item.source_item_id)
    assert mapping["attack_techniques"] == []
    assert mapping["difficulty"]["score"] == 1


# --- Sector classification (word-boundary matching, T-07 defect 2) ---


@pytest.mark.parametrize(
    ("keyword", "expected_sector"),
    [
        ("saas", "technology"),
        ("bank", "finance"),
        ("healthcare", "healthcare"),
        ("agency", "government"),
        ("ecommerce", "retail"),
        ("school", "education"),
    ],
)
def test_sector_keyword_classifies_to_its_sector(keyword: str, expected_sector: str) -> None:
    pattern = build_pattern_candidate(_item(text=keyword))
    assert pattern.sector_targeting == expected_sector


def test_multiple_matching_sectors_take_first_in_dictionary_order() -> None:
    pattern = build_pattern_candidate(_item(text="saas bank"))
    assert pattern.sector_targeting == "technology"


def test_sector_substring_it_no_longer_matches_technology() -> None:
    """Regression (T-07): the technology dictionary contained the bare
    substring "it", so words like "with" or "position" (and even "hospital")
    were misclassified as technology. Sector keywords now match on word
    boundaries only.
    """
    pattern = build_pattern_candidate(_item(title="with", text="position available"))
    assert pattern.sector_targeting is None


def test_hospital_classifies_as_healthcare_not_technology() -> None:
    """Regression (T-07): "hospital" used to hit the "it" substring and was
    classified as technology; it now matches the healthcare keyword."""
    pattern = build_pattern_candidate(_item(text="hospital"))
    assert pattern.sector_targeting == "healthcare"


def test_standalone_it_word_matches_technology() -> None:
    pattern = build_pattern_candidate(_item(title="IT maintenance", text="scheduled downtime"))
    assert pattern.sector_targeting == "technology"


def test_sector_word_boundary_rejects_embedded_and_plural_forms() -> None:
    assert build_pattern_candidate(_item(text="hospitals")).sector_targeting is None
    assert build_pattern_candidate(_item(text="positioning")).sector_targeting is None


# --- Actor-type classification (actor type stays in its own field, T-07 defect 3) ---


@pytest.mark.parametrize(
    ("keyword", "expected_actor"),
    [
        ("extortion", "financially-motivated"),
        ("state-sponsored", "nation-state"),
        ("commodity", "opportunistic"),
    ],
)
def test_actor_keyword_classifies_to_its_actor_type(keyword: str, expected_actor: str) -> None:
    pattern = build_pattern_candidate(_item(text=keyword))
    assert pattern.actor_type == expected_actor
    assert pattern.impersonation_category is None


def test_multiple_matching_actors_take_first_in_dictionary_order() -> None:
    pattern = build_pattern_candidate(_item(text="extortion state-sponsored"))
    assert pattern.actor_type == "financially-motivated"


def test_impersonation_category_no_longer_mirrors_actor_type() -> None:
    """Regression (T-07): `impersonation_category` used to be filled with the
    ACTOR type (e.g. "nation-state") — an actor is not an impersonation
    target. The actor type stays in its own field; the impersonation category
    stays None when no impersonated party is derivable.
    """
    pattern = build_pattern_candidate(_item(text="apt"))
    assert pattern.actor_type == "nation-state"
    assert pattern.impersonation_category is None


# --- Impersonation-target derivation (T-07 defect 3) ---


@pytest.mark.parametrize(
    ("text", "expected_target"),
    [
        ("gift card", "executive-leadership"),
        ("log in", "it-helpdesk"),
        ("account locked", "it-helpdesk"),
        ("multi-factor", "it-helpdesk"),
        ("remittance", "bank"),
        ("pdf", "delivery-courier"),
        ("microsoft", "microsoft"),
    ],
)
def test_impersonation_target_derived_from_lure_theme(text: str, expected_target: str) -> None:
    pattern = build_pattern_candidate(_item(text=text))
    assert pattern.impersonation_category == expected_target


def test_lure_theme_beats_brand_for_impersonation_target() -> None:
    pattern = build_pattern_candidate(_item(text="microsoft log in"))
    assert pattern.impersonation_category == "it-helpdesk"


def test_impersonation_target_absent_when_not_derivable() -> None:
    pattern = build_pattern_candidate(_item(text="click"))
    assert pattern.impersonation_category is None


# --- Case-insensitivity and title inclusion ---


def test_matching_is_case_insensitive_across_title_and_body() -> None:
    pattern = build_pattern_candidate(_item(title="MICROSOFT", text="Verify Your Account"))
    assert pattern.emotional_triggers == ["impersonation", "credential-phish"]
    assert pattern.lure_category == dm.LureCategory.CREDENTIAL_REFERENCE


# --- attack_mapping: provenance plus ATT&CK / difficulty / freshness ---


def test_attack_mapping_preserves_provenance_and_adds_enrichment() -> None:
    item = _item(content_hash="sha256:abc123", text="click")
    mapping = build_pattern_candidate(item).attack_mapping
    assert mapping["source_hash"] == "sha256:abc123"
    assert mapping["source_item_id"] == str(item.source_item_id)
    assert "attack_techniques" in mapping
    assert "difficulty" in mapping
    assert "freshness" in mapping


@pytest.mark.parametrize(
    ("text", "expected_ids"),
    [
        ("click", ["T1566.002"]),
        ("pdf", ["T1566.001"]),
        ("gift card", ["T1566.003"]),
        ("microsoft", ["T1656"]),
        ("multi-factor", ["T1621"]),
        ("log in", ["T1566.002"]),
        ("account locked", ["T1566.002"]),
    ],
)
def test_attack_techniques_mapped_from_lure_theme(text: str, expected_ids: list[str]) -> None:
    pattern = build_pattern_candidate(_item(text=text))
    assert [t["technique_id"] for t in pattern.attack_mapping["attack_techniques"]] == expected_ids


def test_attack_technique_entries_carry_names() -> None:
    pattern = build_pattern_candidate(_item(text="pdf"))
    assert pattern.attack_mapping["attack_techniques"] == [
        {"technique_id": "T1566.001", "technique_name": "Spearphishing Attachment"},
    ]


def test_attack_techniques_dedupe_shared_link_and_credential_mapping() -> None:
    # link and credential-phish both map to T1566.002 — emit it once.
    pattern = build_pattern_candidate(_item(text="click log in"))
    ids = [t["technique_id"] for t in pattern.attack_mapping["attack_techniques"]]
    assert ids == ["T1566.002"]


def test_attack_techniques_keep_trigger_order_across_themes() -> None:
    pattern = build_pattern_candidate(_item(text="click gift card"))
    ids = [t["technique_id"] for t in pattern.attack_mapping["attack_techniques"]]
    assert ids == ["T1566.002", "T1566.003"]


def test_attack_techniques_empty_when_theme_is_unmapped_or_no_match() -> None:
    # Invoice/urgent/malware themes have no listed initial-access technique.
    assert build_pattern_candidate(_item(text="remittance")).attack_mapping["attack_techniques"] == []
    assert build_pattern_candidate(_item(text="final notice")).attack_mapping["attack_techniques"] == []
    assert (
        build_pattern_candidate(_item(title="calm sunset", text="calm sunset")).attack_mapping["attack_techniques"]
        == []
    )


# --- Difficulty heuristic (1-5, deterministic) ---


@pytest.mark.parametrize(
    ("text", "expected_score"),
    [
        ("calm sunset over the meadow", 1),  # fail-closed no-match
        ("click", 2),  # plain link lure
        ("final notice", 3),  # urgency cue on top
        ("trojan", 3),  # malware-themed base
        ("remittance", 2),  # invoice base
        ("log in", 4),  # credential base + credential theme
        ("apt log in", 5),  # ... plus nation-state actor
    ],
)
def test_difficulty_score_combines_category_urgency_actor_and_credential_theme(text: str, expected_score: int) -> None:
    pattern = build_pattern_candidate(_item(text=text))
    assert pattern.attack_mapping["difficulty"]["score"] == expected_score


def test_difficulty_clamped_to_five() -> None:
    # credential base + urgency + nation-state + credential theme = 6 -> 5.
    pattern = build_pattern_candidate(_item(text="state-sponsored urgent log in"))
    assert pattern.attack_mapping["difficulty"]["score"] == 5


def test_difficulty_components_are_reported() -> None:
    pattern = build_pattern_candidate(_item(text="log in"))
    assert pattern.attack_mapping["difficulty"] == {
        "score": 4,
        "components": {
            "category_base": 3,
            "urgency_pressure": 0,
            "actor_sophistication": 0,
            "credential_theme": 1,
        },
    }


def test_difficulty_is_deterministic() -> None:
    item = _item(title="invoice due", text="payment attached")
    first = build_pattern_candidate(item)
    second = build_pattern_candidate(item)
    assert first.attack_mapping["difficulty"] == second.attack_mapping["difficulty"]


# --- Freshness (deterministic decay, caller-supplied as_of) ---


def test_freshness_full_marks_within_seven_days() -> None:
    pattern = build_pattern_candidate(_item(text="click"), as_of=_AS_OF)
    assert pattern.attack_mapping["freshness"] == {
        "published_at": "2026-01-01T00:00:00+00:00",
        "as_of": "2026-01-08T00:00:00+00:00",
        "recency_score": 1.0,
    }


def test_freshness_full_marks_for_future_dated_items() -> None:
    as_of = datetime.datetime(2025, 12, 25, tzinfo=datetime.UTC)
    pattern = build_pattern_candidate(_item(), as_of=as_of)
    assert pattern.attack_mapping["freshness"]["recency_score"] == 1.0


def test_freshness_linear_decay_between_seven_and_ninety_days() -> None:
    # 48.5 days old: 1.0 - (48.5 - 7) / (90 - 7) = 0.5.
    as_of = datetime.datetime(2026, 2, 18, 12, 0, tzinfo=datetime.UTC)
    pattern = build_pattern_candidate(_item(), as_of=as_of)
    assert pattern.attack_mapping["freshness"]["recency_score"] == pytest.approx(0.5)


def test_freshness_zero_at_ninety_days_and_beyond() -> None:
    at_ninety = datetime.datetime(2026, 4, 1, tzinfo=datetime.UTC)  # exactly 90 days
    beyond = datetime.datetime(2026, 5, 1, tzinfo=datetime.UTC)
    assert build_pattern_candidate(_item(), as_of=at_ninety).attack_mapping["freshness"]["recency_score"] == 0.0
    assert build_pattern_candidate(_item(), as_of=beyond).attack_mapping["freshness"]["recency_score"] == 0.0


def test_freshness_recency_unknown_without_as_of() -> None:
    """No wall clock inside the score: without a caller-supplied as_of the
    recency score is None (unknown), while published_at is still carried."""
    pattern = build_pattern_candidate(_item(text="click"))
    assert pattern.attack_mapping["freshness"] == {
        "published_at": "2026-01-01T00:00:00+00:00",
        "as_of": None,
        "recency_score": None,
    }


def test_freshness_unknown_when_published_at_missing() -> None:
    assert _freshness(None, _AS_OF) == {
        "published_at": None,
        "as_of": "2026-01-08T00:00:00+00:00",
        "recency_score": None,
    }


def test_freshness_rejects_mixed_naive_and_aware_datetimes() -> None:
    naive_as_of = datetime.datetime(2026, 1, 8)
    assert _freshness(_PUBLISHED, naive_as_of)["recency_score"] is None


# --- supporting_evidence, ownership, defaults ---


def test_supporting_evidence_carries_item_id_and_title() -> None:
    item = _item(title="CEO fraud wave")
    pattern = build_pattern_candidate(item)
    assert pattern.supporting_evidence == [{"source_item_id": str(item.source_item_id), "title": "CEO fraud wave"}]


def test_pattern_is_created_unowned_and_in_draft_state() -> None:
    """Characterization: the builder always emits created_by=None (builder.py
    sets it explicitly) — ownership is assigned later by the approval workflow,
    never inferred from the source item.
    """
    pattern = build_pattern_candidate(_item())
    assert pattern.created_by is None
    assert pattern.approved_by is None
    assert pattern.approved_at is None
    assert pattern.approval_state == dm.PatternApprovalState.DRAFT


def test_output_defaults_are_fixed() -> None:
    pattern = build_pattern_candidate(_item())
    assert pattern.pattern_version == 1
    assert pattern.delivery_method == "email"
    assert pattern.target_role_category is None
    assert pattern.prohibited_content_indicators == []


def test_confidence_passes_through_from_source_item() -> None:
    pattern = build_pattern_candidate(_item(confidence=dm.Confidence.HIGH))
    assert pattern.confidence == dm.Confidence.HIGH


# --- Derived action / warning cues ---


def test_requested_action_is_click_link_only_when_link_trigger_fires() -> None:
    assert build_pattern_candidate(_item(text="click")).requested_action == "click_link"
    assert build_pattern_candidate(_item(text="pdf")).requested_action == "none"


def test_warning_cues_depend_on_urgent_trigger() -> None:
    assert build_pattern_candidate(_item(text="final notice")).warning_cues == [
        "urgent-language",
        "unexpected-sender",
    ]
    assert build_pattern_candidate(_item(text="pdf")).warning_cues == ["none"]


# --- Determinism ---


def test_builder_is_deterministic_for_the_same_source_item() -> None:
    item = _item(title="invoice due", text="payment attached")
    as_of = datetime.datetime(2026, 1, 15, tzinfo=datetime.UTC)
    first = build_pattern_candidate(item, as_of=as_of)
    second = build_pattern_candidate(item, as_of=as_of)
    assert first.model_dump(exclude={"campaign_pattern_id"}) == second.model_dump(exclude={"campaign_pattern_id"})
    assert first.campaign_pattern_id != second.campaign_pattern_id
