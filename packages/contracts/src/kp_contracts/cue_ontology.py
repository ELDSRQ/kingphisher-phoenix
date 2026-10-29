"""Deterministic social-engineering cue + transformation manifest vocabulary.

Reconstruction (cloning a real phish into a safe DRAFT, and classifying a threat
report into a campaign pattern) must produce a *structured, reviewable, and
deterministic* account of (a) the recognisable social-engineering cues the lure
uses and (b) every component the reconstruction removed or replaced to make the
copy safe. That account is the **cue manifest**. It lets an operator run
cue-complete training and reuse a realistic lure without an AI ever being the
source of truth: known cues are extracted by fixed keyword/regex heuristics
here, and unknown content stays unknown — this module never fabricates urgency
or any other cue that the source text does not literally contain.

Two hard invariants shape the module:

* **Evidence is minimised, never raw.** A cue records *where* its evidence is
  (a bounded ``(field, start, end)`` offset span into the originating text) and
  a SHA-256 of the matched token — never the matched malicious text itself. The
  manifest is therefore safe to persist alongside, and show next to, the safe
  deliverable, because it carries no reusable attacker copy.
* **Determinism.** The ontology is an ordered, frozen tuple; extraction walks it
  in order and emits matches in document order; identical input yields a
  byte-identical manifest (``json.dumps(..., sort_keys=True)``). No wall clock,
  no network, no randomness, no AI.

The ontology is versioned (:data:`CUE_ONTOLOGY_VERSION`); a manifest stamps the
version it was produced under so a later ontology revision is distinguishable
from an older extraction rather than silently reinterpreted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

# A manifest stamps the ontology + extractor identity it was produced under.
# Bump CUE_ONTOLOGY_VERSION when the rule set below changes meaning; bump
# CUE_EXTRACTOR_VERSION when the extraction/serialisation algorithm changes.
CUE_ONTOLOGY_VERSION = "cue-ontology/1"
CUE_EXTRACTOR_VERSION = "deterministic-cue-extractor/1"

# Bounds. Evidence spans are capped per cue, cues per manifest, and
# transformation receipts per manifest, so a hostile source cannot inflate the
# manifest. These are deliberately small: the manifest is review material, not
# an archive of the originating lure.
MAX_SPANS_PER_CUE = 8
MAX_CUES = 64
MAX_TRANSFORMATIONS = 64
MAX_EVIDENCE_HASHES = 32
MAX_FIELD_CHARS = 200_000

# ATT&CK heuristic tags. These map what the *lure* mimics (initial-access
# phishing); the platform never sends an attachment, a payload, or malware.
_ATTACK_NAMES = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1621": "Multi-Factor Authentication Request Generation",
    "T1656": "Impersonation",
}

# Known brands a lure commonly impersonates; the matched brand becomes the cue's
# impersonation target (dynamic, unlike the fixed targets on the other rules).
_BRANDS = (
    "microsoft",
    "office 365",
    "microsoft 365",
    "outlook",
    "google",
    "gmail",
    "apple",
    "icloud",
    "amazon",
    "paypal",
    "docusign",
    "adobe",
    "linkedin",
    "dropbox",
    "netflix",
    "okta",
    "zoom",
    "dhl",
    "fedex",
    "ups",
)


@dataclass(frozen=True)
class CueRule:
    """One deterministic cue definition in the versioned ontology."""

    cue_type: str
    category: str
    pattern: re.Pattern[str]
    impersonation_target: str | None
    attack_technique: str | None
    confidence: float
    #: When True the matched token itself is the impersonation target (brands).
    dynamic_target: bool = False


def _kw(*phrases: str) -> re.Pattern[str]:
    """Case-insensitive, word-boundary alternation over literal phrases."""

    alternation = "|".join(re.escape(phrase) for phrase in phrases)
    return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)


# The ordered, frozen ontology. Order is part of the contract: extraction walks
# it top to bottom, so the manifest's cue order is stable. A rule fires only on
# a literal match in the source text — no rule fabricates a cue.
_ONTOLOGY: tuple[CueRule, ...] = (
    CueRule(
        "brand_impersonation",
        "impersonation",
        _kw(*_BRANDS),
        None,
        "T1656",
        0.8,
        dynamic_target=True,
    ),
    CueRule(
        "executive_impersonation",
        "impersonation",
        _kw("ceo", "cfo", "coo", "managing director", "executive", "president", "chairman"),
        "executive-leadership",
        "T1656",
        0.65,
    ),
    CueRule(
        "helpdesk_impersonation",
        "impersonation",
        _kw("it help desk", "it helpdesk", "help desk", "it support", "service desk", "system administrator"),
        "it-helpdesk",
        "T1656",
        0.65,
    ),
    CueRule(
        "credential_request",
        "credential_harvest",
        _kw(
            "password",
            "verify your account",
            "verify your identity",
            "confirm your identity",
            "verification code",
            "one-time code",
            "one time code",
            "otp",
            "sign in",
            "log in",
            "login credentials",
            "re-enter your credentials",
        ),
        "it-helpdesk",
        "T1566.002",
        0.85,
    ),
    CueRule(
        "mfa_fatigue",
        "credential_harvest",
        _kw(
            "mfa",
            "multi-factor",
            "multi factor",
            "two-factor",
            "two factor",
            "2fa",
            "approve the request",
            "approve the sign-in",
            "push notification",
            "authenticator",
        ),
        "it-helpdesk",
        "T1621",
        0.75,
    ),
    CueRule(
        "link_lure",
        "payload_delivery",
        _kw(
            "click here",
            "click the link",
            "click below",
            "follow this link",
            "verify now",
            "review here",
            "open the portal",
            "access the portal",
            "update your details",
        ),
        None,
        "T1566.002",
        0.7,
    ),
    CueRule(
        "attachment_lure",
        "payload_delivery",
        _kw(
            "attached",
            "attachment",
            "see the attached",
            "download the document",
            "download the file",
            "download the attachment",
            "enclosed document",
            "open the attachment",
            "view the document",
        ),
        None,
        "T1566.001",
        0.7,
    ),
    CueRule(
        "financial_lure",
        "financial",
        _kw(
            "invoice",
            "payment",
            "remittance",
            "wire transfer",
            "gift card",
            "giftcard",
            "purchase order",
            "bank details",
            "direct deposit",
            "billing statement",
            "overdue balance",
        ),
        "finance-department",
        "T1566.003",
        0.7,
    ),
    CueRule(
        "urgency",
        "urgency",
        _kw(
            "urgent",
            "immediate action",
            "immediately",
            "final notice",
            "act now",
            "as soon as possible",
            "asap",
            "time sensitive",
            "last warning",
            "expires today",
            "expiring soon",
        ),
        None,
        "T1566",
        0.8,
    ),
    CueRule(
        "account_threat",
        "urgency",
        _kw(
            "account suspended",
            "account locked",
            "account disabled",
            "account deactivated",
            "account closed",
            "suspend your account",
            "unusual activity",
            "unusual sign-in",
            "unauthorized access",
            "unauthorised access",
        ),
        None,
        "T1566",
        0.75,
    ),
    CueRule(
        "generic_greeting",
        "pretext",
        _kw(
            "dear customer",
            "dear user",
            "dear member",
            "dear valued customer",
            "dear account holder",
            "dear sir/madam",
            "dear sir or madam",
        ),
        None,
        None,
        0.6,
    ),
)

# Bounded, fixed vocabulary of transformation policy reasons. A reconstruction
# receipt must cite one of these — the manifest never carries free-text excuses.
POLICY_REASONS: frozenset[str] = frozenset(
    {
        "payload_link_removed",
        "bare_url_neutralized",
        "active_content_removed",
        "credential_form_removed",
        "embedded_content_removed",
        "disallowed_image_removed",
        "disallowed_tag_removed",
        "disallowed_attribute_removed",
        "training_link_guaranteed",
    }
)

# Map a sanitiser-removed tag to its policy reason, so the receipt explains why.
_TAG_POLICY = {
    "script": "active_content_removed",
    "style": "active_content_removed",
    "noscript": "active_content_removed",
    "form": "credential_form_removed",
    "input": "credential_form_removed",
    "button": "credential_form_removed",
    "select": "credential_form_removed",
    "textarea": "credential_form_removed",
    "label": "credential_form_removed",
    "iframe": "embedded_content_removed",
    "object": "embedded_content_removed",
    "embed": "embedded_content_removed",
    "applet": "embedded_content_removed",
    "img": "disallowed_image_removed",
}


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _attack_tag(technique: str | None) -> dict[str, str] | None:
    if technique is None:
        return None
    return {"technique_id": technique, "technique_name": _ATTACK_NAMES[technique]}


def _span(field: str, match: re.Match[str]) -> dict[str, Any]:
    """A bounded evidence span: offsets + a hash of the matched token, no text."""

    token = match.group(0)
    return {
        "field": field,
        "start": match.start(),
        "end": match.end(),
        "length": len(token),
        "sha256": _sha256(token),
    }


def _scan_rule(rule: CueRule, fields: tuple[tuple[str, str], ...]) -> list[dict[str, Any]]:
    """All occurrences of one rule across the given (name, text) fields.

    For a dynamic-target rule (brands) each distinct matched brand becomes its
    own cue, so the impersonation target is specific. Otherwise every match of
    the rule folds into a single cue with its spans gathered in document order.
    """

    if rule.dynamic_target:
        by_target: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for field_name, text in fields:
            for match in rule.pattern.finditer(text):
                target = match.group(0).lower()
                if target not in by_target:
                    by_target[target] = []
                    order.append(target)
                target_spans = by_target[target]
                if len(target_spans) < MAX_SPANS_PER_CUE:
                    target_spans.append(_span(field_name, match))
        return [
            _cue(rule, by_target[target][:MAX_SPANS_PER_CUE], impersonation_target=target)
            for target in order
            if by_target[target]
        ]

    spans: list[dict[str, Any]] = []
    for field_name, text in fields:
        for match in rule.pattern.finditer(text):
            if len(spans) < MAX_SPANS_PER_CUE:
                spans.append(_span(field_name, match))
    if not spans:
        return []
    return [_cue(rule, spans, impersonation_target=rule.impersonation_target)]


def _cue(rule: CueRule, spans: list[dict[str, Any]], *, impersonation_target: str | None) -> dict[str, Any]:
    return {
        "cue_type": rule.cue_type,
        "category": rule.category,
        "impersonation_target": impersonation_target,
        "attack_tag": _attack_tag(rule.attack_technique),
        "confidence": rule.confidence,
        "evidence_spans": spans,
    }


def extract_cues(subject: str, body: str) -> list[dict[str, Any]]:
    """Deterministically extract the known cues from ``subject`` + ``body``.

    Returns a list of cue records in ontology order (and, within a rule, in
    document order), each carrying a stable ``cue_id``, its category, optional
    impersonation target, optional ATT&CK heuristic tag, a fixed confidence, and
    bounded hashed evidence spans. No cue is emitted that the text does not
    literally match — unknown content stays unknown, and urgency is never
    invented.
    """

    fields = (("subject", (subject or "")[:MAX_FIELD_CHARS]), ("body", (body or "")[:MAX_FIELD_CHARS]))
    cues: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    for rule in _ONTOLOGY:
        for cue in _scan_rule(rule, fields):
            if len(cues) >= MAX_CUES:
                return cues
            counters[rule.cue_type] = counters.get(rule.cue_type, 0) + 1
            # Stable, readable, deterministic identity for a given input.
            cue = {"cue_id": f"cue:{rule.cue_type}:{counters[rule.cue_type]}", **cue}
            cues.append(cue)
    return cues


def transformation_receipt(
    component: str,
    action: str,
    policy_reason: str,
    *,
    count: int = 1,
    evidence_hashes: tuple[str, ...] = (),
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one transformation receipt for a removed/replaced component.

    ``policy_reason`` must be one of :data:`POLICY_REASONS`; a receipt may not
    carry a free-text justification. ``evidence_hashes`` are SHA-256 hashes of
    the removed/replaced token(s) (e.g. an original link destination), never the
    raw value, and are bounded.
    """

    if policy_reason not in POLICY_REASONS:
        raise ValueError(f"unknown transformation policy reason: {policy_reason!r}")
    receipt: dict[str, Any] = {
        "component": component,
        "action": action,
        "policy_reason": policy_reason,
        "count": max(0, int(count)),
    }
    if evidence_hashes:
        receipt["evidence_hashes"] = list(evidence_hashes[:MAX_EVIDENCE_HASHES])
    if detail:
        receipt["detail"] = detail
    return receipt


def receipts_from_removed_tags(removed_tags: dict[str, int]) -> list[dict[str, Any]]:
    """Deterministic receipts for a sanitiser ``removed_tags`` summary."""

    receipts: list[dict[str, Any]] = []
    for tag in sorted(removed_tags):
        count = removed_tags[tag]
        if count <= 0:
            continue
        policy = _TAG_POLICY.get(tag, "disallowed_tag_removed")
        receipts.append(transformation_receipt("tag:" + tag, "removed", policy, count=count))
    return receipts


def build_cue_manifest(
    *,
    subject: str,
    body: str,
    transformations: list[dict[str, Any]] | None = None,
    source: str,
) -> dict[str, Any]:
    """Assemble the full cue + transformation manifest for a reconstruction.

    ``subject`` / ``body`` are the *originating* (pre-neutralisation) text; only
    offsets and hashes derived from them are stored, never the text itself, so
    the manifest can live beside the safe deliverable without re-exposing the
    original copy. ``transformations`` are the receipts the reconstruction
    emitted for each removed/replaced component.

    The returned dict is JSON-safe, bounded, and deterministic for a given
    input. It records ``raw_text_retained: False`` and ``evidence_minimized:
    True`` as an explicit, checkable statement of the provenance-isolation
    invariant.
    """

    receipts = list(transformations or [])[:MAX_TRANSFORMATIONS]
    return {
        "ontology_version": CUE_ONTOLOGY_VERSION,
        "extractor_version": CUE_EXTRACTOR_VERSION,
        "source": source,
        "cues": extract_cues(subject, body),
        "transformations": receipts,
        "provenance": {
            "subject_sha256": _sha256(subject or ""),
            "body_sha256": _sha256(body or ""),
            "evidence_minimized": True,
            "raw_text_retained": False,
        },
    }


def manifest_cue_labels(manifest: dict[str, Any]) -> list[str]:
    """Stable, sorted, de-duplicated cue-type labels for the ``warning_cues`` list.

    This is the free-text-compatible projection of the structured manifest: it
    is what the existing ``warning_cues`` consumers (which expect a short list of
    strings) receive, now sourced from deterministic extraction rather than from
    an AI or a hand-written literal.
    """

    cues = manifest.get("cues") if isinstance(manifest, dict) else None
    if not isinstance(cues, list):
        return []
    labels = {
        cue["cue_type"]
        for cue in cues
        if isinstance(cue, dict) and isinstance(cue.get("cue_type"), str) and cue["cue_type"]
    }
    return sorted(labels)
