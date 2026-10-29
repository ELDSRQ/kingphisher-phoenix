"""Deterministic cue + transformation manifest vocabulary (W3-01).

These pin the invariants the reconstruction manifest depends on: deterministic
extraction, bounded + hashed (never raw) evidence, unknown-stays-unknown (no
fabricated urgency), a versioned ontology, and a fixed transformation-policy
vocabulary.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from kp_contracts.cue_ontology import (
    CUE_EXTRACTOR_VERSION,
    CUE_ONTOLOGY_VERSION,
    MAX_SPANS_PER_CUE,
    POLICY_REASONS,
    build_cue_manifest,
    extract_cues,
    manifest_cue_labels,
    receipts_from_removed_tags,
    transformation_receipt,
)

_SUBJECT = "URGENT: verify your Microsoft 365 password"
_BODY = "Dear user, click here to sign in. Wire transfer the overdue invoice to the CEO."


def _manifest() -> dict:
    return build_cue_manifest(subject=_SUBJECT, body=_BODY, transformations=[], source="reconstruction")


def test_cue_manifest_stamps_the_ontology_and_extractor_version() -> None:
    manifest = _manifest()
    assert manifest["ontology_version"] == CUE_ONTOLOGY_VERSION
    assert manifest["extractor_version"] == CUE_EXTRACTOR_VERSION
    assert manifest["source"] == "reconstruction"


def test_known_cues_are_extracted_deterministically() -> None:
    cues = extract_cues(_SUBJECT, _BODY)
    by_type = {cue["cue_type"] for cue in cues}
    # Each of these appears literally in the fixture text.
    assert {"urgency", "credential_request", "brand_impersonation", "financial_lure"} <= by_type
    # Brand impersonation carries the specific matched brand as its target.
    brand = next(cue for cue in cues if cue["cue_type"] == "brand_impersonation")
    assert brand["impersonation_target"] == "microsoft"
    assert brand["attack_tag"] == {"technique_id": "T1656", "technique_name": "Impersonation"}
    # Every cue carries a stable, readable id and a confidence.
    assert all(cue["cue_id"].startswith("cue:") for cue in cues)
    assert all(0.0 <= cue["confidence"] <= 1.0 for cue in cues)


def test_unknown_content_stays_unknown_no_fabricated_urgency() -> None:
    # A benign, cue-free message yields NO cues — urgency is never invented.
    cues = extract_cues("Team lunch Friday", "We are meeting at noon in the kitchen. See you there.")
    assert cues == []
    manifest = build_cue_manifest(
        subject="Team lunch Friday",
        body="We are meeting at noon in the kitchen.",
        transformations=[],
        source="reconstruction",
    )
    assert manifest["cues"] == []
    assert manifest_cue_labels(manifest) == []


def test_evidence_spans_are_offsets_and_hashes_never_raw_text() -> None:
    cues = extract_cues(_SUBJECT, _BODY)
    for cue in cues:
        assert cue["evidence_spans"], "a matched cue must carry at least one span"
        assert len(cue["evidence_spans"]) <= MAX_SPANS_PER_CUE
        for span in cue["evidence_spans"]:
            assert span["field"] in {"subject", "body"}
            assert 0 <= span["start"] < span["end"]
            assert span["length"] == span["end"] - span["start"]
            # A span records a hash of the matched token, not the token itself.
            assert set(span["sha256"]) <= set("0123456789abcdef") and len(span["sha256"]) == 64
            source = _SUBJECT if span["field"] == "subject" else _BODY
            token = source[span["start"] : span["end"]]
            assert span["sha256"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
            assert "text" not in span and "value" not in span


def test_manifest_never_embeds_the_raw_source_text() -> None:
    body = "Login at http://evil.example/harvest with password hunter2 immediately."
    manifest = build_cue_manifest(subject="Account locked", body=body, transformations=[], source="reconstruction")
    serialized = json.dumps(manifest)
    assert "evil.example" not in serialized
    assert "hunter2" not in serialized
    assert manifest["provenance"]["raw_text_retained"] is False
    assert manifest["provenance"]["evidence_minimized"] is True
    assert manifest["provenance"]["body_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()


def test_transformation_receipt_requires_a_known_policy_reason() -> None:
    receipt = transformation_receipt(
        "anchor_href", "replaced", "payload_link_removed", count=3, evidence_hashes=("a" * 64,)
    )
    assert receipt["policy_reason"] in POLICY_REASONS
    assert receipt["count"] == 3
    assert receipt["evidence_hashes"] == ["a" * 64]
    with pytest.raises(ValueError):
        transformation_receipt("anchor_href", "replaced", "because_i_said_so")


def test_receipts_from_removed_tags_are_sorted_and_policy_mapped() -> None:
    receipts = receipts_from_removed_tags({"script": 2, "form": 1, "img": 3, "zero": 0})
    components = [receipt["component"] for receipt in receipts]
    assert components == ["tag:form", "tag:img", "tag:script"]  # sorted, zero-count dropped
    reasons = {receipt["component"]: receipt["policy_reason"] for receipt in receipts}
    assert reasons["tag:script"] == "active_content_removed"
    assert reasons["tag:form"] == "credential_form_removed"
    assert reasons["tag:img"] == "disallowed_image_removed"


def test_cue_manifest_is_byte_identical_across_runs_snapshot() -> None:
    # Determinism snapshot: the same input always produces the same manifest,
    # byte-for-byte, and pins the exact structured shape so a silent change to
    # the ontology or serialisation is caught.
    transformations = [
        transformation_receipt("anchor_href", "replaced", "payload_link_removed", count=1),
        transformation_receipt("training_cta", "injected", "training_link_guaranteed"),
    ]
    subject, body = "Verify your password", "Click here now."
    first = build_cue_manifest(subject=subject, body=body, transformations=transformations, source="reconstruction")
    second = build_cue_manifest(
        subject=subject, body=body, transformations=list(transformations), source="reconstruction"
    )
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    pw_start = subject.index("password")
    link_start = body.index("Click here")
    expected = {
        "ontology_version": "cue-ontology/1",
        "extractor_version": "deterministic-cue-extractor/1",
        "source": "reconstruction",
        "cues": [
            {
                "cue_id": "cue:credential_request:1",
                "cue_type": "credential_request",
                "category": "credential_harvest",
                "impersonation_target": "it-helpdesk",
                "attack_tag": {"technique_id": "T1566.002", "technique_name": "Spearphishing Link"},
                "confidence": 0.85,
                "evidence_spans": [
                    {
                        "field": "subject",
                        "start": pw_start,
                        "end": pw_start + 8,
                        "length": 8,
                        "sha256": hashlib.sha256(b"password").hexdigest(),
                    }
                ],
            },
            {
                "cue_id": "cue:link_lure:1",
                "cue_type": "link_lure",
                "category": "payload_delivery",
                "impersonation_target": None,
                "attack_tag": {"technique_id": "T1566.002", "technique_name": "Spearphishing Link"},
                "confidence": 0.7,
                "evidence_spans": [
                    {
                        "field": "body",
                        "start": link_start,
                        "end": link_start + 10,
                        "length": 10,
                        "sha256": hashlib.sha256(b"Click here").hexdigest(),
                    }
                ],
            },
        ],
        "transformations": transformations,
        "provenance": {
            "subject_sha256": hashlib.sha256(b"Verify your password").hexdigest(),
            "body_sha256": hashlib.sha256(b"Click here now.").hexdigest(),
            "evidence_minimized": True,
            "raw_text_retained": False,
        },
    }
    assert first == expected
