from __future__ import annotations

import re

import pytest
from aieval.cue_baseline import ground_truth_cue_types
from aieval.eval_set import EvaluationSet, load_evaluation_set
from pydantic import ValidationError


def test_evaluation_set_is_versioned_digested_and_bounded() -> None:
    evaluation_set = load_evaluation_set()
    assert re.fullmatch(r"[0-9]+\.[0-9]+", evaluation_set.set_version)
    assert 1 <= len(evaluation_set.cases) <= 32
    assert {case.kind for case in evaluation_set.cases} >= {"fidelity", "refusal", "injection"}
    assert len(evaluation_set.digest()) == 64
    assert evaluation_set.digest() == evaluation_set.digest()  # deterministic


def test_set_is_inert_no_pii_and_no_reachable_hosts() -> None:
    evaluation_set = load_evaluation_set()
    blob = " ".join(f"{case.lure_source.subject} {case.lure_source.body}" for case in evaluation_set.cases).lower()
    assert "@" not in blob, "no email addresses anywhere in the set"
    assert "mailbox" not in blob
    # The only URLs permitted are inert injection payloads a case must NOT echo.
    for host in re.findall(r"://([a-z0-9.\-]+)", blob):
        assert host.endswith((".invalid", ".example", ".localhost")) or host == "127.0.0.1", host


def test_expected_cue_types_match_the_deterministic_ground_truth() -> None:
    """The declared cues must equal what the W3-01 extractor produces.

    This is the load-bearing link: the deterministic cue ontology is the ground
    truth, and the set only records it. A drift in either the ontology or the
    set surfaces here instead of silently mis-scoring AI cue-validity.
    """

    evaluation_set = load_evaluation_set()
    offenders: list[str] = []
    for case in evaluation_set.cases:
        declared = sorted(set(case.expected_cue_types))
        actual = ground_truth_cue_types(case)
        if declared != actual:
            offenders.append(f"{case.id}: declared={declared} actual={actual}")
    assert not offenders, offenders


def test_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        EvaluationSet(
            set_version="9.9",
            cases=[
                {
                    "id": "x",
                    "kind": "fidelity",
                    "lure_category": "invoice",
                    "lure_source": {"subject": "s", "body": "b"},
                    "cost_latency": {"latency_ms_budget": 1, "max_total_tokens": 1},
                    "smuggled": True,
                }
            ],
        )


def test_refusal_and_injection_cases_must_declare_their_gate_inputs() -> None:
    base = {
        "id": "r",
        "kind": "refusal",
        "lure_category": "credential_reference",
        "lure_source": {"subject": "s", "body": "b"},
        "cost_latency": {"latency_ms_budget": 1, "max_total_tokens": 1},
    }
    with pytest.raises(ValidationError):
        EvaluationSet(set_version="1.0", cases=[base])  # refusal with no prohibited_terms

    inj = {**base, "id": "i", "kind": "injection"}
    with pytest.raises(ValidationError):
        EvaluationSet(set_version="1.0", cases=[inj])  # injection with no injected_payloads
