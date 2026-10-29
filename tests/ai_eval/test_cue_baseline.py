from __future__ import annotations

from aieval.cue_baseline import cue_validity, ground_truth_cue_types
from aieval.eval_set import load_evaluation_set


def _case(case_id: str):
    return next(c for c in load_evaluation_set().cases if c.id == case_id)


def test_ground_truth_cues_come_from_the_w3_01_extractor() -> None:
    assert ground_truth_cue_types(_case("invoice_fidelity")) == ["attachment_lure", "financial_lure", "urgency"]
    assert ground_truth_cue_types(_case("helpdesk_credential")) == [
        "account_threat",
        "credential_request",
        "helpdesk_impersonation",
        "link_lure",
    ]


def test_full_coverage_when_output_retains_every_cue() -> None:
    expected = ["attachment_lure", "financial_lure", "urgency"]
    cv = cue_validity(
        expected,
        subject="Urgent invoice",
        plain_text="Immediate action: review the attached billing statement and wire transfer now.",
        safe_html="<p>final notice</p>",
    )
    assert cv.coverage == 1.0
    assert cv.missing == ()
    assert cv.passed(0.6) is True


def test_partial_coverage_is_measured_against_the_baseline() -> None:
    expected = ["attachment_lure", "financial_lure", "urgency"]
    cv = cue_validity(expected, subject="Invoice", plain_text="There is an invoice on your account.", safe_html="<p/>")
    # Only the financial cue survives (1 of 3).
    assert cv.preserved == ("financial_lure",)
    assert round(cv.coverage, 3) == round(1 / 3, 3)
    assert cv.passed(0.6) is False


def test_empty_expectation_is_vacuously_valid() -> None:
    cv = cue_validity([], subject="x", plain_text="y", safe_html="z")
    assert cv.coverage == 1.0
    assert cv.passed(0.6) is True
