from __future__ import annotations

from aieval.eval_set import RealismRubric
from aieval.realism import score_realism

PLACEHOLDER = "{{ tracking.training_url }}"


def _fidelity_rubric(**overrides) -> RealismRubric:
    base = {
        "require_subject": True,
        "require_training_link": True,
        "require_cta": True,
        "forbid_simulation_disclaimer": True,
        "min_cue_coverage": 0.6,
    }
    base.update(overrides)
    return RealismRubric(**base)


def test_realistic_lure_passes_every_structural_check() -> None:
    score = score_realism(
        _fidelity_rubric(),
        subject="Invoice overdue",
        plain_text=f"Pay now: {PLACEHOLDER}",
        safe_html=f'<p><a href="{PLACEHOLDER}">Pay the invoice</a></p>',
        cue_coverage=1.0,
    )
    assert score.passed is True


def test_missing_training_placeholder_fails() -> None:
    score = score_realism(
        _fidelity_rubric(),
        subject="Invoice",
        plain_text="Pay now (no link)",
        safe_html="<p>Pay now</p>",
        cue_coverage=1.0,
    )
    assert "training_link_present" in score.failed_checks


def test_simulation_disclaimer_breaks_realism_for_a_lure() -> None:
    score = score_realism(
        _fidelity_rubric(),
        subject="Invoice",
        plain_text=f"This is a simulated phishing test. {PLACEHOLDER}",
        safe_html=f'<p><a href="{PLACEHOLDER}">Pay</a></p>',
        cue_coverage=1.0,
    )
    assert "no_simulation_disclaimer" in score.failed_checks


def test_low_cue_coverage_fails_the_rubric() -> None:
    score = score_realism(
        _fidelity_rubric(),
        subject="Invoice",
        plain_text=f"Pay: {PLACEHOLDER}",
        safe_html=f'<p><a href="{PLACEHOLDER}">Pay</a></p>',
        cue_coverage=0.3,
    )
    assert "cue_coverage" in score.failed_checks


def test_refusal_rubric_permits_a_simulation_disclaimer_and_needs_no_cta() -> None:
    rubric = RealismRubric(
        require_subject=True,
        require_training_link=True,
        require_cta=False,
        forbid_simulation_disclaimer=False,
        min_cue_coverage=0.0,
    )
    score = score_realism(
        rubric,
        subject="Awareness note",
        plain_text=f"This is a simulated phishing awareness exercise. {PLACEHOLDER}",
        safe_html=f'<p>simulation</p><p><a href="{PLACEHOLDER}">Learn</a></p>',
        cue_coverage=0.0,
    )
    assert score.passed is True
    assert "no_simulation_disclaimer" not in {c.name for c in score.checks}
    assert "call_to_action" not in {c.name for c in score.checks}
