"""Deterministic, evidence-bound knowledge-check builder tests (TRN-010)."""

from __future__ import annotations

from kp_database.training_builder import (
    KnowledgeCheckDraft,
    build_knowledge_check_draft,
)


def _draft(**overrides: object) -> KnowledgeCheckDraft:
    kwargs: dict[str, object] = {
        "requested_action": "reset your password",
        "lure_category": "password_reset",
        "emotional_triggers": ["Urgent deadline", "Account will expire"],
        "training_explanation": "Attackers fake password-reset notices.",
    }
    kwargs.update(overrides)
    return build_knowledge_check_draft(**kwargs)  # type: ignore[arg-type]


def test_draft_is_deterministic_and_bounded() -> None:
    first = _draft()
    second = _draft()
    assert first == second
    assert first.as_dict() == second.as_dict()
    assert 2 <= len(first.options) <= 5
    assert all(len(option) <= 200 for option in first.options)
    assert 1 <= len(first.question) <= 500


def test_correct_answer_is_always_the_safe_independent_verification() -> None:
    for triggers in (
        ["Urgent deadline"],
        ["Account will expire"],
        None,
        ["Click the link to keep access"],
    ):
        draft = _draft(emotional_triggers=triggers)
        assert draft.answer_index == 0
        assert "trusted, independent channel" in draft.options[draft.answer_index]


def test_question_uses_requested_action_then_category_then_generic_frame() -> None:
    with_action = _draft(requested_action="verify your bank account")
    assert "verify your bank account" in with_action.question

    with_category = _draft(requested_action=None, lure_category="invoice")
    assert "invoice" in with_category.question

    generic = _draft(requested_action=None, lure_category=None)
    assert generic.question == "You receive an unexpected urgent message. What is the safest response?"


def test_urgency_trigger_is_sanitized_and_bounded() -> None:
    dirty = "Act now\x00\x00 or your account  expires  today!!\r\n"
    draft = _draft(emotional_triggers=[dirty])
    assert "\x00" not in draft.question
    assert "\r" not in draft.question
    assert "  " not in draft.question
    assert all("\x00" not in option and "\r" not in option for option in draft.options)


def test_non_string_and_empty_triggers_are_ignored() -> None:
    draft = _draft(emotional_triggers=["", 42, None, "  "])  # type: ignore[list-item]
    assert len(draft.options) == 3
    assert draft.options[1] == "Act immediately so the request does not expire"


def test_question_and_options_are_hard_capped() -> None:
    draft = _draft(requested_action="x" * 2000, lure_category="y" * 2000)
    assert len(draft.question) <= 500
    assert all(len(option) <= 200 for option in draft.options)


def test_options_always_include_generic_distractors_when_no_trigger_matches() -> None:
    draft = _draft(emotional_triggers=["Happy hour", "Team lunch"])
    assert draft.options == (
        "Verify the request through a trusted, independent channel",
        "Act immediately so the request does not expire",
        "Reply with credentials to prove your identity",
    )
