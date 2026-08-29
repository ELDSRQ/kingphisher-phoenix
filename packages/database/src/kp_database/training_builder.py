"""Deterministic, evidence-bound knowledge-check builder for campaign lessons.

TRN-010: approved campaign evidence yields one concise, safe knowledge
check (question + options + correct-answer index) that is bound to the
campaign, human-reviewed, and digest-pinned; lessons without a knowledge
check keep the generic quiz. The builder is deliberately deterministic and
non-AI: it composes only bounded, sanitized strings from approved template
and pattern evidence, and it never invents a correct answer — the safe
independent-verification response is always the correct option (index 0),
mirroring the generic quiz's own semantics.

Trust boundary: the inputs are already operator-approved evidence
(`TemplateVersion`/`CampaignPattern` rows that passed the content review
gate). The builder still treats every string as untrusted: it strips control
characters, collapses whitespace, and hard-caps lengths before composing.
The output is a *draft* for the operator to review before saving; nothing
here writes to the database or changes approval state.
"""

from __future__ import annotations

from dataclasses import dataclass

_QUESTION_MAX = 500
_OPTION_MAX = 200
_OPTIONS_MIN = 2
_OPTIONS_MAX = 5

#: The canonical safe response is always the correct option (index 0).
_SAFE_RESPONSE = "Verify the request through a trusted, independent channel"
#: Generic distractors used when the lure evidence offers no bounded flavor.
_GENERIC_URGENCY = "Act immediately so the request does not expire"
_GENERIC_CREDENTIALS = "Reply with credentials to prove your identity"


def _sanitize(value: str | None, *, maximum: int) -> str | None:
    """Strip control characters and bound a single evidence string.

    Returns ``None`` when the input is absent or collapses to nothing so the
    caller can fall back to a safe default instead of composing an empty or
    injection-shaped question/option.
    """
    if value is None:
        return None
    cleaned = "".join(ch for ch in value if ch.isprintable() and ch not in "\x00\r")
    cleaned = " ".join(cleaned.split())
    if not cleaned:
        return None
    return cleaned[:maximum]


def _snippet(value: str | None, *, maximum: int) -> str | None:
    """Bound a single evidence excerpt for inline use in a question."""
    return _sanitize(value, maximum=maximum)


@dataclass(frozen=True)
class KnowledgeCheckDraft:
    """One deterministic, bounded knowledge check for an operator to review."""

    question: str
    options: tuple[str, ...]
    answer_index: int

    def as_dict(self) -> dict[str, object]:
        return {
            "question": self.question,
            "options": list(self.options),
            "answer_index": self.answer_index,
        }


def build_knowledge_check_draft(
    *,
    requested_action: str | None,
    lure_category: str | None,
    emotional_triggers: list[object] | None,
    training_explanation: str | None,
) -> KnowledgeCheckDraft:
    """Build one bounded knowledge check from approved campaign evidence.

    The question names the lure's requested action when the evidence provides
    one (bounded, sanitized), falling back to the lure category, then to a
    generic unexpected-message frame. The correct answer is always the safe
    independent-verification response at index 0; distractors mirror the
    generic quiz and never instruct a credential reply as the right choice.
    """
    action = _snippet(requested_action, maximum=_QUESTION_MAX)
    category = _snippet(lure_category, maximum=_QUESTION_MAX)
    if action is not None:
        question = f"An unexpected message asks you to {action}. What is the safest response?"
    elif category is not None:
        question = f"You receive an unexpected {category} request. What is the safest response?"
    else:
        question = "You receive an unexpected urgent message. What is the safest response?"
    question = question[:_QUESTION_MAX]

    options = [_SAFE_RESPONSE]
    urgency = _sanitize(
        _emotional_trigger(emotional_triggers, ("urgency", "urgent", "deadline", "expire")),
        maximum=_OPTION_MAX,
    )
    if urgency is not None and len(options) < _OPTIONS_MAX:
        options.append(f"Act immediately — {urgency}")
    elif len(options) < _OPTIONS_MAX:
        options.append(_GENERIC_URGENCY)
    if len(options) < _OPTIONS_MAX:
        options.append(_GENERIC_CREDENTIALS)
    options = options[:_OPTIONS_MAX]
    if len(options) < _OPTIONS_MIN:
        # Unreachable given the static distractors above, but fail closed in
        # case future edits shrink the set below the renderable minimum.
        raise RuntimeError("knowledge check draft options below renderable minimum")

    return KnowledgeCheckDraft(
        question=question,
        options=tuple(options),
        answer_index=0,
    )


def _emotional_trigger(triggers: list[object] | None, keywords: tuple[str, ...]) -> str | None:
    """Return the first bounded trigger matching any keyword, if any."""
    for trigger in triggers or []:
        if isinstance(trigger, str):
            lowered = trigger.casefold()
            if any(keyword in lowered for keyword in keywords):
                return trigger
    return None
