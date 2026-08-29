"""The request and response schema for template generation.

The generation call is the one place where content derived from an external
threat feed leaves this system and reaches a language model. Two consequences
shape this module:

* Everything crossing the boundary is declared here, so what an operator's
  gateway receives is reviewable rather than implicit in a dict literal.
* Every free-text field is expected to have been through
  ``kp_sanitization.neutralize`` *before* it is placed here. A threat report is
  attacker-influenced text; sending it verbatim to a model is prompt injection
  with extra steps.

The response is deliberately narrow. A model proposes *content*; it never
proposes an approval, a recipient, a schedule, or a send.
"""

from __future__ import annotations

import math
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# The gateway receives a Jinja placeholder, never a configured awareness URL.
# Delivery resolves it only after a recipient-bound tracking bearer exists.
TRAINING_URL_PLACEHOLDER: Literal["{{ tracking.training_url }}"] = "{{ tracking.training_url }}"

# These are the same boundaries used by the operator's template preview/edit
# contract. ``model_id`` is additionally constrained by TemplateVersion's
# String(128) database column.
MAX_GENERATED_SUBJECT_CHARS = 998
MAX_GENERATED_BODY_CHARS = 200_000
MAX_GENERATED_MODEL_ID_CHARS = 128

# Outbound context is intentionally much smaller than generated content. It
# comes from an attacker-influenced feed and is both a prompt-injection and a
# provider-cost boundary. The worker truncates sanitized text to these limits;
# the contract independently rejects callers that bypass that assembler.
MAX_GENERATION_REQUEST_BYTES = 64 * 1024
MAX_PATTERN_ID_CHARS = 128
MAX_PATTERN_CONTEXT_FIELD_CHARS = 1_000
MAX_PATTERN_LIST_ITEMS = 12
MAX_PATTERN_LIST_ITEM_CHARS = 500
MAX_SOURCE_EXCERPTS = 5
MAX_SOURCE_EXCERPT_CHARS = 500
MAX_ATTACK_MAPPING_ITEMS = 32
MAX_ATTACK_COLLECTION_ITEMS = 20
MAX_ATTACK_MAPPING_KEY_CHARS = 64
MAX_ATTACK_MAPPING_STRING_CHARS = 500
MAX_ATTACK_MAPPING_DEPTH = 3
MAX_NEUTRALIZATION_REASONS = 20
MAX_NEUTRALIZATION_REASON_CHARS = 256

ContextText = Annotated[str, Field(max_length=MAX_PATTERN_CONTEXT_FIELD_CHARS)]
ContextListText = Annotated[str, Field(max_length=MAX_PATTERN_LIST_ITEM_CHARS)]
SourceExcerpt = Annotated[str, Field(max_length=MAX_SOURCE_EXCERPT_CHARS)]
NeutralizationReason = Annotated[str, Field(max_length=MAX_NEUTRALIZATION_REASON_CHARS)]


def _validate_attack_value(value: Any, *, depth: int = 0) -> Any:
    """Accept bounded JSON values only; reject objects and non-finite numbers."""

    if depth > MAX_ATTACK_MAPPING_DEPTH:
        raise ValueError("attack mapping exceeds maximum nesting depth")
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("attack mapping numbers must be finite")
        return value
    if isinstance(value, str):
        if len(value) > MAX_ATTACK_MAPPING_STRING_CHARS:
            raise ValueError("attack mapping text exceeds maximum length")
        return value
    if isinstance(value, list):
        if len(value) > MAX_ATTACK_COLLECTION_ITEMS:
            raise ValueError("attack mapping list exceeds maximum size")
        return [_validate_attack_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_ATTACK_MAPPING_ITEMS:
            raise ValueError("attack mapping object exceeds maximum size")
        bounded: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > MAX_ATTACK_MAPPING_KEY_CHARS:
                raise ValueError("attack mapping keys must be bounded non-empty strings")
            bounded[key] = _validate_attack_value(item, depth=depth + 1)
        return bounded
    raise ValueError("attack mapping values must be JSON scalars, lists, or objects")


class PatternContext(BaseModel):
    """Sanitized threat context describing the scenario to write about."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str = Field(min_length=1, max_length=MAX_PATTERN_ID_CHARS)
    lure_category: ContextText
    #: Free text, already neutralized. May be empty when the source omitted it.
    impersonation_category: ContextText = ""
    target_role_category: ContextText = ""
    requested_action: ContextText = ""
    delivery_method: ContextText = ""
    emotional_triggers: list[ContextListText] = Field(default_factory=list, max_length=MAX_PATTERN_LIST_ITEMS)
    warning_cues: list[ContextListText] = Field(default_factory=list, max_length=MAX_PATTERN_LIST_ITEMS)
    #: ATT&CK identifiers and difficulty, from the pattern enrichment (T-07).
    attack_mapping: dict[str, Any] = Field(default_factory=dict)
    confidence: ContextText = ""
    #: Short, neutralized excerpts from the originating report.
    source_excerpts: list[SourceExcerpt] = Field(default_factory=list, max_length=MAX_SOURCE_EXCERPTS)

    @field_validator("attack_mapping", mode="before")
    @classmethod
    def reject_non_string_attack_mapping_keys(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            raise ValueError("attack mapping must be an object")
        if any(not isinstance(key, str) for key in value):
            raise ValueError("attack mapping keys must be strings")
        return value

    @field_validator("attack_mapping")
    @classmethod
    def require_bounded_json_attack_mapping(cls, value: dict[str, Any]) -> dict[str, Any]:
        validated = _validate_attack_value(value)
        if not isinstance(validated, dict):  # pragma: no cover - field type guarantees this
            raise ValueError("attack mapping must be an object")
        return validated


class GenerationRequest(BaseModel):
    """What the platform sends to a generation gateway."""

    model_config = ConfigDict(extra="forbid")

    pattern: PatternContext
    #: When the threat context was assembled, so the model can judge freshness
    #: rather than assuming the scenario is current.
    as_of: str = Field(min_length=1, max_length=64)
    #: True when the neutralizer found something it had to strip or flag. The
    #: gateway should treat the context as lower-trust, and the platform records
    #: it on the resulting draft.
    context_untrusted: bool = False
    neutralization_reasons: list[NeutralizationReason] = Field(
        default_factory=list,
        max_length=MAX_NEUTRALIZATION_REASONS,
    )
    #: The exact template placeholder that must appear in generated content.
    #: It deliberately is not a navigable URL: the delivery worker binds it to
    #: the recipient's click -> training-assignment route at render time.
    training_url: Literal["{{ tracking.training_url }}"] = TRAINING_URL_PLACEHOLDER

    #: Advisory only. The platform re-validates every response with its own
    #: SafetyValidator and a human still approves; a gateway that ignores this
    #: cannot widen what the platform will accept.
    guidance: str = Field(
        default=(
            "Write awareness-training content only. It must be recognisable as a simulation, "
            "must not request credentials, and must include the supplied training placeholder "
            "exactly in both the plain-text and HTML bodies. Never replace it with a URL."
        ),
        max_length=512,
    )

    @model_validator(mode="after")
    def require_bounded_serialized_request(self) -> GenerationRequest:
        if len(self.model_dump_json().encode("utf-8")) > MAX_GENERATION_REQUEST_BYTES:
            raise ValueError("generation request exceeds maximum serialized size")
        return self


class GenerationResponse(BaseModel):
    """What a generation gateway returns.

    ``extra="forbid"`` is intentional: a gateway cannot smuggle additional
    fields (an approval flag, a recipient list) past the contract.
    """

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(max_length=MAX_GENERATED_SUBJECT_CHARS)
    plain_text: str = Field(max_length=MAX_GENERATED_BODY_CHARS)
    safe_html: str = Field(max_length=MAX_GENERATED_BODY_CHARS)
    model_id: str = Field(default="unknown", max_length=MAX_GENERATED_MODEL_ID_CHARS)

    @model_validator(mode="after")
    def require_recipient_bound_training_placeholder(self) -> GenerationResponse:
        """Reject drafts that cannot become recipient-bound training links."""

        if TRAINING_URL_PLACEHOLDER not in self.plain_text or TRAINING_URL_PLACEHOLDER not in self.safe_html:
            raise ValueError("generated bodies must contain the training URL placeholder")
        return self
