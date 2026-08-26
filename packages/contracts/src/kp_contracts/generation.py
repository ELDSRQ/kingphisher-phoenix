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

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PatternContext(BaseModel):
    """Sanitized threat context describing the scenario to write about."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    lure_category: str
    #: Free text, already neutralized. May be empty when the source omitted it.
    impersonation_category: str = ""
    target_role_category: str = ""
    requested_action: str = ""
    delivery_method: str = ""
    emotional_triggers: list[str] = Field(default_factory=list)
    warning_cues: list[str] = Field(default_factory=list)
    #: ATT&CK identifiers and difficulty, from the pattern enrichment (T-07).
    attack_mapping: dict[str, Any] = Field(default_factory=dict)
    confidence: str = ""
    #: Short, neutralized excerpts from the originating report.
    source_excerpts: list[str] = Field(default_factory=list)


class GenerationRequest(BaseModel):
    """What the platform sends to a generation gateway."""

    model_config = ConfigDict(extra="forbid")

    pattern: PatternContext
    #: When the threat context was assembled, so the model can judge freshness
    #: rather than assuming the scenario is current.
    as_of: str
    #: True when the neutralizer found something it had to strip or flag. The
    #: gateway should treat the context as lower-trust, and the platform records
    #: it on the resulting draft.
    context_untrusted: bool = False
    neutralization_reasons: list[str] = Field(default_factory=list)
    #: The training destination that must appear in generated content.
    training_url: str = ""

    #: Advisory only. The platform re-validates every response with its own
    #: SafetyValidator and a human still approves; a gateway that ignores this
    #: cannot widen what the platform will accept.
    guidance: str = (
        "Write awareness-training content only. It must be recognisable as a simulation, "
        "must not request credentials, and must link only to the supplied training URL."
    )


class GenerationResponse(BaseModel):
    """What a generation gateway returns.

    ``extra="forbid"`` is intentional: a gateway cannot smuggle additional
    fields (an approval flag, a recipient list) past the contract.
    """

    model_config = ConfigDict(extra="forbid")

    subject: str
    plain_text: str
    safe_html: str
    model_id: str = "unknown"
