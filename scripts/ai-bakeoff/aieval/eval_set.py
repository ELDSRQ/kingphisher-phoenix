"""Versioned evaluation-set schema for the W3-04 AI evaluation harness.

The set is fictional, inert, and fixed. Each case carries, deterministically:

* a ``lure_source`` (subject + body) — the synthetic originating lure the
  deterministic cue extractor runs on to produce the ground-truth cue manifest;
* ``expected_cue_types`` — the cue-type labels that extractor must produce,
  recorded so a change to the ontology or the set is visible in review;
* ``expected_fragments`` — lure content that must survive into a safe output
  (fidelity), scored by the existing bake-off scorer;
* a ``realism_rubric`` — bounded, deterministic structural expectations; and
* ``cost_latency`` — the per-case latency and token budget a provider is held
  to.

The schema only *validates and bounds* the YAML. It never calls the cue
extractor itself (that is ``cue_baseline``), so loading is pure and has no
dependency on the ontology version; the ground-truth agreement is asserted by a
test. ``digest`` pins the canonical serialised set into every report so two
reports produced under different sets are never silently compared.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, model_validator

CaseKind = Literal["fidelity", "refusal", "injection"]

MAX_CASES = 32
MAX_FIELD_CHARS = 4000
MAX_FRAGMENT_CHARS = 120
MAX_LIST_ITEMS = 12


class LureSource(BaseModel):
    """The synthetic originating lure. Inert: no real PII, mailbox, or org."""

    model_config = ConfigDict(extra="forbid")

    subject: str = Field(min_length=1, max_length=MAX_FIELD_CHARS)
    body: str = Field(min_length=1, max_length=MAX_FIELD_CHARS)


class RealismRubric(BaseModel):
    """Deterministic, offline realism expectations for a case's safe output."""

    model_config = ConfigDict(extra="forbid")

    require_subject: bool = True
    require_training_link: bool = True
    require_cta: bool = True
    #: A realistic lure must NOT betray itself with a simulation disclaimer — the
    #: lesson is delivered after the click. Refusal cases flip this off because a
    #: refusal legitimately frames itself as a simulation.
    forbid_simulation_disclaimer: bool = True
    #: Minimum fraction of the ground-truth cues that must survive into the
    #: output. Zero for refusal/injection cases, where cue preservation is not
    #: the objective (safety is).
    min_cue_coverage: float = Field(default=0.6, ge=0.0, le=1.0)


class CostLatency(BaseModel):
    """Per-case latency and token budget a provider is measured against."""

    model_config = ConfigDict(extra="forbid")

    latency_ms_budget: int = Field(gt=0, le=3_600_000)
    max_total_tokens: int = Field(gt=0, le=1_000_000)


class EvalCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    kind: CaseKind
    lure_category: str = Field(min_length=1, max_length=64)
    lure_source: LureSource
    expected_cue_types: list[str] = Field(default_factory=list, max_length=64)
    expected_fragments: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    prohibited_terms: list[str] = Field(default_factory=list, max_length=MAX_LIST_ITEMS)
    injected_payloads: list[str] = Field(default_factory=list, max_length=4)
    realism_rubric: RealismRubric = Field(default_factory=RealismRubric)
    cost_latency: CostLatency

    @model_validator(mode="after")
    def _kind_fields_are_coherent(self) -> EvalCase:
        if self.kind == "refusal" and not self.prohibited_terms:
            raise ValueError(f"refusal case {self.id!r} must declare prohibited_terms")
        if self.kind == "injection" and not self.injected_payloads:
            raise ValueError(f"injection case {self.id!r} must declare injected_payloads")
        for fragment in self.expected_fragments:
            if len(fragment) > MAX_FRAGMENT_CHARS:
                raise ValueError(f"expected fragment too long in case {self.id!r}")
        return self


class EvaluationSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_version: str = Field(pattern=r"^[0-9]+\.[0-9]+$")
    cases: list[EvalCase] = Field(min_length=1, max_length=MAX_CASES)

    @model_validator(mode="after")
    def _ids_unique(self) -> EvaluationSet:
        ids = [case.id for case in self.cases]
        if len(set(ids)) != len(ids):
            raise ValueError("evaluation-set case ids must be unique")
        return self

    def digest(self) -> str:
        """SHA-256 over the canonical serialised set, recorded in every report."""

        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def default_set_path() -> Path:
    return Path(__file__).resolve().parent / "evaluation_set.yaml"


def load_evaluation_set(path: Path | None = None) -> EvaluationSet:
    source = path or default_set_path()
    raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evaluation set must be a YAML mapping with a cases list")
    return EvaluationSet(**raw)
