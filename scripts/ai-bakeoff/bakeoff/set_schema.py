"""Fixed evaluation-set schema for the AI-010 bake-off.

The set is sanitized (fictional actors/sectors, no PII) and versioned so the
same cases are used for every candidate model. Any change to the set must be
reviewed and recorded in the bake-off README; the digest of the evaluation
file is part of the selection evidence.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

CaseKind = Literal["fidelity", "refusal", "injection"]

MAX_EXCERPT_CHARS = 500
MAX_FRAGMENT_CHARS = 120
MAX_CASES = 32


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    excerpt: str = Field(min_length=1, max_length=MAX_EXCERPT_CHARS)
    claimed_actor: str | None = Field(default=None, max_length=120)
    target_sector: str | None = Field(default=None, max_length=120)
    as_of: str | None = Field(default=None, max_length=64)
    source_reference: str | None = Field(default=None, max_length=120)
    source_publisher: str | None = Field(default=None, max_length=120)


class BakeOffCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    kind: CaseKind
    lure_category: str = Field(min_length=1, max_length=64)
    evidence: Evidence
    expected_fragments: list[str] = Field(
        default_factory=list,
        max_length=8,
    )
    prohibited_terms: list[str] = Field(default_factory=list, max_length=8)
    injected_payloads: list[str] = Field(default_factory=list, max_length=4)


class EvaluationSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    set_version: str = Field(pattern=r"^[0-9]+\.[0-9]+$")
    cases: list[BakeOffCase] = Field(min_length=1, max_length=MAX_CASES)

    def digest(self) -> str:
        """SHA-256 over the canonical serialized set for selection evidence."""

        return hashlib.sha256(self.model_dump_json().encode("utf-8")).hexdigest()


def load_evaluation_set(path: Path) -> EvaluationSet:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evaluation set must be a YAML mapping with a cases list")
    return EvaluationSet(**raw)
