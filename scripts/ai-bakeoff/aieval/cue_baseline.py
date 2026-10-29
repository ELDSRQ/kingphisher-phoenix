"""Deterministic cue baseline + AI cue-validity scoring.

The W3-01 cue ontology (``kp_contracts.cue_ontology``) is the ground truth: the
cue manifest it extracts from a case's ``lure_source`` is what a faithful,
value-adding AI proposal should still make recognisable. This module measures
the AI the right way round — it extracts cues from the AI output with the SAME
deterministic extractor and compares them to the baseline, so the AI is scored
against the deterministic manifest, never the manifest against the AI.

Everything here is pure, offline, and free of randomness: identical input yields
an identical result.
"""

from __future__ import annotations

from dataclasses import dataclass

from kp_contracts.cue_ontology import build_cue_manifest, manifest_cue_labels

from aieval.eval_set import EvalCase


def ground_truth_manifest(case: EvalCase) -> dict[str, object]:
    """The deterministic cue + transformation manifest for a case's lure source."""

    return build_cue_manifest(
        subject=case.lure_source.subject,
        body=case.lure_source.body,
        source=f"eval:{case.id}",
    )


def ground_truth_cue_types(case: EvalCase) -> list[str]:
    """Sorted, de-duplicated ground-truth cue-type labels for a case."""

    return manifest_cue_labels(ground_truth_manifest(case))


@dataclass(frozen=True, slots=True)
class CueValidity:
    """How well an AI output preserves the baseline's recognisable cues."""

    coverage: float
    expected: tuple[str, ...]
    preserved: tuple[str, ...]
    missing: tuple[str, ...]

    def passed(self, minimum: float) -> bool:
        # An empty expectation (refusal/injection cases) is vacuously satisfied.
        if not self.expected:
            return True
        return self.coverage >= minimum


def cue_validity(expected_cue_types: list[str], subject: str, plain_text: str, safe_html: str) -> CueValidity:
    """Score cue coverage of an AI output against the baseline cue types.

    The AI output's own cues are extracted deterministically from its subject
    and bodies; coverage is the fraction of baseline cue types that survive.
    Cues the output introduces that the baseline did not have are intentionally
    NOT penalised here (realism scoring and the human reviewer judge additions);
    this dimension only asks whether the teaching cues were retained.
    """

    expected = sorted({label for label in expected_cue_types if label})
    body = f"{plain_text}\n{safe_html}"
    produced = set(manifest_cue_labels(build_cue_manifest(subject=subject, body=body, source="ai-output")))
    preserved = [label for label in expected if label in produced]
    missing = [label for label in expected if label not in produced]
    coverage = (len(preserved) / len(expected)) if expected else 1.0
    return CueValidity(
        coverage=coverage,
        expected=tuple(expected),
        preserved=tuple(preserved),
        missing=tuple(missing),
    )
