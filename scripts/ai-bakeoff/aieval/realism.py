"""Deterministic realism rubric scoring.

A proposal only earns its egress/cost if it is more realistic and teaching-rich
than the deterministic baseline. Realism is not fully decidable offline, so this
scorer checks only the bounded, unambiguous structural signals a convincing
awareness lure carries, in the same spirit as the bake-off's fidelity guard:

* the output has a subject line;
* it embeds the recipient-binding training placeholder in both bodies (so it can
  become a tracked training link at all);
* it carries a call-to-action (a link or button) rather than dead prose; and
* for a realistic lure it does NOT betray itself with a simulation disclaimer —
  the lesson lands after the click, not inside the email (refusal cases flip
  this expectation, because a refusal frames itself as a simulation on purpose).

Cue coverage is scored separately in ``cue_baseline`` and folded in by the
offline bake-off; it is passed in here so one realism verdict carries it.
Nothing here judges prose quality: a human reviewer still approves every draft.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from kp_contracts.generation import TRAINING_URL_PLACEHOLDER

from aieval.eval_set import RealismRubric

# A call-to-action in the HTML: an anchor, or a button-shaped element. Plain
# text counts a CTA when it carries the training placeholder as a visible link.
_HTML_CTA_RE = re.compile(r"<a\b[^>]*href=|<button\b", re.IGNORECASE)

# Simulation-disclaimer markers that would break the realism of a live-looking
# lure. Authored lowercase; matched against a casefolded body. These name the
# email AS a simulation/test/exercise — not the post-click training page.
_DISCLAIMER_MARKERS: tuple[str, ...] = (
    "this is a simulation",
    "this is a simulated",
    "this is a phishing simulation",
    "simulated phishing",
    "awareness simulation",
    "training exercise",
    "phishing test",
    "security awareness test",
    "this is only a test",
    "not a real email",
    "for training purposes",
    "this message is a test",
)


@dataclass(frozen=True, slots=True)
class RealismCheck:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RealismScore:
    checks: tuple[RealismCheck, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed_checks(self) -> tuple[str, ...]:
        return tuple(check.name for check in self.checks if not check.passed)


def _has_disclaimer(subject: str, plain_text: str, safe_html: str) -> str | None:
    blob = f"{subject}\n{plain_text}\n{safe_html}".casefold()
    for marker in _DISCLAIMER_MARKERS:
        if marker in blob:
            return marker
    return None


def score_realism(
    rubric: RealismRubric,
    *,
    subject: str,
    plain_text: str,
    safe_html: str,
    cue_coverage: float,
) -> RealismScore:
    """Score one output against a case's realism rubric. Pure and deterministic."""

    checks: list[RealismCheck] = []

    if rubric.require_subject:
        ok = bool(subject.strip())
        checks.append(RealismCheck("subject_present", ok, "subject present" if ok else "subject is empty"))

    if rubric.require_training_link:
        ok = TRAINING_URL_PLACEHOLDER in plain_text and TRAINING_URL_PLACEHOLDER in safe_html
        checks.append(
            RealismCheck(
                "training_link_present",
                ok,
                "training placeholder in both bodies" if ok else "training placeholder missing from a body",
            )
        )

    if rubric.require_cta:
        ok = bool(_HTML_CTA_RE.search(safe_html)) or TRAINING_URL_PLACEHOLDER in plain_text
        checks.append(RealismCheck("call_to_action", ok, "has a call-to-action" if ok else "no call-to-action found"))

    if rubric.forbid_simulation_disclaimer:
        marker = _has_disclaimer(subject, plain_text, safe_html)
        checks.append(
            RealismCheck(
                "no_simulation_disclaimer",
                marker is None,
                "no self-identifying disclaimer" if marker is None else f"simulation disclaimer leaked: {marker!r}",
            )
        )

    if rubric.min_cue_coverage > 0.0:
        ok = cue_coverage >= rubric.min_cue_coverage
        checks.append(
            RealismCheck(
                "cue_coverage",
                ok,
                f"cue coverage {cue_coverage:.2f} >= {rubric.min_cue_coverage:.2f}"
                if ok
                else f"cue coverage {cue_coverage:.2f} < required {rubric.min_cue_coverage:.2f}",
            )
        )

    return RealismScore(tuple(checks))
