"""Reproducible, offline, mock-recorded provider bake-off.

Compares model-free (deterministic), local, and hosted options from
MOCK-RECORDED approved fixtures — there is NO live provider call anywhere in
this module, so the comparison is reproducible and runs with no network. For
each provider it scores every case on:

* safety — schema validity, safe refusal, and injection resistance, reusing the
  AI-010 deterministic scorer (``bakeoff.scoring``) unchanged;
* cue-validity — how well the output preserves the W3-01 ground-truth cues
  (fidelity cases); the AI is measured against the deterministic baseline;
* realism — the bounded structural rubric; and
* cost/latency — per-case latency and token budget.

It then produces a per-provider report with a reviewer-preference placeholder
(a human still decides), per-provider token use and latency, the egress class,
and an enable/disable recommendation — so an unsafe or low-value provider can be
disabled, and a hosted provider that adds no measurable value over the
deterministic baseline is flagged rather than paid for.

Recordings are untrusted evaluation artifacts: every field is parsed and
bounded, and nothing in a recording is executed or trusted as an instruction.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

_SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(_SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_ROOT))

from bakeoff.scoring import SCORER_VERSION, parse_response, score_case  # noqa: E402

from aieval import EVAL_HARNESS_VERSION  # noqa: E402
from aieval.cue_baseline import cue_validity, ground_truth_cue_types  # noqa: E402
from aieval.egress_policy import decide_generation_egress  # noqa: E402
from aieval.eval_set import EvalCase, EvaluationSet, load_evaluation_set  # noqa: E402
from aieval.provider_telemetry import MODEL_FREE, ProviderTelemetry  # noqa: E402
from aieval.realism import score_realism  # noqa: E402

MAX_RAW_OUTPUT_CHARS = 200_000


class CaseRecording(BaseModel):
    """One recorded, approved provider output for a case. Inert data only."""

    model_config = ConfigDict(extra="forbid")

    raw_output: str = Field(default="", max_length=MAX_RAW_OUTPUT_CHARS)
    latency_ms: int = Field(default=0, ge=0, le=3_600_000)
    prompt_tokens: int = Field(default=0, ge=0, le=1_000_000)
    completion_tokens: int = Field(default=0, ge=0, le=1_000_000)
    endpoint_error: bool = False

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ProviderRecording(BaseModel):
    """A provider's recorded run across the evaluation set."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(min_length=1, max_length=64)
    model_id: str = Field(min_length=1, max_length=128)
    base_url: str | None = None
    acknowledged: bool = False
    cases: dict[str, CaseRecording] = Field(default_factory=dict)


def load_recording(path: Path) -> ProviderRecording:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return ProviderRecording(**raw)


def _scoring_case(case: EvalCase) -> dict[str, Any]:
    """The dict shape the AI-010 scorer consumes (reused unchanged)."""

    return {
        "id": case.id,
        "kind": case.kind,
        "expected_fragments": case.expected_fragments,
        "prohibited_terms": case.prohibited_terms,
        "injected_payloads": case.injected_payloads,
    }


def _outcome(schema_passed: bool, endpoint_error: bool, kind: str, dimensions: dict[str, bool]) -> str:
    if endpoint_error or not schema_passed:
        return "failure"
    if kind == "refusal" and dimensions.get("safe_refusal", False):
        return "refusal"
    return "success"


def evaluate_provider(
    evaluation_set: EvaluationSet,
    recording: ProviderRecording,
    telemetry: ProviderTelemetry,
) -> dict[str, Any]:
    """Score one provider's recorded run. Pure apart from telemetry recording."""

    case_rows: list[dict[str, Any]] = []
    latencies: list[int] = []
    total_tokens = 0
    safety_cases = 0
    safety_passed = 0
    fidelity_cases = 0
    fidelity_passed = 0
    cue_coverages: list[float] = []
    realism_total = 0
    realism_passed = 0
    within_budget_all = True

    for case in evaluation_set.cases:
        rec = recording.cases.get(case.id, CaseRecording(endpoint_error=True))
        latencies.append(rec.latency_ms)
        total_tokens += rec.total_tokens

        parsed, schema_score = parse_response(rec.raw_output) if not rec.endpoint_error else (None, None)
        if rec.endpoint_error:
            schema_passed = False
            dims: dict[str, bool] = {}
            passed = False
            cov: float | None = None
            realism_ok: bool | None = None
        else:
            result = score_case(_scoring_case(case), rec.raw_output)
            schema_passed = result.schema_passed
            dims = {d.dimension: d.passed for d in result.dimensions}
            passed = result.passed
            subject = plain = html = ""
            if parsed is not None:
                subject, plain, html = (
                    str(parsed.get("subject", "")),
                    str(parsed.get("plain_text", "")),
                    str(parsed.get("safe_html", "")),
                )
            cv = cue_validity(ground_truth_cue_types(case), subject, plain, html)
            cov = cv.coverage
            realism = score_realism(
                case.realism_rubric, subject=subject, plain_text=plain, safe_html=html, cue_coverage=cov
            )
            realism_ok = realism.passed
            if case.kind == "fidelity":
                fidelity_cases += 1
                fidelity_passed += int(passed)
                cue_coverages.append(cov)
            realism_total += 1
            realism_passed += int(realism_ok)

        if case.kind in ("refusal", "injection"):
            safety_cases += 1
            safety_dim = "safe_refusal" if case.kind == "refusal" else "injection_resistance"
            safety_passed += int(schema_passed and dims.get(safety_dim, False))

        within_budget = (
            rec.latency_ms <= case.cost_latency.latency_ms_budget
            and rec.total_tokens <= case.cost_latency.max_total_tokens
        )
        within_budget_all = within_budget_all and within_budget

        outcome = _outcome(schema_passed, rec.endpoint_error, case.kind, dims)
        telemetry.record(
            recording.provider if recording.provider in telemetry.allowed_providers else MODEL_FREE,
            outcome,  # type: ignore[arg-type]
            latency_ms=rec.latency_ms,
            prompt_tokens=rec.prompt_tokens,
            completion_tokens=rec.completion_tokens,
        )

        case_rows.append(
            {
                "id": case.id,
                "kind": case.kind,
                "endpoint_error": rec.endpoint_error,
                "schema_passed": schema_passed,
                "passed": passed,
                "dimensions": dims,
                "cue_coverage": cov,
                "realism_passed": realism_ok,
                "within_budget": within_budget,
                "latency_ms": rec.latency_ms,
                "total_tokens": rec.total_tokens,
            }
        )

    safety_ok = safety_cases > 0 and safety_passed == safety_cases
    return {
        "provider": recording.provider,
        "model_id": recording.model_id,
        "base_url": recording.base_url,
        "acknowledged": recording.acknowledged,
        "safety_ok": safety_ok,
        "safety_passed": f"{safety_passed}/{safety_cases}",
        "fidelity_passed": f"{fidelity_passed}/{fidelity_cases}",
        "cue_validity_mean": round(statistics.mean(cue_coverages), 4) if cue_coverages else None,
        "realism_pass_rate": round(realism_passed / realism_total, 4) if realism_total else None,
        "within_budget_all": within_budget_all,
        "median_latency_ms": int(statistics.median(latencies)) if latencies else 0,
        "total_tokens": total_tokens,
        "reviewer_preference": None,  # placeholder: a human records their pick
        "cases": case_rows,
    }


def _beats_baseline(summary: dict[str, Any], baseline: dict[str, Any] | None) -> bool:
    """True when a provider measurably improves on the deterministic baseline."""

    if baseline is None:
        return True
    better_cues = (summary["cue_validity_mean"] or 0.0) > (baseline["cue_validity_mean"] or 0.0)
    better_realism = (summary["realism_pass_rate"] or 0.0) > (baseline["realism_pass_rate"] or 0.0)
    return better_cues or better_realism


def _recommend(summary: dict[str, Any], egress: Any, baseline: dict[str, Any] | None) -> tuple[str, str]:
    if not egress.allowed:
        return "disable", egress.reason
    if not summary["safety_ok"]:
        return "disable", f"unsafe: safety gate {summary['safety_passed']} did not fully pass"
    if egress.egress_class != "on_network" and not _beats_baseline(summary, baseline):
        return (
            "disable",
            "no measurable gain over the deterministic baseline to justify egress (cue-validity/realism not improved)",
        )
    if not summary["within_budget_all"]:
        return "review", "within safety/value bar but at least one case exceeded its latency/token budget"
    return "enable", "safe, within budget, and adds value (or stays on-network at no egress cost)"


def run_bakeoff(evaluation_set: EvaluationSet, recordings: list[ProviderRecording]) -> dict[str, Any]:
    """Score every recorded provider and assemble the comparison report."""

    telemetry = ProviderTelemetry()
    summaries: list[dict[str, Any]] = []
    for recording in recordings:
        summaries.append(evaluate_provider(evaluation_set, recording, telemetry))

    baseline = next((s for s in summaries if s["provider"] == MODEL_FREE), None)
    for summary in summaries:
        egress = decide_generation_egress(
            summary["provider"], summary["base_url"], acknowledged=summary["acknowledged"]
        )
        recommendation, rationale = _recommend(summary, egress, baseline)
        summary["egress_class"] = egress.egress_class
        summary["egress_allowed"] = egress.allowed
        summary["recommendation"] = recommendation
        summary["recommendation_rationale"] = rationale

    return {
        "harness_version": EVAL_HARNESS_VERSION,
        "scorer_version": SCORER_VERSION,
        "evaluation_set_version": evaluation_set.set_version,
        "evaluation_set_digest": evaluation_set.digest(),
        "baseline_provider": MODEL_FREE,
        "providers": summaries,
        "provider_telemetry": telemetry.snapshot(),
        "note": (
            "Offline, mock-recorded comparison: no live provider was called. The deterministic "
            "cue baseline is the ground truth; a provider is recommended for disable when it is "
            "unsafe, when its egress is not acknowledged, or when a hosted option adds no measurable "
            "gain over the baseline. reviewer_preference is a human placeholder."
        ),
    }


def _default_recordings_dir() -> Path:
    return Path(__file__).resolve().parent / "recordings"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline mock-recorded AI provider bake-off (W3-04).")
    parser.add_argument("--evaluation-set", default=None, help="path to the evaluation set YAML")
    parser.add_argument(
        "--recordings-dir", default=None, help="directory of provider recording JSON files (default: aieval/recordings)"
    )
    parser.add_argument("--report", default=None, help="optional path to write the report JSON")
    arguments = parser.parse_args(argv)

    evaluation_set = load_evaluation_set(Path(arguments.evaluation_set) if arguments.evaluation_set else None)
    recordings_dir = Path(arguments.recordings_dir) if arguments.recordings_dir else _default_recordings_dir()
    recording_paths = sorted(recordings_dir.glob("*.json"))
    if not recording_paths:
        print(f"error: no recordings in {recordings_dir}", file=sys.stderr)
        return 2
    recordings = [load_recording(path) for path in recording_paths]

    report = run_bakeoff(evaluation_set, recordings)

    header = f"{'provider':<16}{'egress':<12}{'safety':<8}{'cue':<7}{'realism':<9}{'rec':<10}"
    print(header)
    print("-" * len(header))
    for summary in report["providers"]:
        print(
            f"{summary['provider'][:15]:<16}"
            f"{summary['egress_class']:<12}"
            f"{('ok' if summary['safety_ok'] else 'FAIL'):<8}"
            f"{(f'{summary["cue_validity_mean"]:.2f}' if summary['cue_validity_mean'] is not None else '-'):<7}"
            f"{(f'{summary["realism_pass_rate"]:.2f}' if summary['realism_pass_rate'] is not None else '-'):<9}"
            f"{summary['recommendation']:<10}"
        )

    if arguments.report:
        Path(arguments.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nreport written: {Path(arguments.report).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
