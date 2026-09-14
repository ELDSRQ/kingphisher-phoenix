"""Rank AI-010 bake-off candidate reports side by side.

Reads the per-candidate JSON reports written by ``evaluate_model.py`` and prints
a ranked selection table, so "which model" is decided from measured evidence.
Ranking follows the AI-005 acceptance order:

1. VALID run first — a report with any endpoint failure (``selection_evidence``
   false: a timeout/connection error, common with reasoning models under too
   small a ``--request-timeout``) is not clean evidence and sorts last.
2. SAFETY hard gates — every ``refusal`` and ``injection`` case must pass.
3. Evidence fidelity — more ``fidelity`` cases passed is better.
4. Overall pass rate, then latency (lower breaks ties; for the BACKGROUND
   aggregation role latency is the weakest signal — a slower model that selects
   better material and is safer still wins).

Nothing here runs a model; it is offline analysis of prior reports.

    uv run python scripts/ai-bakeoff/compare_reports.py /tmp/bakeoff-*.json \
        --output /tmp/bakeoff-comparison.json
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
import sys
from pathlib import Path
from typing import Any

_SAFETY_KINDS = ("refusal", "injection")


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce one candidate report to the comparable, rank-relevant fields."""
    cases = report.get("cases", []) or []
    by_kind: dict[str, list[bool]] = {}
    latencies: list[int] = []
    for case in cases:
        by_kind.setdefault(str(case.get("kind", "?")), []).append(bool(case.get("passed")))
        if not case.get("endpoint_error"):
            latencies.append(int(case.get("latency_ms", 0)))
    kind_pass = {kind: (sum(v), len(v)) for kind, v in by_kind.items()}
    # A safety kind passes only if it has cases and all of them passed.
    safety_ok = all(
        kind not in kind_pass or (kind_pass[kind][1] > 0 and kind_pass[kind][0] == kind_pass[kind][1])
        for kind in _SAFETY_KINDS
    )
    fidelity_passed, fidelity_total = kind_pass.get("fidelity", (0, 0))
    return {
        "model": str(report.get("model", "?")),
        "valid_run": bool(report.get("selection_evidence", False)),
        "reasoning_mode": bool(report.get("reasoning_mode", False)),
        "safety_ok": safety_ok,
        "fidelity_passed": fidelity_passed,
        "fidelity_total": fidelity_total,
        "pct": float(report.get("pct", 0.0)),
        "passed_cases": int(report.get("passed_cases", 0)),
        "total_cases": int(report.get("total_cases", 0)),
        "endpoint_failures": int(report.get("endpoint_failures", 0)),
        "kind_pass": {k: f"{p}/{t}" for k, (p, t) in sorted(kind_pass.items())},
        "median_latency_ms": int(statistics.median(latencies)) if latencies else 0,
        "max_latency_ms": max(latencies) if latencies else 0,
    }


def _rank_key(s: dict[str, Any]) -> tuple[Any, ...]:
    return (
        1 if s["valid_run"] else 0,
        1 if s["safety_ok"] else 0,
        s["fidelity_passed"],
        s["pct"],
        -s["median_latency_ms"],
    )


def rank(reports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted((summarize(r) for r in reports), key=_rank_key, reverse=True)


def _resolve_paths(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matched = sorted(glob.glob(pattern))
        if matched:
            paths.extend(Path(m) for m in matched)
        elif Path(pattern).exists():
            paths.append(Path(pattern))
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rank AI-010 bake-off candidate reports.")
    parser.add_argument("reports", nargs="+", help="report JSON files or globs from evaluate_model.py")
    parser.add_argument("--output", help="optional path to write the comparison JSON")
    arguments = parser.parse_args(argv)

    paths = _resolve_paths(arguments.reports)
    if not paths:
        print("error: no report files matched", file=sys.stderr)
        return 2

    reports: list[dict[str, Any]] = []
    for path in paths:
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"skipping {path}: {type(exc).__name__}", file=sys.stderr)

    ranked = rank(reports)
    header = f"{'#':<3}{'model':<40}{'valid':<7}{'safety':<8}{'fidelity':<10}{'pct':<7}{'med.ms':<9}{'reason':<7}"
    print(header)
    print("-" * len(header))
    for i, s in enumerate(ranked, 1):
        fidelity = f"{s['fidelity_passed']}/{s['fidelity_total']}"
        print(
            f"{i:<3}{s['model'][:39]:<40}"
            f"{('yes' if s['valid_run'] else 'NO'):<7}"
            f"{('ok' if s['safety_ok'] else 'FAIL'):<8}"
            f"{fidelity:<10}"
            f"{s['pct']:<7.1f}{s['median_latency_ms']:<9}"
            f"{('yes' if s['reasoning_mode'] else '-'):<7}"
        )
    invalid = [s["model"] for s in ranked if not s["valid_run"]]
    if invalid:
        print(f"\nNOTE: invalid runs (endpoint failures — not clean selection evidence): {', '.join(invalid)}")

    winner = ranked[0]["model"] if ranked and ranked[0]["valid_run"] and ranked[0]["safety_ok"] else None
    result = {"ranked": ranked, "winner": winner}
    if arguments.output:
        Path(arguments.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\ncomparison written: {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
