#!/usr/bin/env python3
"""Score one candidate analyst model against the aggregation-quality set.

Usage:
    python scripts/ai-bakeoff/aggregate_evaluate.py \
        --endpoint http://127.0.0.1:8080/v1 --model <name> \
        --report /tmp/bakeoff-agg-<name>.json

The endpoint must be an OpenAI-compatible chat-completions API serving the
candidate with ``response_format: json_schema`` structured output (llama.cpp
GBNF grammars). This runner never downloads weights and performs no outbound
network access beyond the supplied endpoint.

Unlike ``evaluate_model.py`` (which scores GENERATION quality), this scores
AGGREGATION/ANALYSIS quality: given a batch of neutralized feed items, does the
model promote the OPTIMAL current campaign to rank 1? Scoring is deterministic —
the rank-1 candidate's ``source_item_ids`` must intersect the case's
``gold_item_ids``. No LLM judge, no fuzzy matching.

Exit 0 on completion (regardless of pass rate), 2 on usage/validation errors.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from kp_contracts.aggregation import AggregateResponse

_SCRIPT_ROOT = Path(__file__).resolve().parent

# The aggregation model is a REASONING analyst, so we do NOT send the
# from-first-token json_schema grammar (which would suppress reasoning). We ask
# for JSON in the prompt, then validate the result through AggregateResponse
# after the fact — the same re-validation the gateway performs.
_AGGREGATE_PROMPT = (
    "You are a threat-intelligence analyst selecting phishing-simulation material. "
    "Below are already-neutralized threat-feed items. Identify the OPTIMAL current "
    "campaign to simulate: the freshest, most actionable, highest-value material. "
    "Return a JSON object whose 'candidates' list ranks campaigns most valuable "
    "first. Each candidate MUST set 'rank' starting at 1, a 'score' in [0,1], a "
    "short 'title', an 'as_of' date, the 'source_item_ids' (the exact item_ids you "
    "based it on), a one-line 'rationale', and a 'record' with the lure facts "
    "(category, claimed_actor, target_sector, and an excerpt). Never invent a "
    "campaign absent from the items. Do not include a recipient, mailbox, or any "
    "real person.\n\nFeed items:\n"
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_cases(path: Path) -> tuple[str, list[dict[str, Any]]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("set_version") != "1.1":
        raise SystemExit(f"unsupported aggregation eval set (set_version must be 1.1): {path}")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise SystemExit(f"aggregation eval set has no cases: {path}")
    return data["set_version"], cases


def _score_case(result: dict[str, Any], gold: list[str]) -> bool:
    candidates = result.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        return False
    top = candidates[0]
    if not isinstance(top, dict):
        return False
    src = top.get("source_item_ids")
    if not isinstance(src, list):
        return False
    return bool(set(src) & set(gold))


def _evaluate_case(
    client: httpx.Client, endpoint: str, model: str, case: dict[str, Any], timeout: float
) -> dict[str, Any]:
    items = case["items"]
    prompt = _AGGREGATE_PROMPT + json.dumps(items, ensure_ascii=False, indent=2)
    body: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        # Production-faithful: the ai-gateway constrains aggregation with the
        # AggregateResponse json_schema grammar. Sending it here makes the eval
        # match production AND suppresses reasoning-mode models' thinking pass,
        # which is what lets both candidates emit clean JSON on equal terms.
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "aggregate_response",
                "schema": AggregateResponse.model_json_schema(),
            },
        },
    }
    started = time.monotonic()
    try:
        resp = client.post(
            f"{endpoint}/chat/completions",
            json=body,
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        content = payload["choices"][0]["message"].get("content") or ""
        usage = payload.get("usage") or {}
        completion_tokens = usage.get("completion_tokens")
        prompt_tokens = usage.get("prompt_tokens")
        latency_ms = int((time.monotonic() - started) * 1000)
    except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
        return {"passed": False, "endpoint_error": True, "detail": f"{type(exc).__name__}: {str(exc)[:160]}"}

    # Reasoning models may wrap the JSON; extract the first JSON object.
    parsed = _extract_json(content)
    if parsed is None:
        return {"passed": False, "endpoint_error": False, "detail": "no JSON object in response"}
    try:
        validated = AggregateResponse.model_validate(parsed)
    except Exception as exc:  # noqa: BLE001 - pydantic raises ValidationError
        return {"passed": False, "endpoint_error": False, "detail": f"schema invalid: {str(exc)[:160]}"}
    passed = _score_case(validated.model_dump(), case["gold_item_ids"])
    return {
        "passed": passed,
        "endpoint_error": False,
        "detail": "rank-1 sourced from gold items" if passed else "rank-1 not sourced from gold items",
        "latency_ms": latency_ms,
        "completion_tokens": completion_tokens,
        "prompt_tokens": prompt_tokens,
        "rank1_source_ids": validated.candidates[0].source_item_ids if validated.candidates else [],
    }


def _extract_json(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    if start == -1:
        return None
    # Find the matching close brace for the first object.
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--request-timeout", type=float, default=600.0)
    args = parser.parse_args()

    set_path = _SCRIPT_ROOT / "aggregation_evaluation_set.yaml"
    version, cases = _load_cases(set_path)

    report: dict[str, Any] = {
        "endpoint": args.endpoint,
        "model": args.model,
        "evaluated_at": datetime.now(UTC).isoformat(),
        "evaluation_set_digest": _digest(set_path),
        "evaluation_set_version": version,
        "request_timeout_seconds": args.request_timeout,
        "total_cases": len(cases),
    }

    with httpx.Client() as client:
        results = [_evaluate_case(client, args.endpoint, args.model, case, args.request_timeout) for case in cases]

    endpoint_failures = sum(1 for r in results if r.get("endpoint_error"))
    passed = sum(1 for r in results if r.get("passed"))
    report["cases"] = [{"id": case["id"], **result} for case, result in zip(cases, results, strict=True)]
    report["passed_cases"] = passed
    report["scored_cases"] = len(cases) - endpoint_failures
    report["endpoint_failures"] = endpoint_failures
    report["selection_evidence"] = endpoint_failures == 0
    report["pct"] = passed / len(cases) if cases else 0.0

    Path(args.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"aggregation bake-off complete: {passed}/{len(cases)} cases passed; report: {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
