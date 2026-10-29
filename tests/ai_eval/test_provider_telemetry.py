from __future__ import annotations

import inspect

import pytest
from aieval.provider_telemetry import (
    MODEL_FREE,
    RECORDED_FIELDS,
    ProviderTelemetry,
    build_metric_registry,
    export_metrics,
)


def test_records_only_numeric_fields_no_content_parameter() -> None:
    """The recording API must have no parameter through which prompt or
    completion content could be passed — the privacy guarantee is structural."""

    params = set(inspect.signature(ProviderTelemetry.record).parameters) - {"self"}
    assert params == {"provider", "outcome", "latency_ms", "prompt_tokens", "completion_tokens"}
    assert set(RECORDED_FIELDS) == params
    for name in ("prompt", "completion", "subject", "body", "content", "text", "evidence"):
        assert name not in params


def test_rejects_unknown_provider_and_outcome() -> None:
    telemetry = ProviderTelemetry()
    with pytest.raises(ValueError):
        telemetry.record("not-a-provider", "success", latency_ms=1)
    with pytest.raises(ValueError):
        telemetry.record(MODEL_FREE, "bogus", latency_ms=1)  # type: ignore[arg-type]


def test_rejects_non_integer_or_negative_counts() -> None:
    telemetry = ProviderTelemetry()
    with pytest.raises(TypeError):
        telemetry.record(MODEL_FREE, "success", latency_ms="12")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        telemetry.record(MODEL_FREE, "success", latency_ms=True)  # bool is not an int here
    with pytest.raises(ValueError):
        telemetry.record(MODEL_FREE, "success", latency_ms=-1)


def test_snapshot_is_numeric_aggregates_only() -> None:
    telemetry = ProviderTelemetry()
    telemetry.record("local", "success", latency_ms=100, prompt_tokens=10, completion_tokens=5)
    telemetry.record("local", "refusal", latency_ms=200, prompt_tokens=8, completion_tokens=0)
    snap = telemetry.snapshot()["local"]
    assert snap["requests"] == 2
    assert snap["successes"] == 1
    assert snap["refusals"] == 1
    assert snap["total_tokens"] == 23
    assert snap["mean_latency_ms"] == 150.0
    assert snap["circuit_state"] == "closed"
    # Everything in the snapshot is a number or a bounded state string.
    for key, value in snap.items():
        assert isinstance(value, (int, float)) or key == "circuit_state"


def test_circuit_opens_after_threshold_then_half_opens_after_cooldown() -> None:
    clock = {"t": 0.0}
    telemetry = ProviderTelemetry(failure_threshold=3, cooldown_seconds=60.0, clock=lambda: clock["t"])
    for _ in range(2):
        telemetry.record("openai", "failure", latency_ms=5000)
    assert telemetry.circuit_state("openai") == "closed"
    telemetry.record("openai", "failure", latency_ms=5000)  # third consecutive failure opens it
    assert telemetry.circuit_state("openai") == "open"
    clock["t"] = 61.0
    assert telemetry.circuit_state("openai") == "half_open"
    telemetry.record("openai", "success", latency_ms=800)  # a success closes it
    assert telemetry.circuit_state("openai") == "closed"


def test_metric_export_is_bounded_and_rejects_unknown_labels() -> None:
    telemetry = ProviderTelemetry()
    telemetry.record("local", "success", latency_ms=100, prompt_tokens=10, completion_tokens=5)
    registry = build_metric_registry()
    export_metrics(registry, telemetry)
    snapshot = registry.snapshot()
    assert "ai_eval_provider_requests_total" in snapshot
    assert "ai_eval_provider_tokens_total" in snapshot
    with pytest.raises(ValueError):
        registry.increment("ai_eval_provider_requests_total", provider="mystery", outcome="success")
