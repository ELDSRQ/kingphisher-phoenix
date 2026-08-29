from __future__ import annotations

import pytest
import structlog
from kp_workers.observability import MetricRegistry, job_trace, metrics, observe_queue, provider_call


class _Queue:
    def queue_stats(self, topic: str) -> dict[str, int | float | None]:
        assert topic == "deliver"
        return {
            "ready": 3,
            "processing": 1,
            "delayed": 2,
            "dead_letter": 4,
            "oldest_ready_age_seconds": 17.5,
        }


def test_queue_observation_contains_only_aggregate_dimensions() -> None:
    observe_queue("delivery", _Queue(), "deliver")
    rendered = metrics.render_prometheus()

    assert 'kp_worker_queue_jobs{role="delivery",state="dead_letter"} 4' in rendered
    assert 'kp_worker_queue_oldest_ready_age_seconds{role="delivery"} 17.5' in rendered
    assert "deliver" not in rendered.replace('role="delivery"', "").replace("role and lifecycle", "")


def test_provider_observation_records_success_and_error_without_arguments() -> None:
    with provider_call("graph", "poll"):
        pass
    with pytest.raises(RuntimeError), provider_call("graph", "poll"):
        raise RuntimeError("alice@example.com and private MIME")

    rendered = metrics.render_prometheus()
    assert 'provider="graph"' in rendered
    assert 'outcome="success"' in rendered
    assert 'outcome="error"' in rendered
    assert "alice@example.com" not in rendered
    assert "private MIME" not in rendered


def test_job_trace_rejects_payload_correlation_as_trace_id() -> None:
    with job_trace({"trace_id": "recipient@example.com", "payload": {"mime": "secret"}}) as trace_id:
        context = structlog.contextvars.get_contextvars()
        assert context["trace_id"] == trace_id
        assert len(trace_id) == 32
        assert "@" not in trace_id

    assert "trace_id" not in structlog.contextvars.get_contextvars()


def test_observability_module_exports_registry_type_for_injection() -> None:
    assert isinstance(metrics, MetricRegistry)
