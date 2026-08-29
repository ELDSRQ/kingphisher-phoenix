"""Safe worker metrics and trace contexts.

Workers intentionally do not run another HTTP server.  Their aggregate metric
snapshots flow through the existing JSON logs for Azure Monitor ingestion.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog
from kp_telemetry.metrics import MetricDefinition, MetricRegistry

ROLES = frozenset(
    {"alert", "delivery", "directory", "generation", "ingestion", "mailbox", "other", "reminder", "retention"}
)
PROVIDERS = frozenset({"acs", "ai", "feed", "graph", "mailpit", "ntfy", "smtp", "webhook"})
OPERATIONS = frozenset({"fetch", "generate", "poll", "send"})
OUTCOMES = frozenset({"success", "error", "rejected", "indeterminate"})
QUEUE_STATES = frozenset({"ready", "processing", "delayed", "dead_letter"})
_TRACE_ID_RE = re.compile(r"[0-9a-f]{32}\Z")

metrics = MetricRegistry(
    (
        MetricDefinition(
            "kp_worker_role_ready",
            "Whether a worker role is currently ready.",
            "gauge",
            {"role": ROLES},
        ),
        MetricDefinition(
            "kp_worker_queue_jobs",
            "Queue jobs by role and lifecycle state.",
            "gauge",
            {"role": ROLES, "state": QUEUE_STATES},
        ),
        MetricDefinition(
            "kp_worker_queue_oldest_ready_age_seconds",
            "Age of the oldest ready job, or zero for an empty queue.",
            "gauge",
            {"role": ROLES},
        ),
        MetricDefinition(
            "kp_worker_jobs_total",
            "Claimed worker jobs by aggregate outcome.",
            "counter",
            {"role": ROLES, "outcome": OUTCOMES},
        ),
        MetricDefinition(
            "kp_worker_provider_operations_total",
            "External provider calls by provider, operation, and outcome.",
            "counter",
            {"provider": PROVIDERS, "operation": OPERATIONS, "outcome": OUTCOMES},
        ),
        MetricDefinition(
            "kp_worker_provider_latency_seconds_sum",
            "Cumulative external provider call latency in seconds.",
            "counter",
            {"provider": PROVIDERS, "operation": OPERATIONS},
        ),
        MetricDefinition(
            "kp_worker_provider_latency_seconds_count",
            "Count of external provider calls included in the latency sum.",
            "counter",
            {"provider": PROVIDERS, "operation": OPERATIONS},
        ),
    )
)


@contextmanager
def provider_call(provider: str, operation: str) -> Iterator[None]:
    """Measure a call using only predeclared, non-identifying dimensions."""
    start = time.perf_counter()
    outcome = "success"
    try:
        yield
    except Exception:
        outcome = "error"
        raise
    finally:
        duration = max(0.0, time.perf_counter() - start)
        metrics.increment(
            "kp_worker_provider_operations_total",
            provider=provider,
            operation=operation,
            outcome=outcome,
        )
        metrics.increment("kp_worker_provider_latency_seconds_sum", duration, provider=provider, operation=operation)
        metrics.increment("kp_worker_provider_latency_seconds_count", provider=provider, operation=operation)


@contextmanager
def job_trace(message: dict[str, Any]) -> Iterator[str]:
    """Bind a safe trace id for one claim without logging its payload."""
    candidate = message.get("trace_id")
    trace_id = candidate if isinstance(candidate, str) and _TRACE_ID_RE.fullmatch(candidate) else secrets.token_hex(16)
    context = structlog.contextvars.bind_contextvars(trace_id=trace_id)
    try:
        yield trace_id
    finally:
        structlog.contextvars.unbind_contextvars(*context)


def observe_queue(role: str, queue: object, topic: str) -> None:
    """Read the queue's aggregate observability contract when available."""
    role = metric_role(role)
    stats_method = getattr(queue, "queue_stats", None)
    if not callable(stats_method):
        return
    stats = stats_method(topic)
    for state in QUEUE_STATES:
        value = stats.get(state, 0)
        metrics.set_gauge("kp_worker_queue_jobs", float(value or 0), role=role, state=state)
    age = stats.get("oldest_ready_age_seconds")
    metrics.set_gauge("kp_worker_queue_oldest_ready_age_seconds", float(age or 0), role=role)


def metric_role(role: str) -> str:
    """Collapse extension/test role names into one bounded series."""
    return role if role in ROLES else "other"
