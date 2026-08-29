from __future__ import annotations

import pytest
from kp_telemetry.metrics import MetricDefinition, MetricRegistry


def test_registry_exposes_only_predeclared_bounded_series() -> None:
    registry = MetricRegistry(
        (
            MetricDefinition(
                "kp_test_operations_total",
                "Test operations.",
                "counter",
                {"outcome": frozenset({"success", "error"})},
            ),
        )
    )
    registry.increment("kp_test_operations_total", outcome="success")

    rendered = registry.render_prometheus()

    assert "# TYPE kp_test_operations_total counter" in rendered
    assert 'kp_test_operations_total{outcome="success"} 1' in rendered
    assert "@" not in rendered


def test_registry_rejects_undeclared_or_sensitive_dimensions() -> None:
    registry = MetricRegistry(
        (
            MetricDefinition(
                "kp_test_ready",
                "Test readiness.",
                "gauge",
                {"dependency": frozenset({"database"})},
            ),
        )
    )

    with pytest.raises(ValueError, match="rejects label"):
        registry.set_gauge("kp_test_ready", 1, dependency="alice@example.com")
    with pytest.raises(ValueError, match="requires labels"):
        registry.set_gauge("kp_test_ready", 1, dependency="database", mailbox="alice@example.com")
