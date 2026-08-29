"""Small, dependency-free operational metrics with bounded dimensions.

The platform deliberately avoids a separate observability service. API
workers emit aggregate snapshots through the existing structured log pipeline.
The operator and public tracking APIs intentionally do not instantiate a
registry: their former process-local values had no consumer after the public
``/metrics`` routes were removed. ``render_prometheus`` remains an adapter for
a private worker exporter, not evidence that an application publishes a public
``/metrics`` route.

Metric names and label values must be declared up front.  This keeps cardinality
bounded and prevents recipient, mailbox, token, MIME, or provider-correlation
data from accidentally becoming a metric label.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Literal

MetricKind = Literal["counter", "gauge"]


@dataclass(frozen=True)
class MetricDefinition:
    name: str
    help: str
    kind: MetricKind
    labels: dict[str, frozenset[str]] = field(default_factory=dict)


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


class MetricRegistry:
    """Thread-safe registry whose complete series set is statically bounded."""

    def __init__(self, definitions: tuple[MetricDefinition, ...]) -> None:
        self._definitions = {definition.name: definition for definition in definitions}
        if len(self._definitions) != len(definitions):
            raise ValueError("metric names must be unique")
        self._values: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._lock = threading.Lock()

    def _key(self, name: str, labels: dict[str, str]) -> tuple[str, tuple[tuple[str, str], ...]]:
        try:
            definition = self._definitions[name]
        except KeyError as exc:
            raise ValueError(f"undeclared metric: {name}") from exc
        if set(labels) != set(definition.labels):
            raise ValueError(f"metric {name} requires labels {sorted(definition.labels)}")
        for label, value in labels.items():
            if value not in definition.labels[label]:
                raise ValueError(f"metric {name} rejects label {label}={value!r}")
        return name, tuple(sorted(labels.items()))

    def increment(self, name: str, value: float = 1.0, **labels: str) -> None:
        definition = self._definitions.get(name)
        if definition is None or definition.kind != "counter":
            raise ValueError(f"{name} is not a declared counter")
        if not math.isfinite(value) or value < 0:
            raise ValueError("counter increments must be finite and non-negative")
        key = self._key(name, labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def set_gauge(self, name: str, value: float, **labels: str) -> None:
        definition = self._definitions.get(name)
        if definition is None or definition.kind != "gauge":
            raise ValueError(f"{name} is not a declared gauge")
        if not math.isfinite(value):
            raise ValueError("gauge values must be finite")
        key = self._key(name, labels)
        with self._lock:
            self._values[key] = value

    def snapshot(self) -> dict[str, list[dict[str, object]]]:
        """Return only numeric aggregates and their predeclared dimensions."""
        result: dict[str, list[dict[str, object]]] = {}
        with self._lock:
            values = tuple(self._values.items())
        for (name, labels), value in values:
            result.setdefault(name, []).append({"labels": dict(labels), "value": value})
        return result

    def render_prometheus(self) -> str:
        lines: list[str] = []
        with self._lock:
            values = dict(self._values)
        for name in sorted(self._definitions):
            definition = self._definitions[name]
            lines.append(f"# HELP {name} {definition.help}")
            lines.append(f"# TYPE {name} {definition.kind}")
            for (metric_name, labels), value in sorted(values.items()):
                if metric_name != name:
                    continue
                rendered_labels = ""
                if labels:
                    pairs = ",".join(f'{key}="{_escape_label(label_value)}"' for key, label_value in labels)
                    rendered_labels = "{" + pairs + "}"
                lines.append(f"{name}{rendered_labels} {value:g}")
        return "\n".join(lines) + "\n"
