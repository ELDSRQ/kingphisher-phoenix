"""Per-provider usage and circuit telemetry — counts, latency, tokens only.

This is the privacy spine of KP-AUD-012: a provider can be judged and, if
unsafe or low-value, disabled, from numbers alone. The recording API takes only
a provider id, an outcome, a latency, and token counts — there is deliberately
no parameter through which a prompt or completion, or any field derived from
one, could be passed, so raw request/response content is never logged here by
construction (see ``test_provider_telemetry``).

The provider label space is bounded to the known provider registry plus the
model-free baseline, so telemetry can be exported through the existing
``kp_telemetry`` metric registry without unbounded cardinality.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from kp_operator_api.ai_providers import PROVIDERS  # type: ignore[import-untyped]
from kp_telemetry.metrics import MetricDefinition, MetricRegistry

#: The model-free deterministic baseline is a first-class "provider" so it can
#: be compared head to head with the model-backed ones.
MODEL_FREE = "model_free"

#: Bounded provider label space: every registry preset plus the baseline.
ALLOWED_PROVIDERS: frozenset[str] = frozenset(PROVIDERS) | {MODEL_FREE}

Outcome = Literal["success", "failure", "refusal"]
_OUTCOMES: frozenset[str] = frozenset({"success", "failure", "refusal"})

CircuitState = Literal["closed", "open", "half_open"]

#: Documents the invariant for readers and tests: these are the ONLY things a
#: usage record may carry. No prompt, completion, subject, body, or evidence.
RECORDED_FIELDS: tuple[str, ...] = (
    "provider",
    "outcome",
    "latency_ms",
    "prompt_tokens",
    "completion_tokens",
)


@dataclass
class ProviderUsage:
    """Numeric aggregates for one provider. No content, ever."""

    requests: int = 0
    successes: int = 0
    failures: int = 0
    refusals: int = 0
    latency_ms_sum: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    consecutive_failures: int = 0
    circuit_opened_at: float | None = None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def mean_latency_ms(self) -> float:
        return (self.latency_ms_sum / self.requests) if self.requests else 0.0


@dataclass
class ProviderTelemetry:
    """Thread-unsafe, process-local per-provider usage and circuit tracker.

    ``failure_threshold`` consecutive failures open a provider's circuit; after
    ``cooldown_seconds`` it moves to half-open (one trial allowed), and a success
    or refusal closes it again. The clock is injectable so the breaker is tested
    deterministically with no real sleeping.
    """

    allowed_providers: frozenset[str] = ALLOWED_PROVIDERS
    failure_threshold: int = 3
    cooldown_seconds: float = 60.0
    clock: Callable[[], float] = time.monotonic
    _usage: dict[str, ProviderUsage] = field(default_factory=dict)

    def _bucket(self, provider: str) -> ProviderUsage:
        if provider not in self.allowed_providers:
            raise ValueError(f"unknown provider for telemetry: {provider!r}")
        return self._usage.setdefault(provider, ProviderUsage())

    def record(
        self,
        provider: str,
        outcome: Outcome,
        *,
        latency_ms: int,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> None:
        """Record one provider call's numeric result. Rejects content by shape."""

        if outcome not in _OUTCOMES:
            raise ValueError(f"unknown outcome: {outcome!r}")
        for name, value in (
            ("latency_ms", latency_ms),
            ("prompt_tokens", prompt_tokens),
            ("completion_tokens", completion_tokens),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an int")
            if value < 0 or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite non-negative integer")

        usage = self._bucket(provider)
        usage.requests += 1
        usage.latency_ms_sum += latency_ms
        usage.prompt_tokens += prompt_tokens
        usage.completion_tokens += completion_tokens
        if outcome == "failure":
            usage.failures += 1
            usage.consecutive_failures += 1
            if usage.consecutive_failures >= self.failure_threshold and usage.circuit_opened_at is None:
                usage.circuit_opened_at = self.clock()
        else:
            if outcome == "success":
                usage.successes += 1
            else:
                usage.refusals += 1
            usage.consecutive_failures = 0
            usage.circuit_opened_at = None

    def circuit_state(self, provider: str) -> CircuitState:
        usage = self._bucket(provider)
        if usage.circuit_opened_at is None:
            return "closed"
        if (self.clock() - usage.circuit_opened_at) >= self.cooldown_seconds:
            return "half_open"
        return "open"

    def snapshot(self) -> dict[str, dict[str, float | str]]:
        """Numeric aggregates only (plus the bounded circuit-state string)."""

        result: dict[str, dict[str, float | str]] = {}
        for provider, usage in sorted(self._usage.items()):
            result[provider] = {
                "requests": usage.requests,
                "successes": usage.successes,
                "failures": usage.failures,
                "refusals": usage.refusals,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
                "latency_ms_sum": usage.latency_ms_sum,
                "mean_latency_ms": usage.mean_latency_ms,
                "circuit_state": self.circuit_state(provider),
            }
        return result


def build_metric_registry(providers: frozenset[str] = ALLOWED_PROVIDERS) -> MetricRegistry:
    """A bounded ``kp_telemetry`` registry for exporting provider telemetry.

    Label cardinality is statically bounded: provider is one of the known set,
    outcome is one of three, token kind is prompt/completion. No content can
    become a label.
    """

    return MetricRegistry(
        (
            MetricDefinition(
                "ai_eval_provider_requests_total",
                "AI provider calls by provider and outcome.",
                "counter",
                {"provider": providers, "outcome": _OUTCOMES},
            ),
            MetricDefinition(
                "ai_eval_provider_latency_ms_sum",
                "Summed wall-clock latency (ms) of AI provider calls by provider.",
                "counter",
                {"provider": providers},
            ),
            MetricDefinition(
                "ai_eval_provider_tokens_total",
                "Token usage by provider and token kind.",
                "counter",
                {"provider": providers, "kind": frozenset({"prompt", "completion"})},
            ),
        )
    )


def export_metrics(registry: MetricRegistry, telemetry: ProviderTelemetry) -> None:
    """Push a telemetry snapshot into a metric registry (counts/latency/tokens only)."""

    for provider, usage in telemetry._usage.items():  # noqa: SLF001 - sibling module, numeric fields only
        for outcome, count in (("success", usage.successes), ("failure", usage.failures), ("refusal", usage.refusals)):
            if count:
                registry.increment("ai_eval_provider_requests_total", float(count), provider=provider, outcome=outcome)
        if usage.latency_ms_sum:
            registry.increment("ai_eval_provider_latency_ms_sum", float(usage.latency_ms_sum), provider=provider)
        if usage.prompt_tokens:
            registry.increment(
                "ai_eval_provider_tokens_total", float(usage.prompt_tokens), provider=provider, kind="prompt"
            )
        if usage.completion_tokens:
            registry.increment(
                "ai_eval_provider_tokens_total", float(usage.completion_tokens), provider=provider, kind="completion"
            )
