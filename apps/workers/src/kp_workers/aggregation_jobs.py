"""M3: the worker-side of the on-prem BACKGROUND threat-aggregation stage.

On-prem there is no public web search (``/discover`` is Azure-only). Instead a
LARGE local analyst model runs as a BACKGROUND job over the platform's own
already-ingested, neutralized threat-feed items and returns ranked, current
campaign candidates that a human reviews and promotes through the existing
governance path (activate -> approve -> generate). See
``kp_contracts.aggregation`` for the fixed request/response contract.

This module only FETCHES and VALIDATES candidates from the gateway; it does not
persist or send anything. The integrator wires scheduling and where candidates
go. Everything here is fail-closed to "no candidates": aggregation is advisory
enrichment, so it must NEVER crash the worker — every error path degrades to an
empty list plus a content-free log line, exactly like ``jobs.py``'s
``_maybe_extract_campaign_record``.

Two properties matter most, and both live in this file:

* BACKGROUND, not chat. The HTTP call uses ``aggregate_timeout_seconds`` (minutes
  to hours) — a deliberately separate axis from the <=60s chat cap
  ``provider_timeout_seconds``. See ``config.py`` for the WHY.
* Model-agnostic. The worker only knows the gateway URL; the large model lives
  behind the gateway, whose response ``model_id`` is soft-pinned constant-time
  against ``ai_aggregate_model_id``.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from typing import Any, Protocol

import httpx
from kp_contracts.aggregation import (
    AggregatedCampaign,
    AggregateRequest,
    AggregateResponse,
    AggregationSourceItem,
)
from kp_telemetry.logging import get_logger
from pydantic import ValidationError as PydanticValidationError

from kp_workers.observability import metrics

logger = get_logger("kp_workers.aggregation_jobs")

#: Bound the response body the worker will read from the gateway. Mirrors
#: ``jobs.py``'s ``_MAX_AI_RESPONSE_BYTES`` so a hostile or broken backend cannot
#: exhaust worker memory by streaming an unbounded body. Replicated locally
#: rather than imported because ``jobs.py`` is a heavyweight module (SQLAlchemy,
#: templating, sending) and this small job module — like ``directory_jobs`` and
#: ``reported_mail_jobs`` — deliberately avoids importing it.
_MAX_AI_RESPONSE_BYTES = 5 * 1024 * 1024


class AggregationContext(Protocol):
    """Structural view of what this job reads off a ``WorkerContext``.

    A ``Protocol`` (mirroring ``reported_mail_jobs.ReportedMailContext``) instead
    of importing the concrete ``jobs.WorkerContext`` keeps this module free of the
    heavyweight ``jobs`` import / any import cycle; the real ``WorkerContext``
    satisfies it structurally because it exposes ``.settings``.
    """

    settings: Any


class AIResponseError(ValueError):
    """Raised when the gateway's response is malformed, oversize, or unreadable.

    A ``ValueError`` subclass (matching ``jobs.AIResponseError``) so it is caught
    by the same broad, fail-closed ``except`` that swallows validation errors.
    Replicated locally for the reason described on ``_MAX_AI_RESPONSE_BYTES``.
    """


class _BoundedResponseLike(Protocol):
    """The subset of ``httpx.Response`` the bounded reader needs."""

    @property
    def headers(self) -> httpx.Headers: ...

    def iter_bytes(self) -> Iterator[bytes]: ...


def _provider_headers(bearer_token: str | None, api_key: str | None) -> dict[str, str]:
    """Auth headers for the hardened gateway.

    A byte-for-byte copy of ``jobs._provider_headers`` (a module-private helper);
    replicated locally instead of reaching into ``jobs`` so this slice touches no
    other file and pulls in no heavyweight import.
    """

    headers: dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def _bounded_ai_json(response: _BoundedResponseLike, *, max_bytes: int = _MAX_AI_RESPONSE_BYTES) -> Any:
    """Read and JSON-decode a gateway response body under a hard size ceiling.

    A faithful copy of ``jobs._bounded_ai_json``: it rejects a malformed or
    duplicated ``Content-Length`` up front, then counts bytes as it streams so a
    body that lies about (or omits) its length still cannot exceed ``max_bytes``.
    Errors are content-free (never echo provider bytes into a message/log).
    Replicated locally for the reason described on ``_MAX_AI_RESPONSE_BYTES``.
    """

    content_lengths = response.headers.get_list("content-length")
    if len(content_lengths) > 1:
        raise AIResponseError("AI response has duplicate Content-Length headers")
    if content_lengths:
        declared = content_lengths[0]
        if re.fullmatch(r"[0-9]+", declared) is None:
            raise AIResponseError("AI response Content-Length is malformed")
        if len(declared) > 19 or int(declared) > max_bytes:
            raise AIResponseError("AI response exceeds the maximum size")

    body = bytearray()
    for chunk in response.iter_bytes():
        if len(body) + len(chunk) > max_bytes:
            raise AIResponseError("AI response exceeds the maximum size")
        body.extend(chunk)
    try:
        return json.loads(body)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise AIResponseError("AI response is not valid JSON") from None


class _CountingResponse:
    """Count response bytes while delegating to the httpx response object.

    A faithful copy of ``jobs._CountingResponse``: ``_bounded_ai_json`` consumes
    the stream exactly once, and this wrapper tallies each chunk so response size
    can be exposed as a cost/status metric without a second read.
    """

    def __init__(self) -> None:
        self._response: httpx.Response | None = None
        self.bytes_read = 0

    def wrap(self, response: httpx.Response) -> None:
        self._response = response

    @property
    def headers(self) -> httpx.Headers:
        if self._response is None:
            raise AIResponseError("AI response is unavailable")
        return self._response.headers

    def iter_bytes(self) -> Iterator[bytes]:
        if self._response is None:
            raise AIResponseError("AI response is unavailable")
        for chunk in self._response.iter_bytes():
            self.bytes_read += len(chunk)
            yield chunk


@contextmanager
def _aggregate_provider_call() -> Iterator[None]:
    """Time the ``/aggregate`` call and emit provider metrics, best-effort.

    A local mirror of ``observability.provider_call("ai", "aggregate")``. WHY not
    the shared helper directly: ``observability.MetricRegistry`` only accepts
    label values declared UP FRONT, and its ``OPERATIONS`` set does not yet
    include ``"aggregate"`` (registering it belongs to the integrator's
    observability wiring — that module is outside this slice's write-allowlist).
    The shared ``provider_call`` would therefore raise ``ValueError`` from its
    metric emission; because this job fails closed to ``[]`` on ANY exception,
    that would SILENTLY discard a perfectly good aggregation pass. So we emit the
    same three metrics ourselves but swallow a declaration ``ValueError`` — metrics
    are observability, never control flow. Genuine work exceptions still propagate
    to the caller's fail-closed handler (we set ``outcome="error"`` on the way).
    Once the integrator declares ``"aggregate"`` these emissions light up as-is.
    """

    start = time.perf_counter()
    outcome = "success"
    try:
        yield
    except Exception:
        outcome = "error"
        raise
    finally:
        duration = max(0.0, time.perf_counter() - start)
        # "aggregate" not declared in observability.OPERATIONS yet; on a
        # declaration ValueError degrade to a no-op timing wrapper rather than
        # poisoning the result (see docstring). Once the integrator declares it,
        # these three emissions light up unchanged.
        with suppress(ValueError):
            metrics.increment(
                "kp_worker_provider_operations_total",
                provider="ai",
                operation="aggregate",
                outcome=outcome,
            )
            metrics.increment(
                "kp_worker_provider_latency_seconds_sum",
                duration,
                provider="ai",
                operation="aggregate",
            )
            metrics.increment(
                "kp_worker_provider_latency_seconds_count",
                provider="ai",
                operation="aggregate",
            )


def run_campaign_aggregation(
    ctx: AggregationContext,
    items: list[AggregationSourceItem],
    *,
    max_candidates: int = 5,
) -> list[AggregatedCampaign]:
    """Fetch ranked current-campaign candidates from the gateway ``/aggregate``.

    BACKGROUND job: POST a bounded batch of already-neutralized feed ``items`` to
    the gateway and return the validated, ranked candidates for a human to review.
    Fail-closed to ``[]`` on EVERY failure path (feature off, empty input, HTTP
    error, timeout, oversize/garbage body, off-contract response, or a model-pin
    mismatch) — aggregation is advisory enrichment and must never crash the worker.

    It does NOT persist or send anything: the integrator wires scheduling and
    routes these candidates into the existing governance path.
    """

    aggregate_model_id = ctx.settings.ai_aggregate_model_id
    # Feature off -> no-op. Return BEFORE building a request or opening a socket so
    # an unconfigured worker is byte-for-byte unchanged (no HTTP, no metrics).
    if not aggregate_model_id:
        return []
    # Nothing to analyze -> no-op. Also keeps us on the right side of the contract,
    # whose ``AggregateRequest.items`` requires at least one item.
    if not items:
        return []

    try:
        # Validate + serialize through the contract before a socket is opened, so a
        # caller that passed an oversize/off-contract batch fails here (caught
        # below) rather than at the gateway. ``mode="json"`` yields a plain JSON
        # payload for httpx.
        request_payload = AggregateRequest(items=items, max_candidates=max_candidates).model_dump(mode="json")
        counting = _CountingResponse()
        with (
            _aggregate_provider_call(),
            httpx.stream(
                "POST",
                f"{ctx.settings.effective_ai_base_url.rstrip('/')}/aggregate",
                json=request_payload,
                headers=_provider_headers(ctx.settings.ai_bearer_token, ctx.settings.ai_api_key),
                # The LONG background timeout, NOT the <=60s chat cap. This is the
                # whole point of the separate config axis (see config.py).
                timeout=ctx.settings.aggregate_timeout_seconds,
            ) as response,
        ):
            response.raise_for_status()
            counting.wrap(response)
            payload = _bounded_ai_json(counting)
        # Parse through the contract so a gateway cannot smuggle extra fields, and
        # so every candidate is a real ``AggregatedCampaign`` carrying a validated
        # ``CampaignRecord`` ready for the governance path.
        parsed = AggregateResponse.model_validate(payload)
    except (httpx.HTTPError, PydanticValidationError, AIResponseError, ValueError, TypeError) as exc:
        # Any failure degrades to "no candidates". Log the exception TYPE only —
        # never the provider body — mirroring _maybe_extract_campaign_record.
        logger.info("campaign aggregation unavailable (%s); returning no candidates", type(exc).__name__)
        return []

    # Best-effort, same reason as _aggregate_provider_call: the "aggregate"
    # operation label is not declared in observability yet, so this emission must
    # not be allowed to raise and crash a successful pass.
    with suppress(ValueError):
        metrics.increment(
            "kp_worker_ai_response_bytes_total",
            counting.bytes_read,
            provider="ai",
            operation="aggregate",
        )

    # SOFT model pin (AI-010 style): a mismatched analyst model is ignored, not
    # fatal — the candidates simply do not count as coming from the approved
    # model, so we drop them and log. Constant-time compare to avoid leaking the
    # pinned id through timing.
    if not secrets.compare_digest(aggregate_model_id, parsed.model_id):
        metrics.increment("kp_worker_ai_model_mismatch_total")
        logger.info("aggregate model id did not match the pin; returning no candidates")
        return []

    return parsed.candidates
