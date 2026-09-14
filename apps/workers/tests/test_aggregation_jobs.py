"""M3: the background campaign-aggregation job.

These tests pin the properties that make the job safe:

* it is OFF by default (no ``ai_aggregate_model_id`` -> ``[]``, no socket);
* it fails CLOSED to "no candidates" on every failure (HTTP error, timeout,
  oversize/garbage body, off-contract response, model-pin mismatch) and NEVER
  raises out of the worker; and
* it uses the LONG ``aggregate_timeout_seconds`` background tier, NOT the <=60s
  chat cap ``provider_timeout_seconds``.

The httpx call is stubbed by monkeypatching ``httpx.stream`` with a fake
streaming ``httpx.Response`` — the same approach ``test_generation_pipeline``
uses for the ``/extract`` and ``/propose`` paths.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from kp_contracts.aggregation import AggregatedCampaign, AggregationSourceItem
from kp_workers import aggregation_jobs

# --- fixtures / builders -----------------------------------------------------


class _ChunkStream(httpx.SyncByteStream):
    def __init__(self, *chunks: bytes) -> None:
        self.chunks = chunks
        self.iterated = False

    def __iter__(self):
        self.iterated = True
        yield from self.chunks


def _streaming_response(*chunks: bytes, headers: list[tuple[bytes, bytes]] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        headers=headers,
        stream=_ChunkStream(*chunks),
        request=httpx.Request("POST", "https://ai.example/aggregate"),
    )


def _settings(
    model_id: str | None = "aggregate-model",
    *,
    aggregate_timeout_seconds: float = 1800.0,
) -> SimpleNamespace:
    """Only the attributes ``run_campaign_aggregation`` reads."""

    return SimpleNamespace(
        effective_ai_base_url="https://ai.example",
        ai_bearer_token="",
        ai_api_key="",
        ai_aggregate_model_id=model_id,
        aggregate_timeout_seconds=aggregate_timeout_seconds,
    )


def _ctx(**kwargs: Any) -> SimpleNamespace:
    return SimpleNamespace(settings=_settings(**kwargs))


def _source_item(item_id: str = "feed-1") -> AggregationSourceItem:
    return AggregationSourceItem(
        item_id=item_id,
        title="DocuSign invoice lure reported in the wild",
        excerpt="A finance-sector campaign spoofing DocuSign completed-document notices.",
        published_at="2026-09-10T00:00:00+00:00",
        source_reference="threat-feed://sample",
        claimed_actor="unattributed",
        claimed_target_sector="finance",
    )


def _record_dict(model_id: str = "extract-model") -> dict[str, Any]:
    return {
        "campaign_name": "DocuSign invoice lure",
        "claimed_brand": "DocuSign",
        "target_sector": "finance",
        "target_region": "",
        "lure_theme": "completed document",
        "reported_subjects": ["Completed: Invoice for review"],
        "sender_characteristics": "spoofs docusign-mail[.]com",
        "body_characteristics": "links to a credential portal",
        "call_to_action": "review the invoice",
        "delivery_method": "email",
        "evidence_excerpt": "DocuSign invoice lure targeting finance",
        "confidence": 0.8,
        "model_id": model_id,
    }


def _candidate_dict(rank: int = 1) -> dict[str, Any]:
    return {
        "rank": rank,
        "score": 0.91,
        "title": "DocuSign invoice lure",
        "as_of": "2026-09-10T00:00:00+00:00",
        "source_item_ids": ["feed-1"],
        "rationale": "Recent, high-volume, finance-targeting — a strong simulation candidate.",
        "record": _record_dict(),
    }


def _response_body(model_id: str = "aggregate-model", *, candidates: int = 2) -> bytes:
    return json.dumps(
        {
            "model_id": model_id,
            "candidates": [_candidate_dict(rank=i + 1) for i in range(candidates)],
        }
    ).encode()


def _boom_stream(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("aggregation must not open an HTTP connection here")


# --- (1) feature off ---------------------------------------------------------


def test_feature_off_returns_empty_without_any_http_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "stream", _boom_stream)
    ctx = _ctx(model_id=None)  # ai_aggregate_model_id unset -> disabled
    assert aggregation_jobs.run_campaign_aggregation(ctx, [_source_item()]) == []


# --- (2) empty items ---------------------------------------------------------


def test_empty_items_returns_empty_without_any_http_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "stream", _boom_stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), []) == []


# --- (3) happy path ----------------------------------------------------------


def test_happy_path_returns_parsed_validated_candidates(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    @contextmanager
    def stream(*args: object, **kwargs: object) -> Iterator[httpx.Response]:
        captured["args"] = args
        captured.update(kwargs)
        yield _streaming_response(_response_body("aggregate-model", candidates=2))

    monkeypatch.setattr(httpx, "stream", stream)
    candidates = aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()], max_candidates=3)

    assert len(candidates) == 2
    # Each is a real, validated contract object carrying a CampaignRecord.
    for candidate in candidates:
        assert isinstance(candidate, AggregatedCampaign)
        assert candidate.record.claimed_brand == "DocuSign"
    # It POSTed to the /aggregate endpoint (method, url are positional to stream).
    assert str(captured["args"][1]).endswith("/aggregate")


# --- (4) model-id mismatch ---------------------------------------------------


def test_model_id_mismatch_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def stream(*_args: object, **_kwargs: object) -> Iterator[httpx.Response]:
        # Gateway self-reports a different model than the pinned one.
        yield _streaming_response(_response_body("a-different-model"))

    monkeypatch.setattr(httpx, "stream", stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()]) == []


# --- (5) failure paths never raise -------------------------------------------


def test_backend_connect_error_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def stream(*_args: object, **_kwargs: object) -> Iterator[httpx.Response]:
        raise httpx.ConnectError("backend down")
        yield  # pragma: no cover

    monkeypatch.setattr(httpx, "stream", stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()]) == []


def test_backend_timeout_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def stream(*_args: object, **_kwargs: object) -> Iterator[httpx.Response]:
        raise httpx.ReadTimeout("aggregation ran too long")
        yield  # pragma: no cover

    monkeypatch.setattr(httpx, "stream", stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()]) == []


def test_garbage_body_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def stream(*_args: object, **_kwargs: object) -> Iterator[httpx.Response]:
        yield _streaming_response(b"this is not json{{{")

    monkeypatch.setattr(httpx, "stream", stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()]) == []


def test_off_contract_body_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def stream(*_args: object, **_kwargs: object) -> Iterator[httpx.Response]:
        # Valid JSON, but missing the required model_id -> contract validation fails.
        yield _streaming_response(json.dumps({"candidates": []}).encode())

    monkeypatch.setattr(httpx, "stream", stream)
    assert aggregation_jobs.run_campaign_aggregation(_ctx(), [_source_item()]) == []


# --- (6) the LONG timeout, not the <=60s chat cap ----------------------------


def test_uses_the_long_aggregate_timeout_that_can_exceed_sixty_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    @contextmanager
    def stream(*_args: object, **kwargs: object) -> Iterator[httpx.Response]:
        captured.update(kwargs)
        yield _streaming_response(_response_body())

    monkeypatch.setattr(httpx, "stream", stream)
    # A 1-hour background budget — far beyond provider_timeout_seconds' le=60 cap.
    ctx = _ctx(aggregate_timeout_seconds=3600.0)
    aggregation_jobs.run_campaign_aggregation(ctx, [_source_item()])

    assert captured["timeout"] == 3600.0
    assert captured["timeout"] > 60.0  # proves it is NOT the chat-latency cap
