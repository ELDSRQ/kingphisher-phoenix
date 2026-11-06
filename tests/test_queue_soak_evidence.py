"""Qualification cannot report success when jobs or critical progress are lost."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from kp_contracts.queue import CRITICAL_QUEUE_TOPICS

_SPEC = importlib.util.spec_from_file_location(
    "queue_soak_qualification", Path(__file__).resolve().parents[1] / "scripts/operator/queue-soak/qualify.py"
)
assert _SPEC is not None and _SPEC.loader is not None
qualification = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(qualification)


def test_complete_exact_accounting_and_critical_progress_pass() -> None:
    critical = {topic: [0.01, 0.02] for topic in CRITICAL_QUEUE_TOPICS}
    assert qualification.evaluate_observations({"one", "two"}, ["two", "one"], critical, max_latency=1) == []


@pytest.mark.parametrize("consumed", [["one"], ["one", "one", "two"], ["one", "two", "unpublished"]])
def test_missing_duplicate_and_unpublished_jobs_fail_qualification(consumed: list[str]) -> None:
    critical = {topic: [0.01] for topic in CRITICAL_QUEUE_TOPICS}
    assert qualification.evaluate_observations({"one", "two"}, consumed, critical, max_latency=1)


def test_every_critical_topic_must_make_progress_within_the_selected_limit() -> None:
    critical = {"deliver": [0.01], "retention": [2]}
    failures = qualification.evaluate_observations({"one"}, ["one"], critical, max_latency=1)
    assert "critical_topic_no_progress:audit-anchor" in failures
    assert "critical_topic_latency_exceeded:retention" in failures


@pytest.mark.parametrize(
    "url", ["", "redis://example.com:6379/0", "redis://127.0.0.1/0", "redis://127.0.0.1:6379/0?x=1"]
)
def test_qualification_requires_an_explicit_loopback_endpoint(url: str) -> None:
    with pytest.raises(ValueError):
        qualification.validate_redis_url(url)


def test_only_private_qualification_keys_are_constructed() -> None:
    queue = qualification.qualification_queue("redis://127.0.0.1:1/0", "kp:qualification:overload:test:")
    try:
        assert queue._topic("deliver").startswith("kp:qualification:overload:test:")
        assert not queue._topic("deliver").startswith("kp:queue:")
        assert queue._client.connection_pool.connection_kwargs["socket_timeout"] == 2
    finally:
        queue.close()
