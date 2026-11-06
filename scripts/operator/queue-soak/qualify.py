#!/usr/bin/env python3
"""Bounded real-Redis overload evidence using synthetic jobs and private keys.

No provider handlers, application databases, live queue keys or cleanup commands
are used. Evidence and qualification Redis keys are retained for inspection.
This is component qualification, not a provider or full-stack capacity claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import redis
from kp_contracts.queue import CRITICAL_QUEUE_TOPICS, JobQueue, QueueOverflowError
from redis.backoff import NoBackoff
from redis.retry import Retry


def qualification_queue(redis_url: str, prefix: str, budget: int = 64) -> JobQueue:
    queue = JobQueue(redis_url, prefix=prefix, ready_depth_budget=budget)
    queue._client.close()
    queue._client = redis.Redis.from_url(
        redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2, retry=Retry(NoBackoff(), 0)
    )
    return queue


def validate_redis_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("qualification Redis URL is invalid") from None
    if parsed.scheme != "redis" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or port is None:
        raise ValueError("qualification requires an explicit loopback Redis port")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/0", "/15"}:
        raise ValueError("qualification Redis URL has unsupported options")
    return value


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    return sorted(values)[max(0, math.ceil(len(values) * quantile) - 1)]


def evaluate_observations(
    accepted: set[str], consumed: list[str], critical: dict[str, list[float]], *, max_latency: float
) -> list[str]:
    failures = []
    if not accepted:
        failures.append("no_noncritical_jobs_accepted")
    if len(consumed) != len(set(consumed)):
        failures.append("duplicate_noncritical_consumption")
    if accepted != set(consumed):
        failures.append("noncritical_job_accounting_mismatch")
    for topic in sorted(CRITICAL_QUEUE_TOPICS):
        samples = critical.get(topic, [])
        if not samples:
            failures.append(f"critical_topic_no_progress:{topic}")
        elif max(samples) > max_latency:
            failures.append(f"critical_topic_latency_exceeded:{topic}")
    return failures


def check_backpressure(queue: JobQueue, budget: int) -> dict[str, Any]:
    identifiers = [
        queue.publish("generate", {"synthetic": True}, idempotency_key=f"capacity-{i}") for i in range(budget)
    ]
    refused = False
    try:
        queue.publish("generate", {"synthetic": True}, idempotency_key="capacity-overflow")
    except QueueOverflowError:
        refused = True
    dedup_ok = queue.publish("generate", {"synthetic": True}, idempotency_key="capacity-0") == identifiers[0]
    critical_progress = {}
    for topic in sorted(CRITICAL_QUEUE_TOPICS):
        identifier = queue.publish(topic, {"synthetic": True})
        message = queue.pop(topic, timeout=0)
        critical_progress[topic] = message is not None and message["id"] == identifier
        if message is not None:
            queue.ack(topic, message)
    drained = []
    while (message := queue.pop("generate", timeout=0)) is not None:
        drained.append(message["id"])
        queue.ack("generate", message)
    return {
        "overflow_refused": refused,
        "idempotent_republish_at_capacity": dedup_ok,
        "critical_progress_while_full": critical_progress,
        "complete_drain": set(drained) == set(identifiers) and len(drained) == len(identifiers),
        "rejected_job_not_marked_published": not queue.job_published("generate", "capacity-overflow"),
    }


def check_handler_isolation(redis_url: str, prefix: str, max_latency: float) -> dict[str, Any]:
    # Only the supervisor control loop is real here. The callbacks are synthetic
    # and cannot call SMTP, cloud APIs, database services or provider handlers.
    from kp_workers.supervisor import RoleSpec, WorkerSupervisor

    queue = qualification_queue(redis_url, prefix=f"{prefix}deadline:")
    release = threading.Event()
    finished: list[str] = []
    settings = SimpleNamespace(
        visibility_seconds=5,
        effective_lease_seconds=5,
        effective_handler_deadline_seconds=0.05,
        lease_heartbeat_seconds=0.1,
        lease_max_renewals=100,
        queue_reconcile_enabled=False,
        max_retries=3,
        recovery_every_polls=100,
        poll_seconds=0.01,
    )
    context: Any = SimpleNamespace(settings=settings, queue=queue, audit_store=SimpleNamespace())

    def blocked(_context: Any, message: dict[str, Any]) -> None:
        if not release.wait(5):
            raise RuntimeError("qualification handler was not released")
        finished.append(message["id"])

    def delivery(_context: Any, message: dict[str, Any]) -> None:
        finished.append(message["id"])

    try:
        generation_id = queue.publish("generate", {"synthetic": True})
        delivery_id = queue.publish("deliver", {"synthetic": True})
        supervisor = WorkerSupervisor(
            {
                "generation": RoleSpec(name="generation", topic="generate", context=context, process=blocked),
                "delivery": RoleSpec(name="delivery", topic="deliver", context=context, process=delivery),
            }
        )
        started = time.monotonic()
        supervisor.run_cycle()
        elapsed = time.monotonic() - started
        readiness = supervisor.readiness()
        isolated = readiness["generation"] == {"ready": False, "reason": "handler_deadline_exceeded"}
        sibling_progress = delivery_id in finished and generation_id not in finished
        release.set()
        until = time.monotonic() + 5
        while queue.queue_stats("generate")["processing"] and time.monotonic() < until:
            supervisor.run_cycle()
            time.sleep(0.01)
        return {
            "overrun_role_isolated": isolated,
            "delivery_progress_during_overrun": sibling_progress,
            "sibling_completion_seconds": elapsed,
            "within_latency_budget": elapsed <= max_latency,
            "completed_jobs_acked_once": sorted(finished) == sorted([generation_id, delivery_id])
            and queue.queue_stats("generate")["processing"] == 0
            and queue.queue_stats("deliver")["processing"] == 0,
        }
    finally:
        release.set()
        queue.close()


def run_soak(
    redis_url: str, *, seconds: float, producers: int, consumers: int, budget: int, max_latency: float
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    prefix = f"kp:qualification:overload:{run_id}:"
    queue = qualification_queue(redis_url, prefix=prefix, budget=budget)
    queue._client.ping()
    stop = threading.Event()
    producer_done = threading.Event()
    lock = threading.Lock()
    accepted: set[str] = set()
    consumed: list[str] = []
    critical: dict[str, list[float]] = {topic: [] for topic in CRITICAL_QUEUE_TOPICS}
    failures: list[str] = []
    counters = {"refused": 0, "max_observed_ready": 0, "attempts": 0, "producers_exhausted_early": 0}
    attempt_limit = min(100_000, max(1000, math.ceil(seconds * 1000)))

    def producer(index: int) -> None:
        for sequence in range(attempt_limit):
            if stop.is_set():
                break
            try:
                identifier = queue.publish(
                    "generate", {"synthetic": True, "sequence": sequence}, idempotency_key=f"soak-{index}-{sequence}"
                )
                with lock:
                    accepted.add(identifier)
            except QueueOverflowError:
                with lock:
                    counters["refused"] += 1
                stop.wait(0.002)
            with lock:
                counters["attempts"] += 1
        else:
            if not stop.is_set():
                with lock:
                    counters["producers_exhausted_early"] += 1

    def consumer() -> None:
        while not producer_done.is_set() or queue.queue_stats("generate")["ready"]:
            message = queue.pop("generate", timeout=0)
            if message is None:
                stop.wait(0.002)
                continue
            queue.ack("generate", message)
            with lock:
                consumed.append(message["id"])

    def probe(topic: str) -> None:
        while not stop.is_set():
            started = time.monotonic()
            identifier = queue.publish(topic, {"synthetic": True})
            message = queue.pop(topic, timeout=0)
            if message is None or message["id"] != identifier:
                raise RuntimeError("critical probe lost its exact job")
            queue.ack(topic, message)
            with lock:
                critical[topic].append(time.monotonic() - started)
            stop.wait(0.1)

    started = time.monotonic()
    try:
        capacity = check_backpressure(queue, budget)
        handler = check_handler_isolation(redis_url, prefix, max_latency)
        with ThreadPoolExecutor(max_workers=producers + consumers + len(critical)) as executor:
            producer_futures = [executor.submit(producer, index) for index in range(producers)]
            consumer_futures = [executor.submit(consumer) for _ in range(consumers)]
            probe_futures = [executor.submit(probe, topic) for topic in sorted(critical)]
            try:
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    depth = int(queue.queue_stats("generate")["ready"] or 0)
                    counters["max_observed_ready"] = max(counters["max_observed_ready"], depth)
                    stop.wait(min(0.1, max(0, deadline - time.monotonic())))
            finally:
                stop.set()
                for future in producer_futures:
                    try:
                        future.result(timeout=15)
                    except Exception as exc:
                        failures.append(f"producer_failed:{type(exc).__name__}")
                producer_done.set()
            for future in consumer_futures + probe_futures:
                try:
                    future.result(timeout=15)
                except Exception as exc:
                    failures.append(f"consumer_or_probe_failed:{type(exc).__name__}")
        failures += evaluate_observations(accepted, consumed, critical, max_latency=max_latency)
        if counters["producers_exhausted_early"]:
            failures.append("producer_work_budget_exhausted_before_soak_finished")
        if not all(value for value in capacity.values() if isinstance(value, bool)) or not all(
            capacity["critical_progress_while_full"].values()
        ):
            failures.append("serial_capacity_or_dedup_check_failed")
        if not all(value for value in handler.values() if isinstance(value, bool)):
            failures.append("handler_deadline_isolation_failed")
        stats = {topic: queue.queue_stats(topic) for topic in ["generate", *sorted(critical)]}
        if any(row[key] for row in stats.values() for key in ["ready", "processing", "delayed", "dead_letter"]):
            failures.append("queue_not_drained")
        # Current admission checks allow a bounded race between LLEN and push.
        # Record that envelope explicitly; do not claim an atomic strict cap.
        if counters["max_observed_ready"] > budget + producers - 1:
            failures.append("ready_depth_exceeded_concurrent_admission_envelope")
        source_root = Path(__file__).resolve().parents[3]
        return {
            "schema": "kp.queue-soak.v1",
            "run_id": run_id,
            "namespace": prefix,
            "status": "passed" if not failures else "failed",
            "failures": failures,
            "scope": (
                "real Redis queue and supervisor control loop; synthetic handlers; "
                "no provider or application database qualification"
            ),
            "requested_soak_seconds": seconds,
            "elapsed_seconds": time.monotonic() - started,
            "producers": producers,
            "consumers": consumers,
            "ready_budget": budget,
            "concurrent_admission_envelope": budget + producers - 1,
            "attempt_limit_per_producer": attempt_limit,
            "max_critical_latency_seconds": max_latency,
            "accepted": len(accepted),
            "consumed": len(consumed),
            **counters,
            "critical": {
                topic: {
                    "count": len(values),
                    "max_seconds": max(values) if values else None,
                    "p95_seconds": percentile(values, 0.95),
                }
                for topic, values in critical.items()
            },
            "capacity": capacity,
            "handler_isolation": handler,
            "final_queue_stats": stats,
            "source_sha256": {
                name: hashlib.sha256((source_root / name).read_bytes()).hexdigest()
                for name in [
                    "packages/contracts/src/kp_contracts/queue.py",
                    "apps/workers/src/kp_workers/supervisor.py",
                    "scripts/operator/queue-soak/qualify.py",
                ]
            },
        }
    finally:
        stop.set()
        producer_done.set()
        queue.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--producers", type=int, default=4)
    parser.add_argument("--consumers", type=int, default=2)
    parser.add_argument("--ready-budget", type=int, default=64)
    parser.add_argument("--max-critical-latency", type=float, default=2)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not (
        math.isfinite(args.seconds)
        and 1 <= args.seconds <= 3600
        and 1 <= args.producers <= 16
        and 1 <= args.consumers <= 16
        and 1 <= args.ready_budget <= 1000
        and math.isfinite(args.max_critical_latency)
        and 0.05 <= args.max_critical_latency <= 30
    ):
        parser.error("qualification arguments exceed the bounded operating limits")
    try:
        redis_url = validate_redis_url(os.environ.get("KP_QUALIFICATION_REDIS_URL", ""))
    except ValueError as exc:
        parser.error(str(exc))
    os.environ["KP_DISABLE_DOTENV"] = "1"
    with args.output.open("x", encoding="utf-8") as handle:
        try:
            report = run_soak(
                redis_url,
                seconds=args.seconds,
                producers=args.producers,
                consumers=args.consumers,
                budget=args.ready_budget,
                max_latency=args.max_critical_latency,
            )
        except Exception as exc:
            report = {"schema": "kp.queue-soak.v1", "status": "failed", "failures": [type(exc).__name__]}
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print(json.dumps({"status": report["status"], "output": str(args.output)}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
