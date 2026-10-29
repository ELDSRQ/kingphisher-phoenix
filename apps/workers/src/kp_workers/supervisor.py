"""Fair, failure-isolated supervision for one or more queue roles."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from kp_contracts.queue import QUEUE_REPLAY_REVIEW_ONLY_TOPICS
from kp_telemetry.errors import SafetyRejectionError
from kp_telemetry.logging import get_logger

from kp_workers import jobs
from kp_workers.observability import job_trace, metric_role, metrics, observe_queue


class StopEvent(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float) -> bool: ...


@dataclass(frozen=True)
class RoleSpec:
    name: str
    topic: str
    process: Callable[[jobs.WorkerContext, dict[str, Any]], None]
    context: jobs.WorkerContext


@dataclass
class _RoleState:
    polls_since_recovery: int = 0
    last_self_publish: float = 0.0
    consecutive_errors: int = 0
    next_attempt_at: float = 0.0
    ready: bool = False
    readiness_reason: str = "starting"
    integration_required: bool = True
    recovery_required: bool = True
    proven_live: bool = False
    last_readiness_log: float = 0.0
    last_queue_reconcile: float = 0.0


def _exception_code(exc: Exception) -> str:
    """Classify failures without retaining attacker-controlled exception text or types."""
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, ConnectionError):
        return "connection"
    if isinstance(exc, OSError):
        return "io"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "invalid_data"
    return "unexpected"


def _is_first_party(exc: BaseException) -> bool:
    """Whether the failure comes from this codebase rather than a dependency."""

    return type(exc).__module__.startswith("kp_")


def _error_type(exc: BaseException) -> str:
    """Class name for first-party failures only.

    Exception classes raised here are authored by this project, so naming them
    is safe and is what makes a managed failure diagnosable. A third-party
    class name is never recorded: it can hint at internals and the instance
    usually carries caller-supplied text.
    """

    return type(exc).__name__ if _is_first_party(exc) else ""


def _error_detail(exc: BaseException, limit: int = 200) -> str:
    """Bounded text for first-party failures only.

    These messages are authored by this project — for example the Azure Blob
    status inside an anchor failure — so recording them is safe. Third-party
    exception text can echo attacker-controlled input (a recipient address, a
    parsed payload), so for those nothing at all is retained.
    """

    if not _is_first_party(exc):
        return ""
    return str(exc)[:limit]


class _LeaseHeartbeat:
    """Renew an in-flight claim's lease while its handler runs (KP-AUD-006).

    The supervisor processes a claimed message synchronously, so a background
    daemon thread renews the lease on a fixed interval. The renewal is fenced to
    the claim's owner (``JobQueue.renew_lease``), and the number of renewals is
    bounded: a wedged handler stops being renewed after ``max_renewals``, its
    lease then expires, and recovery can reclaim it — so heartbeating cannot keep
    a stuck job alive forever. A healthy handler that finishes within its lease
    is never recovered because the thread keeps the deadline ahead of ``now``.
    """

    def __init__(
        self,
        queue: Any,
        topic: str,
        message: dict[str, Any],
        *,
        interval: float,
        lease_seconds: float,
        max_renewals: int,
        logger: Any,
        role: str,
    ) -> None:
        self._queue = queue
        self._topic = topic
        self._message = message
        self._interval = interval
        self._lease_seconds = lease_seconds
        self._max_renewals = max_renewals
        self._logger = logger
        self._role = role
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> _LeaseHeartbeat:
        self._thread = threading.Thread(
            target=self._run,
            name=f"kp-lease-heartbeat-{self._role}",
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval + 5.0)

    def _run(self) -> None:
        renewals = 0
        while renewals < self._max_renewals and not self._stop.wait(self._interval):
            try:
                extended = self._queue.renew_lease(self._topic, self._message, lease_seconds=self._lease_seconds)
            except Exception:
                # A renewal failure must never crash the worker; the claim's
                # existing lease simply runs down toward normal recovery.
                self._logger.warning("worker_role_lease_renew_failed", role=self._role)
                return
            if not extended:
                # The claim is no longer ours (recovered/re-owned, or acked).
                return
            renewals += 1


class WorkerSupervisor:
    """Poll each enabled role once per round without cross-role starvation.

    Queue claims stay short-lived in the supervisor: each claimed message is
    processed and acknowledged or rejected before the next role is visited.
    A failing role receives its own bounded backoff while every other role
    continues to be polled. Stale leases are recovered at startup and on each
    role's configured cadence.
    """

    def __init__(
        self,
        roles: Mapping[str, RoleSpec],
        *,
        clock: Callable[[], float] = time.monotonic,
        utcnow: Callable[[], datetime] | None = None,
        logger: Any | None = None,
    ) -> None:
        if not roles:
            raise ValueError("at least one worker role must be enabled")
        self._roles = dict(roles)
        self._states = {name: _RoleState() for name in roles}
        self._clock = clock
        self._utcnow = utcnow or (lambda: datetime.now(UTC))
        self._logger = logger if logger is not None else get_logger("kp_workers.supervisor")
        self._initialized = False
        self._last_metrics_log = self._clock()

    @property
    def role_names(self) -> tuple[str, ...]:
        return tuple(self._roles)

    def readiness(self) -> dict[str, dict[str, str | bool]]:
        return {role: {"ready": state.ready, "reason": state.readiness_reason} for role, state in self._states.items()}

    #: Re-emit a role's readiness at least this often even when unchanged, so the
    #: health gate reads a fresh readiness signal per role rather than depending
    #: on a single on-change event surviving Log Analytics ingestion latency.
    _READINESS_HEARTBEAT_SECONDS = 30.0

    def _set_readiness(self, role: str, *, ready: bool, reason: str) -> None:
        state = self._states[role]
        changed = state.ready != ready or state.readiness_reason != reason
        state.ready = ready
        state.readiness_reason = reason
        metrics.set_gauge("kp_worker_role_ready", float(ready), role=metric_role(role))
        now = self._clock()
        if changed or (now - state.last_readiness_log) >= self._READINESS_HEARTBEAT_SECONDS:
            state.last_readiness_log = now
            self._logger.info("worker_role_readiness", role=role, ready=ready, reason=reason)

    def _recover(self, spec: RoleSpec) -> bool:
        settings = spec.context.settings
        try:
            recovered = spec.context.queue.recover_stale(
                spec.topic,
                visibility_seconds=settings.visibility_seconds,
                max_retries=settings.max_retries,
            )
        except Exception as exc:
            self._record_failure(spec.name, "lease_recovery_failed")
            self._logger.error(
                "worker_role_lease_recovery_failed",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return False
        if recovered:
            self._logger.warning("worker_role_leases_recovered", role=spec.name, recovered=recovered)
        self._states[spec.name].recovery_required = False
        return True

    def _prepare_integration(self, spec: RoleSpec) -> bool:
        try:
            if spec.topic == "directory":
                from kp_workers.directory_jobs import ensure_directory_state

                ensure_directory_state(spec.context)
            elif spec.topic == "mailbox":
                from kp_workers.reported_mail_jobs import ensure_reported_mail_state

                ensure_reported_mail_state(spec.context)
            elif spec.topic == "reply-mailbox":
                from kp_workers.reply_mail_jobs import ensure_reply_mail_state

                ensure_reply_mail_state(spec.context)
            elif spec.topic == "audit-anchor":
                from kp_workers.audit_anchor_jobs import ensure_audit_anchor_configured

                ensure_audit_anchor_configured(spec.context)
        except Exception as exc:
            self._record_failure(spec.name, "integration_state_unavailable")
            self._logger.error(
                "worker_role_integration_state_unavailable",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return False
        self._states[spec.name].integration_required = False
        return True

    def initialize(self) -> None:
        if self._initialized:
            return
        for spec in self._roles.values():
            if not self._prepare_integration(spec):
                continue
            if self._recover(spec):
                # A fresh start is the canonical post-Redis-restore moment: audit
                # dispatched outbox rows against the queue before serving.
                self._reconcile_queue_after_restore(spec)
                self._states[spec.name].last_queue_reconcile = self._clock()
                if spec.topic == "audit-anchor":
                    self._set_readiness(spec.name, ready=False, reason="configured_unproven")
                else:
                    self._set_readiness(spec.name, ready=True, reason="polling")
        self._initialized = True
        self._logger.info("worker_supervisor_started", roles=list(self._roles))

    def _record_failure(self, role: str, reason: str) -> None:
        state = self._states[role]
        state.consecutive_errors += 1
        state.next_attempt_at = self._clock() + jobs._retry_delay(state.consecutive_errors)
        self._set_readiness(role, ready=False, reason=reason)

    def _reconcile_outbox(self, spec: RoleSpec) -> bool:
        audit_store = spec.context.audit_store
        try:
            dispatch_audit = getattr(audit_store, "dispatch_pending_audit", None)
            dispatch_queue = getattr(audit_store, "dispatch_pending_queue", None)
            if dispatch_audit is not None:
                dispatch_audit()
            if dispatch_queue is not None:
                dispatch_queue(spec.context.queue)
        except Exception as exc:
            self._record_failure(spec.name, "outbox_unavailable")
            self._logger.error(
                "worker_role_outbox_unavailable",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return False
        return True

    def _lease_heartbeat(self, spec: RoleSpec, message: dict[str, Any]) -> Any:
        """Context manager that renews ``message``'s lease while a handler runs.

        A no-op context when heartbeating is disabled, unsupported by the queue,
        or the claim carries no owner (e.g. a fake/legacy envelope), so the
        synchronous processing path is unchanged in those cases.
        """
        settings = spec.context.settings
        interval = float(getattr(settings, "lease_heartbeat_seconds", 0.0))
        max_renewals = int(getattr(settings, "lease_max_renewals", 0))
        if (
            interval <= 0.0
            or max_renewals <= 0
            or not callable(getattr(spec.context.queue, "renew_lease", None))
            or not message.get("owner")
        ):
            return contextlib.nullcontext()
        return _LeaseHeartbeat(
            spec.context.queue,
            spec.topic,
            message,
            interval=interval,
            lease_seconds=float(getattr(settings, "effective_lease_seconds", settings.visibility_seconds)),
            max_renewals=max_renewals,
            logger=self._logger,
            role=spec.name,
        )

    def _reconcile_queue_after_restore(self, spec: RoleSpec) -> None:
        """Audit this role's dispatched outbox rows vs live queue (KP-AUD-007).

        Opt-in and best-effort: re-enqueues only replay-safe topics, surfaces
        delivery/reply for human review, and never raises into the poll loop.
        Skipped for the read-only audit-anchor role, which holds no queue intents.
        """
        settings = spec.context.settings
        if spec.topic == "audit-anchor" or not getattr(settings, "queue_reconcile_enabled", False):
            return
        reconcile = getattr(spec.context.audit_store, "reconcile_queue_after_restore", None)
        if not callable(reconcile):
            return
        replay_safe = spec.topic not in QUEUE_REPLAY_REVIEW_ONLY_TOPICS
        try:
            report = reconcile(
                spec.context.queue,
                topic=spec.topic,
                replay_safe=replay_safe,
                window_seconds=int(settings.queue_reconcile_window_hours) * 3600,
                limit=int(settings.queue_reconcile_limit),
            )
        except Exception as exc:
            self._logger.error(
                "worker_role_queue_reconcile_failed",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return
        if report.get("replayed") or report.get("review_required"):
            self._logger.warning(
                "worker_role_queue_reconciled",
                role=spec.name,
                replay_safe=replay_safe,
                checked=int(report.get("checked", 0)),
                replayed=int(report.get("replayed", 0)),
                review_required=int(report.get("review_required", 0)),
            )

    def _reject(self, spec: RoleSpec, message: dict[str, Any], *, max_retries: int | None = None) -> bool:
        try:
            spec.context.queue.reject(
                spec.topic,
                message,
                max_retries=spec.context.settings.max_retries if max_retries is None else max_retries,
            )
        except Exception as exc:
            self._record_failure(spec.name, "queue_reject_failed")
            self._logger.error(
                "worker_role_reject_failed",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return False
        return True

    def _poll_role(self, spec: RoleSpec) -> bool:
        state = self._states[spec.name]
        now = self._clock()
        if now < state.next_attempt_at:
            return False
        if state.integration_required and not self._prepare_integration(spec):
            return False
        if state.recovery_required and not self._recover(spec):
            return False
        # The audit anchor is intentionally read-only and must never dispatch
        # another role's audit or queue intents.
        if spec.topic != "audit-anchor" and not self._reconcile_outbox(spec):
            return False

        settings = spec.context.settings
        if getattr(settings, "queue_reconcile_enabled", False) and (
            state.last_queue_reconcile == 0.0
            or now - state.last_queue_reconcile >= settings.queue_reconcile_interval_seconds
        ):
            self._reconcile_queue_after_restore(spec)
            state.last_queue_reconcile = now
        try:
            if (
                spec.topic == "ingest"
                and callable(getattr(spec.context, "session_factory", None))
                and (
                    state.last_self_publish == 0.0
                    or now - state.last_self_publish >= jobs._SOURCE_INGESTION_SCHEDULE_INTERVAL_SECONDS
                )
            ):
                jobs.maybe_publish_source_ingestion(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "retention" and now - state.last_self_publish >= settings.retention_interval_seconds:
                jobs.maybe_publish_retention(spec.context, self._utcnow())
                # H10: piggy-back the weekly digest on the retention cadence. It
                # self-dedupes to one enqueue per ISO week via its idempotency
                # key, so running it at retention cadence is safe, and it is a
                # no-op unless the digest is enabled.
                from kp_workers.digest_jobs import maybe_publish_weekly_digest

                maybe_publish_weekly_digest(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "mailbox" and now - state.last_self_publish >= 60:
                from kp_workers.reported_mail_jobs import maybe_publish_mailbox

                maybe_publish_mailbox(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "reply-mailbox" and now - state.last_self_publish >= 60:
                from kp_workers.reply_mail_jobs import maybe_publish_reply_mailbox

                maybe_publish_reply_mailbox(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "curate" and now - state.last_self_publish >= settings.curation_interval_seconds:
                from kp_workers.curation_jobs import maybe_publish_curate

                maybe_publish_curate(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "audit-anchor" and (
                state.last_self_publish == 0.0
                or now - state.last_self_publish >= settings.audit_anchor_interval_seconds
            ):
                from kp_workers.audit_anchor_jobs import maybe_publish_audit_anchor

                maybe_publish_audit_anchor(spec.context, self._utcnow())
                state.last_self_publish = now

            message = spec.context.queue.pop(
                spec.topic,
                timeout=0,
                lease_seconds=getattr(settings, "effective_lease_seconds", settings.visibility_seconds),
            )
            observe_queue(spec.name, spec.context.queue, spec.topic)
            if message is None:
                state.polls_since_recovery += 1
                if state.polls_since_recovery >= settings.recovery_every_polls:
                    state.recovery_required = True
                    if not self._recover(spec):
                        return False
                    state.polls_since_recovery = 0
                state.consecutive_errors = 0
                state.next_attempt_at = 0.0
                if spec.topic == "audit-anchor" and not state.proven_live:
                    self._set_readiness(spec.name, ready=False, reason="configured_unproven")
                else:
                    reason = "live" if spec.topic == "audit-anchor" else "polling"
                    self._set_readiness(spec.name, ready=True, reason=reason)
                return False

            with job_trace(message):
                self._logger.info("worker_job_started", role=spec.name)
                try:
                    with self._lease_heartbeat(spec, message):
                        spec.process(spec.context, message)
                except SafetyRejectionError:
                    metrics.increment("kp_worker_jobs_total", role=metric_role(spec.name), outcome="rejected")
                    self._logger.warning("worker_role_safety_rejection", role=spec.name)
                    if not self._reject(spec, message):
                        return True
                    state.consecutive_errors = 0
                    state.next_attempt_at = 0.0
                    self._set_readiness(spec.name, ready=True, reason="polling")
                    return True
                except Exception as exc:
                    # A handler may mark an error non-retryable (retryable=False)
                    # when retrying cannot possibly succeed — e.g. an immutable
                    # audit-anchor key already holds different content, or a
                    # published anchor no longer matches the chain (AUD-003).
                    # Route those straight to the dead-letter queue and drop
                    # readiness rather than retrying an unwinnable job.
                    non_retryable = getattr(exc, "retryable", True) is False
                    metrics.increment(
                        "kp_worker_jobs_total",
                        role=metric_role(spec.name),
                        outcome="permanent_failure" if non_retryable else "error",
                    )
                    rejected = self._reject(spec, message, max_retries=1 if non_retryable else None)
                    if rejected and not non_retryable:
                        self._record_failure(spec.name, "processing_failed")
                    if non_retryable:
                        self._set_readiness(spec.name, ready=False, reason="integrity_failure")
                    log = self._logger.critical if non_retryable else self._logger.error
                    log(
                        "worker_role_processing_failed",
                        role=spec.name,
                        error_code=_exception_code(exc),
                        error_type=_error_type(exc),
                        error_detail=_error_detail(exc),
                        retryable=not non_retryable,
                    )
                    return True

                spec.context.queue.ack(spec.topic, message)
                metrics.increment("kp_worker_jobs_total", role=metric_role(spec.name), outcome="success")
                self._logger.info("worker_job_completed", role=spec.name)
                state.consecutive_errors = 0
                state.next_attempt_at = 0.0
                state.proven_live = state.proven_live or spec.topic == "audit-anchor"
                reason = "live" if spec.topic == "audit-anchor" else "polling"
                self._set_readiness(spec.name, ready=True, reason=reason)
                return True
        except Exception as exc:
            self._record_failure(spec.name, "queue_unavailable")
            self._logger.error(
                "worker_role_queue_unavailable",
                role=spec.name,
                error_code=_exception_code(exc),
            )
            return False

    def run_cycle(self) -> bool:
        """Run one fair round and return whether any role claimed work."""
        self.initialize()
        did_work = False
        for spec in self._roles.values():
            did_work = self._poll_role(spec) or did_work
        now = self._clock()
        if now - self._last_metrics_log >= 60.0:
            self._logger.info("worker_metrics_snapshot", metrics=metrics.snapshot())
            self._last_metrics_log = now
        return did_work

    def run(self, stop_event: StopEvent) -> None:
        self.initialize()
        while not stop_event.is_set():
            did_work = self.run_cycle()
            poll_wait = min(float(spec.context.settings.poll_seconds) for spec in self._roles.values())
            stop_event.wait(0.1 if did_work else poll_wait)
        self._logger.info("worker_supervisor_stopped", roles=list(self._roles), readiness=self.readiness())
