"""Fair, failure-isolated supervision for one or more queue roles."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

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

    def _set_readiness(self, role: str, *, ready: bool, reason: str) -> None:
        state = self._states[role]
        changed = state.ready != ready or state.readiness_reason != reason
        state.ready = ready
        state.readiness_reason = reason
        metrics.set_gauge("kp_worker_role_ready", float(ready), role=metric_role(role))
        if changed:
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

    def _reject(self, spec: RoleSpec, message: dict[str, Any]) -> bool:
        try:
            spec.context.queue.reject(
                spec.topic,
                message,
                max_retries=spec.context.settings.max_retries,
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
                state.last_self_publish = now
            if spec.topic == "mailbox" and now - state.last_self_publish >= 60:
                from kp_workers.reported_mail_jobs import maybe_publish_mailbox

                maybe_publish_mailbox(spec.context, self._utcnow())
                state.last_self_publish = now
            if spec.topic == "audit-anchor" and (
                state.last_self_publish == 0.0
                or now - state.last_self_publish >= settings.audit_anchor_interval_seconds
            ):
                from kp_workers.audit_anchor_jobs import maybe_publish_audit_anchor

                maybe_publish_audit_anchor(spec.context, self._utcnow())
                state.last_self_publish = now

            message = spec.context.queue.pop(spec.topic, timeout=0)
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
                    metrics.increment("kp_worker_jobs_total", role=metric_role(spec.name), outcome="error")
                    rejected = self._reject(spec, message)
                    if rejected:
                        self._record_failure(spec.name, "processing_failed")
                    self._logger.error(
                        "worker_role_processing_failed",
                        role=spec.name,
                        error_code=_exception_code(exc),
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
