"""Narrow GitHub Actions orchestration for the reviewed Azure workflow.

The browser never supplies a command, path, repository, ref, workflow name, or
credential.  It can only review the fixed workflow inputs declared here and ask
the server to dispatch the checked-in ``azure-deploy.yml`` workflow.  GitHub's
protected environment remains the final approval boundary.

This module is the deployment facade: constants, exceptions, public error
guidance, and the two frozen value types live in
kp_operator_api.deployment_common; the GitHub workflow connector lives in
kp_operator_api.github_workflow_gateway.  This facade re-exports every name so
route handlers and operator tests that reference
kp_operator_api.deployment_orchestration.X keep resolving exactly as before
the split.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import redis

from kp_operator_api.deployment_common import (
    _ACS_STAGE_RESULT_BY_STAGE,
    _ACS_STATUS_VALUES,
    _CHECKPOINT_EVIDENCE_FIELDS,
    _CHECKPOINT_REASONS,
    _CIPHERTEXT_KEY_ID,
    _COMMON_RECOVERY_STEPS,
    _DIGEST,
    _FOUNDATION_BOOTSTRAP_RECOVERY_STEPS,
    _FOUNDATION_FINALIZE_RECOVERY_STEPS,
    _NEXT_ACTIONS,
    _NEXT_DEPLOYMENT_STAGE,
    _PLAN_ID,
    _PUBLIC_PLAN_ERRORS,
    _SENSITIVE_DEPLOYMENT_VALUE,
    _TERMINAL_RESULTS,
    _VERSIONLESS_KEY_VAULT_SECRET_ID,
    _WORKLOAD_RECOVERY_STEPS,
    ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS,
    ACS_EVIDENCE_ARTIFACT_PATH,
    ACS_EVIDENCE_ARTIFACT_SCHEMA,
    ACTIVE_TTL_SECONDS,
    CHECKPOINT_RESERVE_PER_ATTEMPT,
    CORRELATION_PREFIX,
    DEPLOYMENT_CONFIG_KEYS,
    DEPLOYMENT_STAGES,
    EXPECTED_WORKFLOW_SHA256,
    INTERNAL_ACS_CONFIG_DEFAULTS,
    MAX_ACS_ARTIFACT_BYTES,
    MAX_ACS_EVIDENCE_AGE_SECONDS,
    MAX_ACS_EVIDENCE_BYTES,
    MAX_ACTIVITY,
    MAX_BASELINE_RUNS,
    MAX_CHECKPOINTS,
    MAX_DEPLOYMENT_ATTEMPTS,
    MAX_DEPLOYMENT_CONFIG_BYTES,
    MAX_GITHUB_ACTIVITY_BYTES,
    MAX_GITHUB_METADATA_BYTES,
    MAX_GITHUB_STATUS_BYTES,
    MAX_PLAN_BYTES,
    MAX_RUN_PAGES,
    MAX_STEPS_PER_JOB,
    MAX_WORKFLOW_BYTES,
    OPERATION_TTL_SECONDS,
    PLAN_TTL_SECONDS,
    PRESERVATION_REQUIRED_ASSETS,
    PROHIBITED_AUTOMATIC_ACTIONS,
    PUBLIC_DEPLOYMENT_CONFLICT,
    PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE,
    PUBLIC_DEPLOYMENT_UNAVAILABLE,
    RECOVERY_EVIDENCE_REQUIREMENTS,
    REQUIRED_WORKFLOW_INPUTS,
    RUNS_PER_PAGE,
    WORKFLOW_FILE,
    WORKFLOW_PATH,
    DeploymentConflict,
    DeploymentUnavailable,
    DispatchIndeterminate,
    DispatchRejected,
    WorkflowConfiguration,
    WorkflowPreflight,
    public_deployment_error,
)
from kp_operator_api.github_workflow_gateway import GitHubWorkflowGateway

# Re-export surface of the deployment facade. Tests and console routes reference
# kp_operator_api.deployment_orchestration.<name>; __all__ marks every name that
# must keep resolving here (constants, exceptions, shared types, gateway) as an
# intentional re-export for ruff (F401), even when the orchestrator's own code
# does not use them directly.
__all__ = [
    "ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS",
    "ACS_EVIDENCE_ARTIFACT_PATH",
    "ACS_EVIDENCE_ARTIFACT_SCHEMA",
    "ACTIVE_TTL_SECONDS",
    "CHECKPOINT_RESERVE_PER_ATTEMPT",
    "CORRELATION_PREFIX",
    "DEPLOYMENT_CONFIG_KEYS",
    "DEPLOYMENT_STAGES",
    "EXPECTED_WORKFLOW_SHA256",
    "INTERNAL_ACS_CONFIG_DEFAULTS",
    "MAX_ACS_ARTIFACT_BYTES",
    "MAX_ACS_EVIDENCE_AGE_SECONDS",
    "MAX_ACS_EVIDENCE_BYTES",
    "MAX_ACTIVITY",
    "MAX_BASELINE_RUNS",
    "MAX_CHECKPOINTS",
    "MAX_DEPLOYMENT_ATTEMPTS",
    "MAX_DEPLOYMENT_CONFIG_BYTES",
    "MAX_GITHUB_ACTIVITY_BYTES",
    "MAX_GITHUB_METADATA_BYTES",
    "MAX_GITHUB_STATUS_BYTES",
    "MAX_PLAN_BYTES",
    "MAX_RUN_PAGES",
    "MAX_STEPS_PER_JOB",
    "MAX_WORKFLOW_BYTES",
    "OPERATION_TTL_SECONDS",
    "PLAN_TTL_SECONDS",
    "PRESERVATION_REQUIRED_ASSETS",
    "PROHIBITED_AUTOMATIC_ACTIONS",
    "PUBLIC_DEPLOYMENT_CONFLICT",
    "PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE",
    "PUBLIC_DEPLOYMENT_UNAVAILABLE",
    "RECOVERY_EVIDENCE_REQUIREMENTS",
    "REQUIRED_WORKFLOW_INPUTS",
    "RUNS_PER_PAGE",
    "WORKFLOW_FILE",
    "WORKFLOW_PATH",
    "DeploymentConflict",
    "DeploymentUnavailable",
    "DispatchIndeterminate",
    "DispatchRejected",
    "GitHubWorkflowGateway",
    "WorkflowConfiguration",
    "WorkflowPreflight",
    "public_deployment_error",
]


class PlanStore(Protocol):
    def save(self, plan: dict[str, Any]) -> None: ...

    def load(self, plan_id: str) -> dict[str, Any] | None: ...

    def save_latest(self, actor: str, environment: str, plan_id: str) -> None: ...

    def load_latest(self, actor: str, environment: str) -> str | None: ...

    def acquire_attempt(self, plan_id: str, attempt: int) -> bool: ...

    def release_attempt(self, plan_id: str, attempt: int) -> None: ...

    def acquire_environment(self, environment: str, plan_id: str) -> bool: ...

    def release_environment(self, environment: str, plan_id: str) -> None: ...

    def acquire_operation(self, plan_id: str, token: str) -> bool: ...

    def release_operation(self, plan_id: str, token: str) -> None: ...


class RedisPlanStore:
    """Short-lived durable plan state shared by operator replicas."""

    def __init__(self, redis_url: str, *, prefix: str = "kp:deployment:") -> None:
        self._client = redis.Redis.from_url(redis_url, decode_responses=True)
        self._prefix = prefix

    def _plan_key(self, plan_id: str) -> str:
        return f"{self._prefix}plan:{plan_id}"

    def _latest_key(self, actor: str, environment: str) -> str:
        actor_digest = hashlib.sha256(actor.encode("utf-8")).hexdigest()
        return f"{self._prefix}latest:{actor_digest}:{environment}"

    def save(self, plan: dict[str, Any]) -> None:
        encoded = json.dumps(plan, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > MAX_PLAN_BYTES:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        try:
            stored = self._client.set(self._plan_key(str(plan["plan_id"])), encoded, ex=PLAN_TTL_SECONDS)
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        if not stored:
            raise DeploymentUnavailable("deployment plan storage is unavailable")

    def load(self, plan_id: str) -> dict[str, Any] | None:
        try:
            raw = self._client.get(self._plan_key(plan_id))
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        if raw is None:
            return None
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_PLAN_BYTES:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            raise DeploymentUnavailable("deployment plan storage is malformed") from None
        if not isinstance(value, dict):
            raise DeploymentUnavailable("deployment plan storage is malformed")
        return value

    def save_latest(self, actor: str, environment: str, plan_id: str) -> None:
        if environment not in {"staging", "production"} or _PLAN_ID.fullmatch(plan_id) is None:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        try:
            stored = self._client.set(
                self._latest_key(actor, environment),
                plan_id,
                ex=PLAN_TTL_SECONDS,
            )
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        if not stored:
            raise DeploymentUnavailable("deployment plan storage is unavailable")

    def load_latest(self, actor: str, environment: str) -> str | None:
        if environment not in {"staging", "production"}:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        try:
            plan_id = self._client.get(self._latest_key(actor, environment))
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        if plan_id is None:
            return None
        if not isinstance(plan_id, str) or _PLAN_ID.fullmatch(plan_id) is None:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        return plan_id

    def acquire_attempt(self, plan_id: str, attempt: int) -> bool:
        try:
            acquired = self._client.set(
                f"{self._prefix}attempt:{plan_id}:{attempt}",
                "1",
                nx=True,
                ex=PLAN_TTL_SECONDS,
            )
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        return bool(acquired)

    def release_attempt(self, plan_id: str, attempt: int) -> None:
        try:
            self._client.delete(f"{self._prefix}attempt:{plan_id}:{attempt}")
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None

    def acquire_environment(self, environment: str, plan_id: str) -> bool:
        script = """
        local current = redis.call('GET', KEYS[1])
        if not current then
            local stored = redis.call('SET', KEYS[1], ARGV[1], 'NX', 'EX', ARGV[2])
            return stored and 1 or 0
        end
        if current == ARGV[1] then
            return redis.call('EXPIRE', KEYS[1], ARGV[2])
        end
        return 0
        """
        try:
            result = self._client.eval(
                script,
                1,
                f"{self._prefix}active:{environment}",
                plan_id,
                ACTIVE_TTL_SECONDS,
            )
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        return bool(result)

    def release_environment(self, environment: str, plan_id: str) -> None:
        script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """
        try:
            self._client.eval(script, 1, f"{self._prefix}active:{environment}", plan_id)
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None

    def acquire_operation(self, plan_id: str, token: str) -> bool:
        try:
            acquired = self._client.set(
                f"{self._prefix}operation:{plan_id}",
                token,
                nx=True,
                ex=OPERATION_TTL_SECONDS,
            )
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None
        return bool(acquired)

    def release_operation(self, plan_id: str, token: str) -> None:
        script = """
        if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
        end
        return 0
        """
        try:
            self._client.eval(script, 1, f"{self._prefix}operation:{plan_id}", token)
        except redis.RedisError:
            raise DeploymentUnavailable("deployment plan storage is unavailable") from None

    def close(self) -> None:
        self._client.close()


class MemoryPlanStore:
    """Thread-safe test/local seam; managed construction always uses Redis."""

    def __init__(self) -> None:
        self.plans: dict[str, dict[str, Any]] = {}
        self.attempts: set[tuple[str, int]] = set()
        self.environments: dict[str, str] = {}
        self.operations: dict[str, str] = {}
        self.latest: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def save(self, plan: dict[str, Any]) -> None:
        with self._lock:
            self.plans[str(plan["plan_id"])] = json.loads(json.dumps(plan))

    def load(self, plan_id: str) -> dict[str, Any] | None:
        with self._lock:
            plan = self.plans.get(plan_id)
            return json.loads(json.dumps(plan)) if plan is not None else None

    def save_latest(self, actor: str, environment: str, plan_id: str) -> None:
        if environment not in {"staging", "production"} or _PLAN_ID.fullmatch(plan_id) is None:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        with self._lock:
            self.latest[(actor, environment)] = plan_id

    def load_latest(self, actor: str, environment: str) -> str | None:
        if environment not in {"staging", "production"}:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        with self._lock:
            return self.latest.get((actor, environment))

    def acquire_attempt(self, plan_id: str, attempt: int) -> bool:
        with self._lock:
            key = (plan_id, attempt)
            if key in self.attempts:
                return False
            self.attempts.add(key)
            return True

    def release_attempt(self, plan_id: str, attempt: int) -> None:
        with self._lock:
            self.attempts.discard((plan_id, attempt))

    def acquire_environment(self, environment: str, plan_id: str) -> bool:
        with self._lock:
            current = self.environments.get(environment)
            if current not in {None, plan_id}:
                return False
            self.environments[environment] = plan_id
            return True

    def release_environment(self, environment: str, plan_id: str) -> None:
        with self._lock:
            if self.environments.get(environment) == plan_id:
                self.environments.pop(environment, None)

    def acquire_operation(self, plan_id: str, token: str) -> bool:
        with self._lock:
            if plan_id in self.operations:
                return False
            self.operations[plan_id] = token
            return True

    def release_operation(self, plan_id: str, token: str) -> None:
        with self._lock:
            if self.operations.get(plan_id) == token:
                self.operations.pop(plan_id, None)


class DeploymentOrchestrator:
    def __init__(
        self,
        store: PlanStore,
        gateway: GitHubWorkflowGateway,
        *,
        clock: Callable[[], datetime] | None = None,
        preflight: Callable[[str], WorkflowPreflight] | None = None,
        owns_resources: bool = False,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self._clock = clock or (lambda: datetime.now(UTC))
        self._preflight = preflight or gateway.preflight
        self._owns_resources = owns_resources

    @staticmethod
    def _recovery_policy() -> dict[str, Any]:
        """Return immutable preservation policy, separate from observed evidence."""

        return {
            "strategy": "reconcile_existing_operation",
            "automatic_cleanup_allowed": False,
            "preservation_required": list(PRESERVATION_REQUIRED_ASSETS),
            "prohibited_automatic_actions": list(PROHIBITED_AUTOMATIC_ACTIONS),
            "evidence_requirements": {
                name: list(required_fields) for name, required_fields in RECOVERY_EVIDENCE_REQUIREMENTS.items()
            },
        }

    @staticmethod
    def _required_recovery_steps(phase: str) -> tuple[tuple[str, str], ...]:
        if phase == "foundation_bootstrap":
            return _COMMON_RECOVERY_STEPS + _FOUNDATION_BOOTSTRAP_RECOVERY_STEPS
        if phase == "foundation_finalize":
            return _COMMON_RECOVERY_STEPS + _FOUNDATION_FINALIZE_RECOVERY_STEPS
        if phase == "workloads":
            return _COMMON_RECOVERY_STEPS + _WORKLOAD_RECOVERY_STEPS
        raise DeploymentUnavailable("deployment plan storage is malformed")

    @classmethod
    def _recovery_contract(
        cls,
        phase: str,
        *,
        activity: list[dict[str, str]] | None = None,
        activity_available: bool = False,
        terminal: bool = False,
        run_succeeded: bool = False,
    ) -> dict[str, Any]:
        """Return fixed policy plus bounded connector-derived verification."""

        required_steps = cls._required_recovery_steps(phase)
        required_jobs = tuple(dict.fromkeys(job for job, _step in required_steps))
        missing: list[str] = []
        failed: list[str] = []
        observed = 0
        rows = activity or []
        if terminal and activity_available:
            for job_name in required_jobs:
                matches = [row for row in rows if row.get("kind") == "job" and row.get("name") == job_name]
                label = f"{job_name} / job"
                if not matches:
                    missing.append(label)
                elif (
                    len(matches) != 1
                    or matches[0].get("status") != "completed"
                    or matches[0].get("conclusion") != "success"
                ):
                    failed.append(label)
                else:
                    observed += 1
            for job_name, step_name in required_steps:
                matches = [
                    row
                    for row in rows
                    if row.get("kind") == "step" and row.get("job") == job_name and row.get("name") == step_name
                ]
                label = f"{job_name} / {step_name}"
                if not matches:
                    missing.append(label)
                elif (
                    len(matches) != 1
                    or matches[0].get("status") != "completed"
                    or matches[0].get("conclusion") != "success"
                ):
                    failed.append(label)
                else:
                    observed += 1
        elif terminal:
            missing = [f"{job} / job" for job in required_jobs]
            missing.extend(f"{job} / {step}" for job, step in required_steps)

        connector_verified = terminal and run_succeeded and not missing and not failed
        status = (
            "verified" if connector_verified else "evidence_unverified" if terminal else "awaiting_protected_workflow"
        )
        check_status = (
            "verified_from_pinned_workflow_activity"
            if connector_verified
            else "not_verified_by_connector"
            if terminal
            else "awaiting_pinned_workflow"
        )
        return {
            "policy": cls._recovery_policy(),
            "verification": {
                "status": status,
                "connector_verified": connector_verified,
                "source": "bounded_github_run_job_step_activity",
                "required_activity_count": len(required_jobs) + len(required_steps),
                "observed_activity_count": observed,
                "missing_required_activity": missing,
                "failed_required_activity": failed,
                "checks": {
                    name: {
                        "blocking": True,
                        "status": check_status,
                        "required_fields": list(required_fields),
                    }
                    for name, required_fields in RECOVERY_EVIDENCE_REQUIREMENTS.items()
                },
            },
        }

    @classmethod
    def _valid_recovery(cls, plan: dict[str, Any]) -> bool:
        recovery = plan.get("recovery")
        inputs = plan.get("inputs")
        if (
            not isinstance(recovery, dict)
            or not isinstance(inputs, dict)
            or set(recovery) != {"policy", "verification"}
        ):
            return False
        if recovery.get("policy") != cls._recovery_policy():
            return False
        try:
            required_count = len(
                {job for job, _step in cls._required_recovery_steps(str(inputs.get("deployment_phase")))}
            ) + len(cls._required_recovery_steps(str(inputs.get("deployment_phase"))))
        except DeploymentUnavailable:
            return False
        verification = recovery.get("verification")
        if not isinstance(verification, dict) or set(verification) != {
            "status",
            "connector_verified",
            "source",
            "required_activity_count",
            "observed_activity_count",
            "missing_required_activity",
            "failed_required_activity",
            "checks",
        }:
            return False
        status = verification.get("status")
        verified = verification.get("connector_verified")
        observed = verification.get("observed_activity_count")
        missing = verification.get("missing_required_activity")
        failed = verification.get("failed_required_activity")
        checks = verification.get("checks")
        expected_check_status = (
            {
                "awaiting_protected_workflow": "awaiting_pinned_workflow",
                "evidence_unverified": "not_verified_by_connector",
                "verified": "verified_from_pinned_workflow_activity",
            }.get(status)
            if isinstance(status, str)
            else None
        )
        return bool(
            expected_check_status
            and isinstance(verified, bool)
            and verified is (status == "verified")
            and verification.get("source") == "bounded_github_run_job_step_activity"
            and verification.get("required_activity_count") == required_count
            and isinstance(observed, int)
            and not isinstance(observed, bool)
            and 0 <= observed <= required_count
            and isinstance(missing, list)
            and isinstance(failed, list)
            and len(missing) <= required_count
            and len(failed) <= required_count
            and all(isinstance(item, str) and 1 <= len(item) <= 256 for item in missing + failed)
            and len(set(missing + failed)) == len(missing) + len(failed)
            and isinstance(checks, dict)
            and set(checks) == set(RECOVERY_EVIDENCE_REQUIREMENTS)
            and all(
                check
                == {
                    "blocking": True,
                    "status": expected_check_status,
                    "required_fields": list(RECOVERY_EVIDENCE_REQUIREMENTS[name]),
                }
                for name, check in checks.items()
            )
            and (status != "verified" or (observed == required_count and not missing and not failed))
            and (status != "awaiting_protected_workflow" or (observed == 0 and not missing and not failed))
        )

    @staticmethod
    def _valid_checkpoint_evidence(phase: str, evidence: Any) -> bool:
        expected_fields = _CHECKPOINT_EVIDENCE_FIELDS.get(phase)
        if expected_fields is None or not isinstance(evidence, dict) or set(evidence) != expected_fields:
            return False
        if any(not isinstance(key, str) for key in evidence):
            return False
        for key, value in evidence.items():
            if key in {"review_digest", "source_revision_digest"}:
                if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
                    return False
            elif key == "baseline_run_count":
                if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_BASELINE_RUNS:
                    return False
            elif key in {"retry", "retry_safe"}:
                if not isinstance(value, bool):
                    return False
            elif key == "reason":
                if not isinstance(value, str) or value not in _CHECKPOINT_REASONS:
                    return False
            elif key == "run_id":
                if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                    return False
            elif key == "conclusion":
                if not isinstance(value, str) or value not in _TERMINAL_RESULTS - {"success"}:
                    return False
            elif key == "status":
                if not isinstance(value, str) or value not in {"queued", "running"}:
                    return False
            else:
                return False
        return True

    def _append_checkpoint(
        self,
        plan: dict[str, Any],
        phase: str,
        *,
        evidence: dict[str, str | int | bool | None] | None = None,
    ) -> None:
        """Append one bounded hash-chained operation checkpoint.

        Checkpoints are never edited or removed.  Repeated reconciliation may
        observe the same phase and therefore deliberately avoids appending an
        identical final checkpoint.
        """

        checkpoints = plan.setdefault("checkpoints", [])
        if not isinstance(checkpoints, list) or len(checkpoints) >= MAX_CHECKPOINTS:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        attempt = plan.get("attempt", 0)
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 0:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        safe_evidence = evidence or {}
        if (
            not self._valid_checkpoint_evidence(phase, safe_evidence)
            or len(json.dumps(safe_evidence, separators=(",", ":")).encode("utf-8")) > 2048
        ):
            raise DeploymentUnavailable("deployment plan storage is malformed")
        if checkpoints:
            final = checkpoints[-1]
            if (
                isinstance(final, dict)
                and final.get("phase") == phase
                and final.get("attempt") == attempt
                and final.get("evidence") == safe_evidence
            ):
                return
        body: dict[str, Any] = {
            "sequence": len(checkpoints) + 1,
            "phase": phase,
            "recorded_at": self._clock().isoformat(),
            "attempt": attempt,
            "correlation_id": plan.get("correlation_id"),
            "previous_digest": checkpoints[-1]["digest"] if checkpoints else None,
            "evidence": safe_evidence,
        }
        body["digest"] = hashlib.sha256(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        checkpoints.append(body)

    @staticmethod
    def _valid_checkpoints(plan: dict[str, Any]) -> bool:
        checkpoints = plan.get("checkpoints")
        plan_attempt = plan.get("attempt")
        plan_id = plan.get("plan_id")
        if (
            not isinstance(checkpoints, list)
            or not 1 <= len(checkpoints) <= MAX_CHECKPOINTS
            or not isinstance(plan_attempt, int)
            or isinstance(plan_attempt, bool)
            or plan_attempt < 0
            or not isinstance(plan_id, str)
            or _PLAN_ID.fullmatch(plan_id) is None
        ):
            return False
        previous_digest: str | None = None
        previous_attempt = 0
        for sequence, checkpoint in enumerate(checkpoints, start=1):
            if not isinstance(checkpoint, dict) or set(checkpoint) != {
                "sequence",
                "phase",
                "recorded_at",
                "attempt",
                "correlation_id",
                "previous_digest",
                "evidence",
                "digest",
            }:
                return False
            digest = checkpoint.get("digest")
            evidence = checkpoint.get("evidence")
            attempt = checkpoint.get("attempt")
            correlation_id = checkpoint.get("correlation_id")
            recorded_at = checkpoint.get("recorded_at")
            try:
                recorded_datetime = datetime.fromisoformat(recorded_at) if isinstance(recorded_at, str) else None
            except ValueError:
                recorded_datetime = None
            if (
                checkpoint.get("sequence") != sequence
                or (sequence == 1 and checkpoint.get("phase") != "plan_reviewed")
                or recorded_datetime is None
                or recorded_datetime.tzinfo is None
                or not isinstance(attempt, int)
                or isinstance(attempt, bool)
                or not previous_attempt <= attempt <= plan_attempt
                or (correlation_id != (None if attempt == 0 else f"{CORRELATION_PREFIX}-{plan_id}-{attempt}"))
                or checkpoint.get("previous_digest") != previous_digest
                or not DeploymentOrchestrator._valid_checkpoint_evidence(str(checkpoint.get("phase", "")), evidence)
                or _DIGEST.fullmatch(str(digest)) is None
            ):
                return False
            unsigned = {key: value for key, value in checkpoint.items() if key != "digest"}
            try:
                encoded = json.dumps(unsigned, separators=(",", ":"), sort_keys=True).encode("utf-8")
            except (TypeError, ValueError, RecursionError):
                return False
            expected = hashlib.sha256(encoded).hexdigest()
            if not secrets.compare_digest(str(digest), expected):
                return False
            previous_digest = str(digest)
            previous_attempt = attempt
        return True

    @property
    def owns_resources(self) -> bool:
        return self._owns_resources

    @classmethod
    def from_environment(cls, redis_url: str) -> DeploymentOrchestrator:
        configuration = WorkflowConfiguration.from_environment()
        return cls(
            RedisPlanStore(redis_url),
            GitHubWorkflowGateway(configuration),
            owns_resources=True,
        )

    def close_owned_resources(self) -> None:
        """Release connector clients only for the production-owned assembly."""
        if not self._owns_resources:
            return
        errors: list[Exception] = []
        for resource in (self.gateway, self.store):
            close = getattr(resource, "close", None)
            if not callable(close):
                continue
            try:
                close()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise RuntimeError("deployment connector resource shutdown failed") from errors[0]

    @staticmethod
    def public_configuration() -> dict[str, Any]:
        try:
            configuration = WorkflowConfiguration.from_environment()
        except DeploymentUnavailable as exc:
            return {
                "configured": False,
                "ready": False,
                "reason": public_deployment_error(exc),
                "workflow": WORKFLOW_PATH,
                "deployment_stages": list(DEPLOYMENT_STAGES),
                "stage_advance": "new_server_reviewed_plan_after_verified_final_artifact",
                "acs_evidence_schema": ACS_EVIDENCE_ARTIFACT_SCHEMA,
            }
        return {
            "configured": True,
            "ready": False,
            "readiness_status": "requires_reviewed_plan_preflight",
            "repository": configuration.repository,
            "ref": configuration.ref,
            "workflow": WORKFLOW_PATH,
            "provider": "github_actions",
            "deployment_stages": list(DEPLOYMENT_STAGES),
            "stage_advance": "new_server_reviewed_plan_after_verified_final_artifact",
            "acs_evidence_schema": ACS_EVIDENCE_ARTIFACT_SCHEMA,
            "preflight_proves": [
                "The configured ref resolves to a commit",
                "The fixed workflow is active and exactly matches the connector-pinned content",
                "The selected GitHub environment has non-self required review, branch protection, and no admin bypass",
                "The reviewed plan is bound to the commit, workflow content, and environment metadata",
            ],
            "preflight_limitations": [
                "GitHub does not return protected secret values to this connector",
                (
                    "GitHub has no non-dispatch input-schema dry run; "
                    "exact pinned workflow content proves the input contract"
                ),
                "Custom deployment-branch patterns are not enumerated; GitHub enforces them at job admission",
                "Azure, runner, OIDC, DNS, quota, and tenant consent remain live external prerequisites",
                "The workflow dispatch API accepts a branch or tag, not an immutable commit SHA",
            ],
            "rollback": {
                "supported": False,
                "reason": "No separately reviewed allowlisted rollback workflow exists; recovery remains manual.",
            },
        }

    @staticmethod
    def workflow_inputs(values: dict[str, str]) -> dict[str, str]:
        """Map validated wizard values onto the fixed workflow input schema."""
        config = {key: values.get(key, "") for key in DEPLOYMENT_CONFIG_KEYS}
        config.update(INTERNAL_ACS_CONFIG_DEFAULTS)
        if any(_SENSITIVE_DEPLOYMENT_VALUE.search(value) for value in config.values()):
            raise DeploymentConflict("deployment values must not contain credentials or tokens")
        active_key_id = config["ciphertext_active_key_id"]
        prior_key_ids = (
            [value.strip() for value in config["ciphertext_prior_key_ids"].split(",")]
            if config["ciphertext_prior_key_ids"].strip()
            else []
        )
        prior_secret_id = config["ciphertext_prior_keys_secret_id"]
        secret_reference = _VERSIONLESS_KEY_VAULT_SECRET_ID.fullmatch(prior_secret_id)
        if (
            _CIPHERTEXT_KEY_ID.fullmatch(active_key_id) is None
            or len(prior_key_ids) > 4
            or len(set(prior_key_ids)) != len(prior_key_ids)
            or active_key_id in prior_key_ids
            or any(_CIPHERTEXT_KEY_ID.fullmatch(key_id) is None for key_id in prior_key_ids)
            or bool(prior_key_ids) != bool(prior_secret_id)
            or (prior_secret_id and secret_reference is None)
            or (secret_reference is not None and secret_reference.group(1).lower() != config["subscription_id"].lower())
            or (values.get("deployment_stage") != "workloads" and bool(prior_key_ids))
        ):
            raise DeploymentConflict("ciphertext recovery metadata is invalid")
        serialized_config = json.dumps(config, separators=(",", ":"), sort_keys=True)
        if len(serialized_config.encode("utf-8")) > MAX_DEPLOYMENT_CONFIG_BYTES:
            raise DeploymentConflict("deployment configuration exceeds the fixed workflow limit")
        environment = values["environment"]
        deployment_stage = values["deployment_stage"]
        network_mode = values.get("network_mode", "")
        if (
            network_mode not in {"starter", "private"}
            or deployment_stage not in DEPLOYMENT_STAGES
            or (
                network_mode == "starter"
                and (
                    environment != "staging" or deployment_stage not in {"foundation_bootstrap", "foundation_finalize"}
                )
            )
            or (deployment_stage == "workloads" and network_mode != "private")
        ):
            raise DeploymentConflict("deployment network mode is invalid for the reviewed environment and phase")
        return {
            "environment": environment,
            "network_mode": network_mode,
            "deployment_phase": deployment_stage,
            "deployment_config": serialized_config,
        }

    def create_plan(
        self,
        values: dict[str, str],
        *,
        actor: str,
        predecessor: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        inputs = self.workflow_inputs(values)
        source_revision = self._preflight(inputs["environment"]).review_payload()
        terraform_state_identity = {
            "resource_group": values.get("tf_state_resource_group", ""),
            "storage_account": values.get("tf_state_storage_account", ""),
            "container": values.get("tf_state_container", ""),
        }
        if source_revision.get("terraform_state_identity") != terraform_state_identity:
            raise DeploymentConflict("reviewed Terraform state identity does not match the protected environment")
        plan_id = uuid.uuid4().hex
        created_at = self._clock()
        review_body = {
            "plan_id": plan_id,
            "actor": actor,
            "repository": self.gateway.configuration.repository,
            "ref": self.gateway.configuration.ref,
            "workflow": WORKFLOW_PATH,
            "source_revision": source_revision,
            "inputs": inputs,
            "terraform_state_identity": terraform_state_identity,
            "stage_predecessor": predecessor,
        }
        digest = hashlib.sha256(
            json.dumps(review_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        plan: dict[str, Any] = {
            **review_body,
            "review_digest": digest,
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(seconds=PLAN_TTL_SECONDS)).isoformat(),
            "state": "reviewed",
            "attempt": 0,
            "run_id": None,
            "run": None,
            "activity": [],
            "activity_available": False,
            "baseline_run_ids": [],
            "dispatched_at": None,
            "correlation_id": None,
            "last_error": None,
            "workflow_url": self.gateway.workflow_url,
            "checkpoints": [],
            "recovery": self._recovery_contract(inputs["deployment_phase"]),
            "acs_evidence": {
                "status": "awaiting_workflow",
                "schema": ACS_EVIDENCE_ARTIFACT_SCHEMA,
                "deployment_stage": inputs["deployment_phase"],
            },
            "reviewed_values": {
                **{key: values.get(key, "") for key in DEPLOYMENT_CONFIG_KEYS},
                "environment": values["environment"],
                "network_mode": values["network_mode"],
                "deployment_stage": values["deployment_stage"],
                "tf_state_resource_group": values.get("tf_state_resource_group", ""),
                "tf_state_storage_account": values.get("tf_state_storage_account", ""),
                "tf_state_container": values.get("tf_state_container", ""),
            },
            "review": {
                "environment": inputs["environment"],
                "network_mode": inputs["network_mode"],
                "deployment_stage": inputs["deployment_phase"],
                "terraform_state_identity": terraform_state_identity,
                "directory_sync": values["enable_directory_sync"] == "true",
                "reported_mailbox": values["enable_reported_mailbox"] == "true",
                "acs_resource_mode": values["acs_resource_mode"],
                "ciphertext_active_key_id": values["ciphertext_active_key_id"],
                "ciphertext_prior_key_ids": [
                    key_id.strip() for key_id in values["ciphertext_prior_key_ids"].split(",") if key_id.strip()
                ],
                "ciphertext_prior_keys_source": (
                    "external_versionless_key_vault_reference" if values["ciphertext_prior_keys_secret_id"] else "none"
                ),
            },
            "external_prerequisites": [
                "Protected GitHub environment variable and secret values match the reviewed wizard values",
                "The configured ref satisfies any protected-environment deployment branch policy",
                "The deployment OIDC identity and Azure role assignments are configured",
                (
                    "The private azure-vnet runner can reach the Azure data plane"
                    if inputs["network_mode"] == "private"
                    else "The hosted starter runner is used only for this staging foundation bootstrap"
                ),
                "Terraform state, DNS authority, Graph/Exchange consent, and ACS quota are ready",
                (
                    "The connector verifies the pinned workflow's phase-specific qualification, refusal, apply, "
                    "health, cleanup, completion, and evidence-upload steps"
                ),
            ],
            "limitations": [
                "This plan dispatches the checked-in workflow; it does not write GitHub environment variables",
                "GitHub does not expose protected secret values for this preflight to prove",
                "GitHub has no non-dispatch input-schema dry run; the exact pinned workflow content is checked instead",
                "GitHub environment approval remains mandatory and may reject or delay the run",
                "A successful workflow is required before Azure deployment can be described as complete",
                "Rollback is not supported by this GUI slice; use the protected Azure recovery procedure",
                (
                    "The connector fails closed unless bounded GitHub job and step results verify every required "
                    "phase-specific recovery gate"
                ),
            ],
        }
        self._append_checkpoint(
            plan,
            "plan_reviewed",
            evidence={
                "review_digest": digest,
                "source_revision_digest": hashlib.sha256(
                    json.dumps(source_revision, separators=(",", ":"), sort_keys=True).encode("utf-8")
                ).hexdigest(),
            },
        )
        self.store.save(plan)
        self.store.save_latest(actor, inputs["environment"], plan_id)
        return self._public_plan(plan)

    def get_plan(self, plan_id: str, *, actor: str, refresh: bool = True) -> dict[str, Any]:
        if not refresh:
            return self._public_plan(self._owned_plan(plan_id, actor))
        with self._exclusive_operation(plan_id):
            plan = self._owned_plan(plan_id, actor)
            if plan.get("state") in {
                "dispatching",
                "dispatch_accepted",
                "dispatch_indeterminate",
                "running",
                "queued",
                "run_failed",
                "evidence_unverified",
            }:
                plan = self._refresh(plan)
            return self._public_plan(plan)

    def get_latest_plan(self, environment: str, *, actor: str) -> dict[str, Any] | None:
        if environment not in {"staging", "production"}:
            raise DeploymentConflict("deployment environment is invalid")
        plan_id = self.store.load_latest(actor, environment)
        if plan_id is None:
            return None
        return self.get_plan(plan_id, actor=actor)

    def advance_plan(self, plan_id: str, review_digest: str, *, actor: str) -> dict[str, Any]:
        """Create the next reviewed stage from server-held values; never redispatch the old plan."""

        with self._exclusive_operation(plan_id):
            plan = self._owned_plan(plan_id, actor)
            if _DIGEST.fullmatch(review_digest) is None or not secrets.compare_digest(
                str(plan.get("review_digest", "")), review_digest
            ):
                raise DeploymentConflict("the reviewed deployment digest does not match")
            if plan.get("state") != "workflow_succeeded":
                raise DeploymentConflict("deployment stage evidence is not verified")
            stage = str(plan.get("inputs", {}).get("deployment_phase", ""))
            next_stage = _NEXT_DEPLOYMENT_STAGE.get(stage)
            if next_stage is None:
                raise DeploymentConflict("deployment stage has no successor")
            evidence = plan.get("acs_evidence")
            if (
                not isinstance(evidence, dict)
                or evidence.get("status") != "verified"
                or evidence.get("deployment_stage") != stage
                or not isinstance(evidence.get("evidence_digest"), str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(evidence["evidence_digest"])) is None
            ):
                raise DeploymentConflict("deployment stage evidence is not verified")
            reviewed_values = plan.get("reviewed_values")
            if not isinstance(reviewed_values, dict):
                raise DeploymentUnavailable("deployment plan storage is malformed")
            values = {
                key: value for key, value in reviewed_values.items() if isinstance(key, str) and isinstance(value, str)
            }
            if set(values) != set(reviewed_values):
                raise DeploymentUnavailable("deployment plan storage is malformed")
            values["deployment_stage"] = next_stage
            predecessor = {
                "plan_id": str(plan["plan_id"]),
                "deployment_stage": stage,
                "review_digest": str(plan["review_digest"]),
                "evidence_digest": str(evidence["evidence_digest"]),
            }
            return self.create_plan(values, actor=actor, predecessor=predecessor)

    def apply(
        self,
        plan_id: str,
        review_digest: str,
        *,
        actor: str,
        rationale: str,
        retry: bool,
        audit: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        with self._exclusive_operation(plan_id):
            return self._apply_locked(
                plan_id,
                review_digest,
                actor=actor,
                rationale=rationale,
                retry=retry,
                audit=audit,
            )

    def _apply_locked(
        self,
        plan_id: str,
        review_digest: str,
        *,
        actor: str,
        rationale: str,
        retry: bool,
        audit: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any]:
        plan = self._owned_plan(plan_id, actor)
        if _DIGEST.fullmatch(review_digest) is None or not secrets.compare_digest(
            str(plan["review_digest"]), review_digest
        ):
            raise DeploymentConflict("the reviewed deployment digest does not match")
        state = str(plan.get("state"))
        if retry:
            if not self._retry_allowed(plan):
                raise DeploymentConflict("retry is allowed only after GitHub rejected a dispatch before creating a run")
        elif state != "reviewed":
            raise DeploymentConflict("this reviewed plan has already been submitted")
        checkpoints = plan.get("checkpoints")
        prior_attempt = plan.get("attempt")
        if (
            not isinstance(checkpoints, list)
            or not isinstance(prior_attempt, int)
            or isinstance(prior_attempt, bool)
            or prior_attempt >= MAX_DEPLOYMENT_ATTEMPTS
            or len(checkpoints) > MAX_CHECKPOINTS - CHECKPOINT_RESERVE_PER_ATTEMPT
        ):
            raise DeploymentConflict(
                "deployment plan has reached its safe attempt or checkpoint limit; create and review a new plan"
            )
        environment = str(plan["inputs"]["environment"])
        reviewed_source_revision = plan.get("source_revision")
        if not isinstance(reviewed_source_revision, dict):
            plan["state"] = "review_required"
            plan["last_error"] = "The stored plan lacks reviewed source evidence; create and review a new plan"
            self.store.save(plan)
            raise DeploymentConflict("The stored plan lacks reviewed source evidence; create and review a new plan")
        baseline = self.gateway.recent_runs()
        attempt = int(plan.get("attempt", 0)) + 1
        if not self.store.acquire_environment(environment, plan_id):
            raise DeploymentConflict(f"another {environment} deployment is active")
        if not self.store.acquire_attempt(plan_id, attempt):
            self.store.release_environment(environment, plan_id)
            raise DeploymentConflict("this deployment attempt was already submitted")
        plan.update(
            {
                "attempt": attempt,
                "state": "dispatching",
                "baseline_run_ids": [row["run_id"] for row in baseline],
                "dispatched_at": self._clock().isoformat(),
                "correlation_id": f"{CORRELATION_PREFIX}-{plan_id}-{attempt}",
                "last_error": None,
                "run_id": None,
                "run": None,
                "activity": [],
            }
        )
        try:
            self._append_checkpoint(
                plan,
                "dispatch_intent_saved",
                evidence={
                    "baseline_run_count": len(baseline),
                    "retry": retry,
                },
            )
            self.store.save(plan)
        except Exception:
            with suppress(DeploymentUnavailable):
                self.store.release_attempt(plan_id, attempt)
            with suppress(DeploymentUnavailable):
                self.store.release_environment(environment, plan_id)
            raise
        try:
            audit(
                {
                    "plan_id": plan_id,
                    "review_digest": review_digest,
                    "environment": environment,
                    "workflow": WORKFLOW_PATH,
                    "commit_sha": reviewed_source_revision["commit_sha"],
                    "workflow_content_sha256": reviewed_source_revision["workflow_content_sha256"],
                    "attempt": attempt,
                    "retry": retry,
                    "rationale": rationale,
                }
            )
        except Exception:
            plan["state"] = "dispatch_failed"
            plan["last_error"] = "Audit evidence could not be committed; no workflow was dispatched"
            try:
                self._append_checkpoint(plan, "dispatch_blocked", evidence={"reason": "audit_evidence_unavailable"})
                self.store.save(plan)
            finally:
                self.store.release_environment(environment, plan_id)
            raise
        self._append_checkpoint(plan, "audit_evidence_committed")
        try:
            self.store.save(plan)
        except Exception:
            with suppress(DeploymentUnavailable):
                self.store.release_environment(environment, plan_id)
            raise
        try:
            current_source_revision = self._preflight(environment).review_payload()
        except DeploymentUnavailable:
            plan["state"] = "dispatch_failed"
            plan["last_error"] = "GitHub preflight became unavailable; no workflow was dispatched"
            try:
                self._append_checkpoint(plan, "dispatch_blocked", evidence={"reason": "preflight_unavailable"})
                self.store.save(plan)
            finally:
                self.store.release_environment(environment, plan_id)
            raise
        if not self._same_revision(reviewed_source_revision, current_source_revision):
            plan["state"] = "review_required"
            plan["last_error"] = "GitHub workflow, ref, or protected environment drifted; create and review a new plan"
            try:
                self._append_checkpoint(plan, "review_invalidated", evidence={"reason": "source_revision_drift"})
                self.store.save(plan)
            finally:
                self.store.release_environment(environment, plan_id)
            raise DeploymentConflict(
                "GitHub workflow, ref, or protected environment drifted; create and review a new plan"
            )
        self._append_checkpoint(
            plan,
            "source_revalidated",
            evidence={
                "source_revision_digest": hashlib.sha256(
                    json.dumps(current_source_revision, separators=(",", ":"), sort_keys=True).encode("utf-8")
                ).hexdigest()
            },
        )
        try:
            self.store.save(plan)
        except Exception:
            with suppress(DeploymentUnavailable):
                self.store.release_environment(environment, plan_id)
            raise
        try:
            dispatch_inputs = dict(plan["inputs"])
            dispatch_inputs["deployment_request_id"] = str(plan["correlation_id"])
            dispatch_inputs["reviewed_commit_sha"] = str(current_source_revision["commit_sha"])
            self.gateway.dispatch(dispatch_inputs)
        except DispatchRejected:
            plan["state"] = "dispatch_failed"
            plan["last_error"] = "GitHub conclusively rejected the workflow dispatch; correct access and retry"
            self._append_checkpoint(plan, "dispatch_rejected", evidence={"retry_safe": True})
            self.store.save(plan)
            self.store.release_environment(environment, plan_id)
            return self._public_plan(plan)
        except DispatchIndeterminate:
            plan["state"] = "dispatch_indeterminate"
            plan["last_error"] = "Dispatch outcome is unknown; inspect GitHub Actions and do not retry this plan"
            self._append_checkpoint(plan, "dispatch_indeterminate", evidence={"retry_safe": False})
            self.store.save(plan)
            return self._public_plan(plan)
        plan["state"] = "dispatch_accepted"
        self._append_checkpoint(plan, "dispatch_accepted", evidence={"retry_safe": False})
        self.store.save(plan)
        return self._public_plan(plan)

    def _refresh(self, plan: dict[str, Any]) -> dict[str, Any]:
        environment = str(plan["inputs"]["environment"])
        plan_id = str(plan["plan_id"])
        if not self.store.acquire_environment(environment, plan_id):
            plan["state"] = "dispatch_indeterminate"
            plan["last_error"] = "Deployment exclusivity was lost; inspect GitHub Actions before continuing"
            self._append_checkpoint(plan, "reconciliation_blocked", evidence={"reason": "exclusivity_lost"})
            self.store.save(plan)
            return plan
        run_id = plan.get("run_id")
        if run_id is None:
            baseline = {int(value) for value in plan.get("baseline_run_ids", [])}
            correlation_id = str(plan.get("correlation_id", ""))
            candidates = [
                row
                for row in self.gateway.recent_runs()
                if int(row["run_id"]) not in baseline
                and secrets.compare_digest(str(row.get("run_name", "")), correlation_id)
            ]
            if len(candidates) == 1:
                if not self._run_matches_plan(candidates[0], plan):
                    plan["state"] = "dispatch_indeterminate"
                    plan["last_error"] = "The linked workflow identity changed; inspect GitHub Actions"
                    self._append_checkpoint(plan, "reconciliation_blocked", evidence={"reason": "identity_changed"})
                    self.store.save(plan)
                    return plan
                run_id = int(candidates[0]["run_id"])
                plan["run_id"] = run_id
                self._append_checkpoint(plan, "run_linked", evidence={"run_id": run_id})
            elif len(candidates) > 1:
                plan["state"] = "dispatch_indeterminate"
                plan["last_error"] = "Multiple new workflow runs exist; inspect GitHub Actions before any retry"
                self._append_checkpoint(plan, "reconciliation_blocked", evidence={"reason": "ambiguous_runs"})
                self.store.save(plan)
                return plan
            else:
                if plan.get("state") == "dispatching":
                    final_phase = str(plan["checkpoints"][-1]["phase"])
                    if final_phase in {"dispatch_intent_saved", "audit_evidence_committed"}:
                        plan["state"] = "dispatch_failed"
                        plan["last_error"] = (
                            "The prior operation stopped before workflow dispatch; "
                            "reconcile its checkpoints without redispatching"
                        )
                        self._append_checkpoint(plan, "dispatch_interrupted", evidence={"retry_safe": False})
                        self.store.release_environment(environment, plan_id)
                    else:
                        plan["state"] = "dispatch_indeterminate"
                        plan["last_error"] = (
                            "Dispatch outcome is unknown; inspect GitHub Actions and do not retry this plan"
                        )
                        self._append_checkpoint(plan, "dispatch_indeterminate", evidence={"retry_safe": False})
                self.store.save(plan)
                return plan
        run = self.gateway.run(int(run_id))
        if not secrets.compare_digest(str(run.get("run_name", "")), str(plan.get("correlation_id", ""))):
            plan["state"] = "dispatch_indeterminate"
            plan["last_error"] = "The linked workflow correlation changed; inspect GitHub Actions"
            self._append_checkpoint(plan, "reconciliation_blocked", evidence={"reason": "correlation_changed"})
            self.store.save(plan)
            return plan
        if not self._run_matches_plan(run, plan):
            plan["state"] = "dispatch_indeterminate"
            plan["last_error"] = "The linked workflow identity changed; inspect GitHub Actions"
            self._append_checkpoint(plan, "reconciliation_blocked", evidence={"reason": "identity_changed"})
            self.store.save(plan)
            return plan
        plan["run"] = {key: value for key, value in run.items() if key != "run_name"}
        try:
            plan["activity"] = self.gateway.activity(int(run_id))
            plan["activity_available"] = True
        except DeploymentUnavailable:
            plan["activity"] = []
            plan["activity_available"] = False
        conclusion = run.get("conclusion")
        status = run.get("status")
        prior_state = str(plan.get("state"))
        deployment_phase = str(plan["inputs"]["deployment_phase"])
        if conclusion != "success" and conclusion in _TERMINAL_RESULTS:
            plan["state"] = "run_failed"
            plan["last_error"] = (
                "The protected workflow ended unsuccessfully; reconcile its evidence and Azure state without retrying"
            )
            plan["recovery"] = self._recovery_contract(
                deployment_phase,
                activity=plan["activity"],
                activity_available=bool(plan["activity_available"]),
                terminal=True,
                run_succeeded=False,
            )
            self._append_checkpoint(
                plan,
                "workflow_failed",
                evidence={"run_id": int(run_id), "conclusion": str(conclusion), "retry_safe": False},
            )
            self.store.release_environment(environment, plan_id)
        elif conclusion == "success":
            plan["recovery"] = self._recovery_contract(
                deployment_phase,
                activity=plan["activity"],
                activity_available=bool(plan["activity_available"]),
                terminal=True,
                run_succeeded=True,
            )
            if plan["recovery"]["verification"]["connector_verified"] is True:
                try:
                    plan["acs_evidence"] = self._validated_acs_evidence(plan, run)
                except DeploymentUnavailable:
                    plan["acs_evidence"] = {
                        "status": "evidence_unverified",
                        "schema": ACS_EVIDENCE_ARTIFACT_SCHEMA,
                        "deployment_stage": deployment_phase,
                    }
                    plan["state"] = "evidence_unverified"
                    plan["last_error"] = (
                        "The workflow reported success but required pinned job or step evidence is unavailable "
                        "or incomplete"
                    )
                    self._append_checkpoint(
                        plan,
                        "workflow_evidence_unverified",
                        evidence={"run_id": int(run_id), "reason": "required_activity_unverified"},
                    )
                else:
                    plan["state"] = "workflow_succeeded"
                    plan["last_error"] = None
                    self._append_checkpoint(plan, "workflow_succeeded", evidence={"run_id": int(run_id)})
            else:
                plan["state"] = "evidence_unverified"
                plan["last_error"] = (
                    "The workflow reported success but required pinned job or step evidence is unavailable "
                    "or incomplete"
                )
                self._append_checkpoint(
                    plan,
                    "workflow_evidence_unverified",
                    evidence={"run_id": int(run_id), "reason": "required_activity_unverified"},
                )
            self.store.release_environment(environment, plan_id)
        elif status in {"queued", "waiting", "requested", "pending"}:
            plan["state"] = "queued"
        else:
            plan["state"] = "running"
        if plan["state"] != prior_state and plan["state"] in {"queued", "running"}:
            self._append_checkpoint(
                plan,
                "workflow_status_observed",
                evidence={"run_id": int(run_id), "status": str(plan["state"])},
            )
        self.store.save(plan)
        return plan

    @contextmanager
    def _exclusive_operation(self, plan_id: str) -> Iterator[None]:
        if _PLAN_ID.fullmatch(plan_id) is None:
            raise DeploymentConflict("invalid deployment plan identifier")
        token = uuid.uuid4().hex
        if not self.store.acquire_operation(plan_id, token):
            raise DeploymentConflict("this deployment plan is currently being updated; refresh and retry")
        try:
            yield
        finally:
            # The bounded lease expires on its own. Never obscure a known
            # dispatch result with a best-effort cleanup failure.
            with suppress(DeploymentUnavailable):
                self.store.release_operation(plan_id, token)

    @classmethod
    def _valid_plan_review(cls, plan: dict[str, Any]) -> bool:
        reviewed_values = plan.get("reviewed_values")
        inputs = plan.get("inputs")
        review = plan.get("review")
        predecessor = plan.get("stage_predecessor")
        expected_value_keys = set(DEPLOYMENT_CONFIG_KEYS) | {
            "environment",
            "network_mode",
            "deployment_stage",
            "tf_state_resource_group",
            "tf_state_storage_account",
            "tf_state_container",
        }
        if (
            not isinstance(reviewed_values, dict)
            or set(reviewed_values) != expected_value_keys
            or any(
                not isinstance(value, str) or len(value) > 2048 or "\n" in value or "\r" in value
                for value in reviewed_values.values()
            )
            or not isinstance(inputs, dict)
            or set(inputs) != {"environment", "network_mode", "deployment_phase", "deployment_config"}
            or not isinstance(review, dict)
            or review.get("deployment_stage") != inputs.get("deployment_phase")
        ):
            return False
        try:
            if cls.workflow_inputs(reviewed_values) != inputs:
                return False
        except (DeploymentConflict, KeyError, TypeError):
            return False
        if predecessor is not None and (
            not isinstance(predecessor, dict)
            or set(predecessor) != {"plan_id", "deployment_stage", "review_digest", "evidence_digest"}
            or _PLAN_ID.fullmatch(str(predecessor.get("plan_id", ""))) is None
            or predecessor.get("deployment_stage") not in DEPLOYMENT_STAGES[:-1]
            or _DIGEST.fullmatch(str(predecessor.get("review_digest", ""))) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(predecessor.get("evidence_digest", ""))) is None
        ):
            return False
        review_body = {
            "plan_id": plan.get("plan_id"),
            "actor": plan.get("actor"),
            "repository": plan.get("repository"),
            "ref": plan.get("ref"),
            "workflow": plan.get("workflow"),
            "source_revision": plan.get("source_revision"),
            "inputs": inputs,
            "terraform_state_identity": plan.get("terraform_state_identity"),
            "stage_predecessor": predecessor,
        }
        calculated_review_digest = hashlib.sha256(
            json.dumps(review_body, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        evidence = plan.get("acs_evidence")
        return bool(
            isinstance(plan.get("review_digest"), str)
            and secrets.compare_digest(str(plan["review_digest"]), calculated_review_digest)
            and isinstance(evidence, dict)
            and evidence.get("status") in {"awaiting_workflow", "evidence_unverified", "verified"}
            and evidence.get("schema") == ACS_EVIDENCE_ARTIFACT_SCHEMA
            and evidence.get("deployment_stage") == inputs.get("deployment_phase")
            and len(json.dumps(evidence, separators=(",", ":")).encode("utf-8")) <= MAX_ACS_EVIDENCE_BYTES * 2
            and (
                evidence.get("status") != "verified"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(evidence.get("evidence_digest", ""))) is not None
            )
        )

    def _owned_plan(self, plan_id: str, actor: str) -> dict[str, Any]:
        if _PLAN_ID.fullmatch(plan_id) is None:
            raise DeploymentConflict("invalid deployment plan identifier")
        plan = self.store.load(plan_id)
        if plan is None:
            raise DeploymentConflict("deployment plan is missing or expired")
        if not self._valid_plan_review(plan) or not self._valid_checkpoints(plan) or not self._valid_recovery(plan):
            raise DeploymentUnavailable("deployment plan storage is malformed")
        try:
            expires_at = datetime.fromisoformat(str(plan["expires_at"]))
        except (KeyError, ValueError):
            expires_at = datetime.min.replace(tzinfo=UTC)
        if expires_at.tzinfo is None or self._clock() >= expires_at.astimezone(UTC):
            inputs = plan.get("inputs")
            if isinstance(inputs, dict) and inputs.get("environment") in {"staging", "production"}:
                self.store.release_environment(str(inputs["environment"]), plan_id)
            raise DeploymentConflict("deployment plan is missing or expired")
        if not secrets.compare_digest(str(plan.get("actor", "")), actor):
            raise DeploymentConflict("deployment plans may be used only by the administrator who reviewed them")
        return plan

    @staticmethod
    def _has_valid_evidence_digest(value: dict[str, Any]) -> bool:
        supplied = value.get("evidence_digest")
        if not isinstance(supplied, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", supplied) is None:
            return False
        body = {key: item for key, item in value.items() if key != "evidence_digest"}
        calculated = (
            "sha256:"
            + hashlib.sha256(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
        )
        return secrets.compare_digest(supplied, calculated)

    def _validated_acs_evidence(self, plan: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
        """Validate and reduce the final workflow artifact to a bounded public shape."""

        stage = str(plan.get("inputs", {}).get("deployment_phase", ""))
        if stage not in DEPLOYMENT_STAGES:
            raise DeploymentUnavailable("deployment plan storage is malformed")
        run_id = run.get("run_id")
        run_attempt = run.get("run_attempt")
        if (
            not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or not isinstance(run_attempt, int)
            or isinstance(run_attempt, bool)
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        bundle = self.gateway.acs_evidence_artifact(run_id, run_attempt)
        artifact_digest = bundle.get("artifact_sha256")
        result = bundle.get("stage_result")
        live = bundle.get("live_readiness")
        if (
            not isinstance(artifact_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest) is None
            or not isinstance(result, dict)
            or not isinstance(live, dict)
            or set(result)
            != {
                "schema",
                "recorded_at",
                "result",
                "phase",
                "reviewed_commit_sha",
                "reviewed_deployment_digest",
                "deployment_request_id",
                "source_evidence_digests",
                "workflow_run",
                "claims",
                "evidence_digest",
            }
            or set(live)
            != {
                "schema",
                "observed_at",
                "result",
                "phase",
                "resource_mode",
                "subscription_id",
                "tenant_id",
                "resource_ids",
                "statuses",
                "reviewed_commit_sha",
                "reviewed_deployment_digest",
                "workflow_run",
                "api_version",
                "scope_limits",
                "evidence_digest",
            }
            or result.get("schema") != ACS_EVIDENCE_ARTIFACT_SCHEMA
            or live.get("schema") != "kp.acs-live-readiness.v1"
            or result.get("phase") != stage
            or live.get("phase") != stage
            or result.get("result") not in _ACS_STAGE_RESULT_BY_STAGE[stage]
            or not self._has_valid_evidence_digest(result)
            or not self._has_valid_evidence_digest(live)
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_revision = plan.get("source_revision")
        reviewed_config = plan.get("inputs", {}).get("deployment_config")
        if not isinstance(source_revision, dict) or not isinstance(reviewed_config, str):
            raise DeploymentUnavailable("deployment plan storage is malformed")
        expected_commit = source_revision.get("commit_sha")
        expected_config_digest = "sha256:" + hashlib.sha256(reviewed_config.encode("utf-8")).hexdigest()
        expected_workflow_run = {"run_id": str(run_id), "run_attempt": str(run_attempt)}
        if (
            not isinstance(expected_commit, str)
            or result.get("reviewed_commit_sha") != expected_commit
            or live.get("reviewed_commit_sha") != expected_commit
            or result.get("reviewed_deployment_digest") != expected_config_digest
            or live.get("reviewed_deployment_digest") != expected_config_digest
            or result.get("deployment_request_id") != plan.get("correlation_id")
            or result.get("workflow_run") != expected_workflow_run
            or live.get("workflow_run") != expected_workflow_run
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        for timestamp_key, evidence in (("recorded_at", result), ("observed_at", live)):
            raw_timestamp = evidence.get(timestamp_key)
            try:
                timestamp = datetime.fromisoformat(str(raw_timestamp).replace("Z", "+00:00"))
            except ValueError:
                raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
            now = self._clock()
            if (
                timestamp.tzinfo is None
                or timestamp > now + timedelta(minutes=5)
                or now - timestamp.astimezone(UTC) > timedelta(seconds=MAX_ACS_EVIDENCE_AGE_SECONDS)
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        reviewed_values = plan.get("reviewed_values")
        if not isinstance(reviewed_values, dict):
            raise DeploymentUnavailable("deployment plan storage is malformed")
        subscription_id = str(reviewed_values.get("subscription_id", "")).lower()
        tenant_id = str(reviewed_values.get("entra_tenant_id", "")).lower()
        if (
            live.get("subscription_id") != subscription_id
            or live.get("tenant_id") != tenant_id
            or live.get("resource_mode") != reviewed_values.get("acs_resource_mode")
            or live.get("api_version") != "2023-04-01"
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        statuses = live.get("statuses")
        if (
            not isinstance(statuses, dict)
            or set(statuses) != {"domain", "spf", "dkim", "dkim2", "sender", "association"}
            or any(value not in _ACS_STATUS_VALUES for value in statuses.values())
            or (
                stage in {"foundation_finalize", "workloads"}
                and any(statuses[key] != "verified" for key in ("domain", "spf", "dkim", "dkim2"))
            )
            or (stage == "workloads" and any(statuses[key] != "verified" for key in ("sender", "association")))
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        resource_ids = live.get("resource_ids")
        if not isinstance(resource_ids, dict) or set(resource_ids) not in (
            set(),
            {"communication_service_id", "email_service_id", "email_domain_id", "sender_username_id"},
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        if stage != "foundation_bootstrap" and not resource_ids:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        for resource_id in resource_ids.values():
            if (
                not isinstance(resource_id, str)
                or not 1 <= len(resource_id) <= 512
                or not resource_id.lower().startswith(f"/subscriptions/{subscription_id}/resourcegroups/")
                or any(character in resource_id for character in "?#\r\n")
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        if resource_ids:
            domain_id = str(resource_ids["email_domain_id"])
            sender_id = str(resource_ids["sender_username_id"])
            if (
                not domain_id.lower().endswith(f"/domains/{str(reviewed_values.get('acs_sending_domain', '')).lower()}")
                or not sender_id.lower().endswith(
                    f"/senderusernames/{str(reviewed_values.get('acs_sender_local_part', '')).lower()}"
                )
                or not sender_id.lower().startswith(f"{domain_id.lower()}/")
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
            if reviewed_values.get("acs_resource_mode") == "existing" and (
                str(resource_ids["communication_service_id"]).lower()
                != str(reviewed_values.get("acs_existing_communication_service_id", "")).lower()
                or domain_id.lower() != str(reviewed_values.get("acs_existing_email_domain_id", "")).lower()
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        scope_limits = live.get("scope_limits")
        expected_scope_keys = {
            "dns_provider_state_only",
            "inbox_placement_proven",
            "event_grid_delivery_proven",
            "human_mailbox_validation_proven",
        }
        if (
            not isinstance(scope_limits, dict)
            or set(scope_limits) != expected_scope_keys
            or scope_limits.get("dns_provider_state_only") is not True
            or any(scope_limits.get(key) is not False for key in expected_scope_keys - {"dns_provider_state_only"})
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        claims = result.get("claims")
        claim_keys = {
            "domain_verification_proven",
            "association_proven",
            "sender_proven",
            "workloads_deployed",
            "receipt_subscription_activated",
            "mail_delivery_proven",
            "inbox_placement_proven",
            "human_mailbox_validation_proven",
        }
        if (
            not isinstance(claims, dict)
            or set(claims) != claim_keys
            or any(not isinstance(value, bool) for value in claims.values())
            or any(
                claims[key] is not False
                for key in {"mail_delivery_proven", "inbox_placement_proven", "human_mailbox_validation_proven"}
            )
            or (
                stage == "foundation_finalize"
                and any(
                    claims[key] is not True
                    for key in {"domain_verification_proven", "association_proven", "sender_proven"}
                )
            )
            or (
                stage == "workloads"
                and any(
                    claims[key] is not True
                    for key in {
                        "domain_verification_proven",
                        "association_proven",
                        "sender_proven",
                        "workloads_deployed",
                        "receipt_subscription_activated",
                    }
                )
            )
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_digests = result.get("source_evidence_digests")
        expected_source_keys = {
            "foundation_bootstrap": {"acs_live_readiness", "acs_verification_initiation"},
            "foundation_finalize": {"acs_live_readiness", "acs_finalize_readback"},
            "workloads": {"acs_live_readiness"},
        }[stage]
        if (
            not isinstance(source_digests, dict)
            or set(source_digests) != expected_source_keys
            or any(
                not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None
                for value in source_digests.values()
            )
            or source_digests.get("acs_live_readiness") != live.get("evidence_digest")
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        stage_source = bundle.get("stage_source")
        if stage == "foundation_bootstrap":
            expected_source_digest = source_digests["acs_verification_initiation"]
            if (
                not isinstance(stage_source, dict)
                or set(stage_source)
                != {
                    "schema",
                    "recorded_at",
                    "result",
                    "phase",
                    "resource_mode",
                    "subscription_id",
                    "tenant_id",
                    "email_domain_id",
                    "api_version",
                    "verification_types",
                    "verification_state",
                    "dns_guidance_status",
                    "reviewed_commit_sha",
                    "reviewed_deployment_digest",
                    "deployment_request_id",
                    "workflow_run",
                    "scope_limits",
                    "evidence_digest",
                }
                or stage_source.get("schema") != "kp.acs-verification-initiation.v1"
                or stage_source.get("phase") != stage
                or stage_source.get("resource_mode") != reviewed_values.get("acs_resource_mode")
                or stage_source.get("subscription_id") != subscription_id
                or stage_source.get("tenant_id") != tenant_id
                or stage_source.get("api_version") != "2023-04-01"
                or stage_source.get("reviewed_commit_sha") != expected_commit
                or stage_source.get("reviewed_deployment_digest") != expected_config_digest
                or stage_source.get("deployment_request_id") != plan.get("correlation_id")
                or stage_source.get("workflow_run") != expected_workflow_run
                or not self._has_valid_evidence_digest(stage_source)
                or stage_source.get("evidence_digest") != expected_source_digest
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
            initiation_result = stage_source.get("result")
            verification_types = stage_source.get("verification_types")
            if (
                (
                    initiation_result == "accepted_pending_control_plane_verification"
                    and verification_types != ["Domain", "SPF", "DKIM", "DKIM2"]
                )
                or (
                    initiation_result
                    in {
                        "already_verified_by_authenticated_readback_no_mutation",
                        "not_applicable_existing_resource_no_mutation",
                    }
                    and verification_types != []
                )
                or initiation_result
                not in {
                    "accepted_pending_control_plane_verification",
                    "already_verified_by_authenticated_readback_no_mutation",
                    "not_applicable_existing_resource_no_mutation",
                }
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        elif stage == "foundation_finalize":
            expected_source_digest = source_digests["acs_finalize_readback"]
            if (
                not isinstance(stage_source, dict)
                or stage_source.get("schema") != "kp.acs-finalize-readback.v1"
                or stage_source.get("phase") != stage
                or stage_source.get("result") != "foundation_finalized"
                or stage_source.get("subscription_id") != subscription_id
                or stage_source.get("tenant_id") != tenant_id
                or stage_source.get("reviewed_commit_sha") != expected_commit
                or stage_source.get("reviewed_deployment_digest") != expected_config_digest
                or stage_source.get("workflow_run") != expected_workflow_run
                or stage_source.get("association") != "verified_exact_single_match"
                or stage_source.get("sender") != "verified_exact_readback"
                or stage_source.get("verification")
                != {"domain": "verified", "spf": "verified", "dkim": "verified", "dkim2": "verified"}
                or not self._has_valid_evidence_digest(stage_source)
                or stage_source.get("evidence_digest") != expected_source_digest
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
            finalized_ids = stage_source.get("resource_ids")
            if not isinstance(finalized_ids, dict) or any(
                finalized_ids.get(key) != resource_ids.get(key)
                for key in ("communication_service_id", "email_domain_id", "sender_username_id")
            ):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        elif stage_source is not None:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        dns_status = (
            "provider_verified" if claims.get("domain_verification_proven") is True else "publish_four_provider_records"
        )
        return {
            "status": "verified",
            "schema": ACS_EVIDENCE_ARTIFACT_SCHEMA,
            "deployment_stage": stage,
            "result": result["result"],
            "observed_at": live["observed_at"],
            "dns_status": dns_status,
            "statuses": statuses,
            "resource_ids": resource_ids,
            "scope_limits": scope_limits,
            "claims": claims,
            "evidence_digest": result["evidence_digest"],
            "source_evidence_digests": source_digests,
            "artifact_sha256": artifact_digest,
            "run_id": run_id,
            "run_attempt": run_attempt,
        }

    @staticmethod
    def _same_revision(reviewed: Any, current: dict[str, Any]) -> bool:
        if not isinstance(reviewed, dict):
            return False
        reviewed_digest = hashlib.sha256(
            json.dumps(reviewed, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        current_digest = hashlib.sha256(
            json.dumps(current, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return secrets.compare_digest(reviewed_digest, current_digest)

    @staticmethod
    def _run_matches_plan(run: dict[str, Any], plan: dict[str, Any]) -> bool:
        source_revision = plan.get("source_revision")
        if not isinstance(source_revision, dict):
            return False
        workflow_id = source_revision.get("workflow_id")
        commit_sha = source_revision.get("commit_sha")
        return (
            isinstance(workflow_id, int)
            and not isinstance(workflow_id, bool)
            and isinstance(commit_sha, str)
            and run.get("event") == "workflow_dispatch"
            and run.get("workflow_id") == workflow_id
            and isinstance(run.get("head_sha"), str)
            and secrets.compare_digest(str(run["head_sha"]), commit_sha)
        )

    @staticmethod
    def _retry_allowed(plan: dict[str, Any]) -> bool:
        checkpoints = plan.get("checkpoints")
        final = checkpoints[-1] if isinstance(checkpoints, list) and checkpoints else None
        return bool(
            plan.get("state") == "dispatch_failed"
            and plan.get("run_id") is None
            and isinstance(final, dict)
            and final.get("phase") == "dispatch_rejected"
            and final.get("evidence") == {"retry_safe": True}
        )

    @staticmethod
    def _stage_contract(plan: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        inputs = plan.get("inputs")
        stage = str(inputs.get("deployment_phase", "")) if isinstance(inputs, dict) else ""
        state = str(plan.get("state", ""))
        evidence = plan.get("acs_evidence")
        evidence_verified = bool(
            isinstance(evidence, dict)
            and evidence.get("status") == "verified"
            and evidence.get("deployment_stage") == stage
        )
        ordinal = DEPLOYMENT_STAGES.index(stage) + 1 if stage in DEPLOYMENT_STAGES else 0
        completed = state == "workflow_succeeded" and evidence_verified
        stage_status = {
            "deployment_stage": stage if stage in DEPLOYMENT_STAGES else "unknown",
            "ordinal": ordinal,
            "total": len(DEPLOYMENT_STAGES),
            "workflow_state": state,
            "evidence_status": evidence.get("status", "evidence_unverified")
            if isinstance(evidence, dict)
            else "evidence_unverified",
            "completed": completed,
        }
        next_stage = _NEXT_DEPLOYMENT_STAGE.get(stage)
        if completed and next_stage is None:
            stage_action = {
                "kind": "complete",
                "enabled": False,
                "label": "Deployment stages complete",
                "next_stage": None,
            }
        elif (
            completed
            and next_stage == "workloads"
            and isinstance(inputs, dict)
            and inputs.get("network_mode") != "private"
        ):
            stage_action = {
                "kind": "review_required",
                "enabled": False,
                "label": "Review private network configuration before workloads",
                "next_stage": next_stage,
            }
        elif completed and next_stage is not None:
            stage_action = {
                "kind": "advance",
                "enabled": True,
                "label": f"Review {next_stage.replace('_', ' ')}",
                "next_stage": next_stage,
            }
        elif state == "reviewed":
            stage_action = {
                "kind": "dispatch",
                "enabled": True,
                "label": "Dispatch this reviewed stage",
                "next_stage": None,
            }
        elif state in {"queued", "running", "dispatching", "dispatch_accepted"}:
            stage_action = {
                "kind": "wait",
                "enabled": False,
                "label": "Wait for this stage and refresh status",
                "next_stage": None,
            }
        else:
            stage_action = {
                "kind": "reconcile",
                "enabled": False,
                "label": "Reconcile this stage before continuing",
                "next_stage": None,
            }
        return stage_status, stage_action

    @staticmethod
    def _public_plan(plan: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "plan_id",
            "review_digest",
            "created_at",
            "expires_at",
            "state",
            "attempt",
            "run_id",
            "run",
            "activity",
            "activity_available",
            "last_error",
            "workflow_url",
            "workflow",
            "repository",
            "ref",
            "source_revision",
            "terraform_state_identity",
            "inputs",
            "review",
            "external_prerequisites",
            "limitations",
            "correlation_id",
            "checkpoints",
            "recovery",
            "acs_evidence",
            "stage_predecessor",
        }
        public = {key: value for key, value in plan.items() if key in allowed}
        stored_inputs = public.get("inputs")
        if isinstance(stored_inputs, dict):
            public["inputs"] = {
                "environment": stored_inputs.get("environment"),
                "network_mode": stored_inputs.get("network_mode"),
                "deployment_stage": stored_inputs.get("deployment_phase"),
            }
        last_error = public.get("last_error")
        if last_error is not None and (not isinstance(last_error, str) or last_error not in _PUBLIC_PLAN_ERRORS):
            public["last_error"] = PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE
        state = str(public.get("state", ""))
        retry_allowed = DeploymentOrchestrator._retry_allowed(plan)
        reconcile_only = state in {
            "dispatching",
            "dispatch_accepted",
            "dispatch_indeterminate",
            "queued",
            "running",
            "run_failed",
            "evidence_unverified",
        } or (state == "dispatch_failed" and not retry_allowed)
        public["operator_action"] = {
            "next_action": _NEXT_ACTIONS.get(
                state,
                "Refresh this plan and inspect the protected workflow; do not retry or clean up resources.",
            ),
            "retry_allowed": retry_allowed,
            "reconcile_only": reconcile_only,
            "destructive_cleanup_allowed": False,
        }
        public["stage_status"], public["stage_action"] = DeploymentOrchestrator._stage_contract(plan)
        return public
