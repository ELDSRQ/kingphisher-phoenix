"""Narrow GitHub Actions orchestration for the reviewed Azure workflow.

The browser never supplies a command, path, repository, ref, workflow name, or
credential.  It can only review the fixed workflow inputs declared here and ask
the server to dispatch the checked-in ``azure-deploy.yml`` workflow.  GitHub's
protected environment remains the final approval boundary.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import secrets
import threading
import uuid
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

import httpx
import redis

WORKFLOW_FILE = "azure-deploy.yml"
WORKFLOW_PATH = ".github/workflows/azure-deploy.yml"
PLAN_TTL_SECONDS = 24 * 60 * 60
ACTIVE_TTL_SECONDS = PLAN_TTL_SECONDS
OPERATION_TTL_SECONDS = 5 * 60
RUNS_PER_PAGE = 100
MAX_RUN_PAGES = 3
MAX_BASELINE_RUNS = RUNS_PER_PAGE * MAX_RUN_PAGES
MAX_ACTIVITY = 160
MAX_STEPS_PER_JOB = 96
MAX_DEPLOYMENT_ATTEMPTS = 8
CHECKPOINT_RESERVE_PER_ATTEMPT = 8
CORRELATION_PREFIX = "kp"
MAX_WORKFLOW_BYTES = 256 * 1024
MAX_GITHUB_METADATA_BYTES = 1024 * 1024
MAX_GITHUB_STATUS_BYTES = 256 * 1024
MAX_GITHUB_ACTIVITY_BYTES = 512 * 1024
MAX_DEPLOYMENT_CONFIG_BYTES = 32 * 1024
MAX_PLAN_BYTES = 128 * 1024
MAX_CHECKPOINTS = 64
MAX_ACS_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_ACS_EVIDENCE_BYTES = 16 * 1024
MAX_ACS_EVIDENCE_AGE_SECONDS = 24 * 60 * 60
# Updated only when the fixed workflow and connector contract are reviewed
# together. A repository ref that resolves to any other content is not ready.
EXPECTED_WORKFLOW_SHA256 = "6868067ef5d58c799bc4a07dd832d4852d38dee73e6ff1af9a58c701ce85a4d3"
REQUIRED_WORKFLOW_INPUTS = frozenset(
    {
        "environment",
        "network_mode",
        "deployment_phase",
        "deployment_config",
        "deployment_request_id",
        "reviewed_commit_sha",
    }
)
DEPLOYMENT_CONFIG_KEYS = (
    "subscription_id",
    "location",
    "name_prefix",
    "operator_fqdn",
    "tracking_fqdn",
    "entra_tenant_id",
    "entra_client_id",
    "acs_resource_mode",
    "acs_existing_communication_service_id",
    "acs_existing_email_endpoint",
    "acs_existing_email_domain_id",
    "acs_sending_domain",
    "acs_sender_local_part",
    "acs_sender_display_name",
    "acs_dns_zone_id",
    "acs_daily_message_limit",
    "acs_messages_per_minute",
    "acs_ramp_batch_size",
    "acs_ramp_interval_seconds",
    "communication_data_location",
    "ai_endpoint",
    "enable_directory_sync",
    "directory_group_ids",
    "enable_reported_mailbox",
    "reported_mailbox_address",
    "reported_mailbox_folder",
    "alert_webhook_domains",
    "allowed_recipient_domains",
    "ciphertext_active_key_id",
    "ciphertext_prior_key_ids",
    "ciphertext_prior_keys_secret_id",
)
# These values are workflow-internal defensive defaults. They can never be
# supplied by a browser, AI assistant, export, or caller-controlled allowlist.
# Only authenticated Azure control-plane readback may replace them.
INTERNAL_ACS_CONFIG_DEFAULTS = {
    "acs_domain_verification_status": "pending_live_readback",
    "acs_spf_verification_status": "pending_live_readback",
    "acs_dkim_verification_status": "pending_live_readback",
    "acs_dkim2_verification_status": "pending_live_readback",
    "acs_sender_username_status": "pending_live_readback",
    "acs_domain_association_status": "pending_live_readback",
    "acs_readiness_checked_at": "",
}
DEPLOYMENT_STAGES = ("foundation_bootstrap", "foundation_finalize", "workloads")
_NEXT_DEPLOYMENT_STAGE = {
    "foundation_bootstrap": "foundation_finalize",
    "foundation_finalize": "workloads",
}
ACS_EVIDENCE_ARTIFACT_SCHEMA = "kp.acs-stage-result.v1"
ACS_EVIDENCE_ARTIFACT_PATH = "acs-stage-result.json"
ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS = frozenset(
    {
        "acs-live-readiness.json",
        "acs-verification-initiation.json",
        "acs-finalize-readback.json",
        "acs-stage-result.json",
        "checkpoints.ndjson",
    }
)
_ACS_STAGE_RESULT_BY_STAGE = {
    "foundation_bootstrap": frozenset(
        {
            "foundation_bootstrap_pending_dns",
            "foundation_bootstrap_already_verified_no_mutation",
            "foundation_bootstrap_existing_resource_no_mutation",
        }
    ),
    "foundation_finalize": frozenset({"foundation_finalized"}),
    "workloads": frozenset({"workloads_deployed"}),
}
_ACS_STATUS_VALUES = frozenset(
    {
        "not_observed",
        "not_linked",
        "notstarted",
        "verificationrequested",
        "verificationinprogress",
        "verificationfailed",
        "verified",
    }
)
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_REF = re.compile(r"[A-Za-z0-9._/-]{1,255}\Z")
_PLAN_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_GITHUB_TOKEN = re.compile(r"[A-Za-z0-9_-]{20,512}\Z")
_CIPHERTEXT_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_VERSIONLESS_KEY_VAULT_SECRET_ID = re.compile(
    r"/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/Microsoft\.KeyVault/"
    r"vaults/[A-Za-z0-9-]{3,24}/secrets/[A-Za-z0-9-]{1,127}\Z",
    re.IGNORECASE,
)
_TERMINAL_FAILURES = frozenset({"failure", "cancelled", "timed_out", "action_required", "stale"})
_TERMINAL_RESULTS = _TERMINAL_FAILURES | {"success", "neutral", "skipped"}
_RUN_STATUSES = frozenset({"queued", "in_progress", "completed", "waiting", "requested", "pending"})
_ACTIVITY_STATUSES = _RUN_STATUSES | {"unknown"}
_JSON_CONTENT_TYPE = re.compile(r"application/(?:json|[A-Za-z0-9!#$&^_.+-]+\+json)\Z", re.IGNORECASE)
_SENSITIVE_ACTIVITY = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=])",
    re.IGNORECASE,
)
_SENSITIVE_DEPLOYMENT_VALUE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|"
    r"(?:password|secret|token|api[_-]?key|authorization|accountkey)\s*[:=]\s*\S+|"
    r"bearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)

# Deployment recovery is deliberately preservation-first.  These values are
# returned as reviewed, machine-readable policy; they are not shell commands
# and the connector has no cleanup primitive.
PRESERVATION_REQUIRED_ASSETS = (
    "working_tree",
    "python_environment",
    "terraform_provider_cache",
    "container_images",
    "compose_containers",
    "build_cache",
    "named_volumes",
    "databases",
    "runtime_state",
    "qualification_evidence",
)
PROHIBITED_AUTOMATIC_ACTIONS = (
    "delete_files",
    "prune_build_cache",
    "remove_images",
    "remove_containers",
    "remove_volumes",
    "drop_databases",
    "compose_down",
    "reset_working_tree",
)
RECOVERY_EVIDENCE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "disk": (
        "free_bytes_before_build",
        "required_bytes_estimate",
        "capacity_decision",
    ),
    "runtime": (
        "container_runtime_available",
        "container_runtime_writable",
        "runtime_version",
    ),
    "images": (
        "required_image_references",
        "required_image_digests",
        "missing_images_rebuild_plan",
    ),
    "platform": (
        "runner_operating_system",
        "runner_architecture",
        "target_platform",
    ),
    "volumes": (
        "required_named_volumes",
        "volume_presence",
        "preservation_decision",
    ),
    "databases": (
        "required_databases",
        "schema_revision",
        "backup_or_recovery_evidence",
        "preservation_decision",
    ),
}
QUALIFICATION_JOB = "Qualify source and release gates"
GUARD_JOB = "Guard reviewed deployment inputs"
DEPLOY_JOB = "Deploy reviewed Azure phase"
_COMMON_RECOVERY_STEPS = (
    (QUALIFICATION_JOB, "Record runner disk headroom before qualification"),
    (QUALIFICATION_JOB, "Required hermetic no-skip suite"),
    (QUALIFICATION_JOB, "Validate Terraform without a backend"),
    (QUALIFICATION_JOB, "Upload qualification recovery evidence"),
    (GUARD_JOB, "Validate opaque deployment request correlation"),
    (GUARD_JOB, "Refuse source drift after GUI review"),
    (GUARD_JOB, "Record selected mode"),
    (DEPLOY_JOB, "Initialize append-only deployment checkpoint"),
    (DEPLOY_JOB, "Validate and materialize reviewed deployment values"),
    (DEPLOY_JOB, "Checkpoint reviewed configuration"),
    (DEPLOY_JOB, "Authenticate to Azure"),
    (DEPLOY_JOB, "Checkpoint Azure authentication"),
    (DEPLOY_JOB, "Initialize Terraform"),
    (DEPLOY_JOB, "Checkpoint Terraform state identity"),
    (DEPLOY_JOB, "Validate ciphertext key-rotation lifecycle metadata"),
    (DEPLOY_JOB, "Read ACS readiness from the authenticated Azure control plane"),
    (DEPLOY_JOB, "Checkpoint live ACS control-plane observation"),
    (DEPLOY_JOB, "Summarize"),
    (DEPLOY_JOB, "Checkpoint conclusive ACS stage result"),
    (DEPLOY_JOB, "Record completed cloud operations"),
    (DEPLOY_JOB, "Upload append-only deployment recovery evidence"),
)
_FOUNDATION_BOOTSTRAP_RECOVERY_STEPS = (
    (DEPLOY_JOB, "Plan ACS foundation bootstrap"),
    (DEPLOY_JOB, "Enforce ACS foundation bootstrap plan allowlist"),
    (DEPLOY_JOB, "Checkpoint allowlisted foundation bootstrap plan"),
    (DEPLOY_JOB, "Apply ACS foundation bootstrap"),
    (DEPLOY_JOB, "Checkpoint ACS foundation bootstrap apply"),
    (DEPLOY_JOB, "Publish non-secret integration bootstrap plan"),
    (DEPLOY_JOB, "Checkpoint integration bootstrap plan"),
    (DEPLOY_JOB, "Initiate pending ACS customer-domain verification"),
    (DEPLOY_JOB, "Checkpoint ACS verification initiation"),
)
_FOUNDATION_FINALIZE_RECOVERY_STEPS = (
    (DEPLOY_JOB, "Plan ACS foundation finalize"),
    (DEPLOY_JOB, "Enforce ACS foundation finalize plan allowlist"),
    (DEPLOY_JOB, "Checkpoint allowlisted foundation finalize plan"),
    (DEPLOY_JOB, "Apply ACS foundation finalize"),
    (DEPLOY_JOB, "Checkpoint ACS foundation finalize apply"),
    (DEPLOY_JOB, "Prove finalized ACS association and sender from Azure"),
    (DEPLOY_JOB, "Checkpoint finalized ACS readback"),
)
_WORKLOAD_RECOVERY_STEPS = (
    (QUALIFICATION_JOB, "Required PostgreSQL integration gate"),
    (QUALIFICATION_JOB, "Required Redis integration gate"),
    (QUALIFICATION_JOB, "Required fresh-migration gate"),
    (QUALIFICATION_JOB, "Build and start every release image"),
    (QUALIFICATION_JOB, "Scan the built release images"),
    (DEPLOY_JOB, "Build immutable images in the registry"),
    (DEPLOY_JOB, "Verify registry attestations before deployment"),
    (DEPLOY_JOB, "Checkpoint verified immutable images"),
    (DEPLOY_JOB, "Plan workloads"),
    (DEPLOY_JOB, "Refuse destructive workload changes"),
    (DEPLOY_JOB, "Checkpoint non-destructive workload plan"),
    (DEPLOY_JOB, "Apply workloads"),
    (DEPLOY_JOB, "Checkpoint workload apply"),
    (DEPLOY_JOB, "Migrate and qualify"),
    (DEPLOY_JOB, "Checkpoint migration and health qualification"),
    (DEPLOY_JOB, "Plan ACS receipt subscription activation"),
    (DEPLOY_JOB, "Refuse unrelated changes in receipt activation plan"),
    (DEPLOY_JOB, "Checkpoint non-destructive receipt plan"),
    (DEPLOY_JOB, "Activate ACS receipt subscription after readiness"),
    (DEPLOY_JOB, "Verify ACS Event Grid subscription"),
    (DEPLOY_JOB, "Checkpoint verified receipt activation"),
    (DEPLOY_JOB, "Remove ephemeral registry credentials"),
)
_CHECKPOINT_EVIDENCE_FIELDS = {
    "plan_reviewed": frozenset({"review_digest", "source_revision_digest"}),
    "dispatch_intent_saved": frozenset({"baseline_run_count", "retry"}),
    "dispatch_blocked": frozenset({"reason"}),
    "audit_evidence_committed": frozenset(),
    "review_invalidated": frozenset({"reason"}),
    "source_revalidated": frozenset({"source_revision_digest"}),
    "dispatch_rejected": frozenset({"retry_safe"}),
    "dispatch_indeterminate": frozenset({"retry_safe"}),
    "dispatch_interrupted": frozenset({"retry_safe"}),
    "dispatch_accepted": frozenset({"retry_safe"}),
    "reconciliation_blocked": frozenset({"reason"}),
    "run_linked": frozenset({"run_id"}),
    "workflow_failed": frozenset({"run_id", "conclusion", "retry_safe"}),
    "workflow_evidence_unverified": frozenset({"run_id", "reason"}),
    "workflow_succeeded": frozenset({"run_id"}),
    "workflow_status_observed": frozenset({"run_id", "status"}),
}
_CHECKPOINT_REASONS = frozenset(
    {
        "audit_evidence_unavailable",
        "preflight_unavailable",
        "source_revision_drift",
        "exclusivity_lost",
        "identity_changed",
        "ambiguous_runs",
        "correlation_changed",
        "required_activity_unverified",
    }
)

_NEXT_ACTIONS = {
    "reviewed": "Review the preservation and preflight evidence requirements, then approve this plan.",
    "dispatching": "Refresh this plan to reconcile the existing request; do not retry or clean up resources.",
    "dispatch_accepted": "Refresh this plan while GitHub links the existing run; do not dispatch again.",
    "dispatch_indeterminate": (
        "Inspect GitHub Actions for the displayed correlation ID, then refresh; do not retry or clean up resources."
    ),
    "queued": "Wait for protected-environment approval, then refresh this plan.",
    "running": "Allow the existing protected workflow to finish, then refresh this plan.",
    "dispatch_failed": "Reconcile the confirmed pre-dispatch result; retry is available only for a rejected dispatch.",
    "run_failed": (
        "Review the linked GitHub run and reconcile Azure and Terraform state; do not dispatch this plan again."
    ),
    "evidence_unverified": (
        "The run reported success but required pinned workflow steps were not verified; inspect the run and reconcile "
        "Azure and Terraform state."
    ),
    "review_required": "Create and review a new plan; preserve this plan and its evidence for audit.",
    "workflow_succeeded": (
        "Verify the live Azure resources and required recovery evidence before declaring deployment complete."
    ),
}


class DeploymentUnavailable(RuntimeError):
    """The reviewed workflow connector is not configured or reachable."""


class DeploymentConflict(RuntimeError):
    """The requested transition could duplicate or overlap a deployment."""


class DispatchRejected(RuntimeError):
    """GitHub conclusively rejected the dispatch before it was accepted."""


class DispatchIndeterminate(RuntimeError):
    """The dispatch may have reached GitHub; retrying could duplicate it."""


PUBLIC_DEPLOYMENT_UNAVAILABLE = (
    "GUI deployment is unavailable; review the protected GitHub Actions connector configuration and retry"
)
PUBLIC_DEPLOYMENT_CONFLICT = (
    "the deployment request cannot be completed in its current state; refresh and review the plan"
)
PUBLIC_DEPLOYMENT_STATUS_UNAVAILABLE = (
    "Deployment status details are unavailable; inspect the protected GitHub Actions workflow"
)

# These are the only exception messages allowed to cross the GUI boundary.
# Each value is fixed by this module; provider responses and arbitrary exception
# strings are deliberately excluded.
_PUBLIC_UNAVAILABLE_MESSAGES = frozenset(
    {
        "GUI deployment dispatch is disabled; configure the protected GitHub Actions connector",
        "the server-side GitHub repository is missing or invalid",
        "the server-side GitHub workflow ref is missing or invalid",
        "the server-side GitHub workflow credential is missing or invalid",
        "the server-side GitHub API origin is invalid",
        "the fixed workflow environment is invalid",
        "GitHub configured deployment ref metadata is malformed",
        "GitHub deployment workflow path does not match the fixed connector",
        "the fixed GitHub deployment workflow is disabled",
        "GitHub deployment workflow metadata is malformed",
        "GitHub deployment workflow content metadata is malformed",
        "GitHub deployment workflow content is malformed",
        "GitHub deployment workflow content size is inconsistent",
        "the configured ref does not contain the reviewed deployment workflow",
        "the fixed deployment workflow input contract is incomplete",
        "GitHub protected environment metadata is malformed",
        "GitHub protected environment reviewer metadata is malformed",
        "GitHub protected environment wait timer metadata is malformed",
        "GitHub protected environment branch policy metadata is malformed",
        "GitHub workflow status is unavailable",
        "GitHub workflow status is malformed",
        "GitHub workflow run status is unavailable",
        "GitHub workflow run status is malformed",
        "GitHub workflow activity is unavailable",
        "GitHub returned an invalid workflow run",
        "deployment plan storage is unavailable",
        "deployment plan storage is malformed",
        *{
            message
            for purpose in (
                "configured deployment ref",
                "deployment workflow",
                "deployment workflow content",
                "protected staging environment",
                "protected production environment",
                "protected staging environment variables",
                "protected production environment variables",
            )
            for message in (
                f"GitHub {purpose} is unavailable",
                f"the GitHub connector cannot inspect {purpose}; verify read permissions",
                f"GitHub {purpose} is missing or is not visible to the connector",
                f"GitHub {purpose} metadata exceeds the connector limit",
                f"GitHub {purpose} metadata is malformed",
            )
        },
        *{
            message
            for environment in ("staging", "production")
            for message in (
                f"the GitHub {environment} environment allows administrator approval bypass",
                f"the GitHub {environment} environment has no required reviewer protection",
                f"the GitHub {environment} environment allows reviewer self-approval",
                f"the GitHub {environment} environment has no deployment branch protection",
            )
        },
    }
)

_PUBLIC_CONFLICT_MESSAGES = frozenset(
    {
        "the reviewed deployment digest does not match",
        "retry is allowed only after GitHub rejected a dispatch before creating a run",
        "this reviewed plan has already been submitted",
        "The stored plan lacks reviewed source evidence; create and review a new plan",
        "this deployment attempt was already submitted",
        "this deployment plan is currently being updated; refresh and retry",
        "GitHub workflow, ref, or protected environment drifted; create and review a new plan",
        "invalid deployment plan identifier",
        "deployment plan is missing or expired",
        "deployment plans may be used only by the administrator who reviewed them",
        "deployment values must not contain credentials or tokens",
        "deployment configuration exceeds the fixed workflow limit",
        "ciphertext recovery metadata is invalid",
        "deployment network mode is invalid for the reviewed environment and phase",
        "reviewed Terraform state identity does not match the protected environment",
        "deployment plan has reached its safe attempt or checkpoint limit; create and review a new plan",
        *{f"another {environment} deployment is active" for environment in ("staging", "production")},
    }
)

_PUBLIC_PLAN_ERRORS = frozenset(
    {
        "Audit evidence could not be committed; no workflow was dispatched",
        "GitHub preflight became unavailable; no workflow was dispatched",
        "GitHub workflow, ref, or protected environment drifted; create and review a new plan",
        "GitHub conclusively rejected the workflow dispatch; correct access and retry",
        "Dispatch outcome is unknown; inspect GitHub Actions and do not retry this plan",
        "Multiple new workflow runs exist; inspect GitHub Actions before any retry",
        "The linked workflow correlation changed; inspect GitHub Actions",
        "The linked workflow identity changed; inspect GitHub Actions",
        "Deployment exclusivity was lost; inspect GitHub Actions before continuing",
        "The protected workflow ended unsuccessfully; review its GitHub evidence before retrying",
        "The protected workflow ended unsuccessfully; reconcile its evidence and Azure state without retrying",
        "The workflow reported success but required pinned job or step evidence is unavailable or incomplete",
        "The prior operation stopped before workflow dispatch; reconcile its checkpoints without redispatching",
        "The stored plan lacks reviewed source evidence; create and review a new plan",
    }
)


def public_deployment_error(exc: DeploymentUnavailable | DeploymentConflict) -> str:
    """Return only reviewed operator guidance for a deployment exception."""

    message = str(exc)
    if type(exc) is DeploymentUnavailable and message in _PUBLIC_UNAVAILABLE_MESSAGES:
        return message
    if type(exc) is DeploymentConflict and message in _PUBLIC_CONFLICT_MESSAGES:
        return message
    if isinstance(exc, DeploymentConflict):
        return PUBLIC_DEPLOYMENT_CONFLICT
    return PUBLIC_DEPLOYMENT_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class WorkflowPreflight:
    """Security-relevant GitHub metadata bound into a reviewed plan."""

    commit_sha: str
    workflow_id: int
    workflow_blob_sha: str
    workflow_content_sha256: str
    environment_metadata_sha256: str
    environment: str
    required_reviewer_count: int
    admin_bypass_allowed: bool
    deployment_branch_policy_present: bool
    tf_state_resource_group: str
    tf_state_storage_account: str
    tf_state_container: str

    def review_payload(self) -> dict[str, Any]:
        return {
            "commit_sha": self.commit_sha,
            "workflow_id": self.workflow_id,
            "workflow_blob_sha": self.workflow_blob_sha,
            "workflow_content_sha256": self.workflow_content_sha256,
            "workflow_state": "active",
            "workflow_path": WORKFLOW_PATH,
            "input_contract": "exact_pinned_workflow_content",
            "environment": self.environment,
            "environment_metadata_sha256": self.environment_metadata_sha256,
            "required_reviewer_count": self.required_reviewer_count,
            "admin_bypass_allowed": self.admin_bypass_allowed,
            "deployment_branch_policy_present": self.deployment_branch_policy_present,
            "terraform_state_identity": {
                "resource_group": self.tf_state_resource_group,
                "storage_account": self.tf_state_storage_account,
                "container": self.tf_state_container,
            },
        }


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


@dataclass(frozen=True)
class WorkflowConfiguration:
    repository: str
    ref: str
    token: str

    @classmethod
    def from_environment(cls) -> WorkflowConfiguration:
        mode = os.getenv("OPERATOR_API_DEPLOYMENT_ORCHESTRATION_MODE", "disabled").strip().lower()
        if mode != "github_actions":
            raise DeploymentUnavailable(
                "GUI deployment dispatch is disabled; configure the protected GitHub Actions connector"
            )
        repository = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_REPOSITORY", "").strip()
        ref = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_REF", "main").strip()
        token = os.getenv("OPERATOR_API_DEPLOYMENT_GITHUB_TOKEN", "")
        repository_parts = repository.split("/")
        if _REPOSITORY.fullmatch(repository) is None or any(part in {".", ".."} for part in repository_parts):
            raise DeploymentUnavailable("the server-side GitHub repository is missing or invalid")
        if (
            _REF.fullmatch(ref) is None
            or ref.startswith("/")
            or ref.endswith(("/", ".", ".lock"))
            or ".." in ref
            or "//" in ref
            or any(part.startswith(".") for part in ref.split("/"))
        ):
            raise DeploymentUnavailable("the server-side GitHub workflow ref is missing or invalid")
        if _GITHUB_TOKEN.fullmatch(token) is None:
            raise DeploymentUnavailable("the server-side GitHub workflow credential is missing or invalid")
        return cls(repository=repository, ref=ref, token=token)


class GitHubWorkflowGateway:
    """Fixed-origin GitHub API client; response bodies never cross the boundary."""

    def __init__(self, configuration: WorkflowConfiguration, *, client: httpx.Client | None = None) -> None:
        self.configuration = configuration
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url="https://api.github.com",
            timeout=8.0,
            follow_redirects=False,
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "Authorization": f"Bearer {configuration.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "kingphisher-deployment-orchestrator/1",
            },
        )
        base_url = self._client.base_url
        if (
            base_url.scheme != "https"
            or base_url.host != "api.github.com"
            or base_url.port is not None
            or base_url.userinfo
            or base_url.path != "/"
            or base_url.query
            or base_url.fragment
        ):
            if self._owns_client:
                self._client.close()
            raise DeploymentUnavailable("the server-side GitHub API origin is invalid")
        self._client.headers["Accept-Encoding"] = "identity"

    def close(self) -> None:
        """Close only the HTTP client created by this gateway."""
        if self._owns_client:
            self._client.close()

    @property
    def workflow_url(self) -> str:
        return f"https://github.com/{self.configuration.repository}/actions/workflows/{WORKFLOW_FILE}"

    def _workflow_api(self, suffix: str = "") -> str:
        return f"/repos/{self.configuration.repository}/actions/workflows/{WORKFLOW_FILE}{suffix}"

    def _get_json(
        self,
        path: str,
        *,
        purpose: str,
        params: dict[str, str | int] | None = None,
        max_bytes: int = MAX_GITHUB_METADATA_BYTES,
        unavailable_message: str | None = None,
        malformed_message: str | None = None,
        preserve_access_semantics: bool = True,
    ) -> dict[str, Any]:
        unavailable = unavailable_message or f"GitHub {purpose} is unavailable"
        malformed = malformed_message or f"GitHub {purpose} metadata is malformed"
        try:
            with self._client.stream("GET", path, params=params) as response:
                if preserve_access_semantics and response.status_code in {401, 403}:
                    raise DeploymentUnavailable(
                        f"the GitHub connector cannot inspect {purpose}; verify read permissions"
                    )
                if preserve_access_semantics and response.status_code == 404:
                    raise DeploymentUnavailable(f"GitHub {purpose} is missing or is not visible to the connector")
                if not 200 <= response.status_code < 300:
                    raise DeploymentUnavailable(unavailable)

                content_lengths = response.headers.get_list("content-length")
                if len(content_lengths) > 1:
                    raise DeploymentUnavailable(malformed)
                if content_lengths:
                    declared = content_lengths[0]
                    if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None:
                        raise DeploymentUnavailable(malformed)
                    if int(declared) > max_bytes:
                        raise DeploymentUnavailable(
                            f"GitHub {purpose} metadata exceeds the connector limit"
                            if preserve_access_semantics
                            else unavailable
                        )

                content_encodings = response.headers.get_list("content-encoding")
                if len(content_encodings) > 1 or (
                    content_encodings and content_encodings[0].strip().lower() not in {"", "identity"}
                ):
                    raise DeploymentUnavailable(malformed)
                content_types = response.headers.get_list("content-type")
                if len(content_types) != 1:
                    raise DeploymentUnavailable(malformed)
                media_type = content_types[0].split(";", maxsplit=1)[0].strip()
                if _JSON_CONTENT_TYPE.fullmatch(media_type) is None:
                    raise DeploymentUnavailable(malformed)

                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > max_bytes:
                        raise DeploymentUnavailable(
                            f"GitHub {purpose} metadata exceeds the connector limit"
                            if preserve_access_semantics
                            else unavailable
                        )
                    body.extend(chunk)
        except DeploymentUnavailable:
            raise
        except httpx.HTTPError:
            raise DeploymentUnavailable(unavailable) from None
        try:
            payload = json.loads(bytes(body).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise DeploymentUnavailable(malformed) from None
        if not isinstance(payload, dict):
            raise DeploymentUnavailable(malformed)
        return payload

    @staticmethod
    def _bounded_response_bytes(response: httpx.Response, *, max_bytes: int) -> bytes:
        content_lengths = response.headers.get_list("content-length")
        if len(content_lengths) > 1:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        if content_lengths:
            declared = content_lengths[0]
            if len(declared) > 10 or re.fullmatch(r"[0-9]+", declared) is None or int(declared) > max_bytes:
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        encodings = response.headers.get_list("content-encoding")
        if len(encodings) > 1 or (encodings and encodings[0].strip().lower() not in {"", "identity"}):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > max_bytes:
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
            body.extend(chunk)
        return bytes(body)

    @staticmethod
    def _safe_artifact_redirect(value: str) -> bool:
        try:
            parsed = urlsplit(value)
            host = (parsed.hostname or "").lower()
            return bool(
                parsed.scheme == "https"
                and parsed.port is None
                and parsed.username is None
                and parsed.password is None
                and not parsed.fragment
                and (
                    host == "pipelines.actions.githubusercontent.com"
                    or host.endswith(".actions.githubusercontent.com")
                    or host.endswith(".blob.core.windows.net")
                )
            )
        except ValueError:
            return False

    def _artifact_archive(self, path: str) -> bytes:
        """Download one bounded ZIP without forwarding GitHub credentials cross-origin."""

        try:
            with self._client.stream("GET", path) as response:
                if response.status_code == 200:
                    return self._bounded_response_bytes(response, max_bytes=MAX_ACS_ARTIFACT_BYTES)
                if response.status_code != 302:
                    raise DeploymentUnavailable("GitHub deployment evidence is unavailable")
                locations = response.headers.get_list("location")
                if len(locations) != 1 or not self._safe_artifact_redirect(locations[0]):
                    raise DeploymentUnavailable("GitHub deployment evidence is malformed")
                location = locations[0]
            # Use an isolated client so the GitHub bearer token is never sent to
            # the short-lived object-storage URL.
            with (
                httpx.Client(
                    timeout=8.0,
                    follow_redirects=False,
                    headers={"Accept-Encoding": "identity", "User-Agent": "kingphisher-deployment-orchestrator/1"},
                ) as artifact_client,
                artifact_client.stream("GET", location) as artifact_response,
            ):
                if artifact_response.status_code != 200:
                    raise DeploymentUnavailable("GitHub deployment evidence is unavailable")
                return self._bounded_response_bytes(artifact_response, max_bytes=MAX_ACS_ARTIFACT_BYTES)
        except DeploymentUnavailable:
            raise
        except httpx.HTTPError:
            raise DeploymentUnavailable("GitHub deployment evidence is unavailable") from None

    def acs_evidence_artifact(self, run_id: int, run_attempt: int) -> dict[str, Any]:
        """Return the one exact ACS live-read artifact from a completed workflow attempt."""

        expected_name = f"azure-deployment-evidence-{run_id}-{run_attempt}"
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}/artifacts",
            params={"per_page": 100},
            purpose="deployment evidence",
            max_bytes=MAX_GITHUB_STATUS_BYTES,
            unavailable_message="GitHub deployment evidence is unavailable",
            malformed_message="GitHub deployment evidence is malformed",
            preserve_access_semantics=False,
        )
        artifacts = payload.get("artifacts")
        total_count = payload.get("total_count")
        if (
            not isinstance(artifacts, list)
            or len(artifacts) > 100
            or not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count != len(artifacts)
            or any(not isinstance(item, dict) for item in artifacts)
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        matches = [item for item in artifacts if item.get("name") == expected_name]
        if len(matches) != 1:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        artifact = matches[0]
        artifact_id = artifact.get("id")
        artifact_size = artifact.get("size_in_bytes")
        artifact_digest = artifact.get("digest")
        archive_url = artifact.get("archive_download_url")
        expected_url = (
            f"https://api.github.com/repos/{self.configuration.repository}/actions/artifacts/{artifact_id}/zip"
        )
        if (
            not isinstance(artifact_id, int)
            or isinstance(artifact_id, bool)
            or not 0 < artifact_id <= 2**63 - 1
            or not isinstance(artifact_size, int)
            or isinstance(artifact_size, bool)
            or not 0 < artifact_size <= MAX_ACS_ARTIFACT_BYTES
            or artifact.get("expired") is not False
            or not isinstance(artifact_digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", artifact_digest) is None
            or archive_url != expected_url
        ):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        archive = self._artifact_archive(f"/repos/{self.configuration.repository}/actions/artifacts/{artifact_id}/zip")
        if len(archive) != artifact_size:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        archive_sha256 = f"sha256:{hashlib.sha256(archive).hexdigest()}"
        if not secrets.compare_digest(archive_sha256, artifact_digest):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                members = bundle.infolist()
                names = [member.filename for member in members]
                if (
                    not 1 <= len(members) <= len(ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS)
                    or len(set(names)) != len(names)
                    or ACS_EVIDENCE_ARTIFACT_PATH not in names
                    or any(
                        name not in ACS_EVIDENCE_ARTIFACT_ALLOWED_PATHS
                        or member.is_dir()
                        or member.file_size
                        > (MAX_ACS_ARTIFACT_BYTES if name == "checkpoints.ndjson" else MAX_ACS_EVIDENCE_BYTES)
                        or member.compress_size > MAX_ACS_ARTIFACT_BYTES
                        for name, member in zip(names, members, strict=True)
                    )
                    or bundle.testzip() is not None
                ):
                    raise DeploymentUnavailable("GitHub deployment evidence is malformed")
                evidence_bytes = bundle.read(ACS_EVIDENCE_ARTIFACT_PATH)
                live_bytes = bundle.read("acs-live-readiness.json")
        except (KeyError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
        if not 0 < len(evidence_bytes) <= MAX_ACS_EVIDENCE_BYTES:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        try:
            evidence = json.loads(evidence_bytes.decode("utf-8"))
            live_evidence = json.loads(live_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
        if not isinstance(evidence, dict) or not isinstance(live_evidence, dict):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        phase = evidence.get("phase")
        if not isinstance(phase, str):
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_path = {
            "foundation_bootstrap": "acs-verification-initiation.json",
            "foundation_finalize": "acs-finalize-readback.json",
            "workloads": None,
        }.get(phase, "invalid")
        expected_paths = {"checkpoints.ndjson", "acs-live-readiness.json", "acs-stage-result.json"}
        if isinstance(source_path, str) and source_path != "invalid":
            expected_paths.add(source_path)
        if source_path == "invalid" or set(names) != expected_paths:
            raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        source_evidence: dict[str, Any] | None = None
        if isinstance(source_path, str):
            try:
                with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                    source_evidence = json.loads(bundle.read(source_path).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, KeyError, zipfile.BadZipFile):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed") from None
            if not isinstance(source_evidence, dict):
                raise DeploymentUnavailable("GitHub deployment evidence is malformed")
        return {
            "artifact_sha256": artifact_digest,
            "stage_result": evidence,
            "live_readiness": live_evidence,
            "stage_source": source_evidence,
        }

    def preflight(self, environment: str) -> WorkflowPreflight:
        """Prove the fixed workflow revision and protected environment metadata."""

        if environment not in {"staging", "production"}:
            raise DeploymentUnavailable("the fixed workflow environment is invalid")
        repository_api = f"/repos/{self.configuration.repository}"
        encoded_ref = quote(self.configuration.ref, safe="")
        commit_payload = self._get_json(
            f"{repository_api}/commits/{encoded_ref}",
            purpose="configured deployment ref",
        )
        commit_sha = commit_payload.get("sha")
        if not isinstance(commit_sha, str) or _COMMIT_SHA.fullmatch(commit_sha) is None:
            raise DeploymentUnavailable("GitHub configured deployment ref metadata is malformed")

        workflow_payload = self._get_json(self._workflow_api(), purpose="deployment workflow")
        if workflow_payload.get("path") != WORKFLOW_PATH:
            raise DeploymentUnavailable("GitHub deployment workflow path does not match the fixed connector")
        if workflow_payload.get("state") != "active":
            raise DeploymentUnavailable("the fixed GitHub deployment workflow is disabled")
        workflow_id = workflow_payload.get("id")
        if not isinstance(workflow_id, int) or isinstance(workflow_id, bool) or not 0 < workflow_id <= 2**63 - 1:
            raise DeploymentUnavailable("GitHub deployment workflow metadata is malformed")

        content_payload = self._get_json(
            f"{repository_api}/contents/{WORKFLOW_PATH}",
            purpose="deployment workflow content",
            params={"ref": commit_sha},
        )
        encoded_content = content_payload.get("content")
        workflow_blob_sha = content_payload.get("sha")
        size = content_payload.get("size")
        if (
            content_payload.get("type") != "file"
            or content_payload.get("encoding") != "base64"
            or not isinstance(encoded_content, str)
            or len(encoded_content) > MAX_WORKFLOW_BYTES * 2
            or not isinstance(size, int)
            or not 0 < size <= MAX_WORKFLOW_BYTES
            or not isinstance(workflow_blob_sha, str)
            or _COMMIT_SHA.fullmatch(workflow_blob_sha) is None
        ):
            raise DeploymentUnavailable("GitHub deployment workflow content metadata is malformed")
        try:
            compact_content = "".join(encoded_content.split())
            workflow_content = base64.b64decode(compact_content, validate=True)
        except (ValueError, TypeError) as exc:
            raise DeploymentUnavailable("GitHub deployment workflow content is malformed") from exc
        if len(workflow_content) != size:
            raise DeploymentUnavailable("GitHub deployment workflow content size is inconsistent")
        workflow_content_sha256 = hashlib.sha256(workflow_content).hexdigest()
        if not secrets.compare_digest(workflow_content_sha256, EXPECTED_WORKFLOW_SHA256):
            raise DeploymentUnavailable("the configured ref does not contain the reviewed deployment workflow")
        try:
            workflow_text = workflow_content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DeploymentUnavailable("GitHub deployment workflow content is malformed") from exc
        missing_inputs = [name for name in REQUIRED_WORKFLOW_INPUTS if f"\n      {name}:" not in workflow_text]
        if missing_inputs:
            raise DeploymentUnavailable("the fixed deployment workflow input contract is incomplete")

        environment_payload = self._get_json(
            f"{repository_api}/environments/{environment}",
            purpose=f"protected {environment} environment",
        )
        if environment_payload.get("name") != environment:
            raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
        rules = environment_payload.get("protection_rules")
        admin_bypass_allowed = environment_payload.get("can_admins_bypass")
        if not isinstance(rules, list) or len(rules) > 20 or not isinstance(admin_bypass_allowed, bool):
            raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
        if admin_bypass_allowed:
            raise DeploymentUnavailable(f"the GitHub {environment} environment allows administrator approval bypass")
        normalized_rules: list[dict[str, Any]] = []
        required_reviewer_count = 0
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("type"), str) or len(rule["type"]) > 64:
                raise DeploymentUnavailable("GitHub protected environment metadata is malformed")
            normalized_rule: dict[str, Any] = {"type": rule["type"]}
            if rule["type"] == "required_reviewers":
                reviewers = rule.get("reviewers")
                prevent_self_review = rule.get("prevent_self_review")
                if not isinstance(reviewers, list) or len(reviewers) > 6 or not isinstance(prevent_self_review, bool):
                    raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                reviewer_keys: list[str] = []
                for reviewer in reviewers:
                    if not isinstance(reviewer, dict) or reviewer.get("type") not in {"User", "Team"}:
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    identity = reviewer.get("reviewer")
                    if not isinstance(identity, dict):
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    identity_key = identity.get("node_id", identity.get("id", identity.get("login")))
                    if (
                        not isinstance(identity_key, str | int)
                        or isinstance(identity_key, bool)
                        or len(str(identity_key)) > 256
                    ):
                        raise DeploymentUnavailable("GitHub protected environment reviewer metadata is malformed")
                    reviewer_keys.append(f"{reviewer['type']}:{identity_key}")
                required_reviewer_count += len(reviewer_keys)
                normalized_rule["reviewers"] = sorted(reviewer_keys)
                normalized_rule["prevent_self_review"] = prevent_self_review
                if not prevent_self_review:
                    raise DeploymentUnavailable(f"the GitHub {environment} environment allows reviewer self-approval")
            elif rule["type"] == "wait_timer":
                wait_timer = rule.get("wait_timer")
                if not isinstance(wait_timer, int) or isinstance(wait_timer, bool) or not 0 <= wait_timer <= 43_200:
                    raise DeploymentUnavailable("GitHub protected environment wait timer metadata is malformed")
                normalized_rule["wait_timer"] = wait_timer
            normalized_rules.append(normalized_rule)
        if required_reviewer_count < 1:
            raise DeploymentUnavailable(f"the GitHub {environment} environment has no required reviewer protection")
        branch_policy = environment_payload.get("deployment_branch_policy")
        if not isinstance(branch_policy, dict):
            raise DeploymentUnavailable("GitHub protected environment branch policy metadata is malformed")
        protected_branches = branch_policy.get("protected_branches")
        custom_branch_policies = branch_policy.get("custom_branch_policies")
        if not isinstance(protected_branches, bool) or not isinstance(custom_branch_policies, bool):
            raise DeploymentUnavailable("GitHub protected environment branch policy metadata is malformed")
        if not protected_branches and not custom_branch_policies:
            raise DeploymentUnavailable(f"the GitHub {environment} environment has no deployment branch protection")
        normalized_branch_policy = {
            "protected_branches": protected_branches,
            "custom_branch_policies": custom_branch_policies,
        }
        variables_payload = self._get_json(
            f"{repository_api}/environments/{environment}/variables",
            purpose=f"protected {environment} environment variables",
            params={"per_page": 100},
        )
        variables = variables_payload.get("variables")
        total_count = variables_payload.get("total_count")
        if (
            not isinstance(variables, list)
            or len(variables) > 100
            or not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count != len(variables)
            or any(not isinstance(variable, dict) for variable in variables)
        ):
            raise DeploymentUnavailable("GitHub protected environment variable metadata is malformed")
        protected_values: dict[str, str] = {}
        required_variables = {
            "TF_STATE_RESOURCE_GROUP",
            "TF_STATE_STORAGE_ACCOUNT",
            "TF_STATE_CONTAINER",
        }
        for variable in variables:
            name = variable.get("name")
            value = variable.get("value")
            if name not in required_variables:
                continue
            if name in protected_values or not isinstance(value, str) or len(value) > 128:
                raise DeploymentUnavailable("GitHub protected environment variable metadata is malformed")
            protected_values[str(name)] = value
        if set(protected_values) != required_variables:
            raise DeploymentUnavailable("GitHub protected environment Terraform state variables are incomplete")
        terraform_state_identity = {
            "resource_group": protected_values["TF_STATE_RESOURCE_GROUP"],
            "storage_account": protected_values["TF_STATE_STORAGE_ACCOUNT"],
            "container": protected_values["TF_STATE_CONTAINER"],
        }
        terraform_state_patterns = {
            "resource_group": r"[A-Za-z0-9_.()\-]{1,90}",
            "storage_account": r"[a-z0-9]{3,24}",
            "container": r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?",
        }
        if any(
            re.fullmatch(terraform_state_patterns[key], value) is None
            for key, value in terraform_state_identity.items()
        ):
            raise DeploymentUnavailable("GitHub protected environment Terraform state variables are malformed")
        protected_metadata = {
            "environment": environment,
            "can_admins_bypass": admin_bypass_allowed,
            "protection_rules": sorted(normalized_rules, key=lambda rule: json.dumps(rule, sort_keys=True)),
            "deployment_branch_policy": normalized_branch_policy,
            "terraform_state_identity": terraform_state_identity,
        }
        environment_metadata_sha256 = hashlib.sha256(
            json.dumps(protected_metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        return WorkflowPreflight(
            commit_sha=commit_sha,
            workflow_id=workflow_id,
            workflow_blob_sha=workflow_blob_sha,
            workflow_content_sha256=workflow_content_sha256,
            environment_metadata_sha256=environment_metadata_sha256,
            environment=environment,
            required_reviewer_count=required_reviewer_count,
            admin_bypass_allowed=admin_bypass_allowed,
            deployment_branch_policy_present=True,
            tf_state_resource_group=terraform_state_identity["resource_group"],
            tf_state_storage_account=terraform_state_identity["storage_account"],
            tf_state_container=terraform_state_identity["container"],
        )

    def recent_runs(self) -> list[dict[str, Any]]:
        runs: list[dict[str, Any]] = []
        seen_run_ids: set[int] = set()
        for page in range(1, MAX_RUN_PAGES + 1):
            payload = self._get_json(
                self._workflow_api("/runs"),
                params={"event": "workflow_dispatch", "per_page": RUNS_PER_PAGE, "page": page},
                purpose="workflow status",
                max_bytes=MAX_GITHUB_STATUS_BYTES,
                unavailable_message="GitHub workflow status is unavailable",
                malformed_message="GitHub workflow status is malformed",
                preserve_access_semantics=False,
            )
            rows = payload.get("workflow_runs") if isinstance(payload, dict) else None
            if (
                not isinstance(rows, list)
                or len(rows) > RUNS_PER_PAGE
                or any(not isinstance(row, dict) for row in rows)
            ):
                raise DeploymentUnavailable("GitHub workflow status is malformed")
            for row in rows:
                safe_run = self._safe_run(row)
                run_id = int(safe_run["run_id"])
                if run_id not in seen_run_ids:
                    seen_run_ids.add(run_id)
                    runs.append(safe_run)
            if len(rows) < RUNS_PER_PAGE:
                break
        return runs[:MAX_BASELINE_RUNS]

    def dispatch(self, inputs: dict[str, str]) -> None:
        try:
            with self._client.stream(
                "POST",
                self._workflow_api("/dispatches"),
                json={"ref": self.configuration.ref, "inputs": inputs},
            ) as response:
                status_code = response.status_code
        except httpx.RequestError:
            raise DispatchIndeterminate("GitHub dispatch outcome is unknown; inspect Actions before retrying") from None
        if status_code == 204:
            return
        # Only the documented, pre-dispatch GitHub rejection classes are safe
        # to retry. A timeout, rate-limit, or unfamiliar client-error response
        # can be observed after an intermediary or GitHub accepted the request,
        # so treating every 4xx as conclusive could duplicate a deployment.
        if status_code in {400, 401, 403, 404, 422}:
            raise DispatchRejected("GitHub rejected the fixed workflow dispatch")
        raise DispatchIndeterminate("GitHub dispatch outcome is unknown; inspect Actions before retrying")

    def run(self, run_id: int) -> dict[str, Any]:
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}",
            purpose="workflow run status",
            max_bytes=MAX_GITHUB_STATUS_BYTES,
            unavailable_message="GitHub workflow run status is unavailable",
            malformed_message="GitHub workflow run status is malformed",
            preserve_access_semantics=False,
        )
        return self._safe_run(payload)

    def activity(self, run_id: int) -> list[dict[str, str]]:
        """Return bounded job/step state, never raw workflow logs."""
        payload = self._get_json(
            f"/repos/{self.configuration.repository}/actions/runs/{run_id}/jobs",
            params={"filter": "latest", "per_page": 20},
            purpose="workflow activity",
            max_bytes=MAX_GITHUB_ACTIVITY_BYTES,
            unavailable_message="GitHub workflow activity is unavailable",
            malformed_message="GitHub workflow activity is unavailable",
            preserve_access_semantics=False,
        )
        jobs = payload.get("jobs")
        if not isinstance(jobs, list) or len(jobs) > 20 or any(not isinstance(job, dict) for job in jobs):
            raise DeploymentUnavailable("GitHub workflow activity is unavailable")
        activity: list[dict[str, str]] = []
        for job in jobs:
            safe_job = self._safe_activity("job", job)
            activity.append(safe_job)
            steps = job.get("steps")
            if isinstance(steps, list):
                if len(steps) > MAX_STEPS_PER_JOB or any(not isinstance(step, dict) for step in steps):
                    raise DeploymentUnavailable("GitHub workflow activity is unavailable")
                activity.extend(self._safe_activity("step", step, job_name=safe_job["name"]) for step in steps)
            if len(activity) > MAX_ACTIVITY:
                raise DeploymentUnavailable("GitHub workflow activity is unavailable")
        return activity

    def _safe_run(self, row: dict[str, Any]) -> dict[str, Any]:
        run_id = row.get("id")
        run_attempt = row.get("run_attempt", 1)
        status = row.get("status")
        conclusion = row.get("conclusion")
        workflow_id = row.get("workflow_id")
        event = row.get("event")
        head_sha = row.get("head_sha")
        created_at = row.get("created_at")
        html_url = row.get("html_url")
        display_title = row.get("display_title")
        if (
            not isinstance(run_id, int)
            or isinstance(run_id, bool)
            or not 0 < run_id <= 2**63 - 1
            or not isinstance(run_attempt, int)
            or isinstance(run_attempt, bool)
            or not 1 <= run_attempt <= 100
            or not isinstance(status, str)
            or status not in _RUN_STATUSES
            or not isinstance(workflow_id, int)
            or isinstance(workflow_id, bool)
            or not 0 < workflow_id <= 2**63 - 1
            or event != "workflow_dispatch"
            or not isinstance(head_sha, str)
            or _COMMIT_SHA.fullmatch(head_sha) is None
            or (status == "completed" and (not isinstance(conclusion, str) or conclusion not in _TERMINAL_RESULTS))
            or (status != "completed" and conclusion is not None)
        ):
            raise DeploymentUnavailable("GitHub returned an invalid workflow run")
        return {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "workflow_id": workflow_id,
            "event": event,
            "head_sha": head_sha,
            "status": status,
            "conclusion": conclusion,
            "created_at": created_at if isinstance(created_at, str) and len(created_at) <= 64 else None,
            "run_name": display_title if isinstance(display_title, str) and len(display_title) <= 64 else "",
            "url": html_url if self._safe_run_url(html_url, run_id) else self.workflow_url,
        }

    def _safe_run_url(self, value: Any, run_id: int) -> bool:
        if not isinstance(value, str) or len(value) > 512:
            return False
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.netloc == "github.com"
            and parsed.path == f"/{self.configuration.repository}/actions/runs/{run_id}"
            and not parsed.query
            and not parsed.fragment
        )

    @staticmethod
    def _safe_activity(kind: str, row: dict[str, Any], *, job_name: str = "") -> dict[str, str]:
        name = row.get("name")
        status = row.get("status")
        conclusion = row.get("conclusion")
        safe_name = re.sub(r"[^A-Za-z0-9 ._:/()\[\]-]", "?", name if isinstance(name, str) else kind)[:120]
        if _SENSITIVE_ACTIVITY.search(safe_name):
            safe_name = "[redacted activity name]"
        activity = {
            "kind": kind,
            "name": safe_name,
            "status": status if isinstance(status, str) and status in _ACTIVITY_STATUSES else "unknown",
            "conclusion": (conclusion if isinstance(conclusion, str) and conclusion in _TERMINAL_RESULTS else ""),
        }
        if kind == "step":
            activity["job"] = job_name[:120]
        return activity


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
            except Exception as exc:  # noqa: BLE001 - close every owned resource before reporting
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
